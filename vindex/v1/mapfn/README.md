# Sub-Design: WASM MapFn Plugin SDK & Host Runtime

## 1. Context & Objectives

A Verifiable Index (VIndex) indexes arbitrary append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB). Because log leaf payload schemas vary across ecosystems, VIndex decouples log ingestion from indexing semantics through pluggable **Map Functions (`MapFn`)**.

The **WASM MapFn Plugin SDK & Host Runtime** (`vindex/v1/mapfn`) defines the sandboxed WebAssembly execution environment, the guest-host Application Binary Interface (ABI), memory management lifecycle, multi-language guest SDKs, and offline verification tooling.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            vindexd Ingestion Plane                          │
│                                                                             │
│  [LeafBundle (256 leaves)]                                                  │
│         │                                                                   │
│         ▼                                                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ SandboxPool (max(1, GOMAXPROCS-1) Wazero Instances)                   │  │
│  │                                                                       │  │
│  │   Guest WASM Instance (Linear Memory ≤ 16 MB, Timeout ≤ 100ms)        │  │
│  │   ┌───────────────────────────────────────────────────────────────┐   │  │
│  │   │ 1. Host writes leaf bytes ──► inputBuf [allocate(len)]        │   │  │
│  │   │ 2. Host calls ──────────────► map_leaf(ptr, len)              │   │  │
│  │   │ 3. Guest extracts & hashes ─► outputBuf (N * 32B SHA-256)     │   │  │
│  │   │ 4. Host reads (ptr, len) ───► returns (out_ptr << 32)|out_len │   │  │
│  │   │ 5. Host calls (optional) ───► reset()                         │   │  │
│  │   └───────────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│  [Host Post-Processing: Validate out_len % 32 == 0, Sort, Deduplicate]      │
│                                     │                                       │
│                                     ▼                                       │
│  [MappedBatch -> Resequencer -> KVIndexer]                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Core Principles & Sandboxing Guarantees

1. **Deterministic Hermetic Execution**: Pure Go WebAssembly runtime via [Wazero](https://wazero.io/) with zero cgo dependencies. Every invocation of `map_leaf` on identical input bytes produces identical output key hashes across all CPU architectures and operating systems.
2. **Strict Sandboxed Isolation**: Guest modules operate with zero host capabilities:
   - **Zero Network**: No socket access or network syscalls.
   - **Zero Filesystem**: No access to host disk, directories, or files.
   - **Zero Host Clocks**: System time returns a deterministic constant (e.g. Unix epoch 0); no access to monotonic or real-time clocks.
   - **Zero Host RNG**: Random sources return deterministic pseudorandom or zeroed bytes.
3. **Stateless Invocations**: `MapFn` is pure and stateless. No mutable state persists inside guest modules across consecutive leaves.
4. **Key-Only Indexing & Claim Subjects**: VIndex v1 indexes 32-byte cryptographic hashes of **Claim Subjects** (`KeyHash = SHA256(CanonicalSubjectBytes)`). Values are not stored in the index; clients resolve full payloads by querying the Input Log at the returned leaf index. Host runtime performs no schema guessing or dynamic type reflection. To guarantee discoverability, guest modules and client verifiers should adhere to consistent domain-specific canonicalization rules (case folding, Punycode, trailing dot stripping) as specified in [APPLICATIONS.md](../docs/APPLICATIONS.md#claim-subject-maps--pre-image-canonicalization) and [Claim Subject Maps](../docs/APPLICATIONS.md#recommended-canonicalization-guidelines).

### 1.2 Non-Requirements & Out of Scope

- **No Value Storage in Index**: VIndex v1 maps keys to Input Log sequence numbers (`KeyHash -> []LeafIndex`). Storing arbitrary payloads or secondary attributes inside index chunks is out of scope.
- **No Complex / Predicate Querying**: Cross-key range scans, regular expressions, full-text parsing, and boolean filtering (AND/OR) are out of scope. Point lookups on exact 32-byte key hashes only.
- **No In-Guest Signature / Proof Verification**: Cryptographic validation of log checkpoints, tree tiles, and leaf Merkle inclusion is performed by the host ingestion pipeline (`filippo.io/torchwood`) prior to invoking `MapFn`.

---

## 2. WASM ABI & Memory Management Protocol

Mathematically, a Map Function is a pure, deterministic function `f(leaf_bytes) -> []KeyHash`, mapping an arbitrary byte slice `leaf_bytes` (such as an X.509 certificate, package record, or checkpoint) to a sequence of 32-byte cryptographic hashes `[]KeyHash`, where each `KeyHash = SHA256(canonical_subject)`. `MapFn` contains zero side effects, accesses no external state, and satisfies referential transparency: for any input `b`, `f(b)` is invariant across time, platform, and runtime execution.

The WASM ABI defines the low-level calling convention, 64-bit register bit packing, and memory layout between the Go host and guest plugins.

### 2.1 Exported Function Signatures

Every compliant `MapFn` WASM module MUST export `map_leaf` and `allocate` (or `malloc`). It MAY optionally export `reset`.

| Export Name | Signature | Required | Description |
| :--- | :--- | :--- | :--- |
| `map_leaf` | `(ptr: i32, len: i32) -> i64` | **Mandatory** | Maps input leaf bytes at `ptr` of length `len`. Returns packed `(out_ptr << 32) \| out_len`. |
| `allocate` / `malloc` | `(size: i32) -> i32` | **Mandatory** | Allocates `size` bytes in guest linear memory and returns pointer offset. |
| `reset` | `() -> ()` | Optional | Clears guest scratch arenas between leaves without instance re-instantiation. |

### 2.2 Calling Convention & Return Value Encoding

```text
                 64-bit Return Value (uint64)
 ┌──────────────────────────────┬──────────────────────────────┐
 │     out_ptr (Upper 32 bits)  │     out_len (Lower 32 bits)  │
 ├──────────────────────────────┼──────────────────────────────┤
 │  Bits 63 .. 32               │  Bits 31 .. 0                │
 └──────────────────────────────┴──────────────────────────────┘
```

1. **Input Delivery**:
   - Host calls `allocate(leaf_len)` to obtain `input_ptr`.
   - Host writes raw leaf bytes directly into guest linear memory at `[input_ptr .. input_ptr + leaf_len)`.
   - Host calls `map_leaf(input_ptr, leaf_len)`.
2. **Output Unpacking**:
   - Guest returns a packed 64-bit unsigned integer `ret`.
   - `out_ptr = uint32(ret >> 32)`
   - `out_len = uint32(ret & 0xFFFFFFFF)`
3. **Empty Set / Filter Match**:
   - Returning `ret = 0` (or `(0 << 32) | 0`) signals that the leaf contains no indexable keys or was filtered out. This is a valid, non-error result.

### 2.3 Memory Allocation Contract

- **Mandatory Allocation Export**: Guest modules MUST export `allocate(size: uint32) -> uint32` (or standard C `malloc`).
- **Guest Memory Base Offset Invariant**: Guest allocators (bump pointers or arena allocators) MUST initialize heap memory arenas at an offset `> 0` (e.g. starting heap offsets at byte 8 or 64). Offset `0` is reserved exclusively as an allocation failure indicator (null pointer).
- **No Offset-0 Fallback**: The host runtime **strictly forbids** falling back to offset `0` when `allocate` is missing or fails. If `allocate` returns offset `0` for `size > 0`, the host treats this as an out-of-memory violation and triggers `ErrInvalidMemory` with a deterministic `HALT`.

### 2.4 Memory Lifecycle & Arena Management (`reset`)

To achieve maximum mapping throughput without garbage collection overhead or per-leaf instance re-instantiation:
1. **Arena / Scratch Allocation**: Guests allocate fixed scratch buffers (`inputBuf`, `outputBuf`) or use a fast bump allocator.
2. **`reset()` Export**: If exported, the host calls `reset()` immediately after reading the output of `map_leaf`. The guest resets its internal bump pointer to 0.
3. **Fallback without `reset()`**: If `reset()` is omitted, the guest must manage buffer reuse internally or allocate dynamically within the 16 MB memory cap.

### 2.5 Output Contract & Validation

```text
 ┌──────────────────────────────┬──────────────────────────────┬───┐
 │ KeyHash 0 (32 Bytes SHA-256) │ KeyHash 1 (32 Bytes SHA-256) │...│
 └──────────────────────────────┴──────────────────────────────┴───┘
 ◄────────────────────── out_len (k * 32 Bytes) ───────────────────►
```

- **Binary Layout**: Output memory at `[out_ptr .. out_ptr + out_len)` MUST contain a contiguous slice of 32-byte SHA-256 key hashes.
- **Alignment Invariant**: `out_len` MUST be an exact multiple of 32 bytes (`out_len % 32 == 0`), representing `k = out_len / 32` unique keys.
- **Bounds Invariant**: The range `[out_ptr .. out_ptr + out_len)` MUST reside entirely within the module's allocated linear memory boundary (`out_ptr + out_len <= memory.Size()`).
- **Host Post-Processing**: The host runtime reads raw hashes, sorts them lexicographically via `bytes.Compare`, and deduplicates them using `slices.Compact`. This guarantees that every leaf emits strictly unique, sorted key hashes downstream.

---

## 3. Host Runtime & Wazero Integration

The host runtime embeds Wazero to manage compiled module caching, sandbox instantiation, and pool execution.

### 3.1 Wazero Initialization & Hermetic WASI

Wazero is configured in pure Go (zero cgo) with a fully hermetic `wasi_snapshot_preview1` environment:

```go
// Hermetic WASI configuration with zero host capabilities
wasiConfig := wazero.NewModuleConfig().
    WithStdout(io.Discard).
    WithStderr(io.Discard).
    WithStdin(nil).
    WithArgs().
    WithEnv().
    WithSysWalltime(func() (sec int64, nsec int32) { return 0, 0 }).
    WithSysNanotime(func() int64 { return 0 }).
    WithSysNanosleep(func(int64) {}).
    WithRandSource(bytes.NewReader(make([]byte, 1024)))
```

### 3.2 Concurrency & Instance Pool

- **Pool Sizing**: Strictly partitioned to `max(1, GOMAXPROCS - 1)` reusable WASM module instances.
- **Dedicated CPU Reservation**: Exactly 1 CPU core is reserved for database commits (`KVIndexer`), MPT root publishing (`OutputPublisher`), and live read serving (`server.Server`).
- **Module Caching**: The WASM bytecode is compiled once via `runtime.CompileModule(ctx, wasmBytes)` and instantiated concurrently across workers.

```go
type SandboxPool struct {
    runtime  wazero.Runtime
    compiled wazero.CompiledModule
    pool     chan wazero.api.Module
}
```

### 3.3 Resource Bounds & Guardrails

1. **Linear Memory Cap**: Hard cap of 16 MB linear memory (256 pages of 64 KB). Any guest attempt to grow memory beyond 16 MB triggers an immediate memory trap.
2. **CPU Execution Timeout**: Per-leaf execution deadline of 100ms enforced via Go context cancellation (`context.WithTimeout(ctx, 100*time.Millisecond)`).

### 3.4 Deterministic Error & `HALT` Policy

To prevent witness divergence or silent index corruption, VIndex enforces a strict **Deterministic HALT Policy**:

```text
Any Mapping Fault (Trap / Timeout / OutOfBounds / Unaligned)
                     │
                     ▼
       Log Diagnostic Post-Mortem Context
                     │
                     ▼
      Freeze Pipeline & Read Pointer (Serving_Size)
                     │
                     ▼
         Set Readiness Probe /readyz -> HTTP 503
                     │
                     ▼
                 Daemon HALT
```

The host halts on:
- **Unhandled Guest Trap**: Unreachable instruction, integer divide-by-zero, nil pointer deference, or panic inside guest code.
- **Memory Violation**: `out_ptr + out_len` exceeding linear memory bounds or `allocate` returning offset 0 for non-zero length.
- **Unaligned Output**: `out_len % 32 != 0`.
- **Execution Timeout**: Per-leaf CPU execution exceeding 100ms.
- **Recovery Failure**: Inability to re-instantiate a clean WASM instance during pool recovery.

### 3.5 Graceful Shutdown

During shutdown (`Pipeline.Close()`), the host drains in-flight map operations, closes all instantiated guest modules, and releases the compiled module and runtime without nil-pointer dereferences.

---

## 4. Guest SDK Architecture & Developer Flow

Plugin developers can author `MapFn` modules in Go, TinyGo, or Rust.

### 4.1 Zero-Allocation Scratch Buffer Strategy

To eliminate memory allocation overhead, plugins should declare static pre-allocated buffers in guest linear memory:

```text
Guest Linear Memory
┌──────────────────────────────────────┬──────────────────────────────────────┐
│  inputBuf (e.g. 64 KB static arena)  │  outputBuf (e.g. 8 KB static hashes) │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

1. `allocate(size)` returns the fixed address of `inputBuf` (if `size <= sizeof(inputBuf)`).
2. `map_leaf` processes bytes directly inside `inputBuf` and writes 32-byte SHA-256 hashes into `outputBuf`.
3. `map_leaf` returns `(outputBuf_ptr << 32) | (num_keys * 32)`.

### 4.2 Go Implementation (`wasip1`)

Standard Go (`GOOS=wasip1 GOARCH=wasm`) requires blocking the main goroutine during module initialization to keep the reactor alive:

```go
//go:build wasip1

package main

import (
	"crypto/sha256"
	"unsafe"
)

// ============================================================================
// 1. WASM ABI & Memory Management Boilerplate
// ============================================================================

var (
	inputBuf  [65536]byte
	outputBuf [8192]byte
)

//export allocate
func allocate(size uint32) uint32 {
	if int(size) > len(inputBuf) {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
}

//export map_leaf
func mapLeaf(ptr, length uint32) uint64 {
	data := inputBuf[:length]
	
	// Delegate to domain-specific key extraction logic
	keys := extractSearchKeys(data)
	if len(keys) == 0 {
		return 0
	}

	outPtr := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	var outOffset int

	for _, k := range keys {
		h := sha256.Sum256([]byte(k))
		copy(outputBuf[outOffset:outOffset+32], h[:])
		outOffset += 32
	}

	return (uint64(outPtr) << 32) | uint64(outOffset)
}

//export reset
func reset() {
	// Zero scratch state if needed
}

func main() {
	// Block main to maintain wasip1 reactor lifecycle
	select {}
}

// ============================================================================
// 2. Custom Key Extraction Business Logic
// ============================================================================

// extractSearchKeys parses domain-specific payload bytes and extracts canonical search keys.
// Adhere to canonicalization rules defined in docs/APPLICATIONS.md.
func extractSearchKeys(data []byte) []string {
	// Example: Extract subject domain name, package path, or artifact digest
	// Return canonicalized string identifiers to be hashed as SHA256(canonical_subject)
	return []string{string(data)}
}
```

Compilation:
```bash
GOOS=wasip1 GOARCH=wasm go build -o mapfn.wasm main.go
```

### 4.3 TinyGo Implementation (`-target=wasi`)

TinyGo generates ultra-compact WASM binaries (< 50 KB) with minimal startup latency:

```go
//go:build tinygo

package main

import (
	"crypto/sha256"
	"unsafe"
)

// ============================================================================
// 1. WASM ABI & Memory Management Boilerplate
// ============================================================================

var (
	inputBuf  [65536]byte
	outputBuf [8192]byte
)

//export allocate
func allocate(size uint32) uint32 {
	if int(size) > len(inputBuf) {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
}

//export map_leaf
func mapLeaf(ptr, length uint32) uint64 {
	data := inputBuf[:length]
	
	// Delegate to domain-specific key extraction logic
	keys := extractSearchKeys(data)
	if len(keys) == 0 {
		return 0
	}

	outPtr := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	var outOffset int

	for _, k := range keys {
		h := sha256.Sum256([]byte(k))
		copy(outputBuf[outOffset:outOffset+32], h[:])
		outOffset += 32
	}

	return (uint64(outPtr) << 32) | uint64(outOffset)
}

//export reset
func reset() {
	// Zero scratch state if needed
}

func main() {}

// ============================================================================
// 2. Custom Key Extraction Business Logic
// ============================================================================

// extractSearchKeys parses domain-specific payload bytes and extracts canonical search keys.
// Adhere to canonicalization rules defined in docs/APPLICATIONS.md.
func extractSearchKeys(data []byte) []string {
	// Example: Extract subject domain name, package path, or artifact digest
	return []string{string(data)}
}
```

Compilation:
```bash
tinygo build -o mapfn.wasm -target=wasi -no-debug -opt=2 main.go
```

### 4.4 Rust Implementation (`wasm32-wasip1` / `wasm32-unknown-unknown`)

```rust
use std::slice;
use sha2::{Sha256, Digest};

// ============================================================================
// 1. WASM ABI & Memory Management Boilerplate
// ============================================================================

static mut INPUT_BUF: [u8; 65536] = [0; 65536];
static mut OUTPUT_BUF: [u8; 8192] = [0; 8192];

#[no_mangle]
pub extern "C" fn allocate(size: u32) -> u32 {
    if size as usize > unsafe { INPUT_BUF.len() } {
        return 0;
    }
    unsafe { INPUT_BUF.as_ptr() as u32 }
}

#[no_mangle]
pub extern "C" fn map_leaf(ptr: u32, len: u32) -> u64 {
    let input = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    
    // Delegate to domain-specific key extraction logic
    let keys = extract_search_keys(input);
    if keys.is_empty() {
        return 0;
    }

    let mut out_len = 0;
    unsafe {
        for key in keys {
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let hash = hasher.finalize();
            OUTPUT_BUF[out_len..out_len + 32].copy_from_slice(&hash);
            out_len += 32;
        }
        let out_ptr = OUTPUT_BUF.as_ptr() as u32;
        ((out_ptr as u64) << 32) | (out_len as u64)
    }
}

#[no_mangle]
pub extern "C" fn reset() {
    // Clear scratch arenas if needed
}

// ============================================================================
// 2. Custom Key Extraction Business Logic
// ============================================================================

/// extract_search_keys parses domain-specific payload bytes and extracts canonical search keys.
/// Adhere to canonicalization rules defined in docs/APPLICATIONS.md.
fn extract_search_keys(data: &[u8]) -> Vec<String> {
    // Example: Parse X.509 certificate, package record, or provenance payload
    // Return canonicalized string identifiers to be hashed as SHA256(canonical_subject)
    match std::str::from_utf8(data) {
        Ok(s) => vec![s.to_string()],
        Err(_) => vec![],
    }
}
```

Compilation:
```bash
cargo build --target wasm32-wasip1 --release
```

---

## 5. Testing & Verification Harness (`vindex-map` CLI)

The `vindex-map` CLI tool provides standalone offline testing, deterministic verification, and performance profiling for WASM plugins prior to production deployment.

### 5.1 Tool Capabilities

```text
vindex-map <subcommand> [flags]

Subcommands:
  test                Run mapping on sample leaf or tile files and inspect extracted keys.
  verify-determinism  Execute repeated runs across isolated sandboxes to verify byte-for-byte consistency.
  bench               Benchmark mapping throughput (leaves/sec) and memory utilization.
```

### 5.2 Subcommands & CLI Workflows

#### 1. Standalone Leaf / Tile Testing (`test`)
Executes `MapFn` on a single leaf or 256-leaf entry tile and outputs extracted key hashes:

```bash
vindex-map test \
  --wasm=plugins/ct_map.wasm \
  --input=testdata/leaf_001.bin \
  --format=hex
```

Output:
```text
=== Leaf 0 (Length: 1420 bytes) ===
Extracted Keys: 2
  Key[0]: "example.com"
          Hash: 5ababd3... (32 bytes)
  Key[1]: "*.example.com"
          Hash: 8bc41fa... (32 bytes)
Status: OK (out_len: 64 bytes, alignment: 32B aligned)
```

#### 2. Determinism & Isolation Verification (`verify-determinism`)
Executes `N` iterations across randomized goroutines and separate module instantiations to ensure zero divergence:

```bash
vindex-map verify-determinism \
  --wasm=plugins/sumdb_map.wasm \
  --input=testdata/sample_bundle.bin \
  --runs=10000 \
  --concurrency=8
```

Output:
```text
[✓] Verified 10,000 runs across 8 workers.
[✓] 0 hash divergences detected.
[✓] Memory bounds and alignments asserted.
Determinism: PASSED
```

#### 3. Latency & Throughput Benchmark (`bench`)
Profiles per-leaf latency and sustained throughput:

```bash
vindex-map bench \
  --wasm=plugins/ct_map.wasm \
  --input=testdata/sample_tile_bundle.bin \
  --duration=30s \
  --concurrency=7
```

Output:
```text
Throughput:         284,520 leaves/sec
P50 Latency:        2.4 µs
P90 Latency:        4.1 µs
P99 Latency:        8.7 µs
Peak Linear Memory: 64 KB / instance
Allocations / Leaf: 0
```

---

## 6. Security & Invariant Reference Table

| Invariant / Condition | Threat / Risk | Host Enforcement Action |
| :--- | :--- | :--- |
| **Output Alignment** (`out_len % 32 == 0`) | Malformed or corrupted key hash emitted by guest. | Immediate `HALT`. Emits `ErrUnalignedOutput`. |
| **Linear Memory Boundary** | Guest returns pointer out of linear bounds. | Immediate `HALT`. Emits `ErrInvalidMemory`. |
| **No-Zero Offset Allocation** | Host writes input to offset 0 on failed `allocate`. | Immediate `HALT`. Prohibits offset 0 fallback. |
| **16 MB Linear Memory Cap** | Guest memory leak or unbounded memory growth. | Wazero runtime memory trap and immediate `HALT`. |
| **100ms CPU Execution Limit** | Infinite loop or denial-of-service in guest. | Context cancellation and immediate `HALT`. |
| **Hermetic WASI Isolation** | Guest attempts network, filesystem, or clock access. | Wazero traps on non-whitelisted syscalls; dummy deterministic clocks. |
| **Stateless Execution** | Cross-leaf pollution causing non-deterministic output. | Enforced by optional `reset()` arena clearing and host validation. |
| **Key-Only Indexing** | Schema mismatch or unbounded payload storage. | Fixed 32-byte key hash contract; payload stored strictly in Input Log. |
