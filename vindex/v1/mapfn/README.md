# Sub-Design: WASM MapFn Plugin SDK & Host Runtime

## 1. Context & Objectives

A Verifiable Index (VIndex) indexes arbitrary append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB). Because log leaf payload schemas vary across ecosystems, VIndex decouples log ingestion from indexing semantics through pluggable **Map Functions (`MapFn`)**.

The **WASM MapFn Plugin SDK & Host Runtime** (`vindex/v1/mapfn`) defines the sandboxed WebAssembly execution environment, the guest-host Application Binary Interface (ABI), memory management lifecycle, multi-language guest SDKs, host hardware cryptography pipeline, and offline verification tooling.

### 1.1 Closed-Loop Telemetry & Architectural Evolution

The Plan of Record (PoR) `map_bundle` ABI was established following empirical CPU profiling of per-leaf WASM invocations on production-scale datasets (54M-leaf SumDB and 10M-leaf CT):

1. **FFI Boundary Elimination (~23% CPU -> < 1% CPU)**:
   - *Baseline*: Mapping entries leaf-by-leaf executed 3 FFI calls (`allocate`, `map_leaf`, `reset`) per leaf—totaling **768 FFI transitions per 256-leaf tile**. Parameter marshaling and WASM boundary crossings consumed ~23% of total ingestion CPU time.
   - *PoR*: Bundling tile execution (`map_bundle`) passes all 256 leaves in a single structured buffer, reducing FFI transitions to **2–3 calls per tile** and cutting FFI overhead to **< 1% of CPU time**.
2. **Elimination of In-Guest Software Crypto (~55% CPU -> Hardware Acceleration)**:
   - *Baseline*: Compiling software SHA-256 into WASM bytecode prevented the guest from accessing host CPU SIMD cryptographic instructions, consuming ~55% of total CPU time in pure software hashing.
   - *PoR*: Guest plugins extract and emit raw canonical Claim Subject preimages (e.g. domain strings, module paths). The Go host runtime computes `KeyHash = SHA256(canonical_preimage)` using Go's standard `crypto/sha256`, which utilizes hardware-accelerated instructions (**x86 SHA-NI** or **ARMv8 Crypto** extensions).
3. **Future Prefix-Trie & Subtree Indexing**:
   - Emitting raw canonical preimages allows the host to retain original string identifiers for future prefix-trie / subtree indexing without requiring guest plugin ABI changes.

### 1.2 Core Principles & Sandboxing Guarantees

1. **Deterministic Hermetic Execution**: Pure Go WebAssembly runtime via [Wazero](https://wazero.io/) with zero cgo dependencies. Every invocation of `map_bundle` on identical input bytes produces identical output across all CPU architectures and operating systems.
2. **Strict Sandboxed Isolation**: Guest modules operate with zero host capabilities:
   - **Zero Network**: No socket access or network syscalls.
   - **Zero Filesystem**: No access to host disk, directories, or files.
   - **Zero Host Clocks**: System time returns a deterministic constant (Unix epoch 0); no access to monotonic or real-time clocks.
   - **Zero Host RNG**: Random sources return deterministic pseudorandom or zeroed bytes.
3. **Stateless Invocations**: `MapFn` is pure and stateless. No mutable state persists inside guest modules across consecutive tiles.
4. **Canonical Preimages & Claim Subjects**: Guest modules output canonical byte slices of **Claim Subjects** (domain names, package paths, digests). To guarantee discoverability, guest modules and client verifiers adhere to domain-specific canonicalization rules as specified in [APPLICATIONS.md](../docs/APPLICATIONS.md).

---

## 2. WASM ABI & Memory Management Protocol

The WASM ABI defines the low-level calling convention, 64-bit register packing, and binary serialization framing between the Go host and guest plugins.

### 2.1 Exported Function Signatures

Every compliant `MapFn` WASM module MUST export `map_bundle` and `allocate` (or `malloc`). It MAY optionally export `reset`.

| Export Name | Signature | Required | Description |
| :--- | :--- | :--- | :--- |
| `map_bundle` | `(ptr: i32, len: i32) -> i64` | **Mandatory** | Maps a bundled tile/slice of N leaves (1 <= N <= 256) at `ptr` of length `len`. Returns packed `(out_ptr << 32) \| out_len`. |
| `allocate` / `malloc` | `(size: i32) -> i32` | **Mandatory** | Allocates `size` bytes in guest linear memory and returns pointer offset (`> 0`). |
| `reset` | `() -> ()` | Optional | Clears guest scratch arenas between tiles without re-instantiation. |

### 2.2 Calling Convention & Return Value Encoding

| Bits | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `63 .. 32` | `out_ptr` | Upper 32-bit `uint32` | Pointer to output buffer in guest linear memory |
| `31 .. 0` | `out_len` | Lower 32-bit `uint32` | Length in bytes of output buffer in guest linear memory |

1. **Input Delivery**:
   - Host packs N leaves (1 <= N <= 256) into the binary input layout.
   - Host calls `allocate(input_len)` to obtain `input_ptr`.
   - Host writes bundled bytes directly into guest linear memory at `[input_ptr .. input_ptr + input_len)`.
   - Host calls `map_bundle(input_ptr, input_len)`.
2. **Output Unpacking**:
   - Guest returns a packed 64-bit unsigned integer `ret`.
   - `out_ptr = uint32(ret >> 32)`
   - `out_len = uint32(ret & 0xFFFFFFFF)`
3. **Empty Output**:
   - If no leaves in the bundle produce keys, `out_len` will equal `4 + N*4` bytes (with all key counts equal to 0), or returning `ret = 0` signals an empty bundle.

### 2.3 Binary Input Buffer Layout (Offset Array Framing)

The host serializes N contiguous leaves (1 <= N <= 256) into a contiguous linear memory buffer using a prefix-sum offset array:

| Field | Type / Size | Description |
| :--- | :--- | :--- |
| `leaf_count` | 4 Bytes (`uint32`) | Number of leaves in bundle (`1 <= N <= 256`). |
| `offsets` | `(N + 1) * 4` Bytes (`[N+1]uint32`) | Offsets relative to payload start. |
| `contiguous_leaf_bytes` | Variable length | Concatenated raw leaf payload bytes. |

- `leaf_count`: 4 bytes little-endian integer (`uint32`), representing `N` leaves in the bundle (`1 <= N <= 256`). Full tiles have `N = 256`; partial tiles at unaligned checkpoint boundaries or the log head have `1 <= N < 256`.
- `offsets`: `(N + 1)` little-endian `uint32` values (`(N + 1) * 4` bytes).
  - `offsets[i]` is the byte offset where leaf `i` starts within `contiguous_leaf_bytes`.
  - `offsets[i+1]` is the byte offset where leaf `i` ends.
  - Leaf `i` length is `offsets[i+1] - offsets[i]`.
  - `offsets[0] == 0`, and `offsets[N]` equals the total length of `contiguous_leaf_bytes`.
- `contiguous_leaf_bytes`: Raw payload bytes of all `N` leaves concatenated without delimiters.

### 2.4 Binary Output Buffer Layout (Preimage Framing)

The guest SDK serializes extracted canonical preimages into guest memory using structured length-prefixed framing:

| Field | Type / Size | Description |
| :--- | :--- | :--- |
| `leaf_count` | 4 Bytes (`uint32`) | Number of leaves in bundle (must match input `leaf_count == N`). |
| `key_counts` | `N * 4` Bytes (`[N]uint32`) | Number of canonical keys `K_i` emitted for each leaf `i` (`0 .. N-1`). |
| `framed_key_preimages` | Variable length | Sequential length-prefixed preimages (`key_len: uint32` + `key_bytes`). |

- `leaf_count`: 4 bytes little-endian `uint32` (asserted by host to match input `leaf_count == N`).
- `key_counts`: Array of `N` little-endian `uint32` values (`N * 4` bytes). `key_counts[i]` specifies the number of canonical search keys `K_i` emitted for leaf `i`.
- `framed_key_preimages`: Sequential length-prefixed preimages for all keys across all `N` leaves:
  - For each key: `key_len` (4 bytes little-endian `uint32`) followed immediately by `key_bytes` (raw UTF-8 / ASCII canonical bytes).
- **1:1 Alignment Guarantee**: The output layout strictly preserves the 1:1 positional correspondence between input leaves (`0 .. N-1`) and output key sets, enabling the host to index each key to its exact leaf index (`StartLeafIdx + i`).

### 2.5 Memory Allocation Contract & Arena Management

- **Mandatory Allocation Export**: Guest modules MUST export `allocate(size: uint32) -> uint32` (or `malloc`).
- **Base Offset Invariant**: Guest allocators MUST initialize memory arenas at an offset `> 0` (e.g., offset 64). Offset `0` is reserved exclusively as an allocation failure indicator. The host **strictly forbids** writing to offset 0 and will trigger `ErrInvalidMemory` with a deterministic `HALT`.
- **Scratch Arena Bump Allocator & `reset()`**:
  - The SDK harness uses a static scratch arena bump pointer for input and output buffers.
  - On each `map_bundle` execution, buffers are filled and parsed.
  - Immediately after reading output bytes, the host invokes `reset()`, which resets the guest's internal bump allocator offset back to base in O(1) time with zero memory fragmentation.

---

## 3. Host Runtime & Wazero Integration

The host runtime embeds Wazero to manage compiled module caching, sandbox instantiation, and pool execution.

### 3.1 Wazero Initialization & Hermetic WASI

Wazero is configured in pure Go (zero cgo) with a fully hermetic `wasi_snapshot_preview1` environment:

```go
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

### 3.2 Host-Side Hardware SHA-256 & Sorting Pipeline

Upon receiving the raw preimage buffer from `map_bundle`:
1. **Validation**: Asserts `1 <= leaf_count <= 256` (matching input bundle count) and verifies that all length prefixes and payload offsets fall strictly within `[out_ptr .. out_ptr + out_len)`.
2. **Hardware Cryptographic Hashing**: For each extracted preimage string/bytes:
   ```go
   keyHash := sha256.Sum256(canonicalPreimageBytes)
   ```
   On modern x86-64 and ARM64 CPUs, Go's `crypto/sha256` automatically utilizes hardware SIMD acceleration (**Intel SHA-NI** or **ARMv8 Cryptography Extensions**), processing gigabytes of preimages per second.
3. **Sorting & Deduplication**:
   - Hashes for each leaf are sorted lexicographically via `bytes.Compare`.
   - Hashes are deduplicated via `slices.Compact`.
   - The host associates each unique `KeyHash` with its absolute Input Log leaf index: `leafIdx = StartLeafIdx + uint64(i)`.

### 3.3 Concurrency, Instance Pooling & Sizing

- **Pool Sizing**: Strictly partitioned to `max(1, GOMAXPROCS - 1)` reusable WASM module instances.
- **Dedicated CPU Reservation**: Exactly 1 CPU core is reserved for database commits (`KVIndexer`), MPT root publishing (`OutputPublisher`), and live read serving (`server.Server`).
- **Memory Footprint**: Each guest instance requires ~4 MB of linear memory (64 WASM pages), allowing 24–64 parallel workers to run within < 256 MB of RAM.

```go
type SandboxPool interface {
    MapBundle(ctx context.Context, leaves [][]byte) ([][][sha256.Size]byte, error)
    Close(ctx context.Context) error
}
```

### 3.4 Resource Bounds & Deterministic `HALT` Policy

1. **Linear Memory Cap**: Hard cap of 16 MB linear memory (256 pages of 64 KB). Any guest attempt to grow memory beyond 16 MB triggers an immediate memory trap.
2. **CPU Execution Timeout**: Per-bundle execution deadline of 100ms enforced via Go context cancellation (`context.WithTimeout(ctx, 100*time.Millisecond)`).
3. **Deterministic HALT Policy**: Any guest panic, unhandled trap, linear memory violation, or timeout triggers an immediate daemon `HALT` to prevent unverified witness state divergence.

---

## 4. Guest SDK Architecture & Developer Contract

### 4.1 The Developer Contract

To author a plugin, the developer does **not** write low-level buffer parsing, offset arithmetic, or WASM ABI register packing. Instead, the developer writes a pure single-leaf mapping function:

- **Go / TinyGo**: `func Map(leaf []byte) []string` (or `[][]byte`)
- **Rust**: `fn map(leaf: &[u8]) -> Vec<String>` (or `Vec<Vec<u8>>`)

The **SDK Harness** (provided by `vindex/v1/mapfn`) automatically injects:
1. The exported `map_bundle`, `allocate`, and `reset` entry points.
2. Binary input buffer unmarshaling across the 256-leaf offset array.
3. The sequential execution loop invoking `Map(leaf)`.
4. Output preimage length-prefixed binary framing.
5. Bump allocator scratch arena management for zero GC allocations.

---

### 4.2 Go Implementation (`wasip1`)

Complete, compilable Go SDK harness using standard Go (`GOOS=wasip1 GOARCH=wasm`):

```go
//go:build wasip1

package main

import (
	"encoding/binary"
	"unsafe"
)

// ============================================================================
// 1. Single-Leaf Mapping Business Logic (Developer Implements This)
// ============================================================================

// Map extracts canonical Claim Subject preimages from a single log leaf.
// Adhere to canonicalization rules in docs/APPLICATIONS.md.
func Map(leaf []byte) []string {
	if len(leaf) == 0 {
		return nil
	}
	// Example: Extract domain names, package paths, or artifact identifiers
	return []string{string(leaf)}
}

// ============================================================================
// 2. SDK Harness (Auto-Injected Boilerplate)
// ============================================================================

const (
	MaxInputSize  = 4 * 1024 * 1024 // 4 MB Input Arena
	MaxOutputSize = 4 * 1024 * 1024 // 4 MB Output Arena
)

var (
	inputArena  [MaxInputSize]byte
	outputArena [MaxOutputSize]byte
	arenaOffset uint32
)

//export allocate
func allocate(size uint32) uint32 {
	if size > MaxInputSize {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&inputArena[0])))
}

//export reset
func reset() {
	arenaOffset = 0
}

//export map_bundle
func mapBundle(ptr, length uint32) uint64 {
	if length < 8 { // 4B count + at least 1*4B offset
		return 0
	}

	data := inputArena[:length]
	leafCount := binary.LittleEndian.Uint32(data[0:4])
	if leafCount == 0 || leafCount > 256 {
		return 0
	}

	minHeaderLen := 4 + (leafCount+1)*4
	if length < minHeaderLen {
		return 0
	}

	// Parse offsets
	offsets := make([]uint32, leafCount+1)
	for i := uint32(0); i <= leafCount; i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[4+i*4 : 8+i*4])
	}
	payload := data[minHeaderLen:]

	// Stage output buffer
	out := outputArena[:]
	binary.LittleEndian.PutUint32(out[0:4], leafCount)

	// Pre-allocate header space: 4B leaf_count + N*4B key_counts
	outOffset := int(4 + leafCount*4)
	keyCountsOffset := 4

	for i := uint32(0); i < leafCount; i++ {
		start := offsets[i]
		end := offsets[i+1]
		if end < start || int(end) > len(payload) {
			return 0
		}
		leafBytes := payload[start:end]

		// Invoke developer Map function
		keys := Map(leafBytes)
		binary.LittleEndian.PutUint32(out[keyCountsOffset+int(i)*4:keyCountsOffset+int(i+1)*4], uint32(len(keys)))

		for _, k := range keys {
			kBytes := []byte(k)
			kLen := len(kBytes)
			if outOffset+4+kLen > MaxOutputSize {
				return 0 // Buffer overflow
			}
			binary.LittleEndian.PutUint32(out[outOffset:outOffset+4], uint32(kLen))
			copy(out[outOffset+4:outOffset+4+kLen], kBytes)
			outOffset += 4 + kLen
		}
	}

	outPtr := uint32(uintptr(unsafe.Pointer(&outputArena[0])))
	return (uint64(outPtr) << 32) | uint64(outOffset)
}

func main() {
	select {}
}
```

Compilation:
```bash
GOOS=wasip1 GOARCH=wasm go build -o mapfn.wasm main.go
```

---

### 4.3 TinyGo Implementation (`-target=wasi`)

Complete, compilable TinyGo SDK harness yielding binaries < 50 KB:

```go
//go:build tinygo

package main

import (
	"encoding/binary"
	"unsafe"
)

// ============================================================================
// 1. Single-Leaf Mapping Business Logic (Developer Implements This)
// ============================================================================

func Map(leaf []byte) []string {
	if len(leaf) == 0 {
		return nil
	}
	return []string{string(leaf)}
}

// ============================================================================
// 2. SDK Harness (Auto-Injected Boilerplate)
// ============================================================================

const (
	MaxInputSize  = 2 * 1024 * 1024
	MaxOutputSize = 2 * 1024 * 1024
)

var (
	inputArena  [MaxInputSize]byte
	outputArena [MaxOutputSize]byte
)

//export allocate
func allocate(size uint32) uint32 {
	if size > MaxInputSize {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&inputArena[0])))
}

//export reset
func reset() {}

//export map_bundle
func mapBundle(ptr, length uint32) uint64 {
	if length < 8 {
		return 0
	}

	data := inputArena[:length]
	leafCount := binary.LittleEndian.Uint32(data[0:4])
	if leafCount == 0 || leafCount > 256 {
		return 0
	}

	minHeaderLen := 4 + (leafCount+1)*4
	if length < minHeaderLen {
		return 0
	}

	var offsets [257]uint32
	for i := uint32(0); i <= leafCount; i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[4+i*4 : 8+i*4])
	}
	payload := data[minHeaderLen:]

	out := outputArena[:]
	binary.LittleEndian.PutUint32(out[0:4], leafCount)
	outOffset := int(4 + leafCount*4)
	keyCountsOffset := 4

	for i := uint32(0); i < leafCount; i++ {
		start := offsets[i]
		end := offsets[i+1]
		if end < start || int(end) > len(payload) {
			return 0
		}
		leafBytes := payload[start:end]

		keys := Map(leafBytes)
		binary.LittleEndian.PutUint32(out[keyCountsOffset+int(i)*4:keyCountsOffset+int(i+1)*4], uint32(len(keys)))

		for _, k := range keys {
			kBytes := []byte(k)
			kLen := len(kBytes)
			if outOffset+4+kLen > MaxOutputSize {
				return 0
			}
			binary.LittleEndian.PutUint32(out[outOffset:outOffset+4], uint32(kLen))
			copy(out[outOffset+4:outOffset+4+kLen], kBytes)
			outOffset += 4 + kLen
		}
	}

	outPtr := uint32(uintptr(unsafe.Pointer(&outputArena[0])))
	return (uint64(outPtr) << 32) | uint64(outOffset)
}

func main() {}
```

Compilation:
```bash
tinygo build -o mapfn.wasm -target=wasi -no-debug -opt=2 main.go
```

---

### 4.4 Rust Implementation (`wasm32-wasip1`)

Complete, compilable Rust SDK harness:

```rust
use std::slice;

// ============================================================================
// 1. Single-Leaf Mapping Business Logic (Developer Implements This)
// ============================================================================

fn map_leaf(leaf: &[u8]) -> Vec<String> {
    if leaf.is_empty() {
        return Vec::new();
    }
    match std::str::from_utf8(leaf) {
        Ok(s) => vec![s.to_string()],
        Err(_) => Vec::new(),
    }
}

// ============================================================================
// 2. SDK Harness (Auto-Injected Boilerplate)
// ============================================================================

const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_SIZE: usize = 4 * 1024 * 1024;

static mut INPUT_ARENA: [u8; MAX_INPUT_SIZE] = [0; MAX_INPUT_SIZE];
static mut OUTPUT_ARENA: [u8; MAX_OUTPUT_SIZE] = [0; MAX_OUTPUT_SIZE];

#[no_mangle]
pub extern "C" fn allocate(size: u32) -> u32 {
    if size as usize > MAX_INPUT_SIZE {
        return 0;
    }
    unsafe { INPUT_ARENA.as_ptr() as u32 }
}

#[no_mangle]
pub extern "C" fn reset() {}

#[no_mangle]
pub extern "C" fn map_bundle(ptr: u32, len: u32) -> u64 {
    if len < 8 {
        return 0;
    }

    let input = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    let leaf_count = u32::from_le_bytes(input[0..4].try_into().unwrap());
    if leaf_count == 0 || leaf_count > 256 {
        return 0;
    }

    let min_header_len = 4 + (leaf_count as usize + 1) * 4;
    if (len as usize) < min_header_len {
        return 0;
    }

    let mut offsets = [0u32; 257];
    for i in 0..=leaf_count as usize {
        offsets[i] = u32::from_le_bytes(input[4 + i * 4..8 + i * 4].try_into().unwrap());
    }
    let payload = &input[min_header_len..];

    unsafe {
        OUTPUT_ARENA[0..4].copy_from_slice(&leaf_count.to_le_bytes());
        let mut out_offset = 4 + (leaf_count as usize) * 4;
        let key_counts_offset = 4usize;

        for i in 0..leaf_count as usize {
            let start = offsets[i] as usize;
            let end = offsets[i + 1] as usize;
            if end < start || end > payload.len() {
                return 0;
            }
            let leaf_bytes = &payload[start..end];

            let keys = map_leaf(leaf_bytes);
            let k_count = keys.len() as u32;
            OUTPUT_ARENA[key_counts_offset + i * 4..key_counts_offset + (i + 1) * 4]
                .copy_from_slice(&k_count.to_le_bytes());

            for key in keys {
                let k_bytes = key.as_bytes();
                let k_len = k_bytes.len();
                if out_offset + 4 + k_len > MAX_OUTPUT_SIZE {
                    return 0;
                }
                OUTPUT_ARENA[out_offset..out_offset + 4].copy_from_slice(&(k_len as u32).to_le_bytes());
                OUTPUT_ARENA[out_offset + 4..out_offset + 4 + k_len].copy_from_slice(k_bytes);
                out_offset += 4 + k_len;
            }
        }

        let out_ptr = OUTPUT_ARENA.as_ptr() as u32;
        ((out_ptr as u64) << 32) | (out_offset as u64)
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

### 5.1 Subcommands & CLI Workflows

```bash
# 1. Test map_bundle execution on a raw 256-leaf entry tile file
vindex-map test \
  --wasm=plugins/ct_map.wasm \
  --input=testdata/tile_001.bin \
  --format=hex

# 2. Verify byte-for-byte determinism across 10,000 runs and multiple worker sandboxes
vindex-map verify-determinism \
  --wasm=plugins/sumdb_map.wasm \
  --input=testdata/tile_sample.bin \
  --runs=10000 \
  --concurrency=8

# 3. Benchmark throughput (leaves/sec) and host hardware SHA-256 rate
vindex-map bench \
  --wasm=plugins/ct_map.wasm \
  --input=testdata/tile_sample.bin \
  --duration=30s \
  --concurrency=7
```

---

## 6. Security & Invariant Reference Table

| Invariant / Condition | Threat / Risk | Host Enforcement Action |
| :--- | :--- | :--- |
| **Bundle Leaf Count** (`1 <= leaf_count <= 256`) | Zero, > 256, or mismatched count against input. | Immediate `HALT`. |
| **Framing Bounds** | Key lengths or offsets exceed allocated linear memory. | Immediate `HALT`. Prohibits memory corruption. |
| **No-Zero Offset Allocation** | Host writes input to offset 0 on failed `allocate`. | Immediate `HALT`. Prohibits offset 0 fallback. |
| **16 MB Linear Memory Cap** | Guest memory leak or unbounded memory growth. | Wazero runtime memory trap and immediate `HALT`. |
| **100ms CPU Execution Limit** | Infinite loop or denial-of-service in guest. | Context cancellation and immediate `HALT`. |
| **Hermetic WASI Isolation** | Guest attempts network, filesystem, or clock access. | Wazero traps on non-whitelisted syscalls; dummy deterministic clocks. |
| **Host Hardware SHA-256** | Software crypto performance bottleneck in WASM. | Host Go runtime computes SHA-256 via SIMD instructions. |
| **Preimage Preservation** | Inability to perform future prefix/subtree indexing. | Host receives raw canonical preimages before hashing. |

