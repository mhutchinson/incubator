# Sub-Design: WASM Guest SDK & Plugin Interface

This document defines the WebAssembly guest ABI, developer contract, memory management protocols, load-bearing invariants, and verified performance optimizations for the **WASM Guest SDK** (`vindex/v1/mapfn`).

---

## 1. Context & Objectives

### 1.1 Architectural Separation: User Callback vs. Guest SDK vs. Host Runtime
Mapping in VIndex operates across three decoupled layers:
1. **User Logic (`MapFn`)**: The pure Go function (`func(leaf []byte) []string`) written by ecosystem developers. It has no knowledge of WebAssembly, linear memory pointers, or host runtimes.
2. **Guest SDK (`mapfn/sdk`)**: The runtime harness compiled into the guest `.wasm` binary alongside `MapFn`. It exports the low-level `map_bundle` ABI, manages linear memory slabs, iterates through leaf crates, invokes `MapFn`, and serializes output preimages.
3. **Host Ingest Runtime (`internal/ingest`)**: The host-side Wazero worker pool that loads the compiled `.wasm` plugin, executes `map_bundle` over 256-leaf tiles, and computes 32-byte key hashes using native CPU SIMD instructions.

### 1.2 Problem Statement & Real-World Friction
Every transparency ecosystem indexes different payloads (e.g. DER X.509 certificates in Certificate Transparency, newline-delimited strings in Go SumDB, or JSON provenance records in Sigstore). VIndex must allow ecosystem authors to define custom extraction logic without compromising node security, crashing the host process, or causing state divergence across independent monitors.

Relying on in-process native Go plugins or shared libraries introduces three severe failure modes:
1. **Toolchain Version Drift & Non-Determinism**: If two independent indexers or verifiers compile their code with different Go versions (e.g. Go 1.23 vs. Go 1.25) or execute on different operating systems, standard library behavior can diverge. A subtle parsing change in ASN.1 DER certificate decoding or Unicode normalization across compiler versions on even **one leaf out of 100 million** causes the computed `MapRoot` to diverge permanently, triggering false split-view alarms and destroying ecosystem consensus.
2. **Host Process Fragility**: Untrusted or malformed leaves in public logs could cause out-of-bounds memory accesses, nil pointer panics, or unbounded recursion. Running native code directly in the host engine risks terminating the entire `vindexd` daemon.
3. **Foreign Function Interface (FFI) Overhead**: Naively executing foreign functions across language boundaries on a per-leaf basis introduces excessive context-switching and memory-copying overhead, consuming ~23% of total host CPU time purely in FFI crossings.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide a high-level, idiomatic developer contract (`func([]byte) []string`) allowing ecosystem authors to write pure functions without managing raw WebAssembly linear memory pointers.
  - Provide a zero-allocation guest runtime SDK (`mapfn/sdk`) that binds the developer's function to the high-performance `map_bundle` ABI.
  - Freeze compiler and standard library bytecode inside a hermetic `.wasm` binary, guaranteeing bit-for-bit identical execution across all host architectures, operating systems, and toolchain versions.
  - Amortize boundary-crossing overhead by processing full 256-leaf crates in a single FFI call using contiguous shared-memory slabs.
  - Provide an offline verification CLI (`vindex-map`) to validate determinism, memory bounds, and throughput prior to deployment.
- **Non-Goals**:
  - **No Host Execution in this Package**: The host-side Wazero runtime pool and SIMD hashing pipeline are housed in the Ingest subsystem (`internal/ingest`).
  - **No In-Place Dynamic Upgrades**: Once a compiled plugin binary is published for an Input Log, its bytecode is immutable. Fixing a parsing bug requires deploying a new index instance from leaf 0.
  - **No In-Guest Cryptographic Hashing**: Guest modules do not compute SHA-256 hashes; they emit raw canonical string preimages and delegate hashing to the Go host.
  - **No Host I/O or State**: Guest modules are strictly pure functions; they have zero access to disk, network, environment variables, or host clocks.

### 1.4 Requirements, Constraints & Known Pain Points
- **Host Runtime**: Pure Go WebAssembly runtime via `github.com/tetratelabs/wazero` executing under the `wasip1` specification with zero CGO dependencies.
- **WASM Memory Constraints**: Guest modules execute within a bounded linear memory space (default 16 MB, scalable via configuration).
- **Known Pain Points ("Warts and All")**:
  - **Standard Go WASM Binary Size**: Standard Go (`GOOS=wasip1 GOARCH=wasm`) bundles the complete Go runtime and garbage collector into the binary, resulting in ~1.9 MB to ~2.5 MB binaries. While TinyGo produces ~200 KB binaries, it lacks support for certain standard library packages (such as full `crypto/x509`).
  - **Immutable Logic Cost**: Because mapping logic is frozen to prevent split-view attacks, any bug in key extraction cannot be hot-patched; it requires re-indexing the entire log from leaf 0.
  - **Memory Slab Ceiling**: A tile bundle containing abnormally large leaves (e.g. 50 KB certificates with hundreds of SANs) can exceed the initial guest memory allocation, requiring the host to configure larger linear memory bounds.

---

## 2. Detailed Design

### 2.1 The High-Level Developer Experience
Ecosystem developers write standard, idiomatic Go. They do not write assembly, manage WebAssembly linear pointers, or handle memory layout serialization.

The developer implements a single pure function matching the signature:

```go
type MapFn func(leaf []byte) []string
```

Example implementation for a certificate log:

```go
package main

import (
	"crypto/x509"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
	"golang.org/x/net/idna"
)

func mapCertificate(leaf []byte) []string {
	cert, err := x509.ParseCertificate(leaf)
	if err != nil {
		return nil
	}

	domains := make([]string, 0, len(cert.DNSNames)+1)
	if cert.Subject.CommonName != "" {
		if d, err := normalizeDomain(cert.Subject.CommonName); err == nil {
			domains = append(domains, d)
		}
	}
	for _, san := range cert.DNSNames {
		if d, err := normalizeDomain(san); err == nil {
			domains = append(domains, d)
		}
	}
	return domains
}

func normalizeDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	return idna.Lookup.ToASCII(d)
}

func main() {
	sdk.Register(mapCertificate)
}
```

The `sdk.Register` harness automatically binds the user's pure function to the low-level `map_bundle` FFI export, handling the memory slab unpacking and serialization loops transparently.

#### WASM Guest ABI Contract:
To exchange data across the FFI boundary while eliminating per-leaf allocation overhead:
- **Memory Lifecycle**: The guest provides a linear memory arena for input tile bundles. The host passes the bundle into guest linear memory, invokes the entrypoint, and parses the resulting key-offset entries. The host resets the arena between invocations.
- **Statelessness Invariant**: Guest code must maintain zero mutable state across invocations. All mapping logic must be deterministic and pure; execution depends strictly on the bytes of each individual leaf.

---

### 2.2 Low-Level WASM ABI & The Pack-and-Wipe Memory Slab
To eliminate the 23% CPU overhead of per-leaf FFI boundary crossings, the host and guest communicate through a single contiguous memory slab using the `map_bundle` export:

```text
//go:wasmexport map_bundle
func map_bundle(inputPtr uint32, inputLen uint32) uint64
```

#### Memory Slab Lifecycle:
1. **Pack (Host)**: The Go host serializes all 256 leaves of an Input Log data tile into a contiguous slab in the guest's linear memory.
2. **Execute (FFI Call)**: The host invokes `map_bundle(inputPtr, inputLen)`.
3. **Iterate (Guest SDK)**: Inside WASM, the SDK harness reads the offset table, iterates over all 256 leaves in a tight in-guest loop, invokes the developer's `userMapFn(leaf)`, and appends all returned preimages into an output slab.
4. **Return & Unpack (Host)**: The guest returns a packed 64-bit integer `uint64(outputPtr)<<32 | uint32(outputLen)`. The host reads all extracted preimages directly from the guest linear memory.
5. **Wipe (Host)**: Both input and output memory slab pointers are reset (`offset = 0`) for the next batch, completely eliminating guest heap allocations and GC pauses.

#### Memory Lifecycle Sequence:
1. **Host Ingestion**: The Go host writes the contiguous 256-leaf crate into the pre-allocated input slab in WASM linear memory.
2. **Guest Execution**: The guest SDK loops over the input slab, executing `userMapFn(leaf)` on each entry, and writes canonical string preimages into the output slab.
3. **Register Return**: The guest returns a single 64-bit integer encoding `(outputPtr << 32) | outputLen` across the FFI boundary.
4. **Host SIMD Hashing**: The Go host reads preimages directly from the output slab and computes 32-byte key hashes using host CPU vector instructions.
5. **Arena Wipe**: The host resets slab allocation pointers to zero for the next batch with zero heap allocations.

#### Binary Slab Layouts:

| Memory Buffer | Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Input Slab** | `0` | `LeafCount` | `uint32` (4B) | Number of leaves in the crate (1 to 256). |
| | `4` | `OffsetTable` | `[Count]uint32` | Byte offsets pointing to the start of each leaf in the payload block. |
| | `4 + 4*Count` | `PayloadBlock` | `[]byte` | Raw, contiguous leaf bytes concatenated end-to-end. |
| **Output Slab** | `0` | `LeafCount` | `uint32` (4B) | Number of leaves processed. |
| | `4` | `KeyCountTable` | `[Count]uint32` | Number of preimages emitted by each respective leaf. |
| | Follows | `PreimageBlock` | `[]byte` | Length-prefixed string preimages (`uint32 length` + raw UTF-8 bytes). |

---

### 2.3 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Bytecode Immutability Across Toolchains**:
  - *Rule*: The `MapFn` WASM binary must be compiled once, cryptographically hashed, and referenced by its SHA-256 digest. Every participating indexer and verifier must execute this exact bytecode.
  - *Rationale*: Protects the distributed ecosystem against subtle compiler, standard library, or operating system changes (e.g. updates to Go's ASN.1 parser or Unicode tables).
  - *Consequence ("Or Else")*: If nodes ran native code compiled with different toolchains, edge-case parsing discrepancies would produce conflicting `MapRoot` commitments, causing false split-view detections and breaking verifier trust.

- **[Correctness Invariant] Hermetic Isolation & Fatal HALT Policy**:
  - *Rule*: Guest WASM execution must run in a hermetically sealed environment with zero host filesystem access, zero network sockets, and deterministic frozen clocks. If the guest encounters an unhandled panic, memory fault, or execution trap, the host daemon terminates immediately with a fatal `HALT`.
  - *Rationale*: Ensures that execution is 100% deterministic and reproducible on any machine.
  - *Consequence ("Or Else")*: Silently swallowing guest traps or returning partial results produces divergent key mappings, resulting in false non-inclusion proofs.

- **[Performance Optimization] Bundled FFI Invocation (`map_bundle`)**:
  - *Mechanism*: Packs an entire 256-leaf crate into the input slab and executes a single FFI call per tile, rather than crossing the boundary once per leaf.
  - *Impact*: Reduces FFI transitions from 768 to 2–3 per tile, slashing FFI CPU overhead from ~23% of host CPU time to < 1%.

- **[Performance Optimization] Pack-and-Wipe Slab Allocation**:
  - *Mechanism*: Slabs are allocated once in guest linear memory and reused across sequential tile invocations with simple pointer resets.
  - *Impact*: Eliminates in-guest heap allocations and garbage collector pauses, keeping memory usage bounded and CPU dedicated to parsing.

- **[Performance Optimization] Raw Preimage Emission & Host SIMD Cryptography**:
  - *Mechanism*: Guest sandboxes emit raw string preimages. The Go host performs bulk SHA-256 hashing using native hardware vector instructions (Single Instruction, Multiple Data / SIMD, such as x86 SHA-NI or ARMv8 Crypto extensions).
  - *Impact*: Eliminates the ~55% software crypto bottleneck inside WebAssembly bytecode.

---

### 2.4 Offline Developer Verification Tooling (`vindex-map`)
The mapping subsystem provides a standalone CLI tool (`vindex/v1/cmd/vindex-map`) to allow plugin authors to test and qualify their mapping binaries before production deployment:

```bash
# Test mapping output against a sample tile or leaf
vindex-map test --wasm=map.wasm --input=tile.bin

# Run performance and throughput benchmarks (leaves/sec)
vindex-map bench --wasm=map.wasm --input=tile.bin --iterations=1000

# Assert bit-for-bit determinism across repeated executions
vindex-map determinism --wasm=map.wasm --input=tile.bin

# Inspect exported memory slabs and ABI metadata
vindex-map inspect --wasm=map.wasm
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 Per-Leaf Mapping (`map_leaf`) vs. Bundled Mapping (`map_bundle`)
- **Proposed**: Invoking an exported `map_leaf(ptr, len)` guest function individually for every leaf.
- **Empirical Rejection**: Generated 768 FFI calls per 256-leaf tile (memory allocation, leaf mapping, and arena reset transitions x 256). Profiling revealed that ~23% of total host CPU time was spent purely on boundary-crossing overhead.
- **Chosen Design**: Bundled mapping (`map_bundle`) processes all 256 leaves in a single invocation via shared memory slabs, reducing FFI overhead to < 1%.

### 3.2 In-Guest Software Cryptography vs. Host SIMD Preimage Hashing
- **Proposed**: Compiling SHA-256 hashing libraries directly into the guest WASM bytecode so that the guest outputs 32-byte key hashes directly.
- **Empirical Rejection**: Because WebAssembly runtimes lack direct access to native CPU hardware crypto instructions, software bitwise hashing consumed ~55% of all CPU cycles during mapping.
- **Chosen Design**: Guest modules output raw canonical string preimages; the Go host performs bulk hardware-accelerated SHA-256 using CPU SIMD vector instructions.

### 3.3 Exporting Host Hardware Hashing into WASM vs. Pure Preimage Return
- **Proposed**: Exposing an imported host function (`host.sha256(ptr, len)`) into the WebAssembly sandbox so guest modules could invoke host hardware crypto while still returning pre-computed hashes.
- **Theoretical Rejection (Ergonomics & Architectural Purity)**:
  - Ruled out without benchmarking due to excessive SDK complexity and loss of pure-function abstraction.
  - Requiring a host import forces guest SDK authors across different languages (Go, Rust, TinyGo, Zig) to bind against proprietary host runtime hooks rather than writing a clean, portable function (`leaf []byte -> []string`).
  - Incurring bidirectional FFI hops for every individual hash would introduce its own boundary overhead.
- **Chosen Design**: Keep the guest contract completely pure and self-contained: the guest simply emits raw canonical string preimages, and the Go host performs bulk SIMD hashing natively.

### 3.4 In-Process Go Plugins / CGO vs. WebAssembly Sandboxing
- **Proposed**: Dynamically loading Go plugins (`plugin.Open`) or shared C libraries (`cgo`).
- **Theoretical Rejection**:
  - In-process native plugins do not guarantee determinism across toolchain versions (Go compiler upgrades can alter standard library parsing behavior).
  - Memory corruptions or panics inside the plugin crash the main daemon.
  - Go plugins have poor cross-platform support and require identical dependency version trees between the host and plugin.
- **Chosen Design**: Standardized on Wazero WebAssembly sandboxing.
