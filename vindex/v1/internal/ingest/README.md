# Sub-Design: Ingestion Pipeline & Tile Cache

This document defines the architecture, data structures, concurrency model, load-bearing invariants, and verified performance optimizations for the **Ingestion Subsystem** (`vindex/v1/internal/ingest`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Real-World Friction
The ingestion engine sits at the front of the VIndex pipeline. It must continuously poll remote append-only transparency logs over HTTP, verify Merkle signatures, download 256-leaf data bundles, execute untrusted mapping logic inside WebAssembly sandboxes, and feed sorted batches to downstream storage.

If ingestion is naive, four severe operational failure modes emerge:
1. **Host-Sandbox Boundary Overhead**: Invoking WebAssembly guest functions per leaf incurs severe boundary-crossing penalties. Every transition across the Foreign Function Interface (FFI)—switching execution contexts and copying memory between the Go host process and the WebAssembly sandbox—costs CPU cycles. When executed leaf-by-leaf, FFI boundary overhead alone consumes ~23% of total host CPU time.
2. **Out-of-Order Corruption**: Executing mapping across parallel worker threads causes batches to finish at different times. If out-of-order batches reach the storage engine, the database commits non-contiguous index sequences, permanently corrupting the RFC 6962 compact ranges of affected keys.
3. **Upstream Rate Limiting vs. Catch-Up Bandwidth**: Ingesting high-velocity logs from genesis (tens of millions of leaves) requires saturating network bandwidth, but upstream CDNs and log endpoints enforce strict rate limits (HTTP 429 Too Many Requests). Ingestion must maximize parallel download concurrency while gracefully backing off to avoid upstream bans.
4. **Network-Free Restart Guarantee (Cache Durability)**: Network egress is expensive and external logs can be transiently unreachable. Ingestion stages consumed tiles locally in a bounded staging buffer until downstream storage and trie persistence confirm they are no longer needed, ensuring daemon restarts and crash recoveries complete with zero network roundtrips.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Ingest upstream logs in native 256-leaf bundles matching the underlying tile structure.
  - Maximize upstream download throughput with adaptive concurrency while respecting HTTP 429 rate limits.
  - Parallelize CPU-heavy parsing across worker pools while emitting strictly contiguous leaf sequences.
  - Maintain a bounded local staging buffer and crash-recovery cache (`ManagedTileCache`), enabling restarts and Zero-WAL recovery with zero network egress (not an immutable log of record).
  - Bound local disk growth by having `TileReaper` actively prune cached tiles older than `SafeWatermark`.
- **Non-Goals**:
  - **No Upstream Checkpoint Creation**: The ingestion engine does not publish checkpoints or modify upstream log state; it is strictly a read-only consumer.
  - **No In-Guest Storage Writes**: The WASM sandbox is forbidden from performing disk or network I/O; guest modules solely transform leaf bytes into preimages.
  - **No Cross-Subsystem Watermark Calculation**: The ingestion cache does not inspect the internal state of Pebble DB or the MPT; watermark authority resides strictly with the Coordinator.

### 1.3 Requirements, Dependencies & Known Pain Points
- **Upstream Log Contract**: Upstream log must adhere to standard tile-based specifications: [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) or [C2SP static-ct / static-tiles-api](https://c2sp.org/static-ct).
- **WASM Runtime**: Pure Go WebAssembly runtime via `github.com/tetratelabs/wazero` (zero CGO dependencies).
- **Known Pain Points ("Warts and All")**:
  - **Resequencer Heap Expansion**: If a single WASM worker stalls or hits a garbage collection pause on an anomalous leaf, subsequent workers buffer finished batches in the in-memory min-heap, causing transient RAM spikes during high-concurrency ingestion.
  - **Catch-Up Disk Spikes**: During initial fast-forward ingestion from leaf 0, network download bandwidth temporarily outpaces the background reaper's tick interval, causing temporary disk cache growth before pruning catches up.
  - **Wazero Compilation Warmup**: Initializing JIT-compiled sandboxes across worker pools introduces a 200–500ms startup latency penalty on cold process boot.

---

## 2. Detailed Design

### 2.1 The Assembly Line Sorter Architecture
The ingestion subsystem operates as an assembly line pipeline:

1. **`TileFetcher`**: Queries the upstream log's `/checkpoint` endpoint. Downloads data tiles (`/tile/data/x/y.p/z`) and corresponding Level-0 tree tiles.
2. **`ManagedTileCache`**: Writes downloaded, Merkle-authenticated tiles to the local filesystem. This cache serves as a bounded local staging buffer and crash-recovery cache (not an immutable log of record), ensuring subsequent crash recovery can replay history without network egress.
3. **WASM Worker Pool (`WasmMapper`)**: A pool of `max(1, GOMAXPROCS-1)` parallel Wazero sandboxes running the compiled `.wasm` plugin. Each worker takes an **entire crate (256-leaf bundle)** and maps all 256 leaves in a single `map_bundle` invocation via the in-guest SDK (`mapfn/sdk`).
4. **Host Hardware SIMD Hashing**: The Go host intercepts raw preimages returned by guest sandboxes and computes `KeyHash = sha256.Sum256(preimage)` using hardware vector instructions (Single Instruction, Multiple Data / SIMD, such as x86 SHA-NI or ARMv8 Crypto extensions).
5. **Resequencer (Min-Heap)**: Receives completed batches out of order from workers and buffers them in a priority queue. Emits strictly ascending batches (`BundleIdx = StartLeafIdx / 256`) onto `chan *MappedBatch`.
6. **`TileReaper`**: Periodically receives the authorized `SafeWatermark` from the Coordinator and actively prunes cached tiles older than `SafeWatermark` (where `(tileIndex + 1) * 256 <= SafeWatermark`) to bound local disk usage.

### 2.2 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Target Checkpoint Origin Verification**:
  - *Rule*: Upstream checkpoint notes must be cryptographically validated against configured verifier public keys using `sumdb/note` before the size advancement is accepted.
  - *Rationale*: Guarantees that the indexer only ingests authentic leaves committed by the legitimate log authority.
  - *Consequence ("Or Else")*: If an unauthenticated checkpoint were accepted, an adversary could feed forged leaves, causing the indexer to commit bogus state and permanently diverging from independent witnesses.

- **[Correctness Invariant] Strictly Monotonic Resequencing**:
  - *Rule*: Batches pushed to downstream storage must strictly follow ascending leaf index order without gaps:
    ```text
    batch[i+1].StartLeafIdx == batch[i].EndLeafIdx
    ```
  - *Rationale*: Inverted chunks maintain cumulative RFC 6962 compact ranges. Compact ranges require strictly increasing chronological leaves.
  - *Consequence ("Or Else")*: Committing out-of-order batches breaks the Merkle compact range tree structure, computing invalid mini-log roots that fail verifier inclusion proofs.

- **[Correctness Invariant] TileReaper Authority & Pruning Bounds**:
  - *Rule*: `TileReaper` must strictly prune only those tile files satisfying:
    ```text
    (tileIndex + 1) * 256 <= SafeWatermark
    ```
    where `SafeWatermark` is authoritative input dictated by the Coordinator.
  - *Rationale*: Preserves un-synced historical tiles on disk so that Zero-WAL crash recovery can fast-forward lagging MPT state without network requests.
  - *Consequence ("Or Else")*: Pruning ahead of the durable MPT watermark causes dirty crash recovery to fail, forcing the daemon to re-download historical tiles over the network and violating the sub-500ms time-to-first-serve SLO.

- **[Performance Optimization] Native 256-Leaf Tile Bundling**:
  - *Mechanism*: Fetches and caches data in native 256-leaf tiles rather than issuing individual HTTP requests per leaf.
  - *Impact*: Reduces upstream network requests by 256x compared to REST APIs.

- **[Performance Optimization] Bundled WebAssembly Invocation (`map_bundle`)**:
  - *Mechanism*: Transfers an entire 256-leaf crate across the WASM boundary in a single FFI call.
  - *Impact*: Reduces FFI boundary crossings from 768 to 2–3 per tile, dropping FFI CPU overhead from ~23% of host CPU time to < 1%.

- **[Performance Optimization] Host-Side SIMD Preimage Hashing**:
  - *Mechanism*: The WASM guest emits raw preimages; the Go host computes SHA-256 using native hardware instructions (x86 SHA-NI / ARMv8 Crypto).
  - *Impact*: Eliminates the ~55% software crypto bottleneck inside WebAssembly bytecode.

### 2.3 Ingestion Pipeline Contract

The ingestion subsystem manages upstream data retrieval, sandboxed mapping, and local tile caching:

- **Inputs**:
  - Upstream log HTTP/Tessera endpoint.
  - Tile cache directory.
  - Mapping function runner.
  - Worker concurrency.
- **Outputs**:
  - Stream of mapped key-to-occurrence index batches ordered monotonically by log sequence.
- **Pruning Contract**:
  - Local tile cache retains tiles strictly within the active lag window; tiles older than `SafeWatermark` are deleted by the background reaper.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Per-Leaf Mapping (`map_leaf`) vs. Bundled Mapping (`map_bundle`)
- **Proposed**: Invoking `map_leaf` individually for every leaf entry.
- **Empirical Rejection**: Generated 768 FFI calls per 256-leaf tile (memory allocation, leaf mapping, and arena reset transitions x 256), consuming ~23% of total host CPU cycles purely in boundary crossing overhead.
- **Chosen Design**: Bundled execution (`map_bundle`) passes all 256 leaves per invocation, slashing boundary overhead by 99.6%.

### 3.2 In-Guest Software Crypto vs. Host SIMD Cryptography
- **Proposed**: Compiling SHA-256 into the guest WASM binary.
- **Empirical Rejection**: Software bitwise hashing in WASM consumed ~55% of all CPU cycles during mapping due to the absence of SIMD vector instructions.
- **Chosen Design**: Guest emits raw string preimages; Go host hashes using native CPU hardware instructions (SHA-NI / ARMv8 Crypto).

### 3.3 Exporting Host Hardware Hashing into WASM vs. Pure Preimage Return
- **Proposed**: Exposing an imported host function (`host.sha256(ptr, len)`) into the WebAssembly sandbox so guest modules could invoke host hardware crypto while still returning pre-computed hashes.
- **Theoretical Rejection (Ergonomics & Architectural Purity)**:
  - Ruled out without benchmarking due to excessive SDK complexity and architectural impurity.
  - Binding against bespoke host runtime imports destroys the clean abstraction of `MapFn` as a pure, portable function (`leaf []byte -> []string`). Guest SDKs in other languages (Rust, TinyGo, Zig) would require specialized bindings and FFI boilerplate.
  - Calling a host import for every hash introduces bidirectional FFI context switching overhead.
- **Chosen Design**: Keep the guest contract completely pure and self-contained: the guest simply emits raw canonical string preimages, and the Go host performs bulk SIMD hashing natively.
