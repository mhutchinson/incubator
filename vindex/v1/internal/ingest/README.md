# Sub-Design: Ingestion Pipeline & Tile Cache

This document defines the architecture, load-bearing invariants, verified performance optimizations, optional configurations, and retired design branches for the **Ingestion Pipeline** (`vindex/v1/internal/ingest`).

---

## 1. Core Load-Bearing Invariants

### 1.1 Strictly Monotonic Ascending Batch Resequencing
Parallel map workers complete variable-length leaf bundles out of order.
- **Invariant**: The `Resequencer` min-heap priority queue re-orders completed batches by `BundleIdx = StartLeafIdx / 256` before releasing them downstream.
- Downstream commit channels MUST receive batches in strictly contiguous, gapless ascending sequence:
  ```text
  nextBatch.StartLeafIdx == expectedStartLeafIdx
  ```
- Any gap, inversion, or duplicate sequence halts pipeline delivery immediately.

### 1.2 Unaligned Checkpoint Clamping
When an upstream target checkpoint size is not an exact multiple of the bundle width (256 leaves):
- **Invariant**: The final bundle in the target range is clamped to the exact target boundary:
  ```text
  count = min(bundleSz, targetSize - currIdx)
  ```
- The ingestion pipeline MUST halt processing at the exact target boundary; leaves beyond `targetSize` are never mapped, indexed, or committed.

### 1.3 SafeWatermark Bounded Tile Reaper
The local tile cache serves as the immutable log of record. Cached tiles are pruned only when strictly below the safe watermark:
```text
SafeWatermark = min(m_kv_size, MPT_Durable_Size) == MPT_Durable_Size
```
- **Durability Invariant**: A tile file at `tileIdx` is pruned only if `(tileIdx + 1) * 256 <= SafeWatermark`.
- Tiles in the window `[MPT_Durable_Size .. m_kv_size)` MUST NOT be deleted. This guarantees that if an unclean crash occurs, startup recovery can replay missing tiles from local disk without network egress.

### 1.4 Hermetic Sandboxing & Deterministic Halt Policy
WebAssembly guest execution is strictly sandboxed:
- **Zero Host I/O**: Guests have zero WASI syscall access to host filesystems, network interfaces, random number generators, or real-time clocks.
- **Memory Cap**: Fixed linear memory limit (16 MB heap cap; ~4 MB active arena). Exceeding this triggers an immediate trap.
- **Execution Deadline**: Context cancellation enforces a 100ms per-bundle CPU deadline to prevent guest infinite loops.
- **Deterministic Halt**: Any guest panic, memory violation, framing corruption, or timeout triggers an immediate daemon `HALT` to prevent unverified state divergence across nodes.

### 1.5 Decoupled Storage Separation
The ingestion package contains **zero Pebble dependencies, storage keys, or database transactions**. It communicates with downstream layers exclusively through Go channels emitting `*MappedBatch`.

---

## 2. Verified Performance Optimizations

### 2.1 Native 256-Leaf Entry Bundling
Input Log entries are fetched and unpacked in native Tessera 256-leaf blocks (`LeafBundle`):
- Eliminates per-leaf network request amplification.
- Boundary alignment (`256 * k`) ensures every fetch spans exact integer ranges of storage bundles, eliminating redundant re-fetches.

### 2.2 Bundled WebAssembly Execution (`map_bundle`)
The host passes up to 256 contiguous leaves into guest memory in a single structured arena and invokes `map_bundle` once per bundle:
- Slashing FFI transitions from 768 per tile (in per-leaf mapping) to 2–3 per tile.
- Reduces FFI CPU overhead from **~23% of total CPU time to < 1%**.

### 2.3 Host-Side SIMD Hardware SHA-256
Guest plugins emit raw canonical Claim Subject preimages (e.g. domain names, module paths). The Go host computes:
```text
KeyHash = SHA256(canonical_subject)
```
using standard `crypto/sha256` with CPU hardware vector instructions (**x86 SHA-NI** or **ARMv8 Crypto**):
- Eliminates the **~55% software crypto bottleneck** inside WebAssembly bytecode.
- Drops cryptographic CPU time to **< 5%**.

### 2.4 Lexicographical Key Sorting & Deduplication per Leaf
Within each leaf, extracted key hashes are sorted with `bytes.Compare` and deduplicated with `slices.Compact`:
- Prevents duplicate relative index insertions in chunk records.
- Enforces branch locality for downstream Sparse Merkle Patricia Trie updates.

### 2.5 Parallel Worker Allocation & Backpressure Control
- **Worker Pool**: Defaults to `max(1, GOMAXPROCS - 1)` parallel workers (23 workers on 24-core hardware), reserving 1 dedicated core for database writes and live serving.
- **Bounded Lookahead Window**: Resequencer backpressure pauses tile dispatching if any worker straggles, bounding queue heap growth to < 128 bundles (~50 MB).

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Pluggable Adaptive HTTP Transport
For initial log catch-up against rate-limited CDNs, `TileFetcher` can accept custom `http.RoundTripper` implementations providing token-bucket rate limiting or AIMD adaptive concurrency. This sits purely at the network layer and does not affect pipeline invariants.

### 3.2 Cache Operational Modes
- **Direct Local FS**: Direct zero-copy reading from co-located log signer directory.
- **Remote Managed Cache**: Standard standalone deployment with background `TileReaper` active.
- **Remote Persistent Cache**: Retains full local tile history for archive nodes.
- **Remote Direct Streaming**: Ephemeral memory caching for testing or stateless read replicas.

### 3.3 Forward-Compatibility: Preimage Preservation
Because guest plugins emit raw canonical string preimages rather than one-way hashes, the host runtime can index prefix tries or subtree roots in future versions without modifying guest WASM plugin ABIs.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode Retirement in Ingestion
- **What Was Proposed & Investigated**:
  During initial exploration, a dedicated bulk ingestion mode ("Backfill Mode") was evaluated where the ingestion pipeline streamed leaf bundles directly into storage while bypassing intermediate checkpoint publishing and witness cosignatures.
- **Why It Was Investigated**:
  To determine whether bulk log catch-up from genesis could achieve higher throughput by running ingestion in an uncoordinated, offline mode.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  1. **Ingestion Layer Was Identical**: In the Go implementation, `pipeline.StreamBatches` emitted identical `MappedBatch` channels regardless of whether downstream code ran `SyncOnce` or `Backfill`.
  2. **Zero Throughput Benefit**: Empirical benchmarks showed that Normal Serving Mode (`SyncOnce`) matched or significantly outperformed Backfill Mode (90,797 vs 49,064 leaves/sec on SumDB).
  3. **100% Read Starvation**: Backfill Mode shut down the HTTP read server during ingestion, while Normal Mode maintained sub-2ms P50 latency with 100% availability.
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode provided no performance or architectural benefit to the ingestion subsystem. It was completely removed in Milestone M3, leaving the ingestion pipeline unified around continuous streaming and `SyncOnce` batch catchup.

### 4.2 Per-Leaf WebAssembly Invocations (`map_leaf`)
- Invoked `allocate`, `map_leaf`, and `reset` individually for every leaf entry (768 FFI calls per 256-leaf tile).
- Consumed ~23% of total host CPU time in FFI context switches and parameter marshaling.
- Replaced by `map_bundle` (2–3 FFI calls per tile, < 1% CPU).

### 4.3 In-Guest Software Cryptographic Hashing
- Compiling SHA-256 into guest WebAssembly bytecode prevented the guest from accessing host vector instructions, consuming ~55% of total CPU time.
- Replaced by host-side SIMD hardware hashing.

### 4.4 Go Dynamic Plugins (`plugin.Open`)
- Requires exact compiler and dependency versions, lacks memory isolation (a single null pointer crashes the host), and poses serious security risks.
- Replaced by hermetic Wazero WebAssembly sandboxes.

### 4.5 Leaf-by-Leaf HTTP Streaming
- Fetching individual leaves over HTTP created massive network roundtrip amplification.
- Replaced by native 256-leaf entry bundle fetching.
