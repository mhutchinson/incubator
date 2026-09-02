# Sub-Design: Coordinator & Zero-WAL Startup Recovery

This document defines the lifecycle orchestration, crash recovery protocols, load-bearing invariants, verified performance optimizations, and retired design branches for the **Coordinator Subsystem** (`vindex/v1/internal/coordinator`).

---

## 1. Core Load-Bearing Invariants

### 1.1 3-Phase Zero-WAL Recovery Sequence
On daemon launch, the coordinator executes a 3-phase Zero-WAL recovery sequence before opening read and write interfaces:
1. **Phase 1: Instant Warm Start (< 5ms)**:
   - Evaluates whether the persisted MPT size equals the latest committed Output Log Input Log size (`S_OUT`) and the in-memory root matches the Output Log leaf commitment:
     ```go
     if inCP.Size == mptPersistedSize && c.mptMgr.Root() == mapRoot
     ```
   - If true, clean shutdown is verified. Sets `mptDurableSize = S_OUT`, activates `ServingState = OutputLog[N-1]`, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms)**:
   - If `mptPersistedSize < S_OUT` (dirty crash or lagging MPT):
     * Streams missing historical tiles `[mptPersistedSize .. S_OUT)` from the local tile cache.
     * Evaluates `MapBundle` on replayed tiles with host SIMD SHA-256 to identify modified keys.
     * Queries `store.GetSubRoot(keyHash, S_OUT)` for each modified key, reconstructing mini-log roots at `S_OUT` with **zero storage mutations to Pebble**.
     * Updates in-memory MPT nodes via `mpt.Set` and finalizes with `mpt.Snap(int64(S_OUT))`.
     * Asserts `MPT.Root() == OutputLog[N-1].MapRoot`.
     * Consolidates on-disk state via `mptMgr.Sync()`, activates `ServingState`, and **opens the Read Server (< 500ms)**.
3. **Phase 3: Background Catchup**:
   - Resumes forward ingestion from `m_kv_size` to `m_target_checkpoint`.

### 1.2 Synchronous Commit Barrier & Serialized Commit Loop
To guarantee crash consistency without distributed transactions or complex WAL rollback mechanics:
- `store.WriteBatch(entries, S_k)` executes `pebble.Sync`, blocking until all inverted chunk records and `m_kv_size` are durably persisted to disk.
- Output Log publication (`pub.PublishBatch`) and witness network calls **MUST NOT begin** until `store.WriteBatch` has successfully returned.
- Downstream stages only expose data committed by verified checkpoints.

### 1.3 Universal Crash Invariant Guarantee
Because storage persistence strictly precedes Output Log publication:
```text
m_kv_size >= Output_Size
```
This invariant holds across all crash, kill, and power loss scenarios. Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted KV store chunks. If a crash occurs between storage sync and Output Log publishing, `m_kv_size > S_OUT`; startup recovery safely ignores chunks beyond `S_OUT` via point-in-time `store.GetSubRoot(keyHash, S_OUT)` queries.

### 1.4 Moving-Goalpost Prevention
When indexing high-velocity logs, the log head advances continuously. Polling unverified checkpoints risks synchronization starvation. The coordinator freezes verified target sync checkpoints into Pebble metadata (`m_target_checkpoint`) prior to batch processing, ensuring that the ingestion pipeline processes fixed ranges to completion before advancing.

### 1.5 State Progression Inequality Chain
In steady-state serving, watermarks strictly satisfy:
```text
Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= MPT_Durable_Size
```
*(Note: Active Serving MPT Size == Output_Size)*.

### 1.6 Safe Watermark Pruning Invariant
The local tile cache serves as the immutable log of record. Cached tiles are pruned only when strictly below:
```text
SafeWatermark = min(m_kv_size, MPT_Durable_Size) == MPT_Durable_Size
```
Tiles in the window `[MPT_Durable_Size .. m_kv_size)` are preserved, guaranteeing that dirty crash recovery replays missing MPT state directly from local disk without network egress.

---

## 2. Verified Performance Optimizations

### 2.1 Sub-500ms Time-to-First-Serve (2.4 ms Warm Recovery)
Zero-WAL recovery fast-forwards state to the latest Output Log entry in milliseconds:
- Clean restarts achieve **2.4 ms time-to-first-serve**.
- Dirty crash recovery completes in **< 500ms** by streaming tiles from local cache and using O(1) `store.GetSubRoot` point queries with zero storage mutations.

### 2.2 Commit Batch Aggregation (Amortizing Overhead by 16x)
While parallel map workers process at 256-leaf tile granularity, the coordinator aggregates mapped batches to `DefaultCommitBatchSize = 4096` (16 tiles) before committing to Pebble, amortizing iterator creation and lock acquisition overhead by 16x.

### 2.3 Storage Idempotency Gap Absorption
If a crash occurs when `m_kv_size > S_OUT`, the coordinator resumes ingestion starting at `S_OUT`:
- Relies on `store.WriteBatch`'s internal idempotency filtering (`persistedKVSize`) to absorb the replay gap `[S_OUT .. m_kv_size)`.
- Replayed entries are skipped, sub-roots are computed via `GetSubRoot`, and disk writes are bypassed until batches advance beyond `m_kv_size`, guaranteeing zero duplicate storage mutations.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Single-Node Coordination Scope
The coordinator manages local subsystems within a single process on a single host. No distributed consensus (Raft, Paxos) or clustering protocols are used.

### 3.2 Crash Injection Matrix & Chaos Qualification
- **Crash during Startup Replay**: Cleanly restarts and re-executes replay without database corruption.
- **Crash between KV Commit and Output Publish (`m_kv_size > S_OUT`)**: Replay gap safely absorbed by `store.WriteBatch` idempotency filtering.
- **Crash between Output Publish and MPT Disk Sync (`S_OUT > MPT_Durable_Size`)**: Phase 2 replays missing tiles from local cache and syncs MPT to disk in < 500ms.
- **Unreachable State (`m_kv_size < S_OUT`)**: Physically impossible due to the synchronous commit barrier.

### 3.3 Structured Startup Logging
The coordinator emits structured INFO logs (`log/slog`) at each decision boundary: initial watermark discovery, recovery mode selection, replay milestones, and serving readiness transitions.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode Retirement in Coordinator
- **What Was Proposed & Investigated**:
  A dedicated bulk ingestion method, `Coordinator.Backfill(ctx, targetCP)`, was developed alongside configuration fields (`DefaultBackfillSnapInterval`, `DefaultBackfillSyncInterval`, `backfillSnapInterval`, `backfillSyncInterval`). In Backfill Mode, the coordinator streamed leaf batches into Pebble and updated in-memory MPT nodes directly via `mptMgr.SetBatch`, completely bypassing per-batch root prediction (`mpt.Predict`), Output Log publishing, and witness cosignatures. It executed periodic snapshots and a post-sync publishing step (`pub.PublishDirect`) upon reaching `targetCP`.
- **Why It Was Investigated**:
  Theoretical concern that during initial synchronization from genesis (tens of millions of leaves), per-batch root prediction and Output Log publishing would cause excessive memory bloat and witness network latency bottlenecks.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  Controlled benchmarks on multi-core NVMe hardware comparing Normal Serving Mode (`SyncOnce`) against Backfill Mode revealed:
  1. **Normal Mode is 85.1% Faster on Go SumDB**: Normal Mode achieved **90,797.2 leaves/sec** vs. Backfill Mode's **49,063.6 leaves/sec**. Normal Mode batches storage updates and streams leaf bundles efficiently, avoiding the per-batch in-memory MPT mutation overhead that throttles Backfill Mode.
  2. **100% Read Starvation in Backfill Mode**: Backfill Mode kept the HTTP read server offline (0% availability) for the entire ingestion window. In contrast, Normal Mode sustained sub-2ms P50 latency with 100% availability under concurrent read queries while actively ingesting.
  3. **Identical Memory Footprint**: Backfill Mode yielded no meaningful RSS reduction (saving only 20–30 MB out of a 220 MB working set) because Pebble LSM write buffers and MPT node allocations dominate memory.
  4. **Architectural Duplication**: `Coordinator.Backfill` duplicated batch channel streaming, pending batch aggregation, progress reporting, and checkpoint persistence from `SyncOnce`.
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode provided zero throughput advantage, introduced complete read starvation, and created dead code across the coordinator and test suites. It was permanently pruned from `coordinator.go` and `recovery_test.go` in Milestone M3. The coordinator is unified around `SyncOnce` and `RunSyncLoop`.

### 4.2 Dedicated WAL in Pebble ('w' Prefix with WalReaper)
- Staged records under transient `'w'` prefix before an async `WalReaper` converted them to `'c'` chunks.
- Caused double-write disk amplification, massive LSM compaction churn, and P99 read latency spikes (up to 1,214 ms).
- Replaced by Zero-WAL direct inverted chunk indexing and tile cache replay (+24.7% throughput, ~99% P99 tail reduction).

### 4.3 Synchronous Full-Tree Snapshotting on Every Batch
- Flushing the entire MPT to disk on every commit incurred gigabytes of disk write I/O per batch, causing severe commit latency stalls.
- Replaced by in-memory snapshotting (`mpt.Snap`) with adaptive background disk sync triggers.

### 4.4 Fictional 2x2 Header Matrix
- Early design specifications described a 2x2 recovery decision matrix based on an `exact bool` flag in the on-disk MPT header.
- In implementation, Phase 1 evaluates `if inCP.Size == mptPersistedSize && c.mptMgr.Root() == mapRoot`, which accurately and deterministically verifies clean shutdown without relying on unimplemented header booleans.
