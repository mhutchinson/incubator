# Sub-Design: Coordinator & Lifecycle Engine

This document defines the batch orchestration engine, watermark governance, Zero-WAL startup recovery protocols, load-bearing invariants, and verified performance optimizations for the **Coordinator Subsystem** (`vindex/v1/internal/coordinator`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Orchestration Dilemma
The VIndex architecture decomposes indexing into five specialized, asynchronous subsystems:
1. **`internal/ingest`**: Network fetching and local tile disk caching.
2. **`mapfn`**: Isolated WebAssembly execution and hardware vector hashing.
3. **`internal/kvstore`**: Pebble LSM inverted chunk storage.
4. **`internal/tree`**: Authenticated Sparse Merkle Patricia Trie commitment and Output Log publication.
5. **`internal/server`**: C2SP HTTP read serving.

Without a central orchestrator managing these components behind strict black-box interfaces, three critical failure modes emerge:
1. **Watermark Drift & Ambiguity**: If individual subsystems track state independently, cross-subsystem boundaries drift out of alignment. A crash between storage sync and log publication leaves the node unable to determine where recovery begins.
2. **Moving-Goalpost Starvation**: In high-velocity logs appending thousands of leaves per second, continuously polling the log head prevents the pipeline from ever finalizing a batch, causing synchronization starvation.
3. **Network-Dependent Crash Recovery**: If startup recovery relies on downloading historical tiles over the network, node restart times become unpredictable and fail completely during upstream network outages.

### 1.2 Centralized Watermark Authority & Separation of Concerns
The Coordinator serves as the **single source of truth** for system lifecycle and watermark governance:
- Worker subsystems expose clean, black-box functional interfaces and do not inspect each other's internal metadata or storage engines.
- The Coordinator alone tracks the global progression chain, evaluates persistence boundaries, and calculates the authoritative `SafeWatermark = min(persisted KV storage watermark, MPT_Durable_Size)` communicated to `TileReaper`.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Drive the steady-state batch processing loop across all pipeline stages in strictly monotonic sequence.
  - Prevent moving-goalpost starvation by freezing target sync checkpoints prior to batch ingestion.
  - Enforce the synchronous handoff: persist the KV checkpoint to disk, ratchet forward, predict the MPT change, and promote the checkpoint to the Output Log.
  - Guarantee deterministic, network-free Zero-WAL crash recovery (< 5ms clean start, < 500ms dirty crash recovery).
- **Non-Goals**:
  - **No Distributed Consensus**: Operates strictly within a single process; does not run Raft, Paxos, or distributed leader election.
  - **No Direct In-Memory Mutation**: The Coordinator does not touch trie nodes or LSM chunk bytes directly; it invokes black-box subsystem methods.
  - **No Arbitrary Runtime Mode Switching**: Operates Normal Serving Mode for all serving logs; Genesis Backfill is used strictly during unserved initial bootstrap (`outputLog.Size() == 0`).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Integrates `TileFetcher`, `ManagedTileCache`, `Pipeline`, `IndexStore`, `MPTManager`, and `Publisher`.
- **Known Pain Points ("Warts and All")**:
  - **Dirty Crash Recovery Replay Duration**: While clean restarts open read serving in under 5 milliseconds, recovering from a dirty kill where MPT disk fsync lagged behind the Output Log requires replaying historical tiles from local disk cache, taking up to 500ms before HTTP queries can be served.
  - **Batch Flush Latency on Low-Velocity Logs**: On logs with infrequent appends, waiting for a full 4,096-leaf commit batch could stall commits; the coordinator requires a flush timeout (e.g. 10s) to force partial-batch commits.

---

## 2. Detailed Design

### 2.1 The Master Batch Loop (`SyncOnce` Lifecycle)
The coordinator executes batch synchronization through a structured, 6-step sequential lifecycle:

| Step | Phase | Action & Subsystem Invocation | Durability Transition |
| :- | :--- | :--- | :--- |
| **1** | **Poll & Freeze** | Polls upstream Input Log `/checkpoint`, verifies signature notes, and writes target input checkpoint to Pebble metadata. | Freezes target sync boundary. |
| **2** | **Tile Ingestion** | `fetcher.FetchTiles` downloads missing 256-leaf tiles into `ManagedTileCache`. | Durably stages verified tiles on disk. |
| **3** | **Parallel Mapping** | `pipeline.StreamBatches` feeds tiles to WASM workers, hashes preimages via host SIMD, and re-sequences batches. | In-memory key-index aggregation. |
| **4** | **Storage Commit** | Aggregates 4,096 leaves (`DefaultCommitBatchSize`) and invokes `store.WriteBatch` (which parallelizes in-memory mini-log hashing before sequential commit) with blocking `pebble.Sync`. | **Ratchets persisted KV storage watermark durably to disk and persists `KV_CP`.** |
| **5** | **Commitment & Promotion** | Calls `publisher.PublishBatch`: predicts `MapRoot` lock-free, appends to Output Log, collects witness cosignatures, and ratchets `ServingState` via atomic state promotion under publisher lock (< 5ms). | **Promotes state to Output Log (`Output_CP`) & Serving (`Serving_CP`).** |
| **6** | **Pruning Notification** | Computes `SafeWatermark = min(persisted KV storage watermark, MPT_Durable_Size)` and notifies `TileReaper`. | Bounded disk cache garbage collection. |

### 2.2 Checkpoint Governance & Progression Chain

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` | Durable (`pebble.Sync` in Pebble metadata) | Upstream poll & origin note verification | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (`pebble.Sync` in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | `Output_CP.InputSize` (committed in leaf) | Durable (Tessera Output Log storage) | Append commitment leaf & witness cosigning | Cryptographically commits to index root (`MapRoot` + covered Input Log checkpoint). |
| **`Serving_CP`** | Output Log Leaf | `Serving_CP.InputSize` | Volatile (In-memory atomic pointer) | Pointer swap via atomic state promotion under publisher lock (< 5ms) | Active state exposed to client HTTP readers. |

**Monotonic Checkpoint Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batch aggregation advances toward the target checkpoint in discrete commit slices.
- `KV_CP.Size >= Output_CP.InputSize`: KV storage persistence strictly precedes Output Log publication.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Output Log publication and witness collection execute outside reader locking; `Output_CP` advances before the in-memory serving pointer is swapped via atomic state promotion under publisher lock.

#### Intermediate Buffers & Trailing Durability
- `Target_CP -> KV_CP`: Ingest stages data through `Cached_Tiles` (disk) and worker mapping queues; persisted KV storage watermark accumulates in Pebble write batches until committed at `KV_CP.Size`.
- `KV_CP -> Output_CP`: Lock-free MPT prediction calculates candidate `MapRoot`.
- `Output_CP -> Serving_CP`: In-memory atomic swap ratchets `ServingState` (< 5ms critical section).
- `Trailing Serving_CP`: `MPT_Durable_Size` fsyncs to disk in the background, satisfying `Serving_CP.InputSize >= MPT_Durable_Size`.

### 2.3 Authoritative `SafeWatermark` Calculation for `TileReaper`
To guarantee that the ingestion cache never deletes tiles needed for crash recovery, the Coordinator calculates the authoritative safe pruning boundary:
```go
safeWatermark := min(kvSize, mptDurableSize)
```
Because storage persistence strictly precedes Output Log publication (`kvSize >= Output_Size >= mptDurableSize`), `min(kvSize, mptDurableSize)` strictly equals `mptDurableSize`. The Coordinator communicates this boundary to `TileReaper`, ensuring that tiles in the window `[mptDurableSize .. kvSize)` remain cached on disk until the MPT confirms durable fsync.

### 2.4 Moving-Goalpost Prevention
On high-traffic transparency logs, the log head advances continuously. If the coordinator polled unverified checkpoints on every iteration, the sync target would constantly move, starving downstream commitment.

The Coordinator prevents this by writing the verified target checkpoint note into Pebble DB metadata (target input checkpoint) prior to batch processing. The entire pipeline processes that fixed slice to completion before the coordinator advances to a new target.

### 2.5 Zero-WAL Startup Recovery Sequence & Uncommitted KV Writes
On daemon launch, the coordinator executes a deterministic 3-phase recovery sequence before opening network endpoints:

1. **Phase 1: Instant Warm Start (< 5ms)**:
   - Compares the persisted MPT size on disk against the latest committed Output Log state (`Output_CP.InputSize`), and verifies that the trie root matches the Output Log leaf commitment.
   - If true, clean shutdown is verified. Activates `Serving_CP`, initializes watermarks, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms)**:
   - If the persisted MPT lags behind the latest Output Log commitment (`MPT_Durable_Size < Output_CP.InputSize`) due to a dirty kill:
     - Streams missing historical tiles across the lag window `[MPT_Durable_Size .. Output_CP.InputSize)` directly from the local disk tile cache.
     - Maps replayed tiles via `map_bundle` to identify modified search keys.
     - Reconstructs mini-log sub-roots for modified keys up to `Output_CP.InputSize` with **zero writes to the database**.
     - Updates in-memory MPT nodes and asserts that the resulting root strictly matches the Output Log leaf commitment.
     - Flushes MPT persistence to disk, activates `Serving_CP`, and **opens the Read Server (< 500ms)**.
3. **Phase 3: Background Catch-Up & Uncommitted KV Writes**:
   - Resumes forward ingestion from `Serving_CP.InputLogSize` toward `Target_CP.Size`.
   - **Handling Uncommitted KV Writes**: If a crash occurred after Pebble durably synced a batch to disk but before `PublishBatch` committed to the Output Log (`persisted KV storage watermark > ServingState.InputLogSize`), `SyncOnce` streams starting from `ServingState.InputLogSize`. When re-processing entries that were already written to disk, `kvstore/writer.go` detects `unpersisted == 0` for already-written keys and reconstructs their sub-roots directly from Pebble without re-writing storage. This allows uncommitted batches to be safely published to the Output Log upon initial sync without duplicate entries or storage churn.

### 2.6 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Stage Promotion**:
  - *Rule*: Inverted chunk storage writes must complete `pebble.Sync` and commit `KV_CP` before `publisher.PublishBatch` is permitted to execute (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees `KV_CP.Size >= Output_CP.InputSize` across all crash scenarios.
  - *Consequence ("Or Else")*: A crash between Output Log publishing and storage sync would publish a state commitment referencing missing or rolled-back KV chunks, permanently breaking inclusion proofs for witnessed checkpoints.

- **[Correctness Invariant] Zero-WAL Startup Durability Guarantee**:
  - *Rule*: Because `KV_CP.Size >= Output_CP.InputSize`, crash recovery must resolve all lagging MPT state using local tile cache and local Pebble DB records without issuing external network requests.
  - *Rationale*: Protects node availability against upstream log outages and guarantees predictable cold-boot timing.
  - *Consequence ("Or Else")*: A node recovering from a crash during an upstream network partition would fail to boot, causing extended service downtime.

- **[Performance Optimization] Unified 4,096-Leaf Batch Aggregation**:
  - *Mechanism*: Buffers mapped leaves into 4,096-leaf commit batches (`DefaultCommitBatchSize = 4096`) before invoking storage and commitment.
  - *Impact*: Amortizes `pebble.Sync` disk write latency and external witness network RPCs across 4,096 leaves, sustaining high indexing throughput (>90,000 leaves/sec).

### 2.7 Coordination Contract & State Guarantees

The coordinator acts as the single source of truth for pipeline progression and lifecycle management:

- **Inputs**:
  - Input Log fetcher.
  - Local tile cache.
  - Mapping pipeline.
  - KV store.
  - Trie manager.
  - Output publisher.
- **Recovery Contract**:
  - Enforces 3-phase startup recovery:
    1. Verifies that persisted trie state equals the storage watermark.
    2. Replays uncommitted tiles from the local disk cache to align with the Output Log tip with zero database writes.
    3. Resumes ingestion without duplicating persisted writes.
- **Durability Invariant**:
  - Storage durability strictly precedes public log commitment:
    ```text
    KV_Storage_Durability >= Output_Log_Leaf.InputLogSize
    ```
- **Concurrency**:
  - The background polling loop runs synchronously per iteration; catch-up and steady-state ingestion are strictly single-threaded.

### 2.8 Genesis Backfill Lifecycle (Unserved Bootstrap)

When bootstrapping from leaf 0 on high-cardinality logs (e.g. Certificate Transparency at 900M+ leaves), accumulating intermediate sub-roots across the entire log in an in-memory Go map before a final publish batch consumes >70 GB of heap (95.7% of allocations), triggering severe swap thrashing that collapses ingestion throughput by ~90% (dropping from ~97,000 to ~10,000 leaves/sec).

The coordinator automatically executes the **Genesis Backfill** lifecycle under strict invariants:

1. **Gating Invariant (`outputLog.Size() == 0`)**:
   - Activated automatically if and only if the Output Log has zero commitment leaves (`outputLog.Size() == 0`).
   - Because the log has never served, read availability is unimpacted: `/lookup` endpoints safely return `503 Service Unavailable ("serving state not initialized")`, `/healthz` returns `200 OK`, and `/readyz`/`/syncz` returns `503` with diagnostic JSON (`"genesis_backfill": true`).
   - Once Leaf 0 is committed to the Output Log, the coordinator permanently ratchets to Normal Serving Mode. Subsequent restarts and catch-up cycles execute Normal Serving Mode exclusively.

2. **Pipelined Execution & Memory Bounding**:
   - Double-buffered slabs (4,096 leaves) stream through WASM mapping and commit to Pebble storage normally, ratcheting `m_kv_size`.
   - Sub-root modifications are applied directly to the MPT via `mptMgr.SetBatch(mutations)`.
   - Batch mutation maps are discarded immediately, bounding working memory to < 10 GB RSS with zero swap.
   - Intermediate `mpt.Predict` root predictions, Output Log appends, and witness signatures are completely bypassed.

3. **Coarse Checkpoint Protocol & Durability Barrier**:
   - Calling `tree.Snap` or `tree.Sync` on every 4,096-leaf batch is prohibited (causes O(log N) dirty-node hashing and disk fsync stalls).
   - The coordinator executes coarse periodic checkpoints (every ~1,000,000 leaves) and on graceful shutdown (`SIGINT`/`SIGTERM`) under a strict 3-step durability sequence:
     1. **Pebble Durability Barrier**: Commits the current slab with `pebble.Sync`, guaranteeing `m_kv_size >= currentKVSize` is physically flushed to disk.
     2. **MPT Snapshot**: `mpt.tree.Snap(int64(currentKVSize))` hashes all dirty trie branches up to the root, sets the watermark version in the MPT header, and clears the dirty bit.
     3. **MPT Durability Sync**: `mpt.tree.Sync()` flushes mmap patch frames and executes `fsync(2)` on underlying tree files.
   - **Durability Invariant**: Step 1 strictly precedes Steps 2 and 3, mathematically guaranteeing `kvSize >= mptPersistedSize` under all power-loss and crash scenarios.

4. **Torchwood MPT Version Semantics & Bounded Crash Recovery**:
   - Torchwood MPT exposes snapshot versioning via `Version() (version int64, exact bool)`:
     - **Clean Shutdown (`SIGINT`/`SIGTERM`)**: Traps termination signals, completes the active slab, executes the coarse checkpoint protocol, and closes cleanly. Returns `version = kvSize, exact = true`. On restart, `resumeLeaf = min(kvSize, mptPersistedSize) = kvSize`. Cold restart requires zero leaf replay.
     - **Dirty Crash (`SIGKILL`, panic, power cut)**: Reopening yields `version = lastSnapVersion, exact = false` (indicating uncommitted in-memory mutations occurred after the last snapshot). The coordinator recovers deterministically:
       1. Computes `resumeLeaf = min(kvSize, mptPersistedSize) = mptPersistedSize`.
       2. Resumes ingestion streaming from `resumeLeaf`.
       3. **Zero Storage Write Amplification**: For replayed leaves `[mptPersistedSize .. kvSize)`, `kvstore/writer.go` detects `unpersisted == 0` for already-persisted indices. It performs zero disk writes and reconstructs sub-roots point-in-time via `GetSubRoot(key, batchEnd)`.
       4. `mptMgr.SetBatch` applies reconstructed sub-roots in monotonic sequence, deterministically overwriting any un-snapped trie state.
       5. **Bounded Blast Radius**: Replay work is bounded to at most the last coarse checkpoint interval (< 1,000,000 leaves, < 10 seconds of streaming).

5. **Tile Cache Retention & `SafeWatermark` Governance**:
   - `TileReaper.SafeWatermark` evaluates `min(kvSize, mptPersistedSize)`.
   - During Genesis Backfill, `mptPersistedSize` remains pinned to the last durable coarse checkpoint boundary (e.g. 50M) while `kvSize` advances ahead (e.g. 50.8M). `TileReaper.PruneBefore(50M)` guarantees that all cached tiles in the uncommitted delta `[50M .. 50.8M)` remain preserved on local disk, ensuring crash recovery is 100% local, Zero-WAL, and network-free.

6. **Genesis Finalization & Output Log Leaf 0 Commit**:
   - At target tip, storage commits the final slab with `pebble.Sync`.
   - `mpt.tree.Snap(int64(targetCP.Size))` hashes remaining dirty nodes and computes the final authoritative `MapRoot`.
   - `mpt.tree.Sync()` fsyncs MPT files to disk.
   - Publisher appends Leaf 0 to the Output Log, collects witness cosignatures, and ratchets serving state.
   - Transitions permanently to Normal Serving Mode.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Arbitrary Runtime Backfill Mode Switching (Retired)
- **Proposed**: Allowing running daemons to switch dynamically between a bulk ingestion mode ("Backfill Mode") and Normal Serving Mode during live catch-up operations.
- **Empirical Rejection Findings**:
  1. **Read Starvation on Live Nodes**: Shutting down the HTTP read server during live catch-up breaks availability for active readers.
  2. **State Machine Complexity**: Dynamic mode switching introduced edge cases around checkpoint continuity, witness synchronization, and reader lock handoffs.
- **Resolution**: Arbitrary runtime switching was permanently retired. Live serving nodes always operate in Normal Serving Mode. However, for unserved logs bootstrapping from leaf 0 (`outputLog.Size() == 0`), an automated, low-memory **Genesis Backfill** lifecycle is retained (§2.8) to eliminate the 70+ GB heap accumulation observed on billion-scale Certificate Transparency logs.

### 3.2 Decentralized Subsystem Watermarking vs. Centralized Coordinator Governance
- **Proposed**: Allowing each subsystem to independently determine when to advance watermarks and prune historical state.
- **Theoretical Rejection**: Decentralized state tracking creates race conditions during dirty crashes. Subsystems cannot establish whether sibling components successfully persisted data, leading to either unrecoverable data loss or redundant disk storage.
- **Chosen Design**: Centralized Coordinator governance with a single authoritative progression chain.

### 3.3 Distributed Consensus Orchestration (Raft/Paxos) vs. Single-Host Coordinator
- **Proposed**: Coordinating indexing across a distributed cluster using Raft consensus.
- **Theoretical & Architectural Rejection**:
  - The MPT already requires single-host RAM/mmap locality; clustering the coordinator adds immense operational complexity without solving tree state synchronization.
  - High availability is achieved externally: independent mirrors run standalone VIndex instances against the shared Input Log.
- **Chosen Design**: Single-process, single-host embedded coordinator.
