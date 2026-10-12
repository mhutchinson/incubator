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
- The Coordinator alone tracks the global progression chain, evaluates persistence boundaries, and calculates the authoritative safe pruning watermark (`min(KV_CP.Size, MPT_Durable_Size)`) communicated to the tile cache reaper.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Drive the steady-state batch processing loop across all pipeline stages in strictly monotonic sequence.
  - Prevent moving-goalpost starvation by freezing target sync checkpoints prior to batch ingestion.
  - Enforce the synchronous handoff: persist the KV checkpoint to disk, ratchet forward, predict the MPT change, and promote the checkpoint to the Output Log.
  - Guarantee deterministic, network-free Zero-WAL crash recovery (< 5ms clean start, < 500ms dirty crash recovery).
- **Non-Goals**:
  - **No Distributed Consensus**: Operates strictly within a single process; does not run Raft, Paxos, or distributed leader election.
  - **No Direct In-Memory Mutation**: The Coordinator does not touch trie nodes or LSM chunk bytes directly; it coordinates subsystem boundaries.
  - **No Arbitrary Runtime Mode Switching**: Operates Normal Serving Mode for all serving logs; Genesis Backfill is used strictly during unserved initial bootstrap when the Output Log is empty (`Output_CP.Size == 0`).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Orchestrates the ingestion fetcher and tile cache, WASM mapping pipeline, KV chunk store, MPT commitment manager, and Output Log publisher.
- **Known Pain Points ("Warts and All")**:
  - **Dirty Crash Recovery Replay Duration**: While clean restarts open read serving in under 5 milliseconds, recovering from a dirty kill where MPT disk `fsync` lagged behind the Output Log requires replaying historical tiles from local disk cache, taking up to 500ms before HTTP queries can be served.
  - **End-of-Cycle Partial Batch Flushing**: Each sync cycle streams a bounded leaf range up to the frozen target checkpoint and flushes any trailing partial commit batch at the end of the range so low-velocity logs do not stall waiting to fill a multi-tile slab.

---

## 2. Detailed Design

### 2.1 The Master Batch Loop
The coordinator executes batch synchronization through a structured, 6-step sequential lifecycle:

| Step | Phase | Action & Subsystem Transition | Durability Transition |
| :- | :--- | :--- | :--- |
| **1** | **Poll & Freeze** | Polls upstream Input Log `/checkpoint`, verifies signature notes, and writes target input checkpoint (`Target_CP`) to Pebble metadata. | Freezes target sync boundary. |
| **2** | **Tile Ingestion** | Downloads missing 256-leaf tiles up to `Target_CP.Size` into the local tile cache. | Durably stages verified tiles on disk. |
| **3** | **Parallel Mapping** | Streams tiles to WASM workers, hashes preimages via host SIMD, and re-sequences batches into multi-tile commit slabs. | In-memory key-index aggregation. |
| **4** | **Storage Commit** | Streams commit slabs into the KV store (committing intermediate slabs without disk sync while accumulating modified sub-roots across the target window, and executing a blocking disk `fsync` barrier on the final slab reaching `Target_CP.Size`). | **Ratchets persisted KV storage watermark durably to disk and persists `KV_CP` at `Target_CP.Size`.** |
| **5** | **Commitment & Promotion** | Once `Target_CP.Size` is reached and synced in Pebble, predicts candidate `MapRoot` over accumulated modified sub-roots, appends one commitment leaf for `Target_CP` to the Output Log, collects witness cosignatures, and ratchets `Serving_CP` under the exclusive tree lock (< 5ms). | **Promotes state to Output Log (`Output_CP`) & Serving (`Serving_CP`).** |
| **6** | **Pruning Notification** | Computes the safe pruning watermark (`min(KV_CP.Size, MPT_Durable_Size)`) and notifies the tile cache reaper. | Bounded disk cache garbage collection. |

### 2.2 Checkpoint Governance & Progression Chain

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` | Durable (synced in Pebble metadata) | Upstream poll & origin note verification | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (synced in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | `Output_CP.InputSize` (committed in leaf) | Durable (Tessera Output Log storage) | Append commitment leaf & witness cosigning | Cryptographically commits to index root (`MapRoot` + covered Input Log checkpoint). |
| **`Serving_CP`** | Output Log Leaf | `Serving_CP.InputSize` | Volatile (In-memory atomic pointer) | Pointer swap via atomic state promotion under tree lock (< 5ms) | Active state exposed to client HTTP readers. |

**Monotonic Checkpoint Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batch aggregation advances toward the target checkpoint in discrete commit slices.
- `KV_CP.Size >= Output_CP.InputSize`: KV storage persistence strictly precedes Output Log publication.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Output Log publication and witness collection execute outside reader locking; `Output_CP` advances before the in-memory serving pointer is swapped via atomic state promotion under the tree lock.

#### Intermediate Buffers & Trailing Durability
- `Target_CP -> KV_CP`: Ingest stages data through cached tiles on disk and worker mapping queues; the persisted KV storage watermark accumulates across write batches until synced at `KV_CP.Size`.
- `KV_CP -> Output_CP`: Non-blocking MPT prediction calculates candidate `MapRoot`.
- `Output_CP -> Serving_CP`: In-memory atomic swap ratchets `Serving_CP` (< 5ms critical section).
- `Trailing Serving_CP`: `MPT_Durable_Size` `fsync`s to disk in the background, satisfying `Serving_CP.InputSize >= MPT_Durable_Size`.

### 2.3 Authoritative Safe Pruning Watermark for Tile Cache Reclamation
To guarantee that the ingestion cache never deletes tiles needed for crash recovery, the Coordinator calculates the authoritative safe pruning boundary as the minimum of the persisted KV storage watermark (`KV_CP.Size`) and the durable MPT snapshot watermark (`MPT_Durable_Size`). Because storage persistence strictly precedes Output Log publication and MPT persistence (`KV_CP.Size >= Output_CP.InputSize >= MPT_Durable_Size`), this minimum is governed by `MPT_Durable_Size`. Communicating this boundary to the tile cache reaper ensures that tiles in the window `[MPT_Durable_Size .. KV_CP.Size)` remain cached on disk until the MPT confirms a durable `fsync`.

### 2.4 Moving-Goalpost Prevention
On high-traffic transparency logs, the log head advances continuously. If the coordinator polled unverified checkpoints on every iteration, the sync target would constantly move, starving downstream commitment.

The Coordinator prevents this by writing the verified target checkpoint note into Pebble DB metadata (`Target_CP`) prior to batch processing. The entire pipeline processes that fixed slice to completion before the coordinator advances to a new target.

### 2.5 Zero-WAL Startup Recovery Sequence & Uncommitted KV Writes
On daemon launch, the coordinator executes a deterministic 3-phase recovery sequence before opening network endpoints:

1. **Phase 1: Instant Warm Start (< 5ms)**:
   - Compares the persisted MPT size on disk (`MPT_Durable_Size`) against the latest committed Output Log state (`Output_CP.InputSize`), and verifies that the trie root matches the Output Log leaf commitment.
   - If true, clean shutdown is verified. Activates `Serving_CP`, initializes watermarks, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms)**:
   - If the persisted MPT lags behind the latest Output Log commitment (`MPT_Durable_Size < Output_CP.InputSize`) due to a dirty kill:
     - Streams missing historical tiles across the lag window `[MPT_Durable_Size .. Output_CP.InputSize)` directly from the local disk tile cache.
     - Maps replayed tiles via `map_bundle` to identify modified search keys.
     - Reconstructs mini-log sub-roots for modified keys up to `Output_CP.InputSize` with **zero writes to the database**.
     - Updates in-memory MPT nodes and asserts that the resulting root strictly matches the Output Log leaf commitment.
     - Flushes MPT persistence to disk, activates `Serving_CP`, and **opens the Read Server (< 500ms)**.
3. **Phase 3: Background Catch-Up & Uncommitted KV Writes**:
   - Resumes forward ingestion from `Serving_CP.InputSize` toward `Target_CP.Size`.
   - **Handling Uncommitted KV Writes**: If a crash occurred after Pebble durably synced a batch to disk but before Output Log commitment (`KV_CP.Size > Serving_CP.InputSize`), the next sync cycle streams starting from `Serving_CP.InputSize`. When re-processing entries that were already written to disk, the KV store filters out already-persisted leaf indices and reconstructs their sub-roots directly from Pebble without re-writing storage. This allows uncommitted batches to be safely published to the Output Log upon initial sync without duplicate entries or storage churn.

### 2.6 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Stage Promotion**:
  - *Rule*: Inverted chunk storage writes must complete a durable disk sync and commit `KV_CP` before Output Log publication is permitted to execute (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees `KV_CP.Size >= Output_CP.InputSize` across all crash scenarios.
  - *Consequence ("Or Else")*: A crash between Output Log publishing and storage sync would publish a state commitment referencing missing or rolled-back KV chunks, permanently breaking inclusion proofs for witnessed checkpoints.

- **[Correctness Invariant] Zero-WAL Startup Durability Guarantee**:
  - *Rule*: Because `KV_CP.Size >= Output_CP.InputSize`, crash recovery must resolve all lagging MPT state using local tile cache and local Pebble DB records without issuing external network requests.
  - *Rationale*: Protects node availability against upstream log outages and guarantees predictable cold-boot timing.
  - *Consequence ("Or Else")*: A node recovering from a crash during an upstream network partition would fail to boot, causing extended service downtime.

- **[Performance Optimization] Multi-Tile Slab Aggregation & Target-Level Witnessing**:
  - *Mechanism*: Buffers mapped leaves into multi-tile commit slabs without per-slab disk syncs on intermediate slabs, executing a single durable KV sync and Output Log witness cycle at `Target_CP.Size`.
  - *Impact*: Amortizes disk write latency and external witness network RPCs across the sync window, sustaining high indexing throughput (>90,000 leaves/sec).

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
    1. Verifies that persisted trie state equals the committed Output Log watermark.
    2. Replays uncommitted tiles from the local disk cache to align with the Output Log tip with zero database writes.
    3. Resumes ingestion without duplicating persisted writes.
- **Durability Invariant**:
  - Storage durability strictly precedes public log commitment (`KV_CP.Size >= Output_CP.InputSize`).
- **Concurrency**:
  - The background polling loop runs synchronously per iteration; catch-up and steady-state ingestion are strictly single-threaded.

### 2.8 Genesis Backfill Lifecycle (Unserved Bootstrap)

When bootstrapping from leaf 0 on high-cardinality logs (e.g. Certificate Transparency at 900M+ leaves), accumulating intermediate sub-roots across the entire log in an unbounded in-memory Go map before a final publish batch consumes >70 GB of heap (95.7% of allocations), triggering severe swap thrashing that collapses ingestion throughput by ~90% (dropping from ~97,000 to ~10,000 leaves/sec).

The coordinator automatically executes the **Genesis Backfill** lifecycle under strict invariants:

1. **Gating Invariant (`Output_CP.Size == 0`)**:
   - Activated automatically if and only if the Output Log has zero commitment leaves (`Output_CP.Size == 0`).
   - Because the log has never served, read availability is unimpacted: `/lookup` endpoints safely return `503 Service Unavailable`, `/healthz` returns `200 OK`, and `/readyz`/`/syncz` return `503` with diagnostic JSON (`"genesis_backfill": true`).
   - Once Leaf 0 is committed to the Output Log, the coordinator permanently ratchets to Normal Serving Mode. Subsequent restarts and catch-up cycles execute Normal Serving Mode exclusively.

2. **Double-Buffered Key Coalescing & Memory Bounding**:
   - Mapped commit slabs stream into Pebble storage without per-slab `fsync`, advancing the persisted KV watermark (`KV_CP.Size`) and returning modified sub-roots.
   - Rather than applying MPT mutations on every slab, the coordinator coalesces modified sub-roots in an in-memory double buffer, overwriting repeated keys in O(1) RAM.
   - To accelerate initial tree density while preventing heap bloat, the flush threshold ramps progressively up to tens of millions of keys (or tens of millions of leaves per coarse checkpoint interval).
   - Intermediate root predictions, Output Log appends, and witness signatures are completely bypassed.

3. **Asynchronous Coarse Checkpoint Flush**:
   - When the active buffer reaches its key threshold or the coarse checkpoint leaf interval, the coordinator swaps buffers and dispatches a coarse flush job to a background MPT worker goroutine (on graceful shutdown `SIGINT`/`SIGTERM`, any already-dispatched background flush finishes while uncommitted in-flight batch work is skipped so startup resumes from the last durable coarse checkpoint):
     1. **Pebble Durability Barrier**: Executes a synchronous KV flush, guaranteeing that all KV chunk records up to the flush watermark are physically flushed to disk.
     2. **MPT Batch Application & Snapshot**: Applies the coalesced sub-root batch to the MPT and creates a versioned trie snapshot, hashing dirty trie branches and recording the snapshot watermark in the MPT header.
     3. **MPT Durability Sync**: Flushes mmap patch frames and executes `fsync` on the underlying tree files.
   - **Durability Invariant**: Step 1 must strictly precede Steps 2 and 3, guaranteeing `KV_CP.Size >= MPT_Durable_Size` across all crash scenarios.

4. **Bounded Crash Recovery**:
   - On startup when `Output_CP.Size == 0` and `KV_CP.Size > MPT_Durable_Size`:
     - The coordinator streams cached tiles across the un-snapped delta `[MPT_Durable_Size .. KV_CP.Size)` through the mapping pipeline to collect all distinct modified `KeyHash` values in memory without writing to Pebble.
     - Once all modified keys in `[MPT_Durable_Size .. KV_CP.Size)` are collected, it reconstructs their sub-roots at `KV_CP.Size` in bulk from Pebble and applies them in a single MPT batch, snapshot, and disk sync pass.
     - Ingestion then resumes cleanly from `KV_CP.Size` toward `Target_CP.Size`.

5. **Tile Cache Retention & Safe Watermark Governance**:
   - The safe pruning watermark evaluates `min(KV_CP.Size, MPT_Durable_Size)`.
   - During Genesis Backfill, `MPT_Durable_Size` remains pinned to the last durable coarse checkpoint boundary while `KV_CP.Size` advances ahead. The tile cache reaper preserves all cached tiles in `[MPT_Durable_Size .. KV_CP.Size)` on local disk, ensuring crash recovery is 100% local, Zero-WAL, and network-free.

6. **Genesis Finalization & Output Log Leaf 0 Commit**:
   - Upon reaching `Target_CP.Size`, any remaining buffered sub-roots are flushed, snapshotted, and synced to disk, producing the final authoritative `MapRoot`.
   - The publisher appends Leaf 0 to the Output Log, collects witness cosignatures, and ratchets `Serving_CP`.
   - Transitions permanently to Normal Serving Mode.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Arbitrary Runtime Backfill Mode Switching (Retired)
- **Proposed**: Allowing running daemons to switch dynamically between a bulk ingestion mode ("Backfill Mode") and Normal Serving Mode during live catch-up operations.
- **Empirical Rejection Findings**:
  1. **Read Starvation on Live Nodes**: Shutting down the HTTP read server during live catch-up breaks availability for active readers.
  2. **State Machine Complexity**: Dynamic mode switching introduced edge cases around checkpoint continuity, witness synchronization, and reader lock handoffs.
- **Resolution**: Arbitrary runtime switching was permanently retired. Live serving nodes always operate in Normal Serving Mode. However, for unserved logs bootstrapping from leaf 0 (`Output_CP.Size == 0`), an automated, low-memory **Genesis Backfill** lifecycle is retained (§2.8) to eliminate the 70+ GB heap accumulation observed on billion-scale Certificate Transparency logs.

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
