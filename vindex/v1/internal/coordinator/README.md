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
- The Coordinator alone tracks the global progression chain, evaluates persistence boundaries, and calculates the authoritative `SafeWatermark = min(m_kv_size, MPT_Durable_Size)` communicated to `TileReaper`.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Drive the steady-state batch processing loop across all pipeline stages in strictly monotonic sequence.
  - Prevent moving-goalpost starvation by freezing target sync checkpoints prior to batch ingestion.
  - Enforce the synchronous handoff: persist the KV checkpoint to disk, ratchet forward, predict the MPT change, and promote the checkpoint to the Output Log.
  - Guarantee deterministic, network-free Zero-WAL crash recovery (< 5ms clean start, < 500ms dirty crash recovery).
- **Non-Goals**:
  - **No Distributed Consensus**: Operates strictly within a single process; does not run Raft, Paxos, or distributed leader election.
  - **No Direct In-Memory Mutation**: The Coordinator does not touch trie nodes or LSM chunk bytes directly; it invokes black-box subsystem methods.
  - **No Dual Ingestion Modes**: Operates a single, unified high-throughput pipeline; legacy "Backfill Mode" has been permanently retired.

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
| :--- | :--- | :--- | :--- |
| **1** | **Poll & Freeze** | Polls upstream Input Log `/checkpoint`, verifies signature notes, and writes `m_target_checkpoint` to Pebble metadata. | Freezes target sync boundary. |
| **2** | **Tile Ingestion** | `fetcher.FetchTiles` downloads missing 256-leaf tiles into `ManagedTileCache`. | Durably stages verified tiles on disk. |
| **3** | **Parallel Mapping** | `pipeline.StreamBatches` feeds tiles to WASM workers, hashes preimages via host SIMD, and re-sequences batches. | In-memory key-index aggregation. |
| **4** | **Storage Commit** | Aggregates 4,096 leaves (`DefaultCommitBatchSize`) and calls `store.WriteBatch` with blocking `pebble.Sync`. | **Ratchets `m_kv_size` durably to disk and persists `KV_CP`.** |
| **5** | **Commitment & Promotion** | Calls `publisher.PublishBatch`: predicts `MapRoot` lock-free, appends to Output Log, collects witness cosignatures, and ratchets `ServingState` under < 5ms lock. | **Promotes state to Output Log (`Output_CP`) & Serving (`Serving_CP`).** |
| **6** | **Pruning Notification** | Computes `SafeWatermark = min(m_kv_size, MPT_Durable_Size)` and notifies `TileReaper`. | Bounded disk cache garbage collection. |

### 2.2 Checkpoint Governance & Progression Chain

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` | Durable (`pebble.Sync` in Pebble metadata) | Upstream poll & origin note verification | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (`pebble.Sync` in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | `Output_CP.InputSize` (committed in leaf) | Durable (Tessera Output Log storage) | Append commitment leaf & witness cosigning | Cryptographically commits to index root (`MapRoot` + covered Input Log checkpoint). |
| **`Serving_CP`** | Output Log Leaf | `Serving_CP.InputSize` | Volatile (In-memory atomic pointer) | Pointer swap under `treeMu.Lock()` (< 5ms) | Active state exposed to client HTTP readers. |

**Monotonic Checkpoint Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batch aggregation advances toward the target checkpoint in discrete commit slices.
- `KV_CP.Size >= Output_CP.InputSize`: KV storage persistence strictly precedes Output Log publication.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Output Log publication and witness collection execute outside reader locking; `Output_CP` advances before the in-memory serving pointer is swapped under `treeMu.Lock()`.

#### Intermediate Buffers & Trailing Durability
- `Target_CP -> KV_CP`: Ingest stages data through `Cached_Tiles` (disk) and worker mapping queues; `m_kv_size` accumulates in Pebble write batches until committed at `m_kv_size == KV_CP.Size`.
- `KV_CP -> Output_CP`: Lock-free MPT prediction calculates candidate `MapRoot`.
- `Output_CP -> Serving_CP`: In-memory atomic swap ratchets `ServingState` (< 5ms critical section).
- `Trailing Serving_CP`: `MPT_Durable_Size` fsyncs to disk in the background under `writeMu`, satisfying `Serving_CP.InputSize >= MPT_Durable_Size`.

### 2.3 Authoritative `SafeWatermark` Calculation for `TileReaper`
To guarantee that the ingestion cache never deletes tiles needed for crash recovery, the Coordinator calculates the authoritative safe pruning boundary:
```go
safeWatermark := min(kvSize, mptDurableSize)
```
Because storage persistence strictly precedes Output Log publication (`kvSize >= Output_Size >= mptDurableSize`), `min(kvSize, mptDurableSize)` strictly equals `mptDurableSize`. The Coordinator communicates this boundary to `TileReaper`, ensuring that tiles in the window `[mptDurableSize .. kvSize)` remain cached on disk until the MPT confirms durable fsync.

### 2.4 Moving-Goalpost Prevention
On high-traffic transparency logs, the log head advances continuously. If the coordinator polled unverified checkpoints on every iteration, the sync target would constantly move, starving downstream commitment.

The Coordinator prevents this by writing the verified target checkpoint note into Pebble DB metadata (`m_target_checkpoint`) prior to batch processing. The entire pipeline processes that fixed slice to completion before the coordinator advances to a new target.

### 2.5 Zero-WAL Startup Recovery Sequence
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
3. **Phase 3: Background Catch-Up**:
   - Resumes forward ingestion from `KV_CP.Size` toward `Target_CP.Size`.

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

### 2.7 Go Interfaces & Public Types

```go
package coordinator

import (
	"context"

	"github.com/transparency-dev/formats/log"
)

// Coordinator orchestrates the end-to-end VIndex pipeline.
type Coordinator struct {
	fetcher   TileFetcher
	cache     ManagedTileCache
	pipeline  MappingPipeline
	store     IndexStore
	mptMgr    MPTManager
	publisher Publisher
}

// SyncOptions configures batch processing parameters.
type SyncOptions struct {
	CommitBatchSize uint64
	PollInterval    time.Duration
	FlushTimeout    time.Duration
}

// Watermarks captures the instantaneous cross-subsystem progression state.
type Watermarks struct {
	TargetCheckpoint uint64
	CachedTiles      uint64
	KVSize           uint64
	OutputLogSize    uint64
	MPTDurableSize   uint64
}
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 Dual-Mode Architecture (Backfill Mode vs. Normal Mode) Retirement
- **Proposed**: A dedicated bulk ingestion mode ("Backfill Mode") that streamed leaves into Pebble and applied direct `mpt.SetBatch` mutations to in-memory MPT nodes, completely bypassing per-batch `mpt.Predict` root prediction and Output Log publishing.
- **Why Investigated**: Theoretical concern that running `mpt.Predict` and publishing Output Log commitments per batch would bottleneck catch-up from leaf 0.
- **Empirical Rejection Findings (Go SumDB 61.7M Entries)**:
  1. **Normal Mode is 85.1% Faster**: Normal Serving Mode achieved **90,797 leaves/sec** vs. Backfill Mode's **49,064 leaves/sec**. Normal Mode streams leaf bundles and batches storage updates efficiently without the in-memory trie mutation overhead that throttled Backfill Mode.
  2. **100% Read Starvation in Backfill Mode**: Backfill Mode shut down the HTTP read server, causing 0% query availability during catch-up. Normal Mode sustained sub-2ms P50 latency with 100% availability under concurrent queries.
  3. **Identical Memory Footprint**: Backfill Mode saved only 20–30 MB out of a 220 MB working set.
  4. **Production Personalities Never Adopted Backfill**: `cmd/sumdbindex` and `cmd/mtcindex` achieved headline rates (240,467 leaves/sec) using Normal Serving Mode (`SyncOnce`).
- **Resolution**: Permanently retired in favor of unified normal serving mode catch-up.

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
