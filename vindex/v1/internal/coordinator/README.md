# Sub-Design: Coordinator & Zero-WAL Startup Recovery

## 1. Context & Purpose

The **Coordinator Subsystem** (`vindex/v1/internal/coordinator`) orchestrates lifecycle transitions, synchronizes watermark counters across pipeline planes, and executes the **Zero-WAL Startup Recovery** protocol on daemon startup.

### 1.1 Core Goals
1. **Sub-500ms Time-to-First-Serve**: Open the HTTP Read Server for lookup queries almost instantaneously upon process launch, without waiting for background ingestion sync.
2. **Zero-WAL Deterministic Replay**: Reconstruct and fast-forward un-synced in-memory MPT state to the latest Output Log entry (`S_OUT`) after crashes by streaming historical tiles from cache, evaluating `MapFn`, and reading Pebble KV chunks with O(1) sub-root reconstruction—with **zero mutations or writes to Pebble DB**.
3. **Monotonic Watermark Progression**: Enforce strict pipeline invariants preventing race conditions between ingestion, chunk commits, MPT updates, and serving state.
4. **Moving-Goalpost Prevention**: Persist target Input Log checkpoints to `m_target_checkpoint` to prevent synchronization starvation on high-velocity logs.
5. **Cryptographic Checkpoint Ratcheting**: Enforce mandatory origin signature verification, optional witness policy ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy)) quorums via `torchwood.VerifyCheckpoint`, and Merkle consistency proof verification (`golang.org/x/mod/sumdb/tlog.CheckTree`) on target checkpoint transitions (`CP_old` -> `CP_new`).

### 1.2 Non-Requirements & Out of Scope
- **No Distributed Leader Election / Clustering**: Coordinates local subsystems within a single process on a single host. No Raft, Paxos, or distributed lock services.
- **No Reverse Synchronization / Rollback**: Watermarks progress strictly forward in monotonic sequence; rewinding history to an earlier Input Log size is not supported.

---

## 2. High-Level Architecture & 3-Stage Lifecycle

The Coordinator manages the daemon through three distinct, strictly sequenced lifecycle stages:

```text
[Process Launch]
       │
       ▼
[Stage 1: Startup Recovery (Fast-Forward to Latest Output Log Entry) (< 500ms)]
       ├── 1. Open Pebble DB & query MPT version via mptVersion, exact := mptMgr.Version()
       │      - Hold TileReaper in pending/idle state during Stage 1 to prevent disk I/O contention
       ├── 2. Inspect Output Log (size N, OutputLog[N-1].InputLogSize = S_OUT):
       │      - If N == 0: Idle mode (awaits initial commit)
       │      - Instant Warm Start (exact == true && mptVersion == S_OUT):
       │          • Clean shutdown verified
       │          • Assert OutputLog[N-1].MapRoot == MPT.Root()
       │          • Set mptDurableSize = S_OUT
       │          • Set active serving_state = OutputLog[N-1]
       │          • OPEN READ SERVER FOR LOOKUPS IMMEDIATELY (< 5ms)
       │      - Fast-Forward Tile Replay Catchup (exact == false || mptVersion < S_OUT):
       │          • Dirty/unclean crash or lagging MPT detected
       │          • Execute Replay(mptVersion, S_OUT):
       │              - Stream historical leaves [mptVersion .. S_OUT) from tile cache
       │              - Evaluate MapFn on historical leaves to identify modified keys
       │              - For each key: Invoke store.GetSubRoot(keyHash, S_OUT) (targeted lookup on 'c')
       │              - Reconstruct MiniLog Merkle sub-roots at S_OUT (zero storage writes)
       │              - Apply mutations to in-memory MPT via mpt.Set()
       │          • Finalize root: mpt.Snap(int64(S_OUT))
       │          • Assert MPT.Root() == OutputLog[N-1].MapRoot
       │          • Execute mptMgr.Sync() to consolidate state to disk (sets exact = true, mptDurableSize = S_OUT)
       │          • Set active serving_state = OutputLog[N-1]
       │          • OPEN READ SERVER FOR LOOKUPS IMMEDIATELY (< 500ms)
       ▼
[Stage 2: Live Steady-State Ingestion]
       ├── 1. Checkpoint Verification: Poll upstream checkpoint, verify origin signature & witness policy (torchwood.VerifyCheckpoint), verify Merkle consistency proof (tlog.CheckTree), and persist m_target_checkpoint
       ├── 2. IngestionPipeline: Monotonic forward ingestion from S_OUT to live Target_CP
       ├── 3. Serialized Batch Execution Loop (per batch S_k):
       │      a. store.WriteBatch(entries, S_k): Blocking disk persistence (pebble.Sync) -> advances m_kv_size
       │      b. publisher.PublishBatch(...): Root prediction -> Output Log append -> witness cosignatures -> in-memory MPT ratchet -> advances Output_Size
       └── 4. Advance serving pointer to OutputLog[N]
       ▼ (concurrent background tasks)
[Stage 3: Background Maintenance & Garbage Collection]
       ├── 1. TileReaper: Prunes cached tiles below SafeWatermark = mptDurableSize
       │      (initialized to S_OUT upon startup recovery completion)
       └── 2. MPT Compactor / Sync: Periodically snapshot and fsync MPT working tree to disk
```

### 2.1 Recovery Mode Selection: 2x2 Decision Matrix

On startup, the Coordinator inspects the on-disk MPT header (`mptMgr.Version()`) against the latest committed Output Log entry `OutputLog[N-1]` (`S_OUT`):

```text
                            MPT Disk Header Status (mptMgr.Version())
                         exact == true                 exact == false
                  ┌─────────────────────────────┬─────────────────────────────┐
                  │                             │                             │
mptVersion        │   INSTANT WARM START        │   FAST-FORWARD TILE REPLAY  │
   == S_OUT       │   (< 5ms)                   │   (< 500ms)                 │
                  │   • Clean shutdown verified │   • Dirty header on disk    │
(MPT Matches      │   • Assert Root consistency │   • Replay missing leaves   │
 Output Log)      │   • Set serving_state       │     from last clean version │
                  │   • Open Read Server NOW    │   • mptMgr.Sync() + Open    │
                  │                             │                             │
                  ├─────────────────────────────┼─────────────────────────────┤
                  │                             │                             │
mptVersion        │   FAST-FORWARD TILE REPLAY  │   FAST-FORWARD TILE REPLAY  │
   < S_OUT        │   (< 500ms)                 │   (< 500ms)                 │
                  │   • Clean MPT on disk, but  │   • Dirty/lagging MPT       │
(MPT Lags Behind  │     lagging behind Output   │   • Replay missing leaves   │
 Output Log)      │   • Replay [mptVer..S_OUT)  │     [mptVer..S_OUT) from    │
                  │   • Zero Pebble DB writes   │     local tile cache        │
                  │   • mptMgr.Sync() + Open    │   • Zero Pebble DB writes   │
                  │                             │                             │
                  └─────────────────────────────┴─────────────────────────────┘
```

| Recovery Mode | Header Condition | In-Memory Work | Storage Mutations | Time to First Serve |
| :--- | :--- | :--- | :--- | :--- |
| **Instant Warm Start** | `exact == true && mptVersion == S_OUT` | Assert `MPT.Root() == OutputLog[N-1].MapRoot` | None | **< 5ms** |
| **Fast-Forward Tile Replay** | `exact == false || mptVersion < S_OUT` | Stream leaves `[mptVersion .. S_OUT)`, evaluate `MapFn`, call `store.GetSubRoot`, apply `mpt.Set` + `mpt.Snap` | None (zero writes to Pebble) | **< 500ms** |

---

## 3. Watermark Definitions & State Progression Invariants

### 3.1 Watermark Definitions

| Variable | Location | Embedded Inside | Purpose |
| :--- | :--- | :--- | :--- |
| `Target_Size` | Pebble (`m`) | `m_target_checkpoint` | Target tree size actively being synced by Ingestion. |
| `KV_CP_Size` | Pebble (`m`) | `m_kv_checkpoint` | Tree size of latest fully indexed checkpoint in KV store (`c`). |
| `Output_Size` | Output Log | `StateCommitment.ILCheckpoint` | Input Log tree size committed and witnessed in Output Log. |
| `Cached_Tile_Watermark` | Tile Cache | Directory / Index | Contiguous leaves available in local tile cache. |
| `m_kv_size` | Pebble (`m`) | `uint64` counter | Intermediate leaf count written to `'c'` during batch commits. |
| `MPT_Size` | In-Memory | MPT working tree | Input Log leaf count integrated into in-memory MPT root. |
| `MPT_Durable_Size` | MPT Disk | Metadata / Header | Durably synced MPT Input Log size on disk (`mptMgr.Sync()` / `mptMgr.Version()`). |

### 3.2 State Progression Invariant
```text
Input Log Target CP >= Cached Tile Watermark >= m_kv_size >= Output Log Size >= MPT_Durable_Size
```
*(Note: `Output Log Size == Serving MPT`)*

### 3.3 Serving Invariant
```text
Serving_Size == MPT_Size <= Output_Size
```
Readers are strictly isolated from in-flight writes ahead of `Serving_Size` via watermark filtering.

### 3.4 Mathematical Equivalence & Safe Pruning
Because `MPT_Durable_Size` is strictly bounded by `m_kv_size` (`MPT_Durable_Size <= Output_Size <= m_kv_size`):
```text
min(m_kv_size, MPT_Durable_Size) == MPT_Durable_Size
```
Leaves below `MPT_Durable_Size` are already committed to Pebble (`'c'` chunks) and durably fsync'd in MPT disk files (`exact == true`). Crash recovery never requires raw tiles below `MPT_Durable_Size`.

---

## 4. Public API & Go Interfaces

### Responsibilities
- **Checkpoint Authentication & Progression**: Validates checkpoint origin signatures and witness policy quorums (`torchwood.VerifyCheckpoint`), and verifies Merkle consistency proofs between consecutive target checkpoints (`golang.org/x/mod/sumdb/tlog.CheckTree`).
- **Startup & Recovery Coordination**: Inspects disk state across Pebble DB, MPT files, and Output Log to select between Instant Warm Startup and Tile Replay Catchup.
- **Watermark Synchronization**: Tracks and validates monotonic watermark ratcheting across the pipeline stages.
- **Moving-Goalpost Prevention**: Freezes verified target sync checkpoints into Pebble metadata (`m_target_checkpoint`).
- **Steady-State Lifecycle Management**: Coordinates the ingestion pipeline, orchestrates the serialized batch commit loop (blocking KV persistence -> Output Log publishing), and manages background maintenance tasks like the Tile Reaper.

### Go Interfaces & Types

```go
package coordinator

import (
	"context"
	"crypto/sha256"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

// Watermarks encapsulates the live state of all watermark counters.
type Watermarks struct {
	TargetSize          uint64 // Input Log target tree size actively being synced
	CachedTileWatermark uint64 // Upper bound of contiguous raw tiles in cache
	KVSize              uint64 // Input Log size fully committed to Pebble chunks ('c')
	OutputSize          uint64 // Input Log size witnessed in Output Log
	MPTDurableSize      uint64 // Durably synced MPT input log size on disk (updated on Sync())
	ServingSize         uint64 // Input Log size visible to lookup clients
}

// SubRootReader abstracts reading reconstructed mini-log roots from KV storage.
type SubRootReader interface {
	GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error)
}

// CheckpointVerifier validates checkpoint origin signatures, witness policies, and consistency proofs.
type CheckpointVerifier interface {
	Verify(raw []byte) (*tlog.Tree, error)
	VerifyConsistency(oldTree, newTree *tlog.Tree, proof [][]byte) error
}

// RecoveryCoordinator orchestrates Zero-WAL startup recovery and steady-state lifecycle transitions.
type RecoveryCoordinator struct {
	store     kvstore.IndexStore
	mptMgr    *tree.MPTManager
	outputLog tree.OutputLogClient
	fetcher   ingest.TileFetcher
	cache     ingest.TileCache
	wasmPool  ingest.SandboxPool
	verifier  CheckpointVerifier
}

func NewRecoveryCoordinator(
	store kvstore.IndexStore,
	mptMgr *tree.MPTManager,
	outputLog tree.OutputLogClient,
	fetcher ingest.TileFetcher,
	cache ingest.TileCache,
	wasmPool ingest.SandboxPool,
	verifier CheckpointVerifier,
) *RecoveryCoordinator

// RecoverState executes Stage 1 startup recovery (fast-forward to latest Output Log entry) and returns initial ServingState.
func (rc *RecoveryCoordinator) RecoverState(ctx context.Context) (*tree.ServingState, error)

// StartPipeline transitions to Stage 2 steady-state ingestion and Stage 3 background tasks.
func (rc *RecoveryCoordinator) StartPipeline(ctx context.Context, initialServingState *tree.ServingState) error
```

---

## 5. Detailed Execution Mechanics

### 5.1 Stage 1: Startup Recovery Execution
During daemon startup, `RecoveryCoordinator.RecoverState` runs before opening the read or write interfaces:

1. **State Discovery**:
   - Open Pebble DB and query MPT version via `mptVersion, exact := mptMgr.Version()`.
   - Hold `TileReaper` idle during Stage 1 to prevent disk I/O contention.
   - Inspect Output Log (size `N`). Let `S_OUT = OutputLog[N-1].InputLogSize`.
2. **Instant Warm Start (`exact == true && mptVersion == S_OUT`)**:
   - Asserts `OutputLog[N-1].MapRoot == MPT.Root()`.
   - Sets `mptDurableSize = S_OUT` and initializes active `ServingState = OutputLog[N-1]`.
   - Opens HTTP Read Server for lookup queries immediately (**< 5ms**).
3. **Fast-Forward Tile Replay Catchup (`exact == false || mptVersion < S_OUT`)**:
   - Streams missing historical leaves `[mptVersion .. S_OUT)` from local tile cache.
   - Evaluates `MapFn` over replayed leaves to identify modified key hashes.
   - For each modified key: invokes `store.GetSubRoot(keyHash, S_OUT)` on `'c'` chunks.
   - Reconstructs MiniLog Merkle sub-roots at `S_OUT` with **zero storage writes or disk mutations**.
   - Applies mutations to in-memory MPT via `mpt.Set()`.
   - Finalizes in-memory root via `mpt.Snap(int64(S_OUT))`.
   - Asserts `MPT.Root() == OutputLog[N-1].MapRoot`.
   - Executes `mptMgr.Sync()` to consolidate state to disk (`exact = true`, `mptDurableSize = S_OUT`).
   - Sets active `ServingState = OutputLog[N-1]` and opens Read Server (**< 500ms**).

### 5.2 Stage 2: Live Steady-State Ingestion & Gap Absorption

When transitioning to Stage 2 live ingestion:

1. **Ingestion Resume & Storage Idempotency Gap Absorption**:
   - If a crash occurred after KV persistence but before Output Log publishing (`m_kv_size > S_OUT`), the Coordinator resumes ingestion starting at `S_OUT`.
   - It relies on `store.WriteBatch`'s internal idempotency contract (`persistedKVSize`) to safely absorb the replay gap `[S_OUT .. m_kv_size)`:
     - Entries with `index < m_kv_size` are skipped to prevent duplicate chunk appending.
     - Sub-roots for replayed keys are computed via `store.GetSubRoot(keyHash, batchEnd)` without modifying chunk data on disk.
     - Pebble writes and `pebble.Sync` disk persistence are bypassed until batches advance beyond `m_kv_size` (`batchEnd > m_kv_size`).
     - Guarantees zero duplicate storage mutations with no requirement for rollback or truncation logic.
2. **Serialized Batch Execution Loop**:
   - For each batch `S_k`:
     a. `store.WriteBatch(entries, S_k)`: Executes `pebble.Sync`, blocking until all chunk mutations and `m_kv_size` are durably persisted.
     b. `publisher.PublishBatch(...)`: Computes predicted root (`mptMgr.Predict`), appends `StateCommitment` to Tessera Output Log, collects remote witness cosignatures, and ratchets the in-memory MPT root (`mpt.Snap(S_k)`).
3. **Batch Aggregation**:
   - While parallel map workers process at 256-leaf tile granularity, the Coordinator aggregates mapped batches to `DefaultCommitBatchSize = 4096` (16 tiles) before committing to Pebble, amortizing iterator creation and lock acquisition overhead by 16x.

### 5.3 Stage 3: Background Tasks & TileReaper Wiring

The Coordinator manages the `TileReaper` background task by supplying a dynamic watermark query callback:

```go
watermarkFn := func() uint64 {
    return mptDurableSize // tracked by coordinator upon mptMgr.Sync()
}
```

- **TileReaper Operation**:
  1. Starts concurrently in Stage 3 with `SafeWatermark = mptDurableSize` (initialized to `S_OUT` via `mptMgr.Sync()` upon startup recovery completion).
  2. Runs periodically in the background (e.g., every 60 seconds).
  3. Safely deletes cached tile files whose range satisfies `(tileIdx + 1) * 256 <= SafeWatermark`.
  4. Preserves tiles in `[mptDurableSize .. m_kv_size)` so that in the event of an unclean crash, Stage 1 startup recovery replays MPT catchup up to `S_OUT` entirely from local cache without network egress.
- **MPT Compactor / Background Sync**: Periodically snapshots and fsyncs the MPT working tree to disk based on leaf counts (30k leaves) or time intervals (15s).

---

## 6. Invariants, Concurrency & Crash Safety Model

### 6.1 Synchronous Commit Barrier & Serialized Batch Execution
To guarantee data consistency without distributed transactions or complex WAL rollback mechanics, the coordinator enforces a strict, synchronous commit barrier during steady-state batch processing:
1. **Blocking Storage Persistence**: `store.WriteBatch(entries, S_k)` executes `pebble.Sync`, blocking until all inverted chunk mutations (`'c'`) and `m_kv_size` are durably persisted to disk.
2. **Output Log Publication**: `publisher.PublishBatch(...)` calculates the predicted MPT root (`mptMgr.Predict`), appends `StateCommitment` to the Tessera Output Log, collects remote witness cosignatures, and ratchets the in-memory MPT root (`mpt.Snap(S_k)`).
3. **Strict Sequencing**: Output Log append and witness network calls **MUST NOT begin** until `store.WriteBatch` has successfully returned. `KVCommitter` and `OutputPublisher` are not independent concurrent actors; each batch progresses sequentially through this commit barrier.

### 6.2 Universal Crash Invariant Guarantee
Because storage persistence strictly precedes Output Log publication:
- **Universal Crash Invariant**: `m_kv_size >= Output_Size` is preserved under all crash, power-failure, and process-kill scenarios.
- **Deterministic Zero-WAL Recovery**: Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted or missing KV store chunks. If a crash occurs before Output Log publication, `m_kv_size > S_OUT`; startup recovery simply ignores uncommitted storage chunks beyond `S_OUT` via point-in-time `store.GetSubRoot(keyHash, S_OUT)` queries.

### 6.3 Moving-Goalpost Prevention & Checkpoint Verification
When indexing high-velocity logs, the log head advances continuously.
- **Problem**: Chasing dynamic or unverified checkpoints causes synchronization starvation, unaligned batch boundaries, and risks processing non-monotonic or unauthenticated forks.
- **Verification & Authentication Protocol**:
  Upon discovering a prospective new Input Log checkpoint `CP_new`:
  1. **Checkpoint Origin Signature**: Validates that `CP_new` is signed by the log origin key via `torchwood.VerifyCheckpoint(raw, policy)`.
  2. **Witness Policy Quorum ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy))**: Verifies that witness cosignatures satisfy the configured witness policy.
  3. **Merkle Consistency Proof**: When advancing from `CP_old` to `CP_new`, the coordinator fetches the Merkle consistency proof and invokes:
     ```go
     err := tlog.CheckTree(int64(cpNew.Size), cpNew.Hash, int64(cpOld.Size), cpOld.Hash, consistencyProof)
     ```
     This mathematically proves `CP_new` is an append-only extension of `CP_old`.
  4. **Target Checkpoint Freezing**: The coordinator immediately persists the raw checkpoint bytes:
     ```text
     Key: m_target_checkpoint -> Value: CP_new.Raw
     ```
  5. **Ingestion Dispatch**: The ingestion pipeline processes the fixed range up to `CP_new.Size` to completion before the coordinator polls for subsequent checkpoints.

### 6.4 Crash Injection Matrix & Chaos Qualification
- **Crash during Stage 1 (Startup Replay)**: Cleanly restarts and re-executes replay without database corruption.
- **Crash during Stage 2 (KV Committed, Output Log not yet written)**: `m_kv_size > S_OUT`. Storage state leads Output Log. On restart, Stage 1 sets serving state to `S_OUT`, reads only valid chunks up to `S_OUT` via `store.GetSubRoot`, and Stage 2 resumes ingestion starting at `S_OUT`, relying on `store.WriteBatch`'s idempotency contract to safely absorb `[S_OUT .. m_kv_size)` without duplicate chunk mutations.
- **Crash during Stage 2 (Output Log written, MPT in-memory committed, but MPT not yet synced to disk)**: `S_OUT > mptVersion` or `exact == false`. Header was dirtied on first `Set()` prior to `Sync()`. On restart, Stage 1 detects `exact == false || mptVersion < S_OUT`, executes fast replay `[mptVersion .. S_OUT)`, recovers MPT in RAM, asserts root consistency, consolidates disk state via `mptMgr.Sync()`, and opens the read server in < 500ms.
- **Unreachable State (`m_kv_size < S_OUT`)**: Physically impossible due to the synchronous commit barrier (`store.WriteBatch` with `pebble.Sync` strictly precedes Output Log append and witness RPCs).
- **Crash during Stage 3 (MPT Compaction / Tile Reaper)**: Atomic file renaming (`os.Rename`) prevents partial snapshot files from corrupting previous valid snapshots.

### 6.5 Structured Startup Logging Playbook
The coordinator emits structured INFO logs (`log/slog`) at each critical decision boundary:
- **Initial State Inspection**: Discovered watermarks (`TargetSize`, `KVSize`, `OutputSize`, `MPTDurableSize`).
- **Recovery Mode Selection**: Explicit decision (e.g., `"Selecting Instant Warm Start: exact is true and mptVersion equals OutputSize"` or `"Selecting Tile Replay Catchup: exact is false or mptVersion lags OutputSize, replaying leaves from X to Y"`).
- **Replay Progress**: Milestones during catchup (every 10,000 replayed leaves).
- **Serving Ready**: Confirmation when `ServingState` pointer is ratcheted and Read Server is opened.

---

## 7. Metrics & Telemetry

- `vindex_coordinator_startup_recovery_duration_seconds` (Histogram): Total duration of Stage 1 startup recovery.
- `vindex_coordinator_replayed_leaves_total` (Counter): Count of leaves replayed during Stage 1 catchup.
- `vindex_coordinator_state_transitions_total` (Counter): Count of state machine lifecycle transitions.
- `vindex_coordinator_watermark_lag_leaves` (Gauge): Live distance between `m_target_checkpoint` and `m_kv_size`.
- `vindex_coordinator_target_checkpoint_size` (Gauge): Tree size of the active target Input Log checkpoint.
- `vindex_coordinator_commit_batch_duration_seconds` (Histogram): Total duration of serialized batch commit (storage write + output publish).

---

## 8. Design Rationale & Alternatives Considered

- **Recovery Architecture**:
  - **Selected - Zero-WAL Startup Recovery**: Combines MPT durable version checking with fast tile replay and O(1) GetSubRoot point seeks. Fast-forwards state to the latest Output Log entry in < 500ms with zero writes to Pebble.
  - **Rejected / Retired - Dedicated WAL in Pebble**: A dedicated WAL in Pebble (staging records under `'w'` prefix with an asynchronous WalReaper) was initially implemented. Benchmarks revealed that intermediate WAL serialization and reaper compaction passes created high disk write amplification. Removing the WAL and recovering directly from cached Input Log tiles + O(1) GetSubRoot seeks was vastly superior in throughput (+24.7%) and achieved instant warm recovery (2.4 ms).
  - **Rejected - Synchronous Full-Tree Snapshotting on Every Batch**: Flushes the entire MPT to disk on every commit. Incurs gigabytes of disk write I/O per batch, causing severe commit latency stalls.

