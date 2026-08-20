# Sub-Design: Coordinator & 3-Phase Zero-WAL Crash Recovery

## 1. Context & Objectives

The **Coordinator Subsystem** (`vindex/v1/internal/coordinator`) orchestrates lifecycle transitions, synchronizes watermark counters across pipeline planes, and executes the **3-Phase Zero-WAL Crash Recovery** protocol on daemon startup.

### 1.1 Core Goals
1. **Sub-500ms Time-to-First-Serve**: Open the HTTP Read Server for lookup queries almost instantaneously upon process launch, without waiting for background ingestion sync.
2. **Zero-WAL Deterministic Replay**: Recover unpersisted MPT state after crashes by streaming historical tiles from cache, evaluating `MapFn`, and reading Pebble KV chunks with O(1) sub-root reconstruction—with **zero mutations or writes to Pebble DB**.
3. **Monotonic Watermark Progression**: Enforce strict pipeline invariants preventing race conditions between ingestion, chunk commits, MPT updates, and serving state.
4. **Moving-Goalpost Prevention**: Persist target Input Log checkpoints to `m_target_checkpoint` to prevent synchronization starvation on high-velocity logs.

### 1.2 Non-Requirements & Out of Scope
- **No Distributed Leader Election / Clustering**: Coordinates local subsystems within a single process on a single host. No Raft, Paxos, or distributed lock services.
- **No Reverse Synchronization / Rollback**: Watermarks progress strictly forward in monotonic sequence; rewinding history to an earlier Input Log size is not supported.

### 1.3 Alternatives Considered
- **Recovery Architecture**:
  - **Selected - 3-Phase Zero-WAL Recovery**: Combines MPT persisted version checking with fast tile replay and O(1) GetSubRoot point seeks. Reconstructs state in < 500ms with zero writes to Pebble.
  - **Rejected / Retired - Dedicated WAL in Pebble**: A dedicated WAL in Pebble (staging records under 'w' prefix with an asynchronous WalReaper) was initially implemented. Benchmarks revealed that intermediate WAL serialization and reaper compaction passes created high disk write amplification. Removing the WAL and recovering directly from cached Input Log tiles + O(1) GetSubRoot seeks was vastly superior in throughput (+24.7%) and achieved instant warm recovery (2.4 ms).
  - **Rejected - Synchronous Full-Tree Snapshotting on Every Batch**: Flushes the entire MPT to disk on every commit. Incurs gigabytes of disk write I/O per batch, causing severe commit latency stalls.

---

## 2. Package API & Responsibilities

### Responsibilities
- **Startup & Recovery Coordination**: Inspects disk state across Pebble DB, MPT files, and Output Log to select between Instant Warm Startup and Tile Replay Catchup.
- **Watermark Synchronization**: Tracks and validates monotonic watermark ratcheting across the 4 pipeline stages.
- **Moving-Goalpost Prevention**: Freezes target sync checkpoints into Pebble metadata (`m_target_checkpoint`).
- **Steady-State Lifecycle Management**: Manages background goroutines for the Ingestion Pipeline, KV Committer, Output Publisher, and Tile Reaper.

### Go Interfaces & Types

```go
package coordinator

import (
	"context"
	"crypto/sha256"
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
	MPTPersistedSize    int64  // Durably persisted MPT version on disk
	ServingSize         uint64 // Input Log size visible to lookup clients
}

// SubRootReader abstracts reading reconstructed mini-log roots from KV storage.
type SubRootReader interface {
	GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error)
}

// RecoveryCoordinator orchestrates the 3-Phase Zero-WAL startup sequence.
type RecoveryCoordinator struct {
	db        *kvstore.DB
	mptMgr    *tree.MPTManager
	outputLog tree.OutputLogClient
	fetcher   ingest.TileFetcher
	cache     ingest.TileCache
	wasmPool  ingest.SandboxPool
}

func NewRecoveryCoordinator(
	db *kvstore.DB,
	mptMgr *tree.MPTManager,
	outputLog tree.OutputLogClient,
	fetcher ingest.TileFetcher,
	cache ingest.TileCache,
	wasmPool ingest.SandboxPool,
) *RecoveryCoordinator

// RecoverState executes Phase 1 startup recovery and returns initial ServingState.
func (rc *RecoveryCoordinator) RecoverState(ctx context.Context) (*tree.ServingState, error)

// StartPipeline transitions to Phase 2 steady-state ingestion and Phase 3 background tasks.
func (rc *RecoveryCoordinator) StartPipeline(ctx context.Context, initialServingState *tree.ServingState) error
```

---

## 3. Watermark Hierarchy & State Invariants

### 1. Watermark Definitions

| Variable | Location | Embedded Inside | Purpose |
| :--- | :--- | :--- | :--- |
| `Target_Size` | Pebble (`m`) | `m_target_checkpoint` | Target tree size actively being synced by Ingestion. |
| `KV_CP_Size` | Pebble (`m`) | `m_kv_checkpoint` | Tree size of latest fully indexed checkpoint in KV store (`c`). |
| `Output_Size` | Output Log | `StateCommitment.ILCheckpoint` | Input Log tree size committed and witnessed in Output Log. |
| `Cached_Tile_Watermark` | Tile Cache | Directory / Index | Contiguous leaves available in local tile cache. |
| `m_kv_size` | Pebble (`m`) | `uint64` counter | Intermediate leaf count written to `'c'` during batch commits. |
| `MPT_Size` | In-Memory | MPT working tree | Input Log leaf count integrated into in-memory MPT root. |
| `MPT_Persisted_Size` | MPT Disk | Metadata / Header | Persisted version of MPT on disk (`MPT.PersistedVersion()`). |

### 2. State Progression Invariant
```text
Input Log Target CP >= Cached Tile Watermark >= m_kv_size >= Output Log Size == Serving MPT
```

### 3. Serving Invariant
```text
Serving_Size == MPT_Size <= Output_Size
```
Readers are strictly isolated from in-flight writes ahead of `Serving_Size` via watermark filtering.

---

## 4. 3-Phase Zero-WAL Crash Recovery Flow

```text
[Process Launch]
       │
       ▼
[Phase 1: Startup & Fast-Serve Recovery (< 500ms)]
       ├── 1. Open Pebble DB & load MPT at MPT_Persisted_Size = MPT.PersistedVersion()
       ├── 2. Inspect Output Log (size N, OutputLog[N-1].InputLogSize = S_OUT):
       │      - If N == 0: Idle mode (awaits initial commit)
       │      - If MPT_Persisted_Size == S_OUT:
       │          • Assert OutputLog[N-1].MapRoot == MPT.Root()
       │          • Set active serving_state = OutputLog[N-1]
       │          • OPEN READ SERVER FOR LOOKUPS IMMEDIATELY (< 5ms)
       │      - If MPT_Persisted_Size < S_OUT:
       │          • Execute Replay(MPT_Persisted_Size, S_OUT):
       │              - Stream historical leaves [MPT_Persisted_Size .. S_OUT) from tile cache
       │              - Evaluate MapFn on historical leaves to identify modified keys
       │              - For each key: Invoke KVIndexer.GetSubRoot(keyHash) (O(1) point lookup on 'c')
       │              - Reconstruct MiniLog Merkle sub-roots at S_OUT (zero Pebble writes)
       │              - Commit mutations to in-memory MPT (mpt.CommitWithVersion)
       │          • Finalize MPT (mpt.Snap()) & assert MPT.Root() == OutputLog[N-1].MapRoot
       │          • Set active serving_state = OutputLog[N-1]
       │          • OPEN READ SERVER FOR LOOKUPS IMMEDIATELY (< 500ms)
       ▼
[Phase 2: Live Steady-State Ingestion]
       ├── 1. IngestionPipeline: Resume streaming from m_kv_size to Input Log target checkpoint
       ├── 2. KVCommitter: Continuously append chunk records ('c') and update m_kv_size
       └── 3. OutputPublisher: Predict MPT roots, commit to Output Log, update in-memory MPT
       ▼
[Phase 3: Background Maintenance & Garbage Collection]
       ├── 1. TileReaper: Periodically prune cached tiles below SafeWatermark = min(m_kv_size, MPT.PersistedVersion())
       └── 2. MPT Compactor: Periodically snapshot and fsync MPT working tree to disk
```

### Sub-Root Reconstruction Primitive (`KVIndexer.GetSubRoot`)

During Phase 1 catchup when MPT_Persisted_Size < Output_Size:
1. `RecoveryCoordinator` evaluates `MapFn` over the missing leaves in [MPT_Persisted_Size .. Output_Size) to identify modified key hashes.
2. For each key hash, it calls `GetSubRoot(keyHash)`:
   - Executes a single `SeekPrefixGE` on `'c' + KeyHash`, landing directly on the active inverted chunk in O(1) disk reads.
   - Unmarshals `ChunkRecord`, extracts base `compact.Range`, and folds in active `RelativeIndices` up to Output_Size.
   - Computes and returns `MiniLogRoot`.
3. Mutations are applied directly to the in-memory MPT with **zero Pebble DB writes or disk mutations**.

---

## 5. Moving-Goalpost Prevention (`m_target_checkpoint`)

When indexing high-velocity logs, the log head advances continuously.
- **Problem**: Chasing dynamic checkpoints causes synchronization starvation and unaligned batch boundaries.
- **Solution**: Upon discovering a new Input Log checkpoint CP_N, the coordinator immediately persists its unparsed bytes:
  ```text
  Key: m_target_checkpoint -> Value: CP_N.Raw
  ```
- The ingestion pipeline processes the fixed range up to CP_N.Size to completion before polling for subsequent checkpoints.

---

## 6. Operational Logging & Startup Transparency

### Structured Startup Playbook
The coordinator emits structured INFO logs (using standard `log/slog`) at each critical decision boundary during startup:
- **Initial State Inspection**: Logs discovered watermarks (`TargetSize`, `KVSize`, `OutputSize`, `MPTPersistedSize`).
- **Recovery Mode Selection**: Explicitly logs decision (e.g., `"Selecting Instant Warm Start: MPTPersistedSize equals OutputSize"` or `"Selecting Tile Replay Catchup: replaying leaves from X to Y"`).
- **Replay Progress**: Emits periodic milestones during catchup (e.g. every 10,000 replayed leaves).
- **Serving Ready**: Logs confirmation when `ServingState` pointer is ratcheted and Read Server is opened.

---

## 7. Fault Injection & Chaos Qualification Plan

### Crash Injection Matrix (Verifying Zero State Divergence)
- **Crash during Phase 1 (Startup Replay)**: Verify coordinator cleanly restarts and re-executes replay without database corruption.
- **Crash during Phase 2 (KV Committed, Output Log not yet written)**: `m_kv_size > S_OUT`. Verify that on restart, Phase 1 sets serving state to `S_OUT`, and Phase 2 resumes ingestion without duplicating Pebble chunks.
- **Crash during Phase 2 (Output Log written, MPT in-memory committed, but MPT not yet persisted to disk)**: `S_OUT > MPT_Persisted_Size`. Verify that on restart, Phase 1 executes fast replay `[MPT_Persisted_Size .. S_OUT)`, recovers MPT in RAM, and opens the read server in < 500ms.
- **Crash during Phase 3 (MPT Compaction / Tile Reaper)**: Verify atomic file renaming (`os.Rename`) prevents partial snapshot files from corrupting previous valid snapshots.

---

## 8. Lifecycle & Recovery Metrics

- `coord_recovery_duration_seconds` (Histogram): Total duration of Phase 1 startup recovery.
- `coord_replayed_leaves_count` (Counter): Count of leaves replayed during Phase 1 catchup.
- `coord_state_transitions_total` (Counter): Count of state machine phase transitions.
- `coord_watermark_lag_leaves` (Gauge): Live distance between `m_target_checkpoint` and `m_kv_size`.

