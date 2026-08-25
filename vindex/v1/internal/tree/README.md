# Sub-Design: Authenticated State (MPT & Output Log Commitments)

## 1. Context & Objectives

The **Authenticated State Subsystem** (`vindex/v1/internal/tree`) manages the cryptographic commitments binding search keys to mini-log Merkle roots, publishes state commitments to the Tessera Output Log, collects remote witness cosignatures, and updates the in-memory Merkle Patricia Trie (MPT) with a sub-5ms write lock critical section.

### 1.1 Core Guarantees
1. **Uninterrupted Read Serving**: Uses lock-free MPT root prediction (`mpt.Predict`) and Split-Locking (`writeMu` vs `treeMu`). Long disk fsync operations (5-20ms) during `Sync()` run under `writeMu` and never block `Prove()` lookup reads (`treeMu.RLock()`), maintaining 100% read availability during witness latency windows and disk flushes.
2. **Sub-5ms Critical Section**: The `treeMu` write lock critical section is strictly limited to in-memory MPT node updates (`mpt.Set`), SHA-256 root snap (`mpt.Snap`), and atomic pointer ratcheting.
3. **Equivocation Protection**: Binds `MapRoot` and the exact `InputLogCheckpoint` bytes into an append-only Tessera Output Log with witness cosignatures.
4. **Zero GC Pressure via `mmap`**: The working trie is backed by OS `mmap(2)` via `torchwood/mpt`, bypassing Go runtime garbage collection.

### 1.2 Non-Requirements & Out of Scope
- **No Historical Time-Travel Queries**: The in-memory MPT serves proofs against the active ServingState. Historical root queries are verified via the append-only Output Log, not retained as active in-memory branches.
- **No Multi-Tree Sharding**: A single MPTManager instance manages the global key-space on the host.
- **No Direct Leaf Ingestion**: The tree package does not parse raw log leaves or execute MapFn; it strictly accepts pre-computed modifiedSubRoots map updates from the committer.

### 1.3 Alternatives Considered (Concurrency & Lock Model)
- **Concurrency & Lock Sequencing**:
  - **Selected - Split-Locking with Lock-Free Prediction & Synchronous Storage Barrier**: `writeMu` serializes `Commit` and `Sync` operations while `treeMu` (RWMutex) guards trie operations. `Sync()` fsync (5-20ms) executes without holding `treeMu`, ensuring zero read latency spikes on `Prove()`. Output Log append and witness network I/O are gated behind a synchronous storage barrier (`store.WriteBatch` with `pebble.Sync`). Root prediction allows slow network I/O (Output Log append + witness cosignatures) to run completely lock-free without holding `treeMu`.
  - **Rejected - Coarse Global Lock across Network & Disk Sync**: Holding a single global lock during remote witness RPCs or disk fsync stalls read queries for 100ms–seconds per batch.
  - **Rejected - Full Tree Copy-on-Write**: Duplicating memory-mapped trees for MVCC creates prohibitive memory overhead and Linux dirty page writeback storms.
  - *(Note: For the overarching selection of Binary MPT vs SMT/Verkle, see [ARCHITECTURE.md](../../docs/ARCHITECTURE.md).)*

### 1.4 Empirical Performance Justification (Split-Locking Benchmark)

Microbenchmarks on a 24-core host measuring concurrent `Prove()` lookups under heavy background disk syncs (`tree.Sync()`) demonstrate the necessity of the split-locking architecture:

| Lock Architecture | Baseline Read Latency (`Prove` No Sync) | Read Latency under Disk Sync (`tree.Sync()`) | Lookup Throughput | Reader Availability during `fsync` |
| :--- | :--- | :--- | :--- | :--- |
| **Coarse Global Lock** | 1,473 ns/op | **18,887 ns/op** (12.8x degradation) | ~53,000 reads/s | **0% (100% blocked during msync/fsync)** |
| **Split-Locking (`writeMu` + `treeMu`)** | **1,473 ns/op** | **1,473 ns/op** (in-memory snapshot) | **~678,000 reads/s** | **100% (uninterrupted read serving)** |

- **Zero Reader Contention**: Because `Sync()` executes under `writeMu` without acquiring `treeMu.Lock()`, disk I/O pauses (5–20ms) never block HTTP lookup handlers calling `mptMgr.RLock()` / `ProveLocked()`.
- **Sub-5ms Critical Section**: The exclusive write lock (`treeMu.Lock()`) is held exclusively for in-memory node updates (`mpt.Set`) and snapshot pointer ratcheting (`mpt.Snap`), completing in microseconds.

---

## 2. Package API & Responsibilities

### Responsibilities
- **MPT Working Tree Management**: Allocates and maintains the `torchwood/mpt` binary trie in `mmap`, managing dirty subtree hashing and background compaction.
- **Split-Locking Concurrency**: Isolates background disk `Sync()` operations (`writeMu`) from in-memory lookups (`treeMu.RLock()`).
- **Lock-Free Root Prediction**: Computes the future `MapRoot` across modified sub-roots prior to acquiring writer locks.
- **Output Log State Commitments**: Serializes `StateCommitment` (`hex(MapRoot) + "\n" + ILCheckpoint.Raw`), appends to Tessera Output Log, and queries inclusion proofs.
- **Witness Protocol Coordination**: Submits new Output Log checkpoints to remote witnesses and aggregates signed note cosignatures.
- **Serving State Management**: Maintains the thread-safe active serving state pointer accessed by the Read Server.

### Go Interfaces & Types

```go
package tree

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"github.com/transparency-dev/formats/log"
	torchmpt "filippo.io/torchwood/mpt"
)

// MPTManager wraps the torchwood/mpt in-memory trie with split-locking.
type MPTManager struct {
	writeMu sync.Mutex   // Serializes Commit and Sync operations
	treeMu  sync.RWMutex // Protects trie access during Prove lookups and in-memory root swaps
	tree    *torchmpt.Tree
	mmapDir string
}

func OpenMPT(mmapDir string) (*MPTManager, error)
func (m *MPTManager) Version() (version int64, exact bool)
func (m *MPTManager) Predict(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error)
func (m *MPTManager) Commit(mutations map[[sha256.Size]byte][sha256.Size]byte, inputLogSize uint64) ([sha256.Size]byte, error)
func (m *MPTManager) Sync() (durableSize uint64, err error) // Flushes patch frames, fsyncs disk, asserts exact == true, returns durable InputLogSize
func (m *MPTManager) Prove(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error)
func (m *MPTManager) Root() [sha256.Size]byte
func (m *MPTManager) Close() error

// OutputLogClient abstracts append and proof operations against the Tessera Output Log.
type OutputLogClient interface {
	Append(ctx context.Context, leafData []byte) (leafIdx uint64, rawCP []byte, err error)
	InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error)
}

// WitnessClient abstracts submitting checkpoints to remote witnesses for cosigning.
type WitnessClient interface {
	Witness(ctx context.Context, checkpoint []byte) (witnessedCP []byte, err error)
}

// ServingState represents the immutable active state served to lookup clients.
type ServingState struct {
	OutputLogIndex uint64
	OutputLogSize  uint64
	OutputLogCP    *log.Checkpoint
	RawCheckpoint  []byte // Raw signed note bytes preserving witness cosignatures
	OutputLogProof [][sha256.Size]byte
	InputLogCP     *log.Checkpoint
	RawInputLogCP  []byte // Raw signed Input Log checkpoint note bytes
	InputLogSize   uint64
	MapRoot        [sha256.Size]byte
}

// OutputPublisher coordinates MPT prediction, Output Log publishing, and state ratcheting.
type OutputPublisher struct {
	mptMgr       *MPTManager
	outputLog    OutputLogClient
	witness      WitnessClient
	servingState atomic.Pointer[ServingState]
}

func NewOutputPublisher(mptMgr *MPTManager, outputLog OutputLogClient, witness WitnessClient) *OutputPublisher
func (p *OutputPublisher) PublishBatch(ctx context.Context, modifiedSubRoots map[[sha256.Size]byte][sha256.Size]byte, inputLogCP *log.Checkpoint, rawInputLogCP []byte) (*ServingState, error)
func (p *OutputPublisher) GetServingState() *ServingState
```

---

## 3. MPT Working Tree Architecture (`torchwood/mpt`)

The MPT stores cryptographic sub-roots mapping `KeyHash -> MiniLogRoot` using [`torchwood/mpt`](https://github.com/FiloSottile/torchwood/blob/main/mpt/DESIGN.md), a binary Merkle Patricia Trie.

```text
┌─────────────────────────────────────────────────────────────┐
│ MPT In-Memory Working Tree (mmap)                           │
│                                                             │
│  Trie Nodes (52 Bytes):                                     │
│  [ bitDirty (2B) | left (6B) | right (6B) | leaf (6B) | ihash (32B) ]
│                                                             │
│  Leaf Values:                                               │
│  [ 32-byte MiniLogRoot ] -> Append-only leaf file           │
└─────────────────────────────────────────────────────────────┘
```

1. **In-Memory Working Tree via `mmap`**:
   - Node pointers (`left`, `right`, `leaf`) use 48-bit (6-byte) relocatable byte offsets.
   - Bypasses Go GC overhead entirely.
2. **Lazy Hash Recomputation & Compaction**:
   - Updates flag nodes as `dirty`. `Snap()` recomputes SHA-256 hashes only along dirty subtrees.
   - Non-blocking concurrent compaction writes memory snapshots to a `next` file in the background.

### 3.1 MPT Version Semantics & Input Log Tree Size Binding

The `torchwood/mpt` trie supports versioned snapshots via `mpt.Snap(version int64)`. In VIndex, `Snapshot.Version` is explicitly set to the **Input Log Tree Size** (`InputLogSize`):

```go
snap, err := m.tree.Snap(int64(inputLogSize))
```

This semantic versioning contract provides three key guarantees:
- **Direct Alignment with Input Log Checkpoints**: Binds the cryptographic MPT snapshot directly to the exact Input Log tree size committed in the Output Log leaf (`StateCommitment.ILCheckpoint`).
- **Deterministic Crash Recovery**: Enables `RecoveryCoordinator` on startup to inspect `mptMgr.Version()` (`mptVersion, exact`) against `OutputLog[N-1].InputLogSize` (`S_OUT`) and compute the exact missing tile replay slice `[mptVersion .. S_OUT)` if `exact == false || mptVersion < S_OUT`.
- **Client Verification Simplicity**: Clients parse `ilcp` from the Output Log leaf and construct `mpt.Snapshot{ Version: int64(ilcp.Size), Hash: MapRoot }` to verify inclusion/non-inclusion proofs with zero out-of-band metadata.

### 3.2 Split-Locking Architecture (`writeMu` vs `treeMu`)

To prevent background disk persistence from introducing tail-latency spikes to reader lookups:
- `writeMu` (`sync.Mutex`): Held during `Commit()` and `Sync()`. Serializes write operations and background disk flushes.
- `treeMu` (`sync.RWMutex`): Held in read mode (`RLock()`) during `Prove()` queries, and briefly in write mode (`Lock()`) during in-memory node updates and root pointer swaps in `Commit()` (< 5ms).
- **Zero Read Lock Contention during `Sync()`**: When `Sync()` flushes patch frames and executes `fsync` (5-20ms), it holds `writeMu` but **never** holds `treeMu`. Consequently, concurrent `Prove()` queries execute completely unblocked.

### 3.3 Adaptive / Hybrid Sync Triggers

MPT state persistence to disk is driven by a hybrid trigger model:
1. **Periodic Interval**: Flushes unsynced patch frames every 15 seconds.
2. **Leaf Count Threshold**: Triggers a `Sync()` when 30,000 leaves have been committed since the last sync.
3. **Ingestion Idle Window**: Executes `Sync()` when the ingestion pipeline reaches the target checkpoint and transitions to idle polling.
4. **Graceful Shutdown**: `Close()` invokes a blocking `Sync()` to ensure all patch frames are flushed and fsync'd.

### 3.4 MPT Durability Mechanics, 'exact' State & Lock Isolation

- **The `exact` Flag & Crash Durability**:
  - In `torchwood/mpt`, the on-disk file header stores an `exact` boolean flag alongside `version`.
  - On the first `Set()` mutation following a clean sync, `torchwood/mpt` marks `exact = false` and immediately `fsync`s this updated header to disk before appending any new leaf bytes.
  - While subsequent mutations and in-memory snapshots (`Snap()`) progress in RAM, the on-disk header continuously reflects `exact == false`.
  - Only when `Sync()` is called does `torchwood/mpt` flush patch frames, record the new `version`, set `exact = true`, and `fsync` the file descriptor.
  - **Why Regular Syncing Matters**: If a crash, kill signal, or power failure occurs after any `Set()` without an intervening `Sync()`, the tree on disk will report `exact == false` upon reopening. In that state, the on-disk trie cannot be assumed clean or complete at its recorded `version`, requiring the recovery layer to replay all leaves starting from the last durably synced `version` up to the latest committed Output Log tree size S_OUT.
- **Lock Isolation & Lookup Concurrency**:
  - `Sync()` executes asynchronously in the background, entirely decoupled from the per-batch commit critical section.
  - While `Sync()` holds `writeMu` (serializing with concurrent `Commit()` calls), it does **not** acquire `treeMu`.
  - Consequently, client lookup queries (`Prove()`) acquire `treeMu.RLock()` against in-memory trie nodes and continue serving with zero lock contention throughout the 5–20ms disk `fsync` window.
- **Bounded Replay Slices & Safe Watermark Pruning**:
  - The [Adaptive / Hybrid Sync Triggers](#33-adaptive--hybrid-sync-triggers) bound the unsynced leaf delta to < 30k leaves (or < 15s).
  - Even during dirty crash recovery when `exact == false`, the tile replay slice `[mptVersion .. S_OUT)` is capped to < 30k leaves, guaranteeing recovery in < 150ms.
  - When `mptMgr.Sync()` successfully fsyncs the MPT to disk (establishing `exact == true`), `mptDurableSize` advances to the synced version. The `TileReaper` safely consumes this watermark (`SafeWatermark = mptDurableSize`) to prune older cached tiles. Because `mptDurableSize` is strictly bounded by `m_kv_size` (`Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= mptDurableSize`), `min(m_kv_size, mptDurableSize) == mptDurableSize`. Leaves below `mptDurableSize` are already committed to Pebble and durably fsync'd in MPT disk files, so crash recovery never requires raw tiles below `mptDurableSize`.

### 3.5 MPT Memory Scale & Provisioning

| Scale (Unique Keys) | Inner Nodes in `mmap` | Top Levels (Hot in RAM) | Bottom Levels (Paged) |
| :--- | :--- | :--- | :--- |
| **10 Million** | ~1.04 GB | ~100 MB | ~940 MB |
| **100 Million** | ~10.4 GB | ~100 MB | ~10.3 GB |
| **1 Billion** | ~104 GB | ~100 MB | ~103.9 GB |

> [!IMPORTANT]
> Because key hashes are uniformly distributed, batch updates touch scattered nodes without locality. Production hosts must provision sufficient RAM to keep the active MPT `mmap` resident in physical memory, preventing random NVMe major page faults.

---

## 4. Two-Phase Commit & Lock Sequencing

### 4.1 Serialized Batch Execution Loop & Synchronous Commit Barrier
To guarantee crash consistency without distributed transactions, the batch commit pipeline enforces a strict, synchronous commit barrier: Output Log append and witness network calls **MUST NOT begin** until `kvstore.WriteBatch` has successfully completed and durably persisted to disk (`pebble.Sync`).

The per-batch commit flow is strictly serialized:
```text
store.WriteBatch(entries, S_k) [Blocking Pebble DB Disk Fsync]
       │
       ▼ (Storage persistence verified durable; m_kv_size advanced)
publisher.PublishBatch(modifiedSubRoots, CP_in, rawCP_in)
       ├── 1. Lock-Free Root Prediction (mptMgr.Predict)
       ├── 2. Output Log Append (outputLog.Append)
       ├── 3. Remote Witness Cosignatures (witness.Witness)
       └── 4. In-Memory Critical Section (< 5ms under treeMu.Lock()):
              • Apply mutations (mpt.Set)
              • Snapshot root & record version (mpt.Snap(S_k))
              • Ratchet atomic servingState pointer
```

```text
0. Synchronous Storage Barrier (Prerequisite before Output Publication):
   └── store.WriteBatch(entries, S_k) completes and durably persists to disk (pebble.Sync).
       Output Log append and witness network calls MUST NOT begin until this step finishes.

1. Lock-Free Phase (OutputPublisher - No treeMu Held):
   ├── 1. Calculate predicted MapRoot across modified sub-roots (mptMgr.Predict)
   ├── 2. Construct StateCommitment payload:
   │      hex(MapRoot) + "\n" + rawBytes(inputLogCP)
   ├── 3. Append leaf to Tessera Output Log (outputLog.Append)
   ├── 4. Submit Output Log checkpoint to remote witnesses & collect cosignatures
   └── 5. Query RFC 6962 inclusion proof for the Output Log leaf
       (Read Server continues serving lookups completely unblocked)

2. Critical Section (< 5ms under treeMu.Lock(), writeMu held):
   ├── 1. Acquire writeMu.Lock()
   ├── 2. Acquire treeMu.Lock()
   ├── 3. Apply sub-root mutations to in-memory MPT (mpt.Set())
   ├── 4. Recompute root hash and record Input Log size version: mpt.Snap(int64(inputLogSize))
   ├── 5. Assert actualRoot == predictedMapRoot (FATAL HALT on mismatch)
   ├── 6. Ratchet atomic servingState pointer to new Output Log commitment
   ├── 7. Release treeMu.Unlock()
   └── 8. Release writeMu.Unlock()

3. Background Disk Sync (5-20ms under writeMu.Lock(), treeMu NOT held):
   ├── 1. Acquire writeMu.Lock()
   ├── 2. Flush patch frames to disk
   ├── 3. Execute fsync on MPT file descriptor (5-20ms)
   │      (Concurrent Prove() lookups hold treeMu.RLock() completely unblocked)
   ├── 4. Assert Version() exact == true
   ├── 5. Update MPTDurableSize watermark (advancing SafeWatermark = mptDurableSize for TileReaper)
   └── 6. Release writeMu.Unlock()
```

### 4.2 Parallelism Note
While in-memory root prediction (`mptMgr.Predict()`) could technically run in parallel with the storage sync, Output Log network I/O (append and witness cosignatures) must strictly wait for storage persistence (`store.WriteBatch`). Serializing the entire step per batch (`store.WriteBatch` -> `publisher.PublishBatch`) avoids unnecessary concurrency complexity, state coordination overhead, and race risks.

### 4.3 Crash Invariant Guarantee
Because storage persistence strictly precedes Output Log publication:
- **Crash Invariant**: `m_kv_size >= Output_Size` is preserved under all crash, power loss, or kill scenarios.
- **Clean Recovery**: Startup recovery is guaranteed never to encounter an Output Log entry referencing uncommitted KV store chunks. If a crash occurs between storage sync and Output Log publication, `m_kv_size > S_OUT`; startup recovery simply ignores uncommitted storage chunks beyond `S_OUT` via point-in-time `store.GetSubRoot(keyHash, S_OUT)` queries.

---

## 5. Output Log Commitment Schema

Each leaf in the Tessera Output Log consists of a two-line plain-text `StateCommitment` payload:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
example.com/inputlog
500000
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

— example.com/inputlog/witness BxHj...
```

- **Line 1 (`MapRoot`)**: 64-character lowercase hex string representing the 32-byte MPT root hash.
- **Remaining Lines (`InputLogCheckpoint`)**: Raw unparsed bytes of the signed Input Log checkpoint note committed at this snapshot, including all origin, size, root hash, and witness cosignature lines.

---

## 6. Failure Modes & Witness Recovery Policy

- **Prediction Mismatch (HALT)**: If `actualRoot != predictedMapRoot` during `Commit()`, the system logs a fatal error and triggers a deterministic `HALT` (since the Output Log has already committed to the predicted root).
- **Witness Quorum Timeout**: Configurable retry with exponential backoff before failing the batch commit.

---

## 7. Testing & Qualification Strategy

- **Integration & Synchronization Testing**: Tests for `MPTManager` (Predict vs Commit root consistency across randomized mutations, split-locking concurrency, `Sync()` durability verification), state commitment serialization, and serving state atomic pointer ratcheting. (Core MPT data structure correctness is delegated to upstream `torchwood/mpt` test suites).
- **Witness Mocking & Fault Injection**: End-to-end integration tests using mock Output Log and simulated slow, flaky, or partitioned remote witness networks.

---

## 8. Compaction Sizing & Subsystem Metrics

### 1. Compaction Sizing & Scratch Overhead
- **Compaction Scratch Overhead**: Background MPT compaction writes a new contiguous memory image to disk; host must reserve at least 2x the MPT disk size in scratch capacity.

### 2. Subsystem Telemetry & Metrics
- `vindex_tree_mpt_nodes_count` (Gauge): Current count of trie nodes.
- `vindex_tree_mmap_bytes` (Gauge): Total memory mapped by the working trie.
- `vindex_tree_predict_duration_seconds` (Histogram): Time spent calculating predicted root.
- `vindex_tree_commit_duration_seconds` (Histogram): Critical section duration under `treeMu` write lock (< 5ms).
- `vindex_tree_prove_duration_seconds` (Histogram): Duration of MPT inclusion/non-inclusion proof generation under `treeMu.RLock()`.
- `vindex_tree_sync_duration_seconds` (Histogram): Time spent in `Sync()` disk fsync (5-20ms).
- `vindex_tree_sync_total` (Counter): Total count of successful MPT disk syncs.
- `vindex_tree_compaction_duration_seconds` (Histogram): Duration of background disk compaction.
- `vindex_tree_witness_latency_seconds` (Histogram): Time spent awaiting witness cosignatures.
- `vindex_tree_witness_errors_total` (Counter): Count of witness RPC timeouts / failures.

