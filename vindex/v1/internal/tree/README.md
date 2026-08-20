# Sub-Design: Authenticated State (MPT & Output Log Commitments)

## 1. Context & Objectives

The **Authenticated State Subsystem** (`vindex/v1/internal/tree`) manages the cryptographic commitments binding search keys to mini-log Merkle roots, publishes state commitments to the Tessera Output Log, collects remote witness cosignatures, and updates the in-memory Merkle Patricia Trie (MPT) with a sub-5ms write lock critical section.

### 1.1 Core Guarantees
1. **Uninterrupted Read Serving**: Uses lock-free MPT root prediction (`mpt.Predict`) to publish and witness state commitments over the network without holding write locks, maintaining 100% read availability during witness latency windows (100ms – seconds).
2. **Sub-5ms Critical Section**: The write lock critical section is strictly limited to in-memory MPT node updates (`mpt.Set`), SHA-256 root snap (`mpt.Snap`), and atomic pointer ratcheting.
3. **Equivocation Protection**: Binds `MapRoot` and the exact `InputLogCheckpoint` bytes into an append-only Tessera Output Log with witness cosignatures.
4. **Zero GC Pressure via `mmap`**: The working trie is backed by OS `mmap(2)` via `torchwood/mpt`, bypassing Go runtime garbage collection.

### 1.2 Non-Requirements & Out of Scope
- **No Historical Time-Travel Queries**: The in-memory MPT serves proofs against the active ServingState. Historical root queries are verified via the append-only Output Log, not retained as active in-memory branches.
- **No Multi-Tree Sharding**: A single MPTManager instance manages the global key-space on the host.
- **No Direct Leaf Ingestion**: The tree package does not parse raw log leaves or execute MapFn; it strictly accepts pre-computed modifiedSubRoots map updates from the committer.

### 1.3 Alternatives Considered (Concurrency & Lock Model)
- **Concurrency & Lock Sequencing**:
  - **Selected - Lock-Free Prediction with 2-Phase Commit**: Predicts root hash upfront so slow network I/O (Output Log append + witness cosignatures) runs completely without holding writer locks.
  - **Rejected - Exclusive Lock across Network Calls**: Holding write locks during remote witness RPCs stalls read queries for 100ms–seconds per batch.
  - **Rejected - Full Tree Copy-on-Write**: Duplicating memory-mapped trees for MVCC creates prohibitive memory overhead and Linux dirty page writeback storms.
  - *(Note: For the overarching selection of Binary MPT vs SMT/Verkle, see [ARCHITECTURE.md](../../docs/ARCHITECTURE.md).)*

---

## 2. Package API & Responsibilities

### Responsibilities
- **MPT Working Tree Management**: Allocates and maintains the `torchwood/mpt` binary trie in `mmap`, managing dirty subtree hashing and background compaction.
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

// MPTManager wraps the torchwood/mpt in-memory trie.
type MPTManager struct {
	mu      sync.RWMutex
	tree    *torchmpt.Tree
	mmapDir string
}

func OpenMPT(mmapDir string) (*MPTManager, error)
func (m *MPTManager) Predict(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error)
func (m *MPTManager) Commit(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error)
func (m *MPTManager) Prove(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error)
func (m *MPTManager) Root() [sha256.Size]byte
func (m *MPTManager) PersistedVersion() int64
func (m *MPTManager) PersistedSize() uint64
func (m *MPTManager) Persist() error

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

### MPT Memory Scale & Provisioning

| Scale (Unique Keys) | Inner Nodes in `mmap` | Top Levels (Hot in RAM) | Bottom Levels (Paged) |
| :--- | :--- | :--- | :--- |
| **10 Million** | ~1.04 GB | ~100 MB | ~940 MB |
| **100 Million** | ~10.4 GB | ~100 MB | ~10.3 GB |
| **1 Billion** | ~104 GB | ~100 MB | ~103.9 GB |

> [!IMPORTANT]
> Because key hashes are uniformly distributed, batch updates touch scattered nodes without locality. Production hosts must provision sufficient RAM to keep the active MPT `mmap` resident in physical memory, preventing random NVMe major page faults.

---

## 4. Two-Phase Commit & Lock Sequencing

To prevent network witness latency (100ms – seconds) from stalling query serving, publishing utilizes a 2-phase commit model with root prediction:

```text
1. Lock-Free Phase (OutputPublisher - No Lock Held):
   ├── 1. Calculate predicted MapRoot across modified sub-roots (mptMgr.Predict)
   ├── 2. Construct StateCommitment payload:
   │      hex(MapRoot) + "\n" + rawBytes(inputLogCP)
   ├── 3. Append leaf to Tessera Output Log (outputLog.Append)
   ├── 4. Submit Output Log checkpoint to remote witnesses & collect cosignatures
   └── 5. Query RFC 6962 inclusion proof for the Output Log leaf
       (Read Server continues serving lookups completely unblocked)

2. Critical Section (< 5ms under mptMgr.mu.Lock()):
   ├── 1. Apply sub-root mutations to MPT (mpt.Set())
   ├── 2. Recompute root hash (mpt.Snap())
   ├── 3. Assert actualRoot == predictedMapRoot (FATAL HALT on mismatch)
   ├── 4. Ratchet atomic servingState pointer to new Output Log commitment
   └── 5. Release mptMgr.mu.Unlock()
```

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

- **Integration & Synchronization Testing**: Tests for `MPTManager` (Predict vs Commit root consistency across randomized mutations), state commitment serialization, and serving state atomic pointer ratcheting. (Core MPT data structure correctness is delegated to upstream `torchwood/mpt` test suites).
- **Witness Mocking & Fault Injection**: End-to-end integration tests using mock Output Log and simulated slow, flaky, or partitioned remote witness networks.

---

## 8. Compaction Sizing & Subsystem Metrics

### 1. Compaction Sizing & Scratch Overhead
- **Compaction Scratch Overhead**: Background MPT compaction writes a new contiguous memory image to disk; host must reserve at least 2x the MPT disk size in scratch capacity.

### 2. Subsystem Metrics
- `tree_mpt_nodes_count` (Gauge): Current count of trie nodes.
- `tree_predict_duration_seconds` (Histogram): Time spent calculating predicted root.
- `tree_commit_lock_duration_seconds` (Histogram): Critical section duration under MPT write lock (< 5ms).
- `tree_mpt_compaction_duration_seconds` (Histogram): Duration of background disk compaction.
- `tree_witness_latency_seconds` (Histogram): Time spent awaiting witness cosignatures.
- `tree_witness_errors_total` (Counter): Count of witness RPC timeouts / failures.

