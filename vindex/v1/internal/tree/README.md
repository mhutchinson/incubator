# Sub-Design: Authenticated State Commitment (MPT & Publisher)

This document defines the cryptographic commitment engine, tree synchronization protocols, concurrency model, load-bearing invariants, and verified performance optimizations for the **Tree Subsystem** (`vindex/v1/internal/tree`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Concurrency Dilemma
The tree subsystem binds the search index into an authenticated 32-byte cryptographic root (`MapRoot`), anchors it in an immutable Output Log, and serves cryptographic inclusion and non-inclusion proofs to HTTP readers.

Because readers must verify proofs against a coherent snapshot, all mutations to the in-memory Sparse Merkle Patricia Trie (MPT) require taking a write lock (`treeMu.Lock()`). This creates a severe operational dilemma:
1. **The Reader Starvation Trap**: A full commit requires computing tree updates, persisting MPT files to disk (5–20ms), appending a state commitment entry to the Output Log, and awaiting cosignatures from external witnesses over the network (50–200ms). If the writer lock is held across this entire sequence, concurrent HTTP readers are starved. Under heavy traffic, query availability collapses and lookups time out.
2. **The Equivocation Trap**: If the system writes a state commitment to the append-only Output Log and *subsequently* encounters an in-memory trie mutation error or calculation mismatch, the node has permanently committed an unprovable root to public witnesses, destroying operator trust.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Deliver cryptographic inclusion and non-inclusion proofs in constant time with logarithmic proof sizes (<= 256 hashes).
  - Minimize reader lock contention during continuous ingestion, keeping write lock duration under 5 milliseconds.
  - Eliminate split-view equivocation by coupling `MapRoot` commitments to signed Input Log checkpoints.
  - Maintain an immutable on-disk MPT log for Zero-WAL crash recovery.
- **Non-Goals**:
  - **No Dynamic Rollbacks**: The MPT is strictly append-only; state transitions progress monotonically forward.
  - **No In-Memory Tree Duplication**: Does not duplicate full in-memory trie trees across buffers; memory constraints require mutating a single in-memory trie under short-lived locks.
  - **No Multi-Master Consensus**: Tree sequencing is driven by a single local publisher process.

### 1.3 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Binary Sparse Merkle Patricia Trie via `filippo.io/torchwood/mpt`, Tessera Output Log writer, and external witness clients.
- **Known Pain Points ("Warts and All")**:
  - **Fatal Panic on Prediction Divergence**: If an in-memory calculation bug causes `actualRoot != predictedMapRoot`, the node halts immediately. The Output Log has already been appended; there is no graceful in-memory recovery path.
  - **RAM Sizing for Branch Locality**: Uniform 32-byte key hash distribution scatters updates across the 256-bit trie keyspace. While leaf data resides in `mmap` files, active branch nodes must remain resident in RAM (scaling from ~1 GB for 10M keys to 100+ GB for 1B keys).
  - **External Witness Network Latency**: Waiting for witness cosignatures introduces commit cycle latency, though lock-free pre-computation insulates HTTP readers from this delay.

---

## 2. Detailed Design

### 2.1 The Binary Sparse Merkle Patricia Trie (`torchwood/mpt`)
The commitment plane maps 32-byte key hashes (`KeyHash`) to 32-byte mini-log roots (`SubRoot`):

1. **Binary Radix Structure**: Keys represent 256-bit paths from the root. Non-existent subtrees are represented by implicit zero-hash nodes, allowing concise non-inclusion proofs.
2. **Memory-Mapped Storage**: Tree nodes and leaves are stored in append-only files managed via memory mapping (`mmap`), allowing fast lookups without loading entire historical trees into the Go heap.
3. **SubRoot Values**: The value committed at each leaf is the RFC 6962 mini-log root computed by `kvstore.GetSubRoot`, authenticating all occurrences of that key in the Input Log.

### 2.2 The 3-Step Atomic Commitment Dance
The publisher coordinates the progression from KV storage to public commitment through a structured 3-step sequence. To keep reader lock contention under 5 milliseconds while guaranteeing that no unprovable root is ever published, the commit sequence operates like the classic idol swap in *Raiders of the Lost Ark*:
1. **Weighing the sandbag (lock-free preparation)**: Pre-computing the exact future root (`mpt.Predict`), writing the commitment to the Output Log, and gathering witness cosignatures without holding the trie write lock.
2. **The split-second swap (< 5ms critical section)**: Acquiring `treeMu.Lock()`, committing the mutations, verifying root equality, and ratcheting `ServingState` in under 5 milliseconds.
3. **The hair-trigger boulder (fatal panic)**: If the actual root diverges by even a single byte from the prediction (`actualRoot != predictedMapRoot`), the temple collapses: the node halts immediately with a fatal panic, freezing disk state before an unprovable or equivocal state can be served.

| Step | Phase | Operations | Lock State | Reader Impact |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Lock-Free Prediction & Witnessing** | 1. `predictedMapRoot = mpt.Predict(modifiedSubRoots)`<br>2. `outputLog.Append(predictedMapRoot, inputLogCP)`<br>3. `witness.Witness(outputLogCheckpoint)` | No tree lock held | **Zero blocking**; concurrent queries run unimpeded. |
| **2** | **The Atomic Swap** | 1. `treeMu.Lock()`<br>2. `actualRoot = mpt.CommitWithVersionLocked(...)`<br>3. `assert(actualRoot == predictedMapRoot)`<br>4. Ratchet `ServingState`<br>5. `treeMu.Unlock()` | `treeMu.Lock()` held | **< 5ms** critical section duration. |
| **3** | **Background Durability** | 1. `mptMgr.Sync()` (flushes dirty mmap pages to disk)<br>2. Advance `MPT_Durable_Size` | `writeMu.Lock()` held; `treeMu` released | **Zero blocking**; disk fsync runs outside reader lock. |

#### Step Details:
1. **Lock-Free Prediction & Witnessing**:
   - The publisher calls `mptMgr.Predict(modifiedSubRoots)`. This computes candidate trie hashes on cloned branch nodes without acquiring `treeMu.Lock()`.
   - The commitment string (`hex(predictedMapRoot) + "\n" + rawInputLogCP`) is appended to the Tessera Output Log.
   - The new Output Log checkpoint is submitted to external witnesses to gather threshold cosignatures.
   - **Throughout this entire phase, concurrent readers execute lookups without blocking.**
2. **The Split-Second Swap**:
   - The publisher acquires `treeMu.Lock()`.
   - Mutates in-memory MPT nodes in place via `CommitWithVersionLocked`.
   - Asserts `actualRoot == predictedMapRoot`. If mismatched, panics immediately.
   - Ratchets `ServingState` pointer to the new witnessed Output Log checkpoint.
   - Releases `treeMu.Lock()`.
   - **Total critical section duration: < 5 milliseconds.**
3. **Background Durability**:
   - Under an independent `writeMu` lock, the publisher calls `mptMgr.Sync()`, issuing an `msync`/`fsync` to flush modified mmap pages to disk.
   - Once durable, `MPT_Durable_Size` is advanced, unblocking `TileReaper` in the ingestion layer.

### 2.3 Concurrency Architecture & Split-Locking
The subsystem enforces strict isolation between read serving and background disk persistence using two distinct locks:

| Lock Name | Primitive | Scope & Protected State | Typical Duration |
| :--- | :--- | :--- | :--- |
| **`treeMu`** | `sync.RWMutex` | In-memory MPT nodes, `torchmpt.Tree` instance, and active `ServingState` pointer. Read-locked by HTTP readers (`ProveLocked`); write-locked during in-memory ratchets. | **< 5ms** (write)<br>**< 50µs** (read) |
| **`writeMu`** | `sync.Mutex` | Disk fsync operations (`mptMgr.Sync()`), Output Log appends, and witness network calls. | **5ms – 200ms** |

Because `writeMu` is completely decoupled from `treeMu`, slow disk syncs and network calls never block readers.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Fatal Panic on Root Prediction Divergence**:
  - *Rule*: After the Output Log append succeeds, when the writer lock is acquired to commit in-memory mutations, the actual computed root must strictly match the predicted root:
    ```go
    if actualRoot != predictedMapRoot {
        p.mptMgr.Unlock()
        panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual %x != predicted %x", actualRoot, predictedMapRoot))
    }
    ```
  - *Rationale*: The Output Log is immutable. If the actual root diverges from the predicted root that was already appended and witnessed, execution must halt immediately.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal commitment to the Output Log that cannot be cryptographically proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published state commitment leaf binds the exact `MapRoot` to the exact signed `InputLogCheckpoint`.
  - *Rationale*: Independent witnesses sign the Output Log checkpoint note. The index operator cannot present conflicting views of index state to different clients without producing split-view signatures detectable by public monitors.
  - *Consequence ("Or Else")*: An operator attempting to selectively hide certificates or packages would be mathematically detected by any monitor cross-checking witness cosignatures.

- **[Correctness Invariant] Serving Isolation & Atomic Ratcheting**:
  - *Rule*: HTTP readers evaluate state strictly bounded by the active serving checkpoint:
    ```text
    Serving_CP.InputSize <= Output_CP.InputSize
    ```
  - *Rationale*: HTTP requests snapshot `ServingState` and enforce index filtering `index < Serving_CP.InputSize` across all storage reads.
  - *Consequence ("Or Else")*: Readers would observe uncommitted, un-witnessed entries that are ahead of the latest published checkpoint, breaking client-side Merkle proof verification.

- **[Performance Optimization] Lock-Free MPT Prediction**:
  - *Mechanism*: Computes candidate trie roots without holding `treeMu.Lock()`, allowing Output Log writes and witness network roundtrips to complete outside the critical section.
  - *Impact*: Reduces the writer lock duration from ~250ms to < 5ms per commit cycle.

- **[Performance Optimization] Split-Locking Concurrency Engine**:
  - *Mechanism*: Isolates background disk fsyncs (`writeMu`) from in-memory trie reads (`treeMu.RLock()`).
  - *Impact*: Sustains 678,000 read queries/sec during active disk commits, compared to 53,000 reads/sec under coarse global locking (12.8x throughput improvement).

### 2.5 Go Interfaces & Public Types

```go
package tree

import (
	"context"
	"crypto/sha256"

	"github.com/transparency-dev/formats/log"
)

// MPTManager manages the lifecycle and proofs for the Sparse Merkle Patricia Trie.
type MPTManager interface {
	Predict(modifiedSubRoots map[[sha256.Size]byte][]byte) ([sha256.Size]byte, error)
	CommitWithVersionLocked(modifiedSubRoots map[[sha256.Size]byte][]byte, version int64) ([sha256.Size]byte, error)
	Prove(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error)
	ProveLocked(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error)
	Lock()
	Unlock()
	RLock()
	RUnlock()
	Sync() error
	PersistedSize() uint64
}

// Publisher coordinates atomic commitment between the MPT, Output Log, and witnesses.
type Publisher interface {
	PublishBatch(ctx context.Context, inputLogCP *log.Checkpoint, modifiedSubRoots map[[sha256.Size]byte][]byte) (*ServingState, error)
	SetServingState(state *ServingState)
	GetServingState() *ServingState
}

// ServingState captures an immutable snapshot of committed, witnessed serving state.
type ServingState struct {
	MapRoot          [sha256.Size]byte
	OutputLogSize    uint64
	OutputCheckpoint []byte
	InputLogSize     uint64
	InputCheckpoint  []byte
}
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 Coarse Global Locking vs. Split-Locking with Prediction
- **Proposed**: Holding a single global lock across the entire commitment cycle (prediction, Output Log append, witness network calls, in-memory trie mutation, and disk fsync).
- **Empirical Rejection**: Benchmark profiling under heavy concurrent read traffic showed that coarse locking dropped HTTP read throughput to **53,000 queries/sec**, with P99 read latency ballooning past 250ms due to writer lock starvation.
- **Chosen Design**: Split-locking with lock-free prediction holds `treeMu.Lock()` for < 5ms, sustaining **678,000 queries/sec** (a 12.8x speedup) with sub-millisecond P50 read latency.

### 3.2 Sparse Merkle Trees (SMT) vs. Binary Sparse Merkle Patricia Trie
- **Proposed**: Using a standard Sparse Merkle Tree (SMT) with fixed 256-level depth.
- **Theoretical & Empirical Rejection**: Standard SMTs require generating and traversing 256 levels of nodes per operation. Even with default empty node optimizations, SMTs incur massive memory footprint and excessive disk I/O during random-insert batch workloads.
- **Chosen Design**: Binary Sparse Merkle Patricia Trie (`torchwood/mpt`), which collapses single-child paths, bounding tree depth to the number of active keys and enabling fast mmap persistence.

### 3.3 Post-Commit Output Log Publishing
- **Proposed**: Mutating and syncing the in-memory MPT to disk *first*, and then appending the commitment to the Output Log.
- **Theoretical Rejection**: If the node crashes or power fails after the MPT disk sync but before the Output Log append completes, the local MPT has advanced to a state that was never committed or witnessed in the Output Log. On restart, the node would serve state ahead of the Output Log, violating the universal invariant `MPT_Size <= Output_Size`.
- **Chosen Design**: Predict root lock-free -> append to Output Log -> commit to MPT under short lock.
