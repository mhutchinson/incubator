# Sub-Design: Authenticated State (MPT & Output Log Commitments)

This document defines the authenticated trie architecture, cryptographic invariants, verified performance optimizations, operational considerations, and retired design branches for the **Authenticated State Subsystem** (`vindex/v1/internal/tree`).

---

## 1. Core Load-Bearing Invariants

### 1.1 Output Log State Commitment Schema
Each leaf in the Tessera Output Log consists of a two-line plain-text `StateCommitment` payload:
```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
example.com/inputlog
500000
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

— example.com/inputlog/witness BxHj...
```
- **Line 1 (`MapRoot`)**: 64-character lowercase hex string representing the 32-byte Sparse Merkle Patricia Trie root hash.
- **Remaining Lines (`InputLogCheckpoint`)**: Raw unparsed bytes of the signed Input Log checkpoint note committed at this snapshot, including all origin, size, root hash, and witness cosignature lines.

### 1.2 Lock-Free Root Prediction (`mpt.Predict`)
Before acquiring the writer lock or appending to the Output Log, `OutputPublisher` calls `mptMgr.Predict`:
- Computes the future `MapRoot` across all modified mini-log sub-roots pure in-memory without holding the exclusive writer lock (`treeMu.Lock`).
- Allows Output Log append and remote witness network RPCs to proceed while concurrent readers query `treeMu.RLock()` without blocking.

### 1.3 Fatal Panic on Root Prediction Divergence
In `publisher.PublishBatch`, once the commitment is appended to the Output Log, writer lock `treeMu` is acquired and mutations are committed (`CommitWithVersionLocked`). The actual computed root is asserted against `predictedMapRoot`:
```go
if actualRoot != predictedMapRoot {
    p.mptMgr.Unlock()
    panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", actualRoot, predictedMapRoot))
}
```
- **Invariant**: If `actualRoot != predictedMapRoot`, the node must terminate immediately with a fatal panic. Continuing execution would commit an equivocal root to the Output Log.

### 1.4 Split-Locking Read Isolation
The subsystem uses split-locking to isolate background disk persistence from in-memory lookups:
- `writeMu` (`sync.Mutex`): Held during `CommitWithVersionLocked` and `Sync()`. Serializes write operations and background disk flushes.
- `treeMu` (`sync.RWMutex`): Held in read mode (`RLock()`) during `Prove()` lookups, and briefly in write mode (`Lock()`) during in-memory node updates and root pointer swaps (< 5ms).
- **Invariant**: `Sync()` (5–20ms disk fsync) executes under `writeMu` and **NEVER holds `treeMu`**. Concurrent `Prove()` lookups run completely unblocked during disk flushes.

### 1.5 Semantic MPT Versioning Bound to Input Log Size
The trie supports versioned snapshots via `mpt.Snap(int64(inputLogSize))`:
- Snapshot versions are strictly bound to the Input Log tree size committed in the Output Log leaf.
- Binds cryptographic proofs directly to witnessed Input Log checkpoints with zero out-of-band metadata.

### 1.6 Atomic Serving State Ratchet
`OutputPublisher` ratchets the reader-visible state via an `atomic.Pointer[ServingState]`:
- Readers observe new commitments atomically after write lock verification.
- Guarantees readers never observe partial, intermediate, or uncommitted trie mutations.

---

## 2. Verified Performance Optimizations

### 2.1 Binary Sparse MPT in `mmap` via `torchwood/mpt`
The working trie is backed by OS `mmap(2)` via `filippo.io/torchwood/mpt`:
- Node pointers (`left`, `right`, `leaf`) use 48-bit (6-byte) relocatable offsets, achieving ~52 bytes/node density.
- Operates outside the Go runtime heap, completely eliminating Go garbage collection (GC) scan and pause overheads.

### 2.2 Split-Locking Microbenchmark Justification
Microbenchmarks on a 24-core host measuring concurrent `Prove()` lookups under heavy background disk syncs (`tree.Sync()`) prove the value of split-locking:

| Lock Architecture | Baseline Read Latency (`Prove` No Sync) | Read Latency under Disk Sync (`tree.Sync()`) | Lookup Throughput | Reader Availability during `fsync` |
| :--- | :--- | :--- | :--- | :--- |
| **Coarse Global Lock** | 1,473 ns/op | **18,887 ns/op** (12.8x degradation) | ~53,000 reads/s | **0% (100% blocked during msync/fsync)** |
| **Split-Locking (`writeMu` + `treeMu`)** | **1,473 ns/op** | **1,473 ns/op** (in-memory snapshot) | **~678,000 reads/s** | **100% (uninterrupted read serving)** |

- Reader throughput is 12.8x higher under split-locking, maintaining 100% availability during 5–20ms disk fsync operations.

### 2.3 Sub-5ms MPT Write Critical Section
The exclusive write lock (`treeMu.Lock()`) is held strictly for in-memory node updates (`mpt.Set`), snapshot ratcheting (`mpt.Snap`), and atomic pointer swapping, completing in microseconds (< 5ms).

### 2.4 Lazy Hash Recomputation
Updates flag trie nodes as `dirty`. `Snap()` recomputes SHA-256 hashes only along dirty subtrees, avoiding full-tree traversal.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Adaptive / Hybrid Sync Triggers
To bound recovery replay time and disk scratch space, the tree subsystem executes `Sync()` based on:
1. **Periodic Interval**: Flushes unsynced patch frames every 15 seconds.
2. **Leaf Count Threshold**: Triggers `Sync()` when 30,000 leaves have been committed.
3. **Ingestion Idle Window**: Executes `Sync()` when ingestion reaches the target checkpoint and transitions to idle polling.
4. **Graceful Shutdown**: `Close()` invokes a blocking `Sync()` to consolidate on-disk state.

### 3.2 MPT Memory Provisioning Matrix

| Scale (Unique Keys) | Inner Nodes in `mmap` | Top Levels (Hot in RAM) | Bottom Levels (Paged) |
| :--- | :--- | :--- | :--- |
| **10 Million** | ~1.04 GB | ~100 MB | ~940 MB |
| **100 Million** | ~10.4 GB | ~100 MB | ~10.3 GB |
| **1 Billion** | ~104 GB | ~100 MB | ~103.9 GB |

Production hosts must provision sufficient RAM to keep the active MPT resident, preventing random NVMe major page faults.

### 3.3 Compaction Scratch Overhead
Background MPT compaction writes a new contiguous memory image to disk; hosts must reserve at least 2x the MPT disk size in scratch storage capacity.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode & `PublishDirect` Retirement
- **What Was Proposed & Investigated**:
  A dedicated publishing method, `PublishDirect(ctx, mapRoot, inputLogCP, rawInputLogCP)`, was implemented in `publisher.go` exclusively to serve Backfill Mode. In Backfill Mode, the coordinator updated MPT nodes directly via `mptMgr.SetBatch` and called `PublishDirect` once upon reaching the target checkpoint, bypassing lock-free root prediction (`mpt.Predict`) and intermediate Output Log publishing.
- **Why It Was Investigated**:
  Hypothesized that running `mpt.Predict` and publishing commitments per batch across tens of millions of leaves would cause excessive memory bloat and witness roundtrip latency during genesis sync.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  1. **Normal Mode Outperformed Backfill by 85.1% on SumDB**: Normal Mode achieved **90,797.2 leaves/sec** vs. Backfill's **49,063.6 leaves/sec**. `mpt.Predict` is an efficient in-memory trie path computation that introduced negligible overhead.
  2. **100% Read Starvation**: Backfill Mode shut down read serving (0% availability) during bulk ingestion, whereas Normal Mode served queries with P50 < 2ms.
  3. **Identical Memory Footprint**: Backfill Mode yielded no meaningful RSS savings (saving only 20–30 MB out of 220 MB).
  4. **Prediction Bypass Risk**: `PublishDirect` bypassed root prediction consistency checks, creating an unverified code path.
- **Why Permanently Set Aside & Pruned**:
  `PublishDirect` was pruned from `publisher.go` in Milestone M3 along with its unit test `TestPublisher_PublishDirect`. The publisher is permanently unified around `PublishBatch` with prediction assertions.

### 4.2 Coarse Global Locking across Network RPCs & Disk Sync
- Holding a single global lock during remote witness RPCs or disk fsync stalled read queries for 100ms–seconds per batch.
- Replaced by split-locking (`writeMu` vs `treeMu`) and lock-free root prediction.

### 4.3 Full Tree Copy-on-Write
- Duplicating memory-mapped trees for multi-version concurrency created prohibitive memory overhead and Linux dirty page writeback storms.
- Replaced by single in-memory working tree with split-locking and atomic pointer ratcheting.

### 4.4 Sparse Merkle Trees (SMT) & Verkle Trees
- Sparse Merkle Trees: Prohibitive memory and disk I/O across 256-level trie depths.
- Verkle Trees: Prohibitive CPU costs for polynomial commitment computation during high-throughput ingestion.
- Replaced by binary Sparse Merkle Patricia Trie in `mmap` (`torchwood/mpt`).
