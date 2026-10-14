# Sub-Design: Authenticated State Commitment (MPT & Publisher)

This document defines the cryptographic commitment engine, tree synchronization protocols, concurrency model, load-bearing invariants, and verified performance optimizations for the **MPT Subsystem** (`vindex/v1/internal/mpt`) and **Output Log Publisher Subsystem** (`vindex/v1/internal/tree`).

---

## 1. Context & Objectives

### 1.1 Problem Statement, Package Decoupling & Concurrency Dilemma
The commitment plane is split into two focused packages:
- **`vindex/v1/internal/mpt`**: Houses the `filippo.io/torchwood/mpt` variable-length Sparse Merkle Patricia Trie (`Manager`), canonical key validation (`ValidateCanonicalKey`), point proof generation/verification (`ProveKey`/`VerifyKey`), and two-sided prefix proof generation/verification (`ProvePrefix`/`VerifyPrefix`), with zero dependencies on `pebble` or `tessera` so it can be imported by `vindex/v1/client`.
- **`vindex/v1/internal/tree`**: Houses the `OutputPublisher`, Tessera POSIX Output Log (`PosixOutputLog`), and 3-step atomic commitment lifecycle, while re-exporting `internal/mpt` types as aliases for server subsystems.

The tree subsystem binds the search index into an authenticated 32-byte cryptographic root (`MapRoot`), anchors it in an immutable Output Log, and serves cryptographic inclusion, non-inclusion, and prefix proofs to HTTP readers.

Because readers must verify proofs against a coherent snapshot, all mutations to the in-memory Sparse Merkle Patricia Trie (MPT) require taking an exclusive publisher lock. This creates a severe operational dilemma:
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
  - **Fatal Halt on Prediction Divergence**: If an in-memory calculation defect causes the committed trie root to differ from the predicted root that was just appended to the Output Log, the node halts immediately. Because the Output Log is append-only, there is no graceful in-memory rollback path.
  - **RAM Sizing for Branch Locality**: Variable-length canonical keys and uniform key hashes scatter updates across the trie keyspace. While leaf data (`leaves`) and node records (`nodes`) reside in `mmap` files, active branch nodes remain resident in the OS page cache (scaling from ~1–1.5 GB for 10M keys to 100–150 GB for 1B keys).
  - **Cold-Start Journal Replay Latency**: On process restart, `mpt.Open()` replays uncompacted `torchwood/mpt` journal frames on disk before `coord.Recover()` begins (see [`docs/BENCHMARKS.md §5`](../../docs/BENCHMARKS.md#5-post-run-empirical-evaluation--cold-startup-investigation-2026-09-22)). To prevent connection refusals during journal replay, `vindexd` binds the HTTP server immediately (`200 OK` on `/healthz`, `503` `"status": "mpt_initializing"` on `/readyz`) while `mpt.Open()` runs asynchronously.
  - **External Witness Network Latency**: Waiting for witness cosignatures introduces commit cycle latency, though non-blocking root prediction insulates HTTP readers from this delay.

---

## 2. Detailed Design

### 2.1 The Variable-Length Binary Sparse Merkle Patricia Trie (`internal/mpt`)
The commitment plane maps variable-length canonical keys (`1..1024` printable ASCII bytes `0x21..0x7E`, or 64-character lowercase hex strings for hash-only mappers) to 32-byte mini-log roots (`SubRoot`):

1. **Variable-Length Radix Structure**: `filippo.io/torchwood/mpt` (`v0.10.1+`) stores variable-length keys (`mpt.Key`, up to 1024 bytes) in bitwise big-endian paths. Keys sharing a common byte prefix share a single subtrie, enabling both point proofs (`ProveKey` / `VerifyKey`) and two-sided prefix subtree proofs (`ProvePrefix` / `VerifyPrefix`).
2. **Memory-Mapped Storage**: Tree nodes (`nodes`, 32 bytes/node) and variable-length leaf records (`leaves`) are stored in append-only files managed via memory mapping (`mmap`), allowing fast lookups without loading entire historical trees into the Go heap.
3. **SubRoot Values**: The value committed at each leaf is the RFC 6962 mini-log root computed by the KV storage layer (`wire.ComputeMiniLogRoot`), authenticating all occurrences of that key in the Input Log.

### 2.2 The 3-Step Atomic Commitment Sequence
The publisher coordinates the progression from KV storage to public commitment through a structured 3-step sequence designed to satisfy two strict system constraints:

1. **System Constraint 1 (Zero Unwitnessed State)**: Readers must never observe or obtain proofs against an in-memory root that has not yet been committed to the append-only Output Log and signed by a threshold of external witnesses. Mutating the live trie before publishing would leak unwitnessed state to readers.
2. **System Constraint 2 (Sub-Millisecond Read Latency)**: Readers must never block on external network I/O. Because appending to the Output Log and collecting witness cosignatures takes 50ms–200ms+, holding an exclusive tree write lock across network calls would stall concurrent client queries and violate read latency SLOs (< 15ms P99).
3. **Solution (Separate Prediction from Mutation)**: Pre-compute the deterministic candidate root under a shared read lock without mutating the live trie, release the read lock, and then append to the Output Log and gather witness cosignatures while readers query unblocked. Once proofs and signatures are secured, acquire the exclusive tree lock briefly (< 5ms) to commit in-memory mutations, assert that the committed root equals the predicted root, and atomically ratchet the serving state snapshot.
4. **Why Halt on Divergence**: Candidate root prediction and in-place mutation are deterministic functions over identical inputs. Any divergence indicates an internal invariant violation or memory corruption in the trie. Halting immediately prevents the node from serving proofs that contradict the witnessed log.

#### Batch Publication Locking & Concurrency:
Batch commits are serialized by the single-writer coordinator. Within each commit cycle, lock scope is minimized so readers never block on network or disk I/O:

| Step | Phase | Operations | Lock State | Reader Impact |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Non-Blocking Prediction & Witnessing** | 1. Compute candidate `MapRoot` over modified sub-roots.<br>2. Append commitment leaf to Output Log.<br>3. Obtain witness cosignatures on Output Log checkpoint. | Shared read lock held only during in-memory prediction; **no lock held** during Output Log append and witness network calls. | **Zero blocking**; shared read locks allow concurrent HTTP proof generation to run in parallel. |
| **2** | **Atomic Mutation & Ratchet** | 1. Acquire exclusive tree and persistence locks.<br>2. Commit batch mutations to in-memory trie.<br>3. Assert committed root equals predicted `MapRoot`.<br>4. Ratchet active serving state pointer.<br>5. Release locks. | Exclusive tree & persistence locks held. | **< 5ms** critical section duration. |
| **3** | **Background Durability** | 1. Snapshot dirty trie pages (under brief shared read lock) and flush to disk.<br>2. Advance durable trie watermark. | Exclusive persistence lock held; exclusive tree lock released. | **Zero blocking**; disk `fsync` runs outside the exclusive tree lock. |

#### Step Details:
1. **Non-Blocking Prediction & Witnessing**:
   - The publisher acquires a shared read lock on the trie to compute candidate hashes over cloned branch nodes without mutating the live tree, then immediately releases the read lock.
   - The canonical commitment leaf (`"<64-char-lowercase-hex-mapRoot>\n<right-newline-trimmed-rawInputLogCP>\n"`) is appended to the Output Log with zero tree or persistence locks held.
   - The resulting Output Log checkpoint is submitted to external witnesses to gather threshold cosignatures.
   - **Throughout this entire phase, concurrent HTTP readers acquire shared read locks and generate proofs without blocking.**
2. **Atomic Mutation & Ratchet**:
   - The publisher acquires the exclusive tree lock (alongside the persistence lock).
   - Mutates in-memory MPT nodes in place.
   - Asserts that the committed root equals the predicted root. If mismatched, the process terminates immediately.
   - Ratchets the active serving state pointer to the newly witnessed Output Log checkpoint.
   - Releases the locks.
   - **Total critical section duration: < 5 milliseconds.**
3. **Background Durability**:
   - Under the independent persistence lock (acquiring only a brief shared read lock to snapshot dirty page references), the trie flushes modified memory-mapped pages to disk via `msync`/`fsync`.
   - Once durable on disk, the durable trie watermark advances, allowing the tile cache reaper to prune superseded raw tiles.

### 2.3 Concurrency Architecture & Split-Locking
The subsystem enforces strict isolation between in-memory proof serving and background disk persistence using two distinct locks:

| Conceptual Lock | Synchronization Model | Scope & Protected State | Typical Duration |
| :--- | :--- | :--- | :--- |
| **In-Memory Tree Lock** | Read-write lock | Protects in-memory MPT nodes and the active serving state snapshot. Acquired in shared read mode by HTTP proof readers and candidate root prediction; acquired in exclusive write mode only during the in-memory batch commit and serving state ratchet. | **< 5ms** (exclusive write)<br>**< 50µs** (shared read) |
| **Disk Persistence Lock** | Exclusive mutex | Serializes in-memory trie mutations against background snapshot serialization and disk `fsync` operations. Never held during Output Log appends or witness network calls. | **5ms – 20ms** |

Because disk persistence and network witnessing are decoupled from the exclusive tree lock, slow disk syncs and witness roundtrips never block HTTP readers.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Fatal Halt on Root Prediction Divergence**:
  - *Rule*: After the Output Log append succeeds, when the exclusive tree lock is acquired to apply the batch mutations in memory, the resulting trie root must equal the predicted root committed to the Output Log; any mismatch must immediately terminate the process.
  - *Rationale*: The Output Log is immutable. If the committed in-memory root diverges from the predicted root that was already appended and witnessed, execution must halt immediately.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal commitment to the Output Log that cannot be cryptographically proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published state commitment leaf binds the exact `MapRoot` to the exact signed Input Log checkpoint.
  - *Rationale*: Independent witnesses sign the Output Log checkpoint note. The index operator cannot present conflicting views of index state to different clients without producing split-view signatures detectable by public monitors.
  - *Consequence ("Or Else")*: An operator attempting to selectively hide certificates or packages would be mathematically detected by any monitor cross-checking witness cosignatures.

- **[Correctness Invariant] Serving Isolation & Atomic Ratcheting**:
  - *Rule*: HTTP readers evaluate state strictly bounded by the active serving checkpoint (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: HTTP requests capture an atomic snapshot of the serving state and filter all storage reads to leaf indices strictly below the serving checkpoint's Input Log size.
  - *Consequence ("Or Else")*: Readers would observe uncommitted, unwitnessed entries that are ahead of the latest published checkpoint, breaking client-side Merkle proof verification.

- **[Performance Optimization] Non-Blocking MPT Prediction**:
  - *Mechanism*: Computes candidate trie roots under a shared read lock and performs Output Log writes and witness network roundtrips with no tree locks held.
  - *Impact*: Reduces exclusive writer lock duration from ~250ms to < 5ms per commit cycle.

- **[Performance Optimization] Split-Locking Concurrency Engine**:
  - *Mechanism*: Isolates background disk `fsync` operations from in-memory trie read locks.
  - *Impact*: Sustains 678,000 read queries/sec during active disk commits, compared to 53,000 reads/sec under coarse global locking (12.8x throughput improvement).

### 2.5 State Trie & Commitment Contract

The state commitment subsystem provides authenticated indexing over search keys and coordinates public log commitments:

- **Inputs**:
  - Batch of modified key-to-subroot mappings.
  - Input Log checkpoint note.
- **Outputs**:
  - Signed Output Log leaf commitment.
  - Verified inclusion proof.
  - Atomically updated serving state.
- **Concurrency Contract**:
  - Readers are wait-free and never block on disk fsync or network calls.
  - Publisher commits are strictly serialized (single-writer); state ratcheting promotes the new serving state atomically.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Coarse Global Locking vs. Split-Locking with Prediction
- **Proposed**: Holding a single global lock across the entire commitment cycle (prediction, Output Log append, witness network calls, in-memory trie mutation, and disk fsync).
- **Empirical Rejection**: Benchmark profiling under heavy concurrent read traffic showed that coarse locking dropped HTTP read throughput to **53,000 queries/sec**, with P99 read latency ballooning past 250ms due to writer lock starvation.
- **Chosen Design**: Split-locking with lock-free prediction holds the exclusive publisher lock for < 5ms, sustaining **678,000 queries/sec** (a 12.8x speedup) with sub-millisecond P50 read latency.

### 3.2 Sparse Merkle Trees (SMT) vs. Binary Sparse Merkle Patricia Trie
- **Proposed**: Using a standard Sparse Merkle Tree (SMT) with fixed 256-level depth.
- **Theoretical & Empirical Rejection**: Standard SMTs require generating and traversing 256 levels of nodes per operation. Even with default empty node optimizations, SMTs incur massive memory footprint and excessive disk I/O during random-insert batch workloads.
- **Chosen Design**: Binary Sparse Merkle Patricia Trie (`torchwood/mpt`), which collapses single-child paths, bounding tree depth to the number of active keys and enabling fast mmap persistence.

### 3.3 Post-Commit Output Log Publishing
- **Proposed**: Mutating and syncing the in-memory MPT to disk *first*, and then appending the commitment to the Output Log.
- **Theoretical Rejection**: If the node crashes or power fails after the MPT disk sync but before the Output Log append completes, the local MPT has advanced to a state that was never committed or witnessed in the Output Log. On restart, the node would serve state ahead of the Output Log, violating the universal invariant `MPT_Size <= Output_Size`.
- **Chosen Design**: Predict root lock-free -> append to Output Log -> commit to MPT under short lock.

---

## 4. Verification Gate

All MPT variable-length canonical key, prefix proof, and Output Log publisher tests are verified via:

```bash
go test -race ./vindex/v1/internal/mpt/... ./vindex/v1/internal/tree/...
```

---

## 5. Design Log

| Date | Milestone | Summary |
| :--- | :--- | :--- |
| 2026-09-22 | v1 Initial | Defined 3-step atomic commitment sequence and split-locking concurrency model. |
| 2026-10-14 | M1–M3 | Tracked separate `durableSize` and `IsExact()` watermark (M1), upgraded `torchwood/mpt` for variable-length canonical keys and two-sided prefix proofs (`ProvePrefix`/`VerifyPrefix`) (M2), and decoupled `internal/mpt` from `internal/tree` (M3). |
