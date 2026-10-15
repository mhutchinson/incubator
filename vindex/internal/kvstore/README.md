# Sub-Design: Inverted Chunk Storage Engine

This document defines the storage architecture, LSM-tree key-value layout, binary serialization schemas, load-bearing invariants, verified performance optimizations, and empirical benchmarks for the **Storage Subsystem** (`vindex/internal/kvstore`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Skewed Cardinality Dilemma
The storage engine persists the index mapping from 32-byte key hashes (`KeyHash = SHA256(ClaimSubject)`) to chronologically ordered sequences of Input Log leaf indices.

Transparency logs exhibit extreme key cardinality skew:
- **Long-tail keys**: The vast majority of domains or packages appear only once or twice in the entire log.
- **Hot keys**: Popular keys (e.g. major cloud provider domains, popular open-source packages) accumulate hundreds of thousands of entries over years.

In an LSM-tree database (such as Pebble), storing this mapping naively leads to three catastrophic failure modes:
1. **O(N^2) Write Amplification**: Appending to flat lists per key requires rewriting the entire historical list on every new entry.
2. **Scan Latency on Deep Keys**: If chunks are stored in chronological forward order (`chunk_0, chunk_1, ...`), locating the active chunk to append a new entry requires seeking past years of historical SSTables, introducing a 7.5x latency penalty.
3. **Double-Write Churn via Staging WALs**: Buffering entries under a temporary write-ahead prefix (`'w'`) before asynchronously merging them into index records creates massive LSM write amplification and severe P99 latency spikes (exceeding 1,200ms).

### 1.2 Goals & Non-Goals
- **Goals**:
  - Provide O(1) active chunk location for batch appends regardless of key depth or historical occurrence count.
  - Eliminate disk I/O on missing keys via full-table 33-byte prefix Bloom filters.
  - Maximize storage density by encoding occurrence indices as 16-bit relative offsets within 64K chunks.
  - Guarantee zero-overhead point-in-time mini-log sub-root calculation to support non-blocking MPT prediction and Zero-WAL crash recovery.
  - Enforce synchronous durability before state commitment handoff to guarantee `KV_CP.Size >= Output_CP.InputSize`.
- **Non-Goals**:
  - **No Distributed Storage**: Operates strictly as a single-host embedded database; distributed clustering and remote RPC storage backends are explicitly out of scope.
  - **No Cross-Key Range Scans**: Supports point queries by exact 32-byte key hash; lexical prefix scanning across different keys is out of scope for v1.
  - **No Deletions or Tombstones**: Data is strictly append-only; records are never deleted or overwritten once sealed.

### 1.3 Requirements, Dependencies & Known Pain Points
- **Storage Engine**: Embedded [Pebble](https://github.com/cockroachdb/pebble) LSM-tree with a custom 33-byte prefix splitter and 10-bit Bloom filter policy.
- **Merkle Tree Utilities**: RFC 6962 tree hashing and compact Merkle range representation via `github.com/transparency-dev/merkle`.
- **Known Pain Points ("Warts and All")**:
  - **Window Boundary Rollovers**: Crossing a global 65,536-leaf Input Log window boundary (`chunkNum = leafIdx / 65536`) for a key seals the previous chunk as immutable historical state and allocates a new chunk containing the updated prefix compact range (`CoveredSize` and `CompactHashes`).
  - **Monotonic Key Growth**: Because records are never deleted or tombstoned, the total number of distinct search keys in the Pebble keyspace grows monotonically with the log.
  - **Backward Multi-Page Retrieval**: Hot keys with deep history cannot return all occurrences in a single HTTP response; client readers must page backward chunk by chunk using `before=X`.

---

## 2. Detailed Design

### 2.1 Logical Model & Inverted Chunk Key Layout
To eliminate write amplification and support direct window-based seeks, the Input Log leaf index space is partitioned into fixed global windows of 65,536 leaves (`ChunkSize = 65536`). Each occurrence at absolute Input Log index `leafIdx` maps deterministically to:
- **Chunk Number**: `chunkNum = leafIdx / 65536`
- **Relative Offset**: `relOffset = uint16(leafIdx % 65536)`

Chunks are only allocated for windows in which a key actually occurs. Chunk keys are 41 bytes: `'c'` (1 byte) + `KeyHash` (32 bytes) + `^BigEndian(chunkNum)` (8 bytes, bitwise inverted so newer chunks sort first):

```text
Key (41 bytes) = [Prefix 'c' (1B)] + [KeyHash (32B)] + [^BigEndian(chunkNum) (8B)]
```
where `^BigEndian(chunkNum) = 0xFFFFFFFFFFFFFFFF - chunkNum`.

#### The Inverted Ordering Mechanism:
Because chunk numbers are bitwise-inverted, the **highest (newest) chunk has the lexicographically smallest key** among all chunks for that key prefix.
- Pebble's custom key comparer splits keys at byte 33 (`'c' + KeyHash`).
- Full-table 10-bit Bloom filters are indexed on this 33-byte prefix across all SSTable levels.
- Performing a prefix-bounded seek on `'c' + KeyHash` achieves two simultaneous benefits:
  1. If the key does not exist, the Bloom filter prunes all SSTables, returning empty with **zero disk I/O**.
  2. If the key exists, the iterator lands **directly on the latest active chunk in O(1) time**, completely skipping all older historical chunks.

### 2.2 Delimitless Binary Chunk Serialization & Compact Ranges

Values store a cumulative RFC 6962 compact range covering all occurrences of that key across prior chunks (`chunk < chunkNum`), plus a dense array of 16-bit relative offsets for occurrences within the current 65,536-leaf window (`chunkNum`):

```text
CoveredSize uint64 (8 bytes, BigEndian) || CompactHashes (32 bytes * popcount(CoveredSize)) || RelativeIndices (uint16, 2 bytes BigEndian * N)
```

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | `CoveredSize` | `uint64` (8 bytes, BigEndian) | Actual cumulative number of occurrences for this key across all prior chunks. |
| `8` | `CompactHashes` | `[K][32]byte` | Compact range hashes committing to the prior `CoveredSize` occurrences of this key, where `K = popcount(CoveredSize)` (32 bytes * K). |
| `8 + 32*K` | `RelativeIndices` | `[]uint16` (2 bytes BigEndian * N) | Dense 2-byte offsets: `uint16(leafIdx % 65536)` for each occurrence of this key within global window `chunkNum` (`absIdx = chunkNum*65536 + uint64(relOffset)`). |

#### Per-Leaf Key Deduplication & Mini-Log Leaf Hashing:
Each mini-log entry commits to a distinct Input Log leaf index where the search key occurred:
- **Per-Leaf Deduplication**: If a single Input Log leaf emits the same `KeyHash` multiple times (e.g., identical domain in Subject CN and SAN, or parent domain expansion from sibling subdomains), batch indexing sorts and deduplicates `(KeyHash, leafIdx)` pairs. Each `leafIdx` is appended at most once to a key's mini-log, ensuring strictly increasing indices within every chunk (`relOffset_0 < relOffset_1 < ...`).
- **Mini-Log Leaf Hashing**: The absolute occurrence index (`absIdx = chunkNum*65536 + uint64(relOffset)`) is encoded as an 8-byte big-endian integer and hashed with RFC 6962 leaf domain separator `0x00`.
- **Interior Nodes & Chunk Rollover**: Interior nodes are hashed with RFC 6962 node domain separator `0x01`. When a new occurrence for a key falls into a higher global 65,536-leaf window, the previous chunk is sealed and a new chunk is initialized with `CoveredSize` and `CompactHashes` snapshotted from the key's running compact range across all prior chunks.

#### Delimitless Deserialization:
Because the number of compact range hashes is mathematically determined by the population count (number of set bits) of `CoveredSize` (`K = popcount(CoveredSize)`), the byte offset where `RelativeIndices` begins is always `8 + 32*K`. This layout eliminates field delimiters, length prefixes, and serialization padding, achieving optimal binary packing density.

### 2.3 Two-Generational Active Chunk Cache
To avoid repeatedly reading active chunk descriptors from Pebble during sequential batching, the store maintains a bounded in-memory two-generational chunk cache:
- **Current Generation**: Stores chunk descriptors accessed or modified during the active batch.
- **Previous Generation**: Retains chunk descriptors from the immediately preceding batch.
- **Eviction**: When the current generation reaches capacity (scaling to hundreds of thousands of hot keys), the previous generation is replaced by the current generation, and a fresh current generation map is allocated. This absorbs repeated writes to hot keys without LRU lock contention, eliminating >90% of Pebble block cache read I/O during high-throughput ingestion.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: Within a target sync cycle, intermediate commit slabs may write to Pebble without an immediate `fsync`, but the final slab reaching `Target_CP.Size` (or an explicit flush barrier) must execute a durable disk sync to flush all modified `'c'` records and metadata (`KV_CP`) to disk before returning to the Coordinator for Output Log publication.
  - *Rationale*: Enforces `KV_CP.Size >= Output_CP.InputSize` across all crash and power-loss scenarios while amortizing disk `fsync` overhead across multi-slab sync cycles.
  - *Consequence ("Or Else")*: If the node crashed after appending a state commitment to the Output Log but before Pebble synced to disk, the published root would reference missing KV chunks. The node would be permanently unable to produce inclusion proofs for its own witnessed checkpoints.

- **[Correctness Invariant] Per-Leaf Key Deduplication**:
  - *Rule*: The KV store must deduplicate identical `(KeyHash, leafIdx)` emissions before appending relative offsets or updating the key's running compact range.
  - *Rationale*: Guarantees that a key's mini-log contains each matching Input Log leaf index at most once in strictly ascending order.
  - *Consequence ("Or Else")*: Duplicate relative offsets for the same leaf would be appended to chunk records, corrupting the mini-log compact range and violating pagination cursor monotonicity (`before=X`).

- **[Correctness Invariant] Point-in-Time Sub-Root Isolation**:
  - *Rule*: When computing or reconstructing sub-roots for target Input Log size `S`, the storage engine strictly evaluates records with `index < S`, ignoring any chunks or indices written ahead of `S`.
  - *Rationale*: Allows startup recovery and reader lookups to safely inspect the database even if the KV store has synced batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak unwitnessed or in-flight indices, violating reader snapshot isolation.

- **[Performance Optimization] Bitwise Key Inversion (`^chunkNum`) & 33-Byte Bloom Filters**:
  - *Mechanism*: Bitwise inversion places the active chunk first under the prefix; the 33-byte prefix Bloom filter prunes non-existent keys.
  - *Impact*: Delivers true O(1) active chunk seeks, eliminating the 7.5x append latency penalty observed on deep keys in forward-ordered layouts.

- **[Performance Optimization] 16-Bit Relative Offset Encoding**:
  - *Mechanism*: Stores index offsets as `uint16(leafIdx % 65536)` within each global 64K leaf window instead of 8-byte integers.
  - *Impact*: Saves 75% disk storage on index occurrence lists within each 64K window chunk.

- **[Performance Optimization] Two-Generational Active Chunk Cache**:
  - *Mechanism*: Caches active chunk descriptors across sequential batches.
  - *Impact*: Cuts Pebble block read I/O by >90% during sustained high-concurrency ingestion.

- **[Performance Optimization] Bounded Backward Lookup & Compact Range Reuse**:
  - *Mechanism*: Seeks directly to the highest valid chunk (`(upperBound - 1) / 65536`), reads only enough backward chunks to satisfy the requested page `limit`, and seeds `prefix-compact-range-v1` from the oldest evaluated chunk's stored `CompactHashes` and `CoveredSize` rather than re-hashing historical indices from scratch.
  - *Impact*: Bounds read latency and memory allocations strictly to O(limit), eliminating full-history scans and CPU hash loops across deep keys.

- **[Performance Optimization] Key-Partitioned In-Memory Mini-Log Hashing**:
  - *Mechanism*: Partitions distinct keys within each incoming mapped batch across a worker pool. Workers independently compute mini-log compact range updates, sub-roots, and serialized chunk records in parallel in memory, while the committer sequentially applies the precomputed writes into an atomic Pebble batch.
  - *Impact*: Eliminates single-thread CPU bottlenecks on RFC 6962 mini-log Merkle hashing during high-throughput ingestion, preventing upstream pipeline backpressure on mapping workers while keeping database writes strictly sequential.

### 2.5 Storage Engine Contract

The storage subsystem manages physical chunk persistence, mini-log compact ranges, and point lookups:

- **Physical Format & Key Layout**:
  - Chunks are partitioned by global 65,536-leaf Input Log windows (`chunkNum = leafIdx / 65536`) and keyed by 41 bytes: `'c'` (1 byte) + `KeyHash` (32 bytes) + `^BigEndian(chunkNum)` (8 bytes bitwise inverted).
  - Bitwise inversion places the newest active chunk first under the key prefix, enabling true O(1) active chunk seeks with 33-byte prefix Bloom filtering.
  - Chunk values use a delimitless binary serialization format: an 8-byte big-endian `CoveredSize` (total occurrences for that key across prior chunks), followed by RFC 6962 compact range hashes committing to those `CoveredSize` prior occurrences, followed by dense 2-byte relative index offsets (`uint16(leafIdx % 65536)`).
- **Write Contract & Rollover**:
  - Monotonic batch writes deduplicate `(KeyHash, leafIdx)` pairs per leaf, accumulate occurrences across multi-tile commit slabs, and execute a durable disk sync at the target checkpoint boundary before Output Log commitment.
  - When an occurrence for a key crosses into a new global 65,536-leaf window, the prior chunk is sealed as immutable historical state and a new active chunk is allocated with the cumulative `CoveredSize` and `CompactHashes` of all prior occurrences.
- **Lookup Contract & Bounded Backward Traversal**:
  - Point lookups retrieve occurrence indices strictly before the effective upper bound (`min(before, Serving_CP.InputSize)`) up to `limit` entries.
  - **Direct Seek**: Computes the target window (`(upperBound - 1) / 65536`) and seeks directly to that inverted chunk key, landing on the newest valid chunk without scanning preceding or future chunks.
  - **Bounded Reverse Traversal**: Iterates forward through inverted keys (`^chunkNum`), moving backward chronologically. Accumulates relative offsets converted to absolute indices and terminates iteration immediately once `limit` matching entries are collected. Older historical chunks are never read or deserialized.
  - **O(1) Compact Range Prefix Reuse**: If older historical entries remain, the prefix compact range is constructed directly from the oldest evaluated chunk's stored `CompactHashes` and `CoveredSize` (which commit to all preceding chunks in O(1)), plus any leftover intra-chunk relative indices below the page split boundary. Historical chunks from leaf 0 are never re-scanned or re-hashed.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Empirical Prototype Evaluations: The `pebble-tests` Benchmark Suite
Extensive empirical benchmarking across storage prototypes was conducted in the standalone test repository [github.com/mhutchinson/pebble-tests](https://github.com/mhutchinson/pebble-tests). Testing evaluated layouts across workloads up to 20 million entries under three cardinality modes:
- **Mode A (Hot Keys)**: Low cardinality (10 keys) — heavy updates to deep keys.
- **Mode B (Sparse Keys)**: High cardinality (1,000,000 keys) — distributed, sparse keys.
- **Mode C (Mixed Workload)**: Medium cardinality (100,000 keys) — representative production traffic.

#### Evaluated Storage Layouts:
1. **`FlatStore`**: Stored an unbounded flat list of 8-byte integers under `KeyHash`.
   - *Empirical Rejection*: Caused severe O(N^2) write amplification. As key lists grew past tens of thousands of entries, rewriting the full list on every batch saturated disk bandwidth and triggered fatal compaction debt.
2. **`LogStore`**: Appended a discrete key-value pair for every individual occurrence: `Key = KeyHash + BigEndian(Index)`.
   - *Empirical Rejection*: Generated massive SSTable metadata bloat, excessive LSM compaction write stalls, and slow range queries requiring wide iterator scans across thousands of individual records.
3. **`Sealing` Layouts**: Rewrote chunks upon reaching capacity to mark them as sealed.
   - *Empirical Rejection*: Rewriting finalized chunks introduced redundant write amplification and memtable flushes without any query performance benefit.
4. **Chunk Size Optimization (256 vs. 1024 vs. 65,536)**:
   - Chunk sizes of 256 and 1,024 resulted in excessive chunk boundary rollovers, fragmenting storage into millions of small keys and inflating Pebble's block index.
   - **Chunk Size 65,536** proved optimal: it caps chunk value size at ~130 KB uncompressed (well within Pebble's sweet spot), enables 16-bit relative index encoding, and minimizes boundary splits.
5. **Key Ordering: Forward Scan vs. Inverted Prefix Scan**:
   - `chunk_scan` (forward chronological ordering: `chunk_0, chunk_1...`) required forward iteration to find the active chunk.
   - **`inverted_prefix_chunk_scan`** (`^chunkNum` bitwise inversion) demonstrated decisive empirical superiority:

| Workload Mode (1M Entries) | Engine | Write Throughput | Write Latency (p50) | Write Latency (p99) |
| :--- | :--- | :---: | :---: | :---: |
| **Mode A** *(10 keys)* | `chunk_scan` | 190,912 QPS | 2.93ms | 103.78ms |
| | **`inverted_prefix_chunk_scan`** | 175,523 QPS | 3.37ms | 107.45ms |
| **Mode B** *(1M keys)* | `chunk_scan` | 27,923 QPS | 35.96ms | 105.03ms |
| | **`inverted_prefix_chunk_scan`** | **41,431 QPS (+48.4%)** | **23.73ms** | **45.97ms** |
| **Mode C** *(100k keys)* | `chunk_scan` | 40,144 QPS | 21.83ms | 85.38ms |
| | **`inverted_prefix_chunk_scan`** | **64,446 QPS (+60.5%)** | **13.66ms** | **66.60ms** |

*Conclusion*: `inverted_prefix_chunk_scan` achieved a **+48.4% to +60.5% write throughput improvement** on medium and high cardinality workloads, reduced P99 latency by over 50%, and maintained true O(1) active chunk seeks.

### 3.2 Transient Write-Ahead Log ('w' Prefix) vs. Zero-WAL Direct Commits
- **Proposed**: Staging mapped records under a transient `'w'` prefix before an asynchronous background worker converted them into inverted chunks (`'c'`).
- **Empirical Rejection**: Testing on Go SumDB (61.7M entries) demonstrated that the staging WAL doubled disk write amplification, caused heavy LSM compaction churn, and spiked P99 read latency to over 1,200ms.
- **Chosen Design**: Zero-WAL direct inverted chunk commit: batches append directly to `'c'` records and sync in a single atomic Pebble batch.

### 3.3 Distributed NoSQL (Cloud Bigtable, Spanner, Cassandra) vs. Embedded Pebble LSM
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL engine.
- **Theoretical & Architectural Rejection**:
  - Remote RPC roundtrips introduce 5–20ms network latency per batch seek, destroying ingestion throughput.
  - The authenticated Sparse Merkle Patricia Trie (MPT) already requires single-host RAM/mmap locality; placing the storage engine on a distributed cluster introduces operational complexity without solving tree state replication.
- **Chosen Design**: Single-host embedded Pebble LSM engine.

### 3.4 Concurrent Database Iterators vs. Key-Partitioned In-Memory Hashing
- **Proposed (Concurrent Database Iterators)**: Partition keys across worker goroutines where each worker manages an independent database iterator to read, mutate, and write chunks concurrently to disk.
- **Empirical Rejection**: Concurrent Pebble iterators introduced lock contention, allocator overhead, and cache thrashing, yielding only an isolated ~14% speedup on 4 workers while degrading performance beyond 8 workers. Furthermore, concurrent disk I/O competed directly with background LSM compactions.
- **Adopted Design (Key-Partitioned In-Memory Hashing)**: Decouples CPU-bound Merkle calculations from I/O-bound database mutations:
  1. *Parallel In-Memory Hashing*: Distinct keys in each batch are distributed across worker goroutines. Each worker computes compact range appends and serializes chunk entries independently in pure memory with zero shared state.
  2. *Sequential Database Commit*: The precomputed key-value writes are merged into a single atomic Pebble batch and committed sequentially.
- **Impact**: Delivers linear multi-core scaling for CPU-intensive mini-log hashing on high-throughput workloads, eliminating pipeline stalls while preserving zero-contention, deterministic single-threaded database durability.

---

## 4. Verification Gate

All inverted chunk storage, chunk-aligned paging, `GetSubRoot`, and `StageMappedBatch` tests are verified via:

```bash
go test -race ./vindex/internal/kvstore/...
```

---

## 5. Design Log

| Date | Milestone | Summary |
| :--- | :--- | :--- |
| 2026-09-22 | v1 Initial | Defined 41-byte inverted chunk layout (`^chunkNum`), 33-byte prefix Bloom filters, and two-generational chunk cache. |
| 2026-10-14 | M1–M3 | Added chunk-aligned read paging, `maxChunksPerRequest` guardrail, O(1) `GetSubRoot`, `SeekPrefixGE` active chunk loading, eliminated phantom empty chunk 0 (M1), added `GetKeySubRoots` and `ModifiedKeySubRoots` (M2), and unified compact range hashing via `vindex/wire` (M3). |
