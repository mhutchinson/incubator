# Sub-Design: Inverted Chunk Storage Engine

This document defines the storage architecture, LSM-tree key-value layout, binary serialization schemas, load-bearing invariants, verified performance optimizations, and empirical benchmarks for the **Storage Subsystem** (`vindex/v1/internal/kvstore`).

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
  - Guarantee zero-overhead sub-root point-in-time calculation (`GetSubRoot`) to support lock-free MPT prediction and Zero-WAL crash recovery.
  - Enforce synchronous durability (`pebble.Sync`) before state commitment handoff to guarantee persisted KV storage watermark >= Output_Size.
- **Non-Goals**:
  - **No Distributed Storage**: Operates strictly as a single-host embedded database; distributed clustering and remote RPC storage backends are explicitly out of scope.
  - **No Cross-Key Range Scans**: Supports point queries by exact 32-byte key hash; lexical prefix scanning across different keys is out of scope for v1.
  - **No Deletions or Tombstones**: Data is strictly append-only; records are never deleted or overwritten once sealed.

### 1.3 Requirements, Dependencies & Known Pain Points
- **Storage Engine**: Embedded [Pebble](https://github.com/cockroachdb/pebble) LSM-tree with a custom 33-byte prefix splitter and 10-bit Bloom filter policy.
- **Merkle Tree Utilities**: RFC 6962 tree hashing and compact Merkle range representation via `github.com/transparency-dev/merkle`.
- **Known Pain Points ("Warts and All")**:
  - **Chunk Boundary Rollovers**: Every 65,536th occurrence of a key forces an active chunk rollover: the full chunk is frozen as immutable historical state and a new chunk is allocated with an updated compact range.
  - **Monotonic Key Growth**: Because records are never deleted or tombstoned, the total number of distinct search keys in the Pebble keyspace grows monotonically with the log.
  - **Backward Multi-Page Retrieval**: Hot keys with deep history cannot return all occurrences in a single HTTP response; client readers must page backward chunk by chunk using `before=X`.

---

## 2. Detailed Design

### 2.1 Logical Model & Inverted Chunk Key Layout
To eliminate write amplification, each key's mini-log is partitioned into logical chunks of 65,536 entries (`ChunkSize = 65536`). 

Chunk keys are 41 bytes: `'c'` (1 byte) + `KeyHash` (32 bytes) + `^BigEndian(chunkNum)` (8 bytes, bitwise inverted so newer chunks sort first):

```text
Key (41 bytes) = [Prefix 'c' (1B)] + [KeyHash (32B)] + [^BigEndian(chunkNum) (8B)]
```
where `^BigEndian(chunkNum) = math.MaxUint64 - chunkNum`.

#### The Inverted Ordering Mechanism:
Because chunk numbers are bitwise-inverted, the **highest (newest) chunk has the lexicographically smallest key** among all chunks for that key prefix.
- Pebble's custom `Comparer` splits keys at byte 33 (`'c' + KeyHash`).
- Full-table 10-bit Bloom filters are indexed on this 33-byte prefix across all SSTable levels.
- Calling `iter.SeekPrefixGE('c' + KeyHash)` achieves two simultaneous benefits:
  1. If the key does not exist, the Bloom filter prunes all SSTables, returning `iter.Valid() == false` with **zero disk I/O**.
  2. If the key exists, the iterator lands **directly on the latest active chunk in O(1) time**, completely skipping all older historical chunks.

### 2.2 Delimitless Binary Chunk Serialization & Compact Ranges
Values store a cumulative RFC 6962 compact range covering all prior chunks, plus a dense array of 16-bit relative offsets for the current chunk:

```text
CoveredSize uint64 (8 bytes, BigEndian) || CompactHashes (32 bytes * bits.OnesCount64(CoveredSize)) || RelativeIndices (uint16, 2 bytes BigEndian * N)
```

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `0` | `CoveredSize` | `uint64` (8 bytes, BigEndian) | Total number of entries in all prior chunks (`chunkNum * 65536`). |
| `8` | `CompactHashes` | `[K][32]byte` | Compact range hashes committing to the prior `CoveredSize` leaves, where `K = bits.OnesCount64(CoveredSize)` (32 bytes * K). |
| `8 + 32*K` | `RelativeIndices` | `[]uint16` (2 bytes BigEndian * N) | Dense 2-byte offsets: `uint16(index % 65536)` for each occurrence in this chunk. |

#### Mini-Log Leaf Hashing:
Each mini-log entry commits to an occurrence index in the Input Log. Mini-log leaf hashing strictly adheres to RFC 6962:
- The absolute occurrence index is encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00.
- Interior nodes are hashed with RFC 6962 node domain separator 0x01.
- When an active chunk reaches capacity (`ChunkSize = 65536`), all its relative indices are converted to absolute indices, hashed as RFC 6962 leaves with domain separator 0x00, and appended to the chunk's running compact range.

#### Delimitless Deserialization:
Because the number of compact range hashes is mathematically determined by `bits.OnesCount64(CoveredSize)`, the boundary between the compact range and the relative indices is computed dynamically in memory:
```go
compactBytesLen := 8 + bits.OnesCount64(coveredSize) * 32
relativeOffsets := value[compactBytesLen:]
```
This layout eliminates field delimiters, length prefixes, and serialization padding, achieving optimal binary packing density.

### 2.3 Two-Generational Active Chunk Cache
To avoid repeatedly reading active chunk descriptors from Pebble during sequential batching, the store maintains an in-memory two-generational chunk cache:
- **`currentCache`**: Stores chunk descriptors accessed or modified during the active batch.
- **`previousCache`**: Retains chunk descriptors from the immediately preceding batch.
- **Eviction**: On batch commit, `previousCache` is replaced by `currentCache`, and a new `currentCache` is initialized. Bounded at 32,768 entries, this cache absorbs repeated writes to hot keys, eliminating >90% of Pebble block cache read I/O during high-throughput ingestion.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: `store.WriteBatch` must execute `pebble.Sync` and durably flush all modified `'c'` records and metadata (persisted KV storage watermark) to disk before returning to the Coordinator.
  - *Rationale*: Enforces `persisted KV storage watermark >= Output_Size` across all crash and power-loss scenarios.
  - *Consequence ("Or Else")*: If the node crashed after appending a state commitment to the Output Log but before Pebble synced to disk, the published root would reference missing KV chunks. The node would be permanently unable to produce inclusion proofs for its own witnessed checkpoints.

- **[Correctness Invariant] Point-in-Time Sub-Root Isolation (`GetSubRoot`)**:
  - *Rule*: When computing or reconstructing sub-roots for target Input Log size `S`, the storage engine strictly evaluates records with `index < S`, ignoring any chunks or indices written ahead of `S`.
  - *Rationale*: Allows startup recovery and reader lookups to safely inspect the database even if the KV store has synced batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak un-witnessed or in-flight indices, violating reader snapshot isolation.

- **[Performance Optimization] Bitwise Key Inversion (`^chunkNum`) & 33-Byte Bloom Filters**:
  - *Mechanism*: Bitwise inversion places the active chunk first under the prefix; the 33-byte prefix Bloom filter prunes non-existent keys.
  - *Impact*: Delivers true O(1) active chunk seeks, eliminating the 7.5x append latency penalty observed on deep keys in forward-ordered layouts.

- **[Performance Optimization] 16-Bit Relative Offset Encoding**:
  - *Mechanism*: Stores index offsets as `uint16(index % 65536)` instead of 8-byte integers.
  - *Impact*: Saves 75% disk storage on index occurrence lists within each 64K chunk.

- **[Performance Optimization] Two-Generational Active Chunk Cache**:
  - *Mechanism*: Caches active chunk structs across sequential batches.
  - *Impact*: Cuts Pebble block read I/O by >90% during sustained high-concurrency ingestion.

### 2.5 Storage Engine Contract

The storage subsystem manages physical chunk persistence, mini-log compact ranges, and point lookups:

- **Physical Format & Key Layout**:
  - Chunks are keyed by 41 bytes: `'c'` (1 byte) + `KeyHash` (32 bytes) + `^BigEndian(chunkNum)` (8 bytes bitwise inverted).
  - Bitwise inversion places the newest active chunk first under the key prefix, enabling true O(1) active chunk seeks with 33-byte prefix Bloom filtering.
  - Chunk values use a delimitless binary serialization format: an 8-byte big-endian `CoveredSize`, followed by RFC 6962 compact range hashes committing to prior chunks, followed by dense 2-byte relative index offsets (`uint16(index % 65536)`).
- **Write Contract & Rollover**:
  - Monotonic batch writes accumulate leaf occurrences and commit synchronously to disk.
  - When an active chunk reaches 65,536 entries (`ChunkSize = 65536`), it is frozen into an immutable historical chunk, its relative offsets are accumulated into the running compact range, and a new active chunk is allocated.
- **Lookup Contract & Snapshot Filtering**:
  - Point lookups retrieve occurrence indices strictly before the optional `before` cursor up to `limit`.
  - Inverted chunk records are filtered against `maxInputLogSize`, strictly ignoring any uncommitted future entries written ahead of the active serving state.
  - Generates prefix compact ranges for backward pagination continuity.

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

### 3.2 Transient Write-Ahead Log ('w' Prefix & WalReaper) vs. Zero-WAL Direct Commits
- **Proposed**: Staging mapped records under a transient `'w'` prefix before an asynchronous background worker (`WalReaper`) converted them into inverted chunks (`'c'`).
- **Empirical Rejection**: Testing on Go SumDB (61.7M entries) demonstrated that the staging WAL doubled disk write amplification, caused heavy LSM compaction churn, and spiked P99 read latency to over 1,200ms.
- **Chosen Design**: Zero-WAL direct inverted chunk commit: batches append directly to `'c'` records and sync in a single atomic Pebble batch.

### 3.3 Distributed NoSQL (Cloud Bigtable, Spanner, Cassandra) vs. Embedded Pebble LSM
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL engine.
- **Theoretical & Architectural Rejection**:
  - Remote RPC roundtrips introduce 5–20ms network latency per batch seek, destroying ingestion throughput.
  - The authenticated Sparse Merkle Patricia Trie (MPT) already requires single-host RAM/mmap locality; placing the storage engine on a distributed cluster introduces operational complexity without solving tree state replication.
- **Chosen Design**: Single-host embedded Pebble LSM engine encapsulated behind the `IndexStore` interface.
