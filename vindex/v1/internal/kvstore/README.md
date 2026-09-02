# Sub-Design: KV Storage (Inverted Chunk Storage Engine)

This document defines the storage architecture, load-bearing invariants, verified performance optimizations, optional abstractions, and retired design branches for the **KV Storage Engine** (`vindex/v1/internal/kvstore`).

---

## 1. Core Load-Bearing Invariants

### 1.1 Inverted Chunk Key Encoding
Storage keys use a 1-byte domain separation prefix, 32-byte key hash, and an 8-byte big-endian bitwise-inverted chunk number:
```text
Key = 'c' (1B) + KeyHash (32B) + BigEndian(^chunkNum) (8B)
```
where `^chunkNum = math.MaxUint64 - chunkNum`.
- **Domain Separation**: The `'c'` prefix isolates index records from metadata keys (`'m'`), allowing prefix Bloom filters to operate cleanly.
- **Bitwise Inversion**: Inverting `chunkNum` ensures that the newest active chunk sorts lexicographically *first* under the `'c' + KeyHash` prefix.

### 1.2 Delimitless Binary Chunk Schema
Every chunk record uses a self-contained binary layout embedding cumulative RFC 6962 compact ranges and relative index offsets:
| Field | Byte Offset | Size | Description |
| :--- | :--- | :--- | :--- |
| `CoveredSize` | `0 .. 7` | 8B uint64 (Big-Endian) | Cumulative leaf count committed in this chunk's compact range. |
| `Hashes` | `8 .. 8 + 32*OnesCount(CoveredSize)` | Variable (`32B * bits.OnesCount64(CoveredSize)`) | Raw concatenation of RFC 6962 compact range hashes. |
| `RelativeIndices` | `offset .. end` | Variable (`2B * count`) | Relative leaf offsets stored as `uint16(index % 65536)`. |
- **Delimitless Slicing**: The number of 32-byte compact hashes is strictly `bits.OnesCount64(CoveredSize)`. The boundary is calculated exactly without length headers:
  ```go
  offset := 8 + 32 * bits.OnesCount64(rec.CoveredSize)
  ```
- **Chunk Capacity**: Fixed at 65,536 (2^16) leaf index capacity. Indices are stored as `uint16(index % 65536)`.

### 1.3 Synchronous Write Persistence Barrier
`KVIndexer.IndexBatch` enforces a strict persistence barrier:
- When writing a batch that reaches or exceeds the target checkpoint size (`newKVSize == targetSize`), the batch is committed with `pebble.Sync`.
- Downstream Output Log publication and witness network RPCs **MUST NOT begin** until `store.WriteBatch` returns successfully.
- Preserves the **Universal Crash Invariant**: `m_kv_size >= Output_Size` under all crash, kill, and power-loss conditions.

### 1.4 Read-Only Sub-Root Recovery Primitive (`GetSubRoot`)
`GetSubRoot(keyHash, maxInputLogSize)` reconstructs the mini-log Merkle root for `keyHash` up to `maxInputLogSize`:
- Performs an inverted seek: `iter.SeekGE('c' + keyHash + ^targetChunk)`.
- If the current chunk equals `targetChunk`, folds only relative indices `< maxInputLogSize`.
- If the current chunk is `< targetChunk`, folds all relative indices in that chunk.
- If the key is absent or was first observed after `maxInputLogSize`, returns `[32]byte{}` (empty tree root).
- Operates with **zero storage mutations or disk writes**, serving as the primary primitive during Zero-WAL startup recovery.

### 1.5 Replay Idempotency & Entry Filtering
- `IndexStore` maintains an in-memory watermark `persistedKVSize` initialized from Pebble metadata `m_kv_size`.
- Entries with `index < persistedKVSize` are skipped, preventing duplicate leaf index appends.
- If an entire batch satisfies `batchEnd <= persistedKVSize`, disk I/O (`pebble.WriteBatch` and `pebble.Sync`) is completely bypassed, and modified sub-roots are computed via `GetSubRoot(keyHash, batchEnd)`.

---

## 2. Verified Performance Optimizations

### 2.1 33-Byte Prefix Bloom Filters & O(1) Active Chunk Discovery
The storage engine configures Pebble with an `InvertedPrefixChunkComparer` (33-byte prefix: `'c' + KeyHash`) and 10-bit table/block Bloom filters:
- **New Keys**: A single `iter.SeekPrefixGE('c' + KeyHash)` checks the Bloom filter and discovers key absence with **zero disk reads**.
- **Active Chunk Discovery**: Because chunk numbers are bitwise-inverted (`^chunkNum`), `SeekPrefixGE` lands directly on the latest active chunk in a single O(1) probe, avoiding forward scans through older historical chunks (eliminating up to 7.5x append latency penalties on deep keys).

### 2.2 16-Bit Relative Index Encoding (75% Storage Savings)
Within each 65,536-leaf chunk, indices are stored as 2-byte offsets `uint16(index % 65536)`:
- Saves 75% disk space compared to 8-byte `uint64` values.
- Bounds maximum chunk size to ~131 KB (65,536 * 2B + compact range), fitting comfortably within storage block caches.

### 2.3 Two-Generational Active Chunk Cache
`KVIndexer` maintains a bounded 2-generational cache (`currentCache` and `previousCache`, capped at 32,768 entries):
- Retains hot chunk records in memory across sequential batches.
- Eliminates 90%+ of Pebble read block I/O on active chunks without coarse full-cache invalidation freezes.

### 2.4 Lexicographical Key Sorting for Sequential LSM Writes
Batch keys are sorted with `bytes.Compare` before executing `SeekPrefixGE` and inserting into Pebble `WriteBatch`, maximizing sequential SSTable write performance.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Black-Box Storage Encapsulation
The `IndexStore` interface completely encapsulates Pebble:
- No external subsystem (`coordinator`, `server`, `ingest`, `tree`) imports Pebble or accesses low-level iterators.
- Alternative storage engines (e.g., SQLite, DuckDB, bbolt, or cloud KV) can be substituted with zero changes to other packages.

### 3.2 Schema Evolution & Metadata Management
Database-wide format versions are tracked in the metadata namespace (key `m_schema_version`), enabling schema compatibility checks on startup without per-row versioning bytes.

### 3.3 Resource Bounds & Tuned Compaction
- Default 2 GB Pebble block cache + 64 MB write buffer (`MemTableSize = 64 << 20`) with `MaxConcurrentCompactions = 4`, eliminating write stalls during sustained high-throughput ingestion.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode Retirement in KVStore
- **What Was Proposed & Investigated**:
  During initial design, Backfill Mode was evaluated to determine if bulk ingestion into Pebble could be optimized by running storage writes without intermediate Output Log publishing or witness cosignatures.
- **Why It Was Investigated**:
  Hypothesized that isolating storage writes during bulk sync would maximize Pebble ingestion bandwidth.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  1. **Storage Layer Was Already Fully Decoupled**: `KVIndexer.IndexBatch` operated identically under Normal Mode and Backfill Mode. The storage engine itself was never aware of whether the caller was in Normal or Backfill mode.
  2. **Zero Ingestion Advantage**: On real Go SumDB logs, Normal Serving Mode achieved **90,797.2 leaves/sec** vs. Backfill's **49,063.6 leaves/sec** (Normal was 85.1% faster!). Backfill's per-batch in-memory MPT mutations throttled pipeline throughput.
  3. **100% Read Starvation**: Backfill Mode shut down the HTTP read server, causing 0% query availability during the entire bulk ingest window.
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode provided zero storage performance benefit and created dead branches across the codebase. It was permanently pruned in Milestone M3.

### 4.2 Intermediate Write-Ahead Log in Pebble ('w' Prefix & WalReaper)
- Staged records under transient `'w'` prefix before an async `WalReaper` converted them to `'c'` chunks.
- Caused double-write disk amplification, massive LSM compaction churn, and P99 read latency spikes (up to 1,214 ms).
- Replaced by Zero-WAL direct inverted chunk indexing (+24.7% throughput, ~99% P99 tail reduction).

### 4.3 Natural Ascending Chunk Order (0, 1, ..., N)
- Storing chunks in natural ascending order caused `SeekPrefixGE('c' + KeyHash)` to land on Chunk 0.
- Reaching active chunk N required scanning forward through all sealed historical chunks (0 .. N-1), degrading append throughput by up to 7.5x on deep keys.
- Replaced by bitwise inverted chunk keys (`^chunkNum`).

### 4.4 Storing Full Merkle Trees per Key in Storage
- Persisting all internal Merkle tree branch hashes for every key caused > 4x storage amplification.
- Replaced by on-the-fly compact range accumulation from 64K chunk boundaries.
