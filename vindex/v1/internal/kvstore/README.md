# Sub-Design: KV Storage (Inverted Chunk Storage Engine)

## 1. Context & Logical Data Model

The **KV Storage Engine** (`vindex/v1/internal/kvstore`) provides an LSM-tree optimized storage layout in Pebble for verifiable index records.

### 1.1 Logical Data Model
The logical data model maps each 32-byte cryptographic search key hash to a chronologically ordered sequence of 64-bit Input Log leaf indices:

```text
KeyHash ([32]byte) -> []LeafIndex (uint64)
```

To achieve bounded read latency, compact binary encoding, and O(1) active appends, this unbounded sequence is partitioned into fixed **64K (65,536) leaf index chunks**:
- **Chunk Numbering**: `chunkNum = index / 65536`.
- **Relative Index Encoding**: Within each chunk, indices are stored as 2-byte offsets `relIndex = uint16(index % 65536)`, saving 75% disk space compared to 8-byte integers.
- **Incremental Mini-Log Commitments**: Each chunk embeds an RFC 6962 `compact.Range` committing to all preceding historical occurrences (`0 .. chunkNum*65536 - 1`).

### 1.2 Core Storage Requirements
1. **Complete Black-Box Encapsulation**: Strictly encapsulates all storage engine details (Pebble DB, LSM Bloom filters, bitwise key inversion `^chunkNum`, chunk binary layouts, and Pebble iterators). External subsystems (`coordinator`, `server`, `ingest`, `tree`) interact exclusively through the abstract `IndexStore` domain interface, allowing alternative storage backends (e.g. SQLite, DuckDB, cloud-managed KV) to be substituted with zero changes to other packages.
2. **High-Throughput Batch Appends (`WriteBatch`)**: Ingest hundreds of thousands of key-index updates per second across sparse, highly distributed keys.
3. **Sub-Log Merkle Commitments (`GetSubRoot`)**: Dynamically compute or retrieve the Merkle root hash committing to all historical occurrences of a key in O(1) disk reads.
4. **Range Queries (`Lookup`)**: Efficiently fetch index sequence numbers and prefix compact ranges prior to an upper bound (`before`).

### 1.3 Non-Requirements & Out of Scope
- **No Deletions or Tombstones**: The index is strictly append-only. No deletion, tombstone marking, or rollback of index entries.
- **No Cross-Key Range Iteration**: Queries across multiple distinct key hashes (e.g., scanning all keys alphabetically) are not supported. Only prefix-bound seeks on a specific 32-byte key hash (`'c'` + KeyHash) are exposed.
- **No Concurrent Multi-Writer Access**: Storage writes are strictly serialized by the coordinator's sequential batch loop; concurrent write batches are out of scope.

---

## 2. Package API & Responsibilities

### Responsibilities
- **Black-Box Storage Abstraction**: Exposes the `IndexStore` domain interface; hides all SSTable, iterator, and key-inversion mechanics.
- **Pebble Database Management**: Configures the default Pebble backend with a custom 33-byte prefix splitter and 10-bit Bloom filter policy.
- **Inverted Chunk Key Encoding**: Formats keys with `'c'` prefix, 32-byte key hash, and bitwise-inverted chunk numbers (`^chunkNum`) to place the active chunk first.
- **Delimitless Binary Serialization**: Serializes and deserializes self-contained chunk records containing cumulative RFC 6962 compact ranges and relative index offsets.
- **Atomic Metadata Storage**: Provides atomic accessors for metadata keys (`'m'`: `m_target_checkpoint`, `m_kv_checkpoint`, `m_kv_size`).
- **Read-Only Sub-Root Recovery Primitive (`GetSubRoot`)**: Reads chunks to reconstruct the mini-log Merkle root without mutating the database.

### Go Interfaces & Types

```go
package kvstore

import (
	"crypto/sha256"

	"github.com/cockroachdb/pebble"
)

const (
	ChunkSize       uint64 = 65536
	PrefixChunkByte byte   = 'c'
	PrefixMetaByte  byte   = 'm'
)

var (
	KeyMetaTargetCheckpoint = []byte("m_target_checkpoint")
	KeyMetaKVCheckpoint     = []byte("m_kv_checkpoint")
	KeyMetaKVSize           = []byte("m_kv_size")
)

// LookupResult encapsulates range lookup matches and the prefix compact range.
type LookupResult struct {
	MatchedIndices  []uint64
	NextBefore      *uint64
	PrefixCoveredSz uint64
	PrefixHashes    [][sha256.Size]byte
}

// IndexStore defines the abstract, black-box storage contract for VIndex.
// External subsystems interact ONLY through this interface.
type IndexStore interface {
	// WriteBatch commits an ordered batch of mapped key entries and updates kv_size atomically.
	WriteBatch(entries map[[sha256.Size]byte][]uint64, targetSize uint64) error

	// Lookup retrieves matching leaf indices and prefix compact ranges for keyHash up to before.
	Lookup(keyHash [sha256.Size]byte, before *uint64, limit uint64, maxInputLogSize uint64) (*LookupResult, error)

	// GetSubRoot calculates the Merkle sub-root for keyHash up to maxInputLogSize without writes.
	GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error)

	// Metadata accessors for checkpoint and watermark persistence.
	GetMetadata(key []byte) ([]byte, error)
	SetMetadata(key, val []byte) error
	GetKVSize() (uint64, error)
	SetKVSize(size uint64) error

	// Lifecycle
	Close() error
}

// Open opens the default Pebble-backed storage engine implementing IndexStore.
func Open(dir string, opts *pebble.Options) (IndexStore, error)
```

---

## 3. Storage Layout & Pedagogical Inverted Key Space

### 3.1 Key Encoding

Keys use an explicit 1-byte domain separation prefix, 32-byte key hash, and an 8-byte big-endian bitwise-inverted chunk number:

```text
Key = 'c' (1B) + KeyHash (32B) + BigEndian(^chunkNum) (8B)
```

where `^chunkNum = math.MaxUint64 - chunkNum`.

- **Domain Separation**: The 1-byte `'c'` prefix isolates index records from metadata keys (`'m'`), allowing prefix filters to operate cleanly.
- **Logical Chunk Capacity**: `chunkSize = 65536`. Logical chunk number is `chunkNum = index / chunkSize`.
- **Prefix Comparer**: `Split(key)` returns 33 bytes (`'c' + KeyHash`). Pebble uses this prefix to construct table and block Bloom filters.

### 3.2 Pedagogical Inversion Explanation

The bitwise inversion of `chunkNum` is a core design choice solving the tension between LSM Bloom filters and chronological chunk appends:

1. **Goal (O(1) Active Chunk Discovery)**:
   During batch ingestion and write commits, the storage engine must find the active (latest) chunk for a given `KeyHash` with minimum I/O overhead.
2. **Problem with Natural Ascending Order (LSM Scan Penalty)**:
   - In LSM engines like Pebble, Bloom filters are built on key prefixes (`'c' + KeyHash`) and can **only be evaluated during forward prefix seeks (`SeekPrefixGE`)**. They cannot be evaluated during reverse seeks (`SeekLT`).
   - If chunk numbers were stored in natural ascending order (0, 1, ..., N), calling `SeekPrefixGE('c' + KeyHash)` would land on Chunk 0.
   - To reach the latest active chunk (N), the engine would be forced to scan forward through all older sealed chunks (0 ... N-1) via `iter.Next()`. On hot or deep keys with many chunks, this degrades append throughput by up to 7.5x and incurs severe read amplification.
3. **Inversion Solution (`^chunkNum = math.MaxUint64 - chunkNum`)**:
   - Bitwise inversion reverses key sorting order (`^N < ^0`), ensuring that the newest active chunk (N) is lexicographically the *first* key under the `'c' + KeyHash` prefix.
   - A single `SeekPrefixGE('c' + KeyHash)` evaluates the Bloom filter for zero-I/O skipping on new/absent keys **and lands directly on the active chunk in a single O(1) probe**.

---

## 4. Value Schema, Merkle Compact Ranges & Deserialization

### 4.1 Binary Value Layout

Every chunk record uses a uniform, self-contained binary schema:

```text
+-------------------------------------------------------------+------------------------------------+
|                Serialized compact.Range                     |      Relative Indices ([]uint16)   |
+------------------------------+------------------------------+------------------+-----------------+
|   Covered Size (8B uint64)   | Hashes (32B * OnesCount(Size))| relIndex 0 (2B)  | relIndex 1 (2B) |
+------------------------------+------------------------------+------------------+-----------------+
```

1. **Covered Size (`N_prior`)**: 8 bytes big-endian representing total elements committed across all preceding chunks (0 to `chunkNum-1`). For chunk 0, `N_prior = 0`.
2. **Compact Hashes**: Contiguous array of `bits.OnesCount64(N_prior)` SHA-256 hashes (32 bytes each).
3. **Relative Indices**: Continuous byte array of 2-byte unsigned integers representing `index % chunkSize`.

### 4.2 Merkle Compact Range Intuition Note
In RFC 6962 append-only Merkle trees, any tree of size N is uniquely decomposed into a set of perfect, complete binary subtrees whose leaf capacities are descending powers of two corresponding to the 1-bits in the binary representation of N.
- For example, a tree of size 11 (11 = 8 + 2 + 1 = 1011 in binary) is formed by exactly 3 perfect subtrees of sizes 8, 2, and 1.
- Therefore, the number of subtree root hashes required to represent the compact range of `CoveredSize` elements is strictly `bits.OnesCount64(CoveredSize)`.
- Because each SHA-256 hash is exactly 32 bytes, the compact range portion of the record occupies `8 + 32 * bits.OnesCount64(CoveredSize)` bytes, enabling exact delimitless boundary slicing without length headers.

### 4.3 Delimitless Parsing
The parser extracts the exact boundary without delimiters or extra length headers:
```go
offset := 8 + 32 * bits.OnesCount64(rec.CoveredSize)
```

### 4.4 Schema Evolution & Versioning
- **Zero Row-Level Overhead**: Individual chunk records maintain the compact delimitless binary layout without per-row version bytes.
- **Global Schema Versioning**: Database-wide format versions are tracked in the metadata namespace (e.g., key `m_schema_version`), ensuring forward compatibility checks at database open time without increasing storage footprint.

---

## 5. Write Path (`WriteBatch`)

```text
[Incoming MappedBatch]
          │
          ▼ (1. Filter entries: skip index < persistedKVSize)
          ▼ (2. Sort unique key hashes via bytes.Compare)
[Open Shared pebble.Iterator across batch]
          │
          ▼ (3. For each keyHash: iter.SeekPrefixGE('c' + keyHash))
   ┌──────┴──────────────────────────────────────────────────────┐
   ▼ (New Key: Bloom Filter says absent)                         ▼ (Existing Key: Lands on Active Chunk ^currChunkNum)
[Init Chunk 0 (^0)]                                           [Unmarshal ChunkRecord & reconstruct compact.Range]
   │                                                             │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
[Append Relative Index: uint16(index % chunkSize)]
                                  │
                                  ├──────────────────────────────┐
                                  ▼ (No Rollover)                ▼ (Chunk Boundary Exceeded: idx/chunkSize > currChunkNum)
                        [Stage Active Chunk]          [Seal Old Chunk: 'c' + keyHash + ^currChunkNum]
                                  │                   [Finalize compact.Range with relative indices]
                                  │                   [Allocate New Chunk: CoveredSize = finalizedRange.End()]
                                  │                              │
                                  └──────────────┬───────────────┘
                                                 ▼
                               [Compute Sub-Root via compact.Range or GetSubRoot]
                                                 │
                                                 ▼
                               [Commit Pebble Batch with Sync (if batchEnd > persistedKVSize)]
```

1. **Replay Filtering & Idempotency**:
   - `IndexStore` maintains an in-memory watermark `persistedKVSize` (initialized from Pebble metadata `m_kv_size` at startup).
   - In `WriteBatch`, entries with `entry.Index < persistedKVSize` are dropped/skipped to prevent duplicate appending in active chunks.
   - For keys whose entries in the batch are fully skipped, `WriteBatch` computes `modifiedSubRoots` via `GetSubRoot(keyHash, batchEnd)` without modifying chunk data on disk.
2. **Key Sorting**: Batch keys are sorted in lexicographical order to maximize LSM sequential write performance.
3. **O(1) Active Chunk Discovery**:
   - `iter.SeekPrefixGE(prefix)`.
   - **New Key**: Bloom filter prunes SSTable seeks with **zero disk reads**.
   - **Existing Key**: Lands directly on the latest active chunk in O(1) time.
4. **Append & Boundary Transition**:
   - Append `index % chunkSize` to `RelativeIndices`.
   - If crossing a boundary: write immutable sealed chunk, finalize `compact.Range`, and allocate a new chunk with `CoveredSize = finalizedRange.End()`.
5. **Atomic Synchronous Commit**:
   - If the entire batch satisfies `batchEnd <= persistedKVSize`, skip the `pebble.WriteBatch` and `pebble.Sync` disk persistence entirely.
   - If `batchEnd > persistedKVSize`, commit chunk updates and `KeyMetaKVSize` (`m_kv_size`) to Pebble in a single atomic batch with `pebble.Sync`, and advance `persistedKVSize = batchEnd`.

### 5.1 Synchronous Commit Barrier & Serialized Batch Execution
`WriteBatch` enforces a strict, blocking persistence barrier:
- **Durable Disk Fsync (`pebble.Sync`)**: `WriteBatch` blocks until all SSTable chunk records and the updated `m_kv_size` are durably fsync'd to disk.
- **Strict Sequencing**: Downstream Output Log publication (`publisher.PublishBatch`) and witness network RPCs **MUST NOT begin** until `WriteBatch` returns successfully.
- **Serialized Batch Execution Loop**:
  `store.WriteBatch(entries, S_k)` (blocking disk persistence) -> `publisher.PublishBatch(...)` (root prediction + Output Log append + witness cosignatures + in-memory MPT ratchet).
- **Crash Invariant Guarantee (`m_kv_size >= Output_Size`)**: Because storage persistence strictly precedes Output Log publication, the invariant `m_kv_size >= Output_Size` is preserved across all crash, kill, and power loss scenarios. Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted KV store chunks. If a crash occurs after `WriteBatch` but before Output Log append, `m_kv_size > S_OUT`; startup recovery safely ignores chunks beyond `S_OUT` via point-in-time `GetSubRoot(keyHash, S_OUT)` queries.

### 5.2 Idempotency Contract & Deterministic Replay
`WriteBatch` guarantees strict idempotency under deterministic replay:
- **Contract Assumption**: Writes are strictly deterministic (the same leaf indices always map to the identical key hashes across restarts and re-indexing runs).
- **In-Memory Watermark (`persistedKVSize`)**: At startup, `IndexStore` initializes `persistedKVSize` from the persisted `m_kv_size` metadata in Pebble.
- **Deduplication / Entry Filtering**: Any entry with `entry.Index < persistedKVSize` is filtered out before mutating active chunks, preventing duplicate leaf index appends.
- **Sub-Root Calculation on Replay**: For keys where all entries in the batch are skipped (already persisted in earlier chunks), `WriteBatch` uses `GetSubRoot(keyHash, batchEnd)` to reconstruct `modifiedSubRoots` without modifying underlying chunk data.
- **Persistence Bypass**: If `batchEnd <= persistedKVSize`, disk I/O (`pebble.WriteBatch` and `pebble.Sync`) is completely bypassed.
- **Watermark Advance**: When `batchEnd > persistedKVSize`, the batch commits to Pebble with `pebble.Sync` and ratchets `persistedKVSize = batchEnd`.

---

## 6. Read Path Execution Mechanics (`Lookup` & `GetSubRoot`)

```text
[Incoming Lookup(keyHash, before, limit, maxInputLogSize)]
                     │
                     ├─────────────────────────────────────────────────┐
                     ▼ (before == nil: Start at Newest)                ▼ (before != nil: Bounded Seek)
          [iter.SeekPrefixGE('c' + keyHash)]              [targetChunk = (*before - 1) / chunkSize]
                     │                                    [iter.SeekGE('c' + keyHash + ^targetChunk)]
                     └────────────────────────┬────────────────────────┘
                                              ▼
                             [Inverted Traversal via iter.Next()]
                             [Read chunks from newest to oldest]
                             [Collect up to limit indices < before and < maxInputLogSize]
                                              │
                                              ▼
                             [Oldest collected index defines next_before]
                             [Extract compact.Range for history 0..next_before-1]
                             [Reconstruct absolute indices: chunkNum*chunkSize + relOffset]
                                              │
                                              ▼
                             [Return LookupResult: MatchedIndices, NextBefore, PrefixHashes]

[Incoming GetSubRoot(keyHash, maxInputLogSize)]
                     │
                     ▼ (targetChunk = maxInputLogSize / chunkSize)
          [iter.SeekGE('c' + keyHash + ^targetChunk)]
                     │
         ┌───────────┴─────────────────────────────────────────┐
         ▼ (Key absent or chunk > targetChunk)                 ▼ (Found chunk with currChunk <= targetChunk)
   [Return [32]byte{} (Empty Tree)]                ┌───────────┴─────────────────────────────┐
                                                   ▼ (currChunk == targetChunk)              ▼ (currChunk < targetChunk)
                                         [Unmarshal ChunkRecord]                   [Unmarshal ChunkRecord]
                                         [Init compact.Range from base]            [Init compact.Range from base]
                                         [Fold ONLY relIndices < maxInputLogSize]  [Fold ALL relIndices in chunk]
                                                   │                                         │
                                                   └────────────────────┬────────────────────┘
                                                                        ▼
                                                       [Compute & Return MiniLogRoot]
```

### 6.1 Backward Range Lookup (`Lookup(keyHash, before, limit, maxInputLogSize)`)
1. **Target Chunk Resolution**: If `before == nil`, start from the latest active chunk via `SeekPrefixGE('c' + keyHash)`. If `before != nil`, compute `targetChunkNum = (*before - 1) / chunkSize` and seek `iter.SeekGE(EncodeChunkKey(keyHash, targetChunkNum))`.
2. **Inverted Traversal**: Scan chunks from newest to oldest (using `iter.Next()` across inverted chunk keys `^chunkNum`) collecting the newest `limit` indices strictly satisfying `idx < before` (when set) and `idx < maxInputLogSize`.
3. **Prefix Compact Range Extraction**: The oldest returned index defines `next_before`. Extract the compact range covering all prior historical occurrences (`0 .. next_before-1`) from the base chunk record and folded intermediate indices, returning it in `PrefixHashes` and `PrefixCoveredSz`.
4. **Absolute Index Reconstruction**: Reconstruct absolute indices (`chunkNum * chunkSize + relOffset`) in strictly monotonic ascending order.

### 6.2 Authenticated Sub-Root Query (`GetSubRoot(keyHash, maxInputLogSize)`)
1. Determine `targetChunkNum = maxInputLogSize / chunkSize`.
2. Seek `iter.SeekGE(EncodeChunkKey(keyHash, targetChunkNum))`:
   - In inverted key space (`'c' + KeyHash + ^chunkNum`), `SeekGE` automatically lands on the chunk record with `^chunkNum >= ^targetChunkNum`, which is the most recent existing chunk with `chunkNum <= targetChunkNum`.
   - If `iter.Valid()` and `iter.Key()` matches prefix (`'c' + KeyHash`):
     - Decode `currChunkNum := DecodeChunkKey(iter.Key())` (guaranteed `currChunkNum <= targetChunkNum`).
     - If `currChunkNum == targetChunkNum`: Unmarshal `ChunkRecord`, initialize `compact.Range` from its base `CoveredSize` and `CompactHashes`, and fold only `RelativeIndices` satisfying `currChunkNum * chunkSize + relOffset < maxInputLogSize`.
     - If `currChunkNum < targetChunkNum`: Unmarshal `ChunkRecord`, initialize `compact.Range`, and fold all its `RelativeIndices` (as all entries in that chunk are `< targetChunkNum * chunkSize <= maxInputLogSize`), and compute the sub-root.
   - If `!iter.Valid()` or the key does not match prefix `'c' + KeyHash`: No chunk exists with `chunkNum <= targetChunkNum` (key was first observed after `maxInputLogSize`), return `[32]byte{}` (empty tree root).
3. Used as the read-only recovery primitive on daemon startup with **zero Pebble mutations**.

---

## 7. Testing, Fuzzing & Crash Consistency

### 1. Unit Testing
- Tests for `InvertedPrefixChunkComparer`, key encoding/decoding, delimitless serialization roundtrips, and boundary rollover transitions (65,535 -> 65,536).

### 2. Fuzz Testing
- Fuzzing `UnmarshalChunkValue` against corrupted payloads, truncated byte slices, and mismatched `CoveredSize` / `CompactHashes` length headers.
- Fuzzing `DecodeChunkKey` against malformed key byte lengths.

### 3. Crash Consistency Tests
- Simulating process termination during `WriteBatch` to verify atomic persistence of chunk mutations and `m_kv_size`.
- Verifying that because storage persistence precedes Output Log publication, `m_kv_size >= Output_Size` is preserved under simulated crashes, ensuring `GetSubRoot` during startup recovery never encounters missing chunks for witnessed states.

---

## 8. Sizing, Resource Bounds & Subsystem Metrics

### 1. Resource Bounds
- Default 2 GB Pebble block cache + 64 MB write buffer (memtable) budget.

### 2. Subsystem Telemetry & Metrics
- `vindex_kvstore_write_batch_duration_seconds` (Histogram): Latency of `WriteBatch` execution.
- `vindex_kvstore_write_batch_keys_count` (Histogram): Number of unique keys in a write batch.
- `vindex_kvstore_lookup_duration_seconds` (Histogram): Latency of storage `Lookup` range queries across inverted chunks.
- `vindex_kvstore_get_subroot_duration_seconds` (Histogram): Latency of `GetSubRoot` recovery seeks.
- `vindex_kvstore_active_chunks_total` (Gauge): Count of active chunk records open for modification.
- `vindex_kvstore_pebble_sync_duration_seconds` (Histogram): Duration of synchronous disk fsync operations during batch writes.
- `vindex_kvstore_pebble_block_cache_hit_ratio` (Gauge): Pebble block cache hit efficiency.
- `vindex_kvstore_pebble_disk_bytes_written_total` (Counter): Disk write volume from LSM flushes and compactions.

---

## 9. Design Rationale & Alternatives Considered

- **Storage Engine Selection**:
  - **Default Engine (Pebble)**: Pure Go, robust prefix Bloom filter support, custom prefix comparers (`InvertedPrefixChunkComparer`), zero cgo overhead, and high NVMe write throughput.
  - **Pluggability**: Because all Pebble specifics are encapsulated behind `IndexStore`, alternative storage engines (e.g., SQLite, bbolt, or cloud KV) can be implemented by providing a conforming `IndexStore` backend.
- **Paging Model & Storage Traversal Alignment**:
  - **Merkle Log Prefix Property**: Merkle tree compact ranges natively commit to a contiguous prefix of history (`0 .. K-1`). Returning the latest tail entries alongside a single `prefix-compact-range-v1` allows O(log N) cryptographic verification of all prior history in a single response, without requiring complex arbitrary suffix/middle sub-tree proofs.
  - **Access Pattern & Recency Bias**: Transparency log auditing is heavily biased toward the most recent entries (new certificates, latest package releases, fresh signatures). Earlier entries are typically stale, superseded, or already observed by recurring index auditors. Backward paging delivers the freshest data on Page 1 immediately.
  - **Storage & Traversal Alignment**: Inverted chunk storage (`'c' + KeyHash + ^chunkNum`) naturally positions the active, newest chunk first, enabling O(1) seek and chronological reverse traversal (`iter.Next()` forward through inverted keys / older chunks).
- **Chunk Size Rationale (65,536)**:
  - Fixed 65,536 (2^16) chunk capacity allows relative indices to be encoded as compact 2-byte unsigned integers (`uint16`), reducing storage footprint by 75% compared to 8-byte `uint64` values.
  - Maximum chunk payload is bounded to ~131 KB (65,536 * 2B + compact.Range), ensuring chunks fit comfortably within storage block caches without memory fragmentation.

