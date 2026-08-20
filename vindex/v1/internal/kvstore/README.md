# Sub-Design: KV Storage (Inverted Chunk Storage Engine)

## 1. Context & Objectives

The **KV Storage Engine** (`vindex/v1/internal/kvstore`) provides an LSM-tree optimized storage layout in Pebble for verifiable index records. It maps 32-byte cryptographic key hashes to sequences of Input Log indices, supporting high-throughput batch appends, $O(1)$ sub-root Merkle commitments, and efficient chronological range lookups without write amplification or compaction write stalls.

### 1.1 Core Storage Requirements
1. **High-Throughput Batch Appends (`WriteBatch`)**: Ingest hundreds of thousands of key-index updates per second across sparse, highly distributed keys.
2. **Sub-Log Merkle Commitments (`GetSubRoot`)**: Dynamically compute or retrieve the Merkle root hash committing to all historical occurrences of a key in $O(1)$ disk reads.
3. **Range Queries (`Lookup`)**: Efficiently fetch index sequence numbers starting from an arbitrary offset $K$.

### 1.2 Non-Requirements & Out of Scope
- **No Deletions or Tombstones**: The index is strictly append-only. No deletion, tombstone marking, or rollback of index entries.
- **No Cross-Key Range Iteration**: Queries across multiple distinct key hashes (e.g., scanning all keys alphabetically) are not supported. Only prefix-bound seeks on a specific 32-byte key hash (`'c'` + KeyHash) are exposed.
- **No Concurrent Multi-Writer Access**: `kvstore.DB` writes are strictly executed by a single dedicated committer goroutine; concurrent write batches are out of scope.

### 1.3 Storage Engine Alternatives & Chunk Sizing Rationale
- **Storage Engine Selection**:
  - **Selected (Pebble)**: Pure Go, robust prefix Bloom filter support, custom prefix comparers (`InvertedPrefixChunkComparer`), zero cgo overhead, and high NVMe write throughput.
  - **Other Engines Note**: Different storage engines have not yet been exhaustively benchmarked against this specific workload. Pure-Go B+ tree engines (e.g., bbolt) could be evaluated in future tests. cgo-based engines (RocksDB, LevelDB) are ruled out to maintain pure-Go build portability and avoid FFI overhead. BadgerDB is avoided due to prior operational complexity/pain observed in Tessera deduplication.
- **Chunk Size Rationale (65,536)**:
  - Fixed 65,536 ($2^{16}$) chunk capacity allows relative indices to be encoded as compact 2-byte unsigned integers (`uint16`), reducing storage footprint by 75% compared to 8-byte `uint64` values.
  - Maximum chunk payload is bounded to ~131 KB ($65,536 \times 2\text{B} + \text{compact.Range}$), ensuring chunks fit comfortably within Pebble block caches without memory fragmentation.

---

## 2. Package API & Responsibilities

### Responsibilities
- **Pebble Database Management**: Configures Pebble with a custom 33-byte prefix splitter and 10-bit Bloom filter policy.
- **Inverted Chunk Key Encoding**: Formats keys with `'c'` prefix, 32-byte key hash, and bitwise-inverted chunk numbers (`^chunkNum`) to place the active chunk first.
- **Delimitless Binary Serialization**: Serializes and deserializes self-contained chunk records containing cumulative RFC 6962 compact ranges and relative index offsets.
- **Atomic Metadata Storage**: Provides atomic accessors for metadata keys (`'m'`: `m_target_checkpoint`, `m_kv_checkpoint`, `m_kv_size`).
- **Read-Only Sub-Root Recovery Primitive (`GetSubRoot`)**: Reads the active chunk in $O(1)$ time to reconstruct the mini-log Merkle root without mutating the database.

### Go Interfaces & Types

```go
package kvstore

import (
	"crypto/sha256"
	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/merkle/compact"
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

// ChunkRecord represents a self-contained chunk value in Pebble.
type ChunkRecord struct {
	CoveredSize     uint64
	CompactHashes   [][sha256.Size]byte
	RelativeIndices []uint16
}

// DB wraps a Pebble database instance configured with VIndex comparers.
type DB struct {
	db *pebble.DB
}

func Open(dir string, opts *pebble.Options) (*DB, error)
func (d *DB) Close() error
func (d *DB) NewBatch() *pebble.Batch
func (d *DB) NewIter(opts *pebble.IterOptions) *pebble.Iterator

// Inverted Prefix Comparer for Pebble
func InvertedPrefixChunkComparer() *pebble.Comparer

// Key Formatting Functions
func EncodeChunkPrefix(keyHash [sha256.Size]byte) []byte
func EncodeChunkKey(keyHash [sha256.Size]byte, chunkNum uint64) []byte
func DecodeChunkKey(key []byte) (keyHash [sha256.Size]byte, chunkNum uint64, err error)

// Delimitless Value Marshaling
func MarshalChunkValue(rec *ChunkRecord) []byte
func UnmarshalChunkValue(data []byte) (*ChunkRecord, error)

// Metadata Accessors
func (d *DB) GetMetadata(key []byte) ([]byte, error)
func (d *DB) SetMetadata(batch *pebble.Batch, key, val []byte) error
func (d *DB) GetUint64(key []byte) (uint64, error)
func (d *DB) SetUint64(batch *pebble.Batch, key []byte, val uint64) error

// Read-Only Recovery Primitive
func (d *DB) GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error)
```

---

## 3. Storage Layout & Inverted Chunk Space

### 1. Key Encoding

Keys use an explicit 1-byte domain separation prefix, 32-byte key hash, and an 8-byte big-endian bitwise-inverted chunk number:

```text
Key = 'c' (1B) + KeyHash (32B) + BigEndian(^chunkNum) (8B)
```

where `^chunkNum = math.MaxUint64 - chunkNum`.

- **Domain Separation**: The 1-byte `'c'` prefix isolates index records from metadata keys (`'m'`), allowing prefix filters to operate cleanly.
- **Logical Chunk Capacity**: `chunkSize = 65536`. Logical chunk number is `chunkNum = index / chunkSize`.
- **Prefix Comparer**: `Split(key)` returns 33 bytes (`'c' + KeyHash`). Pebble uses this prefix to construct table and block Bloom filters.

### 2. LSM-Tree Bloom Filter Constraint & Inversion Rationale

- **The Bloom Filter Constraint**: In LSM engines like Pebble, Bloom filters are built on key prefixes and can **only be evaluated during forward prefix seeks (`SeekPrefixGE`)**. They cannot be evaluated during reverse seeks (`SeekLT`).
- **The Ascending Chunk Flaw**: If chunk numbers are stored in natural ascending order ($0, 1, \dots, N$), calling `SeekPrefixGE(prefix)` lands on Chunk 0 and forces the engine to scan forward through all older sealed chunks ($0 \dots N$) via `iter.Next()`. On deep/hot keys, this degrades append throughput by up to 7.5x.
- **The Inversion Solution**: By storing chunk numbers as `^chunkNum = math.MaxUint64 - chunkNum`, the latest active chunk ($N$) is lexicographically the *first* key under the prefix (`^N < ^0`). A single `SeekPrefixGE(prefix)` call evaluates the Bloom filter for zero-I/O skipping on new keys **and lands directly on the latest active chunk in a single $O(1)$ probe**.

---

## 4. Value Schema & Delimitless Deserialization

### 4.1 Binary Value Layout

Every chunk record uses a uniform, self-contained binary schema:

```text
+-------------------------------------------------------------+------------------------------------+
|                Serialized compact.Range                     |      Relative Indices ([]uint16)   |
+------------------------------+------------------------------+------------------+-----------------+
|   Covered Size (8B uint64)   | Hashes (32B * OnesCount(Size))| relIndex 0 (2B)  | relIndex 1 (2B) |
+------------------------------+------------------------------+------------------+-----------------+
```

1. **Covered Size ($N_\text{prior}$)**: 8 bytes big-endian representing total elements committed across all preceding chunks (0 to $chunkNum-1$). For chunk 0, $N_\text{prior} = 0$.
2. **Compact Hashes**: Contiguous array of `bits.OnesCount64(N_prior)` SHA-256 hashes (32 bytes each).
3. **Relative Indices**: Continuous byte array of 2-byte unsigned integers representing `index % chunkSize`.

### 4.2 Delimitless Parsing
The parser extracts the exact boundary without delimiters or extra length headers:
```go
offset := 8 + 32 * bits.OnesCount64(rec.CoveredSize)
```

### 4.3 Schema Evolution & Versioning
- **Zero Row-Level Overhead**: Individual chunk records maintain the compact delimitless binary layout without per-row version bytes.
- **Global Schema Versioning**: Database-wide format versions are tracked in the metadata namespace (e.g., key `m_schema_version`), ensuring forward compatibility checks at database open time without increasing storage footprint.

---

## 5. Write Path (`WriteBatch`)

```text
[Incoming MappedBatch]
          │
          ▼ (1. Sort unique key hashes via bytes.Compare)
[Open Shared pebble.Iterator across batch]
          │
          ▼ (2. For each keyHash: iter.SeekPrefixGE('c' + keyHash))
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
                               [Compute Sub-Root via compact.Range]
                                                 │
                                                 ▼
                               [Commit Pebble Batch with Sync]
```

1. **Key Sorting**: Batch keys are sorted in lexicographical order to maximize LSM sequential write performance.
2. **$O(1)$ Active Chunk Discovery**:
   - `iter.SeekPrefixGE(prefix)`.
   - **New Key**: Bloom filter prunes SSTable seeks with **zero disk reads**.
   - **Existing Key**: Lands directly on the latest active chunk in $O(1)$ time.
3. **Append & Boundary Transition**:
   - Append `index % chunkSize` to `RelativeIndices`.
   - If crossing a boundary: write immutable sealed chunk, finalize `compact.Range`, and allocate a new chunk with `CoveredSize = finalizedRange.End()`.
4. **Atomic Commit**: Write chunk updates and `KeyMetaKVSize` to Pebble in a single atomic sync batch.

---

## 6. Read Path (`Lookup` & `GetSubRoot`)

### 1. Range Lookup (`Lookup(keyHash, start, limit)`)
1. Compute `startChunkNum = start / chunkSize`.
2. Seek `iter.SeekGE('c' + keyHash + BigEndian(^startChunkNum))`.
3. Because keys are inverted, `iter.SeekGE` lands directly on `startChunkNum` (which already embeds the historical compact range covering all chunks $< startChunkNum$).
4. Reverse-scan using `iter.Prev()` while matching `prefix`: traverses chunks in forward chronological order toward newer chunks.
5. Reconstruct absolute indices (`chunkNum * chunkSize + relOffset`) and filter: `start <= idx < serving_state.InputLogSize`.

### 2. Authenticated Sub-Root Query (`GetSubRoot(keyHash)`)
1. Call `iter.SeekPrefixGE(prefix)` to position on the active chunk in 1 seek.
2. Deserialize `ChunkRecord`, compute leaf hashes for active `RelativeIndices`, append them to `compact.Range`, and return `compactRange.Root()`.
3. Used as the read-only recovery primitive on daemon startup with **zero Pebble mutations**.

---

## 7. Testing, Fuzzing & Crash Consistency

### 1. Unit Testing
- Tests for `InvertedPrefixChunkComparer`, key encoding/decoding, delimitless serialization roundtrips, and boundary rollover transitions (65,535 -> 65,536).

### 2. Fuzz Testing
- Fuzzing `UnmarshalChunkValue` against corrupted payloads, truncated byte slices, and mismatched `CoveredSize` / `CompactHashes` length headers.
- Fuzzing `DecodeChunkKey` against malformed key byte lengths.

### 3. Crash Consistency Tests
- Simulating process termination during batch writes to verify atomic rollback to the last committed `m_kv_size`.

---

## 8. Sizing, Resource Bounds & Subsystem Metrics

### 1. Resource Bounds
- Default 2 GB Pebble block cache + 64 MB write buffer (memtable) budget.

### 2. Subsystem Metrics
- `kvstore_write_batch_duration_seconds` (Histogram): Latency of `WriteBatch` execution.
- `kvstore_write_batch_keys_count` (Histogram): Number of unique keys in a write batch.
- `kvstore_get_subroot_duration_seconds` (Histogram): Latency of `GetSubRoot` recovery seeks.
- `pebble_block_cache_hit_ratio` (Gauge): Pebble block cache hit efficiency.
- `pebble_disk_bytes_written_total` (Counter): Disk write volume from LSM flushes and compactions.

