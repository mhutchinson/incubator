# Sub-Design: Ingestion Pipeline & Tile Cache

## 1. Context & Objectives

The **Ingestion Pipeline** (`vindex/v1/internal/ingest`) is responsible for streaming leaves from an append-only Input Log, executing deterministic `MapFn` mapping across parallel WebAssembly sandboxes, enforcing strictly chronological leaf ordering via an in-memory resequencer, and delivering ordered mapped batches to the database commit plane without write-ahead log (WAL) overhead.

### 1.1 Key Guarantees

1. **High Throughput Streaming**: Native 256-leaf entry bundle fetching (`TileFetcher.FetchTiles`) eliminates per-leaf function call and network overhead.
2. **Deterministic Hermetic Mapping**: Sandboxed WASM execution via Wazero with a strict `HALT` policy on memory violations or guest traps.
3. **Monotonic Leaf Ordering**: Out-of-order map worker completions are sorted into strictly ascending order by an in-memory priority queue min-heap before downstream delivery.
4. **Zero-WAL Architecture**: Local tile cache acts as the immutable log of record; intermediate database WAL writes are completely eliminated.
5. **Decoupled Storage**: The ingestion package contains **zero Pebble dependencies, keys, or transactions**.

### 1.2 Non-Requirements & Out of Scope

- **No Network / Host I/O in MapFn**: WebAssembly sandboxes have zero WASI syscall access (no network, no filesystem I/O, no system clock, no RNG). Execution is pure, hermetic function of leaf bytes.
- **No Cross-Leaf State Retention**: `MapFn` is strictly stateless across invocations. No mutable state persists inside guest modules between leaves.
- **No Direct Storage Mutation**: Ingestion has zero dependencies on Pebble DB, MPT, or Output Log schemas; it strictly outputs monotonically ordered `MappedBatch` channels.

### 1.3 Alternatives Considered

- **Mapping Execution Engine**:
  - **Option A (Selected) - Wazero WebAssembly Sandboxes**: Hermetic, deterministic execution across heterogeneous host platforms, hardware memory boundary enforcement, zero cgo overhead, strict CPU/memory isolation.
  - **Option B (Rejected) - Go Plugins (`plugin.Open`)**: Requires exact compiler/dependency matching, unsafe (unbounded memory access can corrupt host state or crash process), non-deterministic host behavior can break consensus.
- **Ingestion Batch Granularity**:
  - **Option A (Selected) - Native 256-Leaf Entry Bundles**: Aligns with Tessera's physical storage layout, fetching full tiles in single I/O operations without unbundling overhead.
  - **Option B (Rejected) - Leaf-by-Leaf Streaming**: Massive HTTP request amplification and high CPU serialization overhead.

---

## 2. Architecture & Pipeline Topology

The Ingestion Pipeline is structured as a 3-stage asynchronous pipeline with Go channel handoffs:

```text
[Input Log Source / Cache]
       │
       ▼ (Stage 1: I/O Bound, 32-128 workers)
┌─────────────────────────────────────────────────────────────┐
│ TileFetcher & Cache                                         │
│ • Fetch aligned entry bundles (tclient.GetEntryBundle)      │
│   across bundle spans [S/256 .. E/256)                      │
│ • Decode leaves & bundle into fixed-size LeafBundle (256)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *LeafBundle (depth: 64-256)
                               ▼ (Stage 2: CPU Bound, max(1, GOMAXPROCS-1) workers)
┌─────────────────────────────────────────────────────────────┐
│ MapWorkerPool                                               │
│ • Wazero WASM Sandbox / Go MapFn execution                  │
│ • Parse leaf -> extract search keys -> SHA-256 hash         │
│ • Sort & deduplicate key hashes per leaf                    │
│ • Construct MappedBatch (unordered completion)              │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *MappedBatch (unordered)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Resequencer (Min-Heap Priority Queue)                       │
│ • Keyed by BundleIdx = StartLeafIdx / 256                   │
│ • Re-establishes strict monotonically ascending order       │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *MappedBatch (ordered)
                               ▼ (Stage 3: Database Commit Plane)
┌─────────────────────────────────────────────────────────────┐
│ KVCommitter & OutputPublisher (1 Dedicated CPU Core)        │
│ • Synchronous Pebble chunk writes ('c')                     │
│ • MPT root prediction & Tessera Output Log commitment       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Package API & Responsibilities

### Responsibilities
- **Entry Bundle Acquisition**: Fetching and caching raw 256-leaf entry bundles from local disk or remote HTTP/cloud storage.
- **WASM Map Sandbox Management**: Spooling a pool of isolated Wazero runtime instances executing `map_leaf(ptr, len)`.
- **Key Hash Extraction & Deduplication**: Parsing leaves into 32-byte SHA-256 search key hashes, sorting lexicographically, and deduplicating per leaf.
- **Monotonic Resequencing**: Buffering unordered mapped batches in a min-heap priority queue to deliver gapless, strictly ascending batches downstream.
- **Tile Cache Garbage Collection (`TileReaper`)**: Pruning cached tiles whose upper bound is below the safe watermark `min(m_kv_size, MPT.PersistedVersion())`.

### Go Interfaces & Types

```go
package ingest

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/transparency-dev/formats/log"
)

var (
	ErrWasmHalt        = errors.New("wasm execution halted due to trap or resource violation")
	ErrInvalidMemory   = errors.New("wasm returned pointer outside linear memory bounds")
	ErrUnalignedOutput = errors.New("wasm output byte length is not a multiple of 32 bytes")
)

// Checkpoint represents an Input Log checkpoint note preserving exact unparsed bytes.
type Checkpoint struct {
	Raw        []byte
	Origin     string
	Size       uint64
	Hash       [32]byte
	Extension  []byte
	Signatures []log.Signature
}

// LeafBundle encapsulates 256 contiguous leaves unpacked from a single Tessera entry bundle.
type LeafBundle struct {
	BundleIdx    uint64
	StartLeafIdx uint64
	Leaves       [][]byte
}

// MappedBatch holds extracted search key mappings for a bundle of leaves.
type MappedBatch struct {
	BundleIdx    uint64
	StartLeafIdx uint64
	Count        uint32
	KeyMap       map[[32]byte][]uint64
}

// TileFetcher abstracts fetching entry bundles and checkpoints from the Input Log.
type TileFetcher interface {
	Checkpoint(ctx context.Context) (*Checkpoint, error)
	FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error)
	Leaf(ctx context.Context, idx uint64) ([]byte, error)
}

// TileCache manages persistent or ephemeral local storage for raw input log tiles.
type TileCache interface {
	GetTile(level, index uint64) ([]byte, error)
	PutTile(level, index uint64, data []byte) error
	PruneBefore(watermark uint64) error
}

// SandboxPool manages a pool of sandboxed WebAssembly execution modules.
type SandboxPool interface {
	MapLeaf(ctx context.Context, leaf []byte) ([][sha256.Size]byte, error)
	Close(ctx context.Context) error
}

// Pipeline coordinates fetching, parallel mapping, and resequencing.
type Pipeline struct {
	fetcher     TileFetcher
	cache       TileCache
	sandboxPool SandboxPool
	outBatches  chan *MappedBatch
}

func NewPipeline(fetcher TileFetcher, cache TileCache, pool SandboxPool, numWorkers int) *Pipeline
func (p *Pipeline) Start(ctx context.Context, fromLeafIdx, targetSize uint64) (<-chan *MappedBatch, error)
func (p *Pipeline) Close() error
```

---

## 4. 3-Stage Pipeline Design

### Stage 1: TileFetcher & Cache
- **Workload Profile**: I/O bound (network latency or local disk reads).
- **Concurrency**: Configurable pool of 32–128 concurrent fetch workers.
- **Direct Entry Bundle Fetching**:
  - `TileFetcher` natively fetches aligned entry bundles (`tclient.GetEntryBundle` across bundle spans $[\lfloor S/256 \rfloor .. \lceil E/256 \rceil)$) rather than leaf-by-leaf abstractions.
  - Retrieves raw 256-leaf chunks in a single network or filesystem operation, eliminating per-leaf function-call and caching overhead during bulk streaming.
- **Batching**: Raw leaves are unpacked into `LeafBundle` slices of exactly 256 contiguous leaves, stamped with `BundleIdx = StartLeafIdx / 256`.

### Stage 2: MapWorkerPool & WASM Sandbox
- **Workload Profile**: CPU bound (WebAssembly execution, parsing, cryptographic hashing).
- **CPU Partitioning**: Strictly sized to $\max(1, \text{GOMAXPROCS} - 1)$ workers. 1 dedicated CPU core is reserved for Pebble chunk writes (`KVIndexer`), MPT root publishing (`OutputPublisher`), and live read queries.
- **WASM Guest ABI & Memory Contract**:
  - **Export**: `map_leaf(leaf_ptr: uint32, leaf_len: uint32) -> (out_ptr: uint32, out_len: uint32)` (packed 64-bit integer `(uint64(out_ptr) << 32) | uint64(out_len)`).
  - **Input**: Host writes raw leaf bytes to guest memory starting at `leaf_ptr`.
  - **Output**: Contiguous array of 32-byte SHA-256 key hashes `[]Hash(MapKey)`. `out_len` MUST be an exact multiple of 32 bytes (`out_len % 32 == 0`).
  - **Validation**: Host asserts `out_len % 32 == 0` and `[out_ptr .. out_ptr+out_len)` is within guest memory.
  - **Host Post-Processing**: Hashes are sorted via `bytes.Compare` and deduplicated with `slices.Compact` to guarantee strictly unique keys per leaf.
  - **Deterministic Error Policy (`HALT`)**: Any guest panic, memory violation, or trap immediately halts the daemon to prevent unverified witness state divergence.

### Stage 3: Resequencer & Output Channel
- **Mechanism**: In-memory priority min-heap indexed by `BundleIdx`.
- **Monotonic Guarantee**: Parallel map workers finish bundles out of order due to variable leaf complexity. The `Resequencer` buffers completed batches and releases them into the downstream channel in strictly ascending chronological order (`nextBatch.StartLeafIdx == expectedStartLeafIdx`).
- **Backpressure**: Buffered Go channels automatically block Stage 1 and Stage 2 when downstream disk commits experience I/O pauses.

---

## 5. Tile Boundary Alignment & Checkpoint Clamping

### Invariant
> Ingestion batch sizes, cache bundle capacities (`bundleSz`), and logical chunk rollover thresholds (`chunkSize`) MUST be integer multiples of the Tessera entry bundle width ($256$).

- **Tessera Alignment**: Tessera entry bundles store entries in blocks of 256 ($2^8$). When batch boundaries align with $256 \times k$ ($k=1$ for `LeafBundle`, $k=256$ for 65,536-leaf Pebble chunks), every fetch spans an exact integer range of entry bundles $[S/256 .. E/256)$, eliminating partial bundle fetches and redundant network requests.
- **Unaligned Target Checkpoints**:
  1. **Clamping**: The final bundle in a target batch is clamped to the exact checkpoint size `targetCP.Size` (`count = min(bundleSz, targetSize - currIdx)`).
  2. **KV Metadata**: `KVIndexer` commits `m_kv_size` to the exact non-aligned checkpoint size upon completing a target batch.
  3. **Conservative Retention**: `TileReaper` only prunes tiles whose full range $(tileIdx + 1) \times 256 \le SafeWatermark$.

---

## 6. Operational Modes & TileReaper Lifecycle

| Mode | Source | Cache Ownership | TileReaper Active | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Direct Local FS** | Local Directory | None (Zero Copy) | No | Co-located with log signer or pre-synced mirror. |
| **Remote Managed Cache** | HTTP / Cloud | Managed Local Dir | **Yes** | Standard standalone deployment. |
| **Remote Persistent Cache**| HTTP / Cloud | Persistent Local Dir| No | High-durability deployment with full local history. |
| **Remote Direct Streaming** | HTTP / Cloud | Ephemeral In-Memory| No | Stateless read replicas or testing nodes. |

### Safe Watermark Formula

```text
SafeWatermark = min(m_kv_size, MPT.PersistedVersion())
```

- **`TileReaper` Operation**:
  1. Runs periodically in the background (e.g., every 60 seconds).
  2. Computes `SafeWatermark = min(m_kv_size, MPT.PersistedVersion())`.
  3. Safely deletes cached tile files whose range satisfies `TileEndIndex < SafeWatermark`.
  4. Preserves tiles between `MPT.PersistedVersion()` and `m_kv_size` so that crash recovery can replay MPT catchup without network refetching.

---

## 7. Security & Sandboxing Constraints

- **Memory Cap**: Fixed linear memory limit (e.g., 16 MB maximum heap per WASM instance). Exceeding this triggers a trap and immediate daemon `HALT`.
- **Execution Timeout**: Per-leaf execution deadline (e.g., 100ms CPU timeout) via context cancellation to prevent guest infinite loops.
- **Memory Safety & Alignment**: Validation of return pointer/length within guest bounds; enforcement of `out_len % 32 == 0`.

---

## 8. Testing, Qualification & Synthetic Benchmarks

### Synthetic Benchmarking Harness
- **Input Log Generation**: Deterministically generate an Input Log using Tessera POSIX with known leaf count and reproducible payload distributions (e.g., synthetic CT/SumDB logs).
- **End-to-End Pipeline Execution**: Stream and map the synthetic log through the full ingestion pipeline (`TileFetcher` -> `MapWorkerPool` -> `Resequencer`) with target `MapFn`.
- **Performance Profiling**: Measure sustained throughput (leaves/sec), bundle fetch latency, and CPU worker utilization.
- **Monotonicity & Correctness**: Assert that output `MappedBatch` instances strictly match expected leaf indices without gaps, drops, or inversions.
- **Crash & Recovery Simulation**: Intermittently halt pipeline at arbitrary bundle boundaries, restart `TileFetcher` from intermediate watermarks, and verify resumption without data loss or corruption.

### Unit & Fuzz Testing
- **Resequencer Queue Tests**: Unit test suite for `Resequencer` min-heap priority queue verifying correct reordering under randomized arrival orders, out-of-order bursts, and backpressure.
- **MapWorkerPool Fuzzing**: Fuzzing `MapWorkerPool` output validation against malformed WASM return pointers, unaligned byte slices, and out-of-bounds linear memory offsets.
- **TileFetcher Fuzzing**: Fuzzing `TileFetcher` against corrupted entry bundles and truncated checkpoints.

---

## 9. Subsystem Metrics

- `ingest_tile_fetch_duration_seconds` (Histogram): Bundle fetch latency.
- `ingest_tile_fetch_bytes_total` (Counter): Total raw bundle bytes fetched.
- `ingest_resequencer_queue_depth` (Gauge): Current buffered batches in the min-heap.
- `ingest_resequencer_gap_wait_seconds` (Histogram): Time spent waiting for missing sequence numbers at head of heap.
- `ingest_wasm_memory_allocated_bytes` (Gauge): Memory consumed by Wazero instances.
- `ingest_wasm_execution_duration_seconds` (Histogram): Per-leaf execution time within WASM runtime.
- `ingest_tile_reaper_deleted_tiles_total` (Counter): Cumulative tiles pruned.

