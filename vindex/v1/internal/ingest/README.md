# Sub-Design: Ingestion Pipeline & Tile Cache

## 1. Context & Objectives

The **Ingestion Pipeline** (`vindex/v1/internal/ingest`) is responsible for streaming leaves from an append-only Input Log, executing deterministic [`MapFn`](../../mapfn/README.md) mapping across parallel WebAssembly sandboxes, enforcing strictly chronological leaf ordering via an in-memory resequencer, and delivering ordered mapped batches to the database commit plane without write-ahead log (WAL) overhead.

### 1.1 Key Guarantees

1. **High Throughput Streaming**: Native 256-leaf entry bundle fetching (`TileFetcher.FetchTiles`) eliminates per-leaf function call and network overhead.
2. **Cryptographic Input Log Authentication**: Verifies checkpoint origin signatures, optional witness policy ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy)), Merkle consistency proofs, and authenticates tree tiles and leaf record hashes (`tlog.RecordHash`) against the target checkpoint root via `torchwood`.
3. **Deterministic Hermetic Mapping**: Sandboxed WASM execution via Wazero with a strict `HALT` policy on memory violations or guest traps.
4. **Monotonic Leaf Ordering**: Out-of-order map worker completions are sorted into strictly ascending order by an in-memory priority queue min-heap before downstream delivery.
5. **Zero-WAL Architecture**: Local tile cache acts as the immutable log of record; intermediate database WAL writes are completely eliminated.
6. **Decoupled Storage**: The ingestion package contains **zero Pebble dependencies, keys, or transactions**.

### 1.2 Non-Requirements & Out of Scope

- **No Network / Host I/O in MapFn**: WebAssembly sandboxes have zero WASI syscall access (no network, no filesystem I/O, no system clock, no RNG). Execution is pure, hermetic function of leaf bytes.
- **No Cross-Leaf State Retention**: `MapFn` is strictly stateless across invocations. No mutable state persists inside guest modules between leaves.
- **No Direct Storage Mutation**: Ingestion has zero dependencies on Pebble DB, MPT, or Output Log schemas; it strictly outputs monotonically ordered `MappedBatch` channels.

### 1.3 Alternatives Considered

- **Input Log Ingestion & Tile Authentication**:
  - **Option A (Selected) - `filippo.io/torchwood`**: End-to-end cryptographic tile and leaf Merkle tree authentication against target checkpoint root (`tree.Hash`), built-in `torchwood.PermanentCache` for Zero-WAL startup recovery, origin signature and witness policy validation (`torchwood.VerifyCheckpoint`), and modular format adapters (`WithTilePath`, `WithCutEntry`).
  - **Option B (Rejected) - Raw / Custom Tile Fetching**: Lacks standardized tile Merkle proof verification; custom cryptographic validation is error-prone and adds unneeded maintenance overhead.
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
│ TileFetcher & Cache (torchwood.Client & PermanentCache)     │
│ • Validate checkpoint & policy (torchwood.VerifyCheckpoint) │
│ • Fetch data & tree tiles (torchwood.Client.Entries)        │
│ • Authenticate tiles & leaf hashes (tlog.RecordHash)        │
│ • Decode authenticated leaves into LeafBundle (256)         │
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
- **Input Log Authentication & Validation**: Validating checkpoint origin signatures, enforcing witness policy quorums via `torchwood.VerifyCheckpoint(raw, policy)`, and authenticating tree tiles and leaf hashes against `tree.Hash`.
- **Authenticated Entry Bundle Acquisition**: Streaming authenticated entry tiles via `torchwood.Client.Entries(ctx, tree, start)`, verifying Level-0 tile hashes against `tlog.RecordHash(leaf)`, and caching verified non-partial tiles via `torchwood.PermanentCache`.
- **Format Adaptation**: Adapting log layouts (`tlog-tiles`, `static-ct`, `sumdb`) via `torchwood.WithTilePath` and `torchwood.WithCutEntry`.
- **WASM Map Sandbox Management**: Spooling a pool of isolated Wazero runtime instances executing `map_leaf(ptr, len)`.
- **Key Hash Extraction & Deduplication**: Parsing leaves into 32-byte SHA-256 search key hashes, sorting lexicographically, and deduplicating per leaf.
- **Monotonic Resequencing**: Buffering unordered mapped batches in a min-heap priority queue to deliver gapless, strictly ascending batches downstream.
- **Tile Cache Garbage Collection (`TileReaper`)**: Pruning cached tiles whose upper bound is below the safe watermark `SafeWatermark = mptDurableSize`. Note: `TileReaper` runs concurrently in the background with `SafeWatermark = mptDurableSize` initialized to `S_OUT` via `mptMgr.Sync()` upon startup recovery completion.

### Go Interfaces & Types

```go
package ingest

import (
	"context"
	"crypto/sha256"
	"errors"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

var (
	ErrWasmHalt        = errors.New("wasm execution halted due to trap or resource violation")
	ErrInvalidMemory   = errors.New("wasm returned pointer outside linear memory bounds")
	ErrUnalignedOutput = errors.New("wasm output byte length is not a multiple of 32 bytes")
)

// Checkpoint represents an Input Log checkpoint validated via torchwood.VerifyCheckpoint.
type Checkpoint struct {
	Raw       []byte
	Origin    string
	Size      uint64
	Hash      [32]byte
	Extension []byte
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

// TileFetcher abstracts authenticated entry streaming and checkpoint fetching using torchwood.Client.
type TileFetcher interface {
	Checkpoint(ctx context.Context) (*Checkpoint, error)
	FetchTiles(ctx context.Context, tree *tlog.Tree, startLeafIdx, count uint64) ([]*LeafBundle, error)
	Leaf(ctx context.Context, tree *tlog.Tree, idx uint64) ([]byte, error)
}

// TileCache manages persistent or ephemeral local storage for raw input log tiles via torchwood.PermanentCache.
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

// Pipeline coordinates authenticated fetching, parallel mapping, and resequencing.
type Pipeline struct {
	client      *torchwood.Client
	cache       TileCache
	sandboxPool SandboxPool
	outBatches  chan *MappedBatch
}

func NewPipeline(client *torchwood.Client, cache TileCache, pool SandboxPool, numWorkers int) *Pipeline
func (p *Pipeline) Start(ctx context.Context, tree *tlog.Tree, fromLeafIdx, targetSize uint64) (<-chan *MappedBatch, error)
func (p *Pipeline) Close() error
```

---

## 4. 3-Stage Pipeline Design

### Stage 1: TileFetcher & Cache
- **Workload Profile**: I/O bound (network latency or local disk reads).
- **Concurrency**: Configurable pool of 32–128 concurrent fetch workers.
- **Checkpoint Origin Signature & Witness Policy**:
  - Validates checkpoint note authenticity via `torchwood.VerifyCheckpoint(raw, policy)`.
  - Enforces mandatory verification of the log origin signature against trusted public keys before accepting any checkpoint.
  - Evaluates optional witness cosignature quorums against the configured witness policy ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy)).
- **Authenticated Tile & Leaf Streaming (`torchwood.Client.Entries`)**:
  - `torchwood.Client.Entries(ctx, tree, start)` fetches data and tree tiles across bundle spans `[floor(S/256) .. ceil(E/256))`.
  - Cryptographically authenticates tree tiles against `tree.Hash` (the target checkpoint root).
  - Computes leaf record hashes using `tlog.RecordHash(leaf)` and verifies them against Level-0 tree tiles before emitting leaves for mapping.
- **Persistent Verified Tile Caching (`torchwood.PermanentCache`)**:
  - Caches verified, non-partial data and tree tiles on local disk.
  - Acts as the immutable log of record powering Zero-WAL startup recovery without network egress.
- **Format Adapters**:
  - Configures log format path conventions via `torchwood.WithTilePath` and entry boundary slicing via `torchwood.WithCutEntry` for standard formats (`tlog-tiles`, `static-ct`, and `sumdb`).
- **Batching**: Authenticated raw leaves are unpacked into `LeafBundle` slices of exactly 256 contiguous leaves, stamped with `BundleIdx = StartLeafIdx / 256`.

### Stage 2: MapWorkerPool & WASM Sandbox
- **Workload Profile**: CPU bound (WebAssembly execution, parsing, cryptographic hashing).
- **Specification**: Complete ABI, memory protocol, and SDK specification detailed in [**WASM MapFn Plugin SDK & Host Runtime**](../../mapfn/README.md).
- **CPU Partitioning**: Strictly sized to max(1, GOMAXPROCS - 1) workers. 1 dedicated CPU core is reserved for Pebble chunk writes (`KVIndexer`), MPT root publishing (`OutputPublisher`), and live read queries.
- **WASM Guest ABI & Memory Contract**:
  - **Export**: `map_leaf(leaf_ptr: uint32, leaf_len: uint32) -> (out_ptr: uint32, out_len: uint32)` (packed 64-bit integer `(uint64(out_ptr) << 32) | uint64(out_len)`).
  - **Input**: Host writes raw leaf bytes to guest memory starting at `leaf_ptr` allocated via `allocate(size)`.
  - **Output**: Contiguous array of 32-byte SHA-256 key hashes `[]Hash(MapKey)`. `out_len` MUST be an exact multiple of 32 bytes (`out_len % 32 == 0`).
  - **Validation**: Host asserts `out_len % 32 == 0` and `[out_ptr .. out_ptr+out_len)` is within guest memory.
  - **Host Post-Processing**: Hashes are sorted via `bytes.Compare` and deduplicated with `slices.Compact` to guarantee strictly unique keys per leaf.
  - **Deterministic Error Policy (`HALT`)**: Any guest panic, memory violation, or trap immediately halts the daemon to prevent unverified witness state divergence.

### Stage 3: Resequencer & Output Channel
- **Mechanism**: In-memory priority min-heap indexed by `BundleIdx`.
- **Serialization Guarantee**: While map workers execute concurrently in parallel across multiple cores, the `Resequencer` re-serializes completed batches into strictly ascending chronological order (`nextBatch.StartLeafIdx == expectedStartLeafIdx`) before passing them downstream to the KV committer.
- **Implementation Note (Backpressure)**: To keep heap memory bounded when parallel worker runtimes vary, the pipeline applies upstream backpressure via a bounded lookahead window (e.g. max 128 bundles) to pause tile dispatching if a single worker straggles. Downstream channel buffers also backpressure Stage 3 during disk I/O commit pauses.

### Note: Pluggable Adaptive Transport (Non-Load-Bearing)
For aggressive initial catch-up against rate-limited CDNs, `TileFetcher` can optionally accept a custom `http.RoundTripper` (via `http.Client.Transport`) implementing global token bucket rate-limiting or AIMD adaptive concurrency. This sits entirely at the HTTP transport layer and is orthogonal to the pipeline invariants.

---

## 5. Tile Boundary Alignment & Checkpoint Clamping

### Invariant
> Ingestion batch sizes, cache bundle capacities (`bundleSz`), and logical chunk rollover thresholds (`chunkSize`) MUST be integer multiples of the Tessera entry bundle width (256).

> **Performance Note**: While parallel map workers process at 256-leaf tile granularity, the Coordinator aggregates mapped batches to `DefaultCommitBatchSize = 4096` (16 tiles) before committing to Pebble, amortizing iterator creation and lock acquisition overhead by 16x.

- **Tessera Alignment**: Tessera entry bundles store entries in blocks of 256 (2^8). When batch boundaries align with `256 * k` (k=1 for `LeafBundle`, k=256 for 65,536-leaf Pebble chunks), every fetch spans an exact integer range of entry bundles `[S/256 .. E/256)`, eliminating partial bundle fetches and redundant network requests.
- **Unaligned Target Checkpoints**:
  1. **Clamping**: The final bundle in a target batch is clamped to the exact checkpoint size `targetCP.Size` (`count = min(bundleSz, targetSize - currIdx)`).
  2. **KV Metadata**: `KVIndexer` commits `m_kv_size` to the exact non-aligned checkpoint size upon completing a target batch.
  3. **Conservative Retention**: `TileReaper` only prunes tiles whose full range `(tileIdx + 1) * 256 <= SafeWatermark`.

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
SafeWatermark = mptDurableSize
```

#### Invariant Justification:
- **State Progression Invariant**: `Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= mptDurableSize`.
- **Mathematical Equivalence**: Because `mptDurableSize` is strictly bounded by `m_kv_size` (`mptDurableSize <= Output_Size <= m_kv_size`), `min(m_kv_size, mptDurableSize) == mptDurableSize`.
- **Durability Guarantee**: Leaves below `mptDurableSize` are already committed to Pebble and durably fsync'd in MPT disk files (`exact == true`). Crash recovery never needs raw tiles below `mptDurableSize`.
- **Startup Recovery Replay**: Tiles in the range `[mptDurableSize .. m_kv_size)` are retained in cache so that in the event of an unclean crash (`exact == false` or lagging MPT), startup recovery can fast-forward MPT state up to `Output_Size` (the latest Output Log entry `S_OUT`) without network refetching.

- **`TileReaper` Operation**:
  1. Starts concurrently in the background with `mptDurableSize` initialized to `S_OUT` via `mptMgr.Sync()` upon startup recovery completion.
  2. Runs periodically in the background (e.g., every 60 seconds) via a watermark query callback (`watermarkFn`).
  3. Evaluates `SafeWatermark = mptDurableSize`.
  4. Safely deletes cached tile files whose range satisfies `(tileIdx + 1) * 256 <= SafeWatermark`.
  5. Preserves tiles between `mptDurableSize` and `m_kv_size` so that startup recovery can replay MPT catchup without network refetching.

---

## 7. Security & Sandboxing Constraints

### 7.1 Input Log Cryptographic Verification
- **Checkpoint Origin Signature**: Mandatory verification of log origin signature before accepting any checkpoint note.
- **Witness Policy ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy))**: Optional verification of witness cosignature quorum matching configured witness policy.
- **Merkle Consistency Proofs**: Mandatory Merkle consistency check via `golang.org/x/mod/sumdb/tlog.CheckTree(...)` whenever target checkpoint advances (`CP_old` -> `CP_new`).
- **Tile & Leaf Merkle Authentication**: `torchwood.Client` strictly authenticates downloaded tree tiles against `tree.Hash`, computes leaf record hashes (`tlog.RecordHash`), and asserts equality against Level-0 tree tiles prior to mapping.

### 7.2 WebAssembly Guest Sandboxing
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

## 9. Subsystem Telemetry & Metrics

- `vindex_ingest_tile_fetch_latency_seconds` (Histogram): Bundle fetch latency.
- `vindex_ingest_tile_fetch_bytes_total` (Counter): Total raw bundle bytes fetched.
- `vindex_ingest_resequencer_heap_size` (Gauge): Current buffered batches in the min-heap.
- `vindex_ingest_resequencer_gap_wait_seconds` (Histogram): Time spent waiting for missing sequence numbers at head of heap.
- `vindex_ingest_map_worker_duration_seconds` (Histogram): Per-leaf execution time within WASM runtime.
- `vindex_ingest_wasm_memory_allocated_bytes` (Gauge): Memory consumed by Wazero instances.
- `vindex_ingest_tile_reaper_deleted_tiles_total` (Counter): Cumulative tiles pruned.

