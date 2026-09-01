# VIndex V1 Benchmarks & Performance Analysis

This document details empirical benchmarks and performance analysis for the **Production Zero-WAL Direct Commit Pipeline** and **Bundled WASM MapFn Architecture** in VIndex v1, followed by comparative analysis against the retired baseline WAL and per-leaf mapping architectures.

---

## 1. Headline Metrics & Key Highlights

The production Zero-WAL architecture streams mapped leaf entries directly into Pebble inverted chunk records (`'c'`) with synchronous durability barriers (`pebble.Sync`), backed by bundled tile WebAssembly execution (`map_bundle`), host SIMD hardware SHA-256 computation, and dynamic `TileReaper` pruning over verified input tiles.

### Production Key Performance Indicators (KPIs)

| Performance Dimension | Production Result (PoR) | Comparison vs. Baseline Architecture | Impact & Significance |
| :--- | :--- | :--- | :--- |
| **Ingestion Throughput (Go SumDB)** | **240,467 leaves/sec** | +24.7% throughput gain | 54.3M leaves indexed in 3m 46s |
| **MapFn FFI CPU Overhead** | **< 1% CPU** | **Down from ~23% CPU** | FFI calls cut from 768 to 2–3 per tile |
| **MapFn Cryptography Bottleneck** | **Hardware Accelerated (0% in WASM)** | **Down from ~55% CPU in WASM** | Leverages host x86 SHA-NI / ARM Crypto SIMD |
| **Median Read Latency (P50)** | **0.780 ms** | Sub-millisecond serving | 50% lower median latency during active writes |
| **Tail Read Latency (P99, 1-to-1)** | **11.343 ms** | **~99% tail reduction** | Down from 1,214 ms under WAL compaction |
| **Tail Read Latency (P99, CT Fanout)** | **62.218 ms** | **~93% tail reduction** | Down from 847.8 ms under WAL compaction |
| **Warm Recovery (Time-to-First-Serve)** | **2.4 ms** | **Instant warm recovery** | Zero WAL replay or index rebuild on restart |
| **Pebble Storage Footprint (CT Fanout)** | **9.91 MB** | **99% space savings** | Eliminates temporary WAL bloat (down from 1.2 GB) |

---

## 2. Test Environment & Hardware Configuration

All benchmarks were conducted under a standardized local dual-process topology on dedicated multi-core NVMe hardware:

- **Host Operating System**: Linux
- **Processor Architecture**: 24-core host (`runtime.GOMAXPROCS(0) = 24`) with hardware SHA-NI / ARMv8 Crypto support
- **Storage Subsystem**: Local high-performance NVMe SSD
- **Dual-Process Topology**:
  - `vindex-hammer`: Tessera POSIX Input Log sequencer and Checkpoint Drip Proxy listening at `http://127.0.0.1:8085`.
  - `vindexd`: Verifiable Index Daemon (Ingestion, KV Indexer, Output Log Publisher, and HTTP Serving API) listening at `http://127.0.0.1:8088`.
- **Communication Channel**: Local loopback HTTP (`:8085` -> `:8088`).

---

## 3. Production Concurrency Architecture

The Zero-WAL pipeline utilizes a pipelined concurrency model to balance CPU-bound mapping against I/O-bound database persistence and cryptographic tree hashing.

### Concurrency Pipeline Diagram

```text
[Input Log / ManagedTileCache]
              │
              ▼ (Stage 1: I/O Bound Fetch)
┌─────────────────────────────────────────────────────────────┐
│ TileFetcher & Cache Pool                                    │
│ • Unpacks tiles into contiguous LeafBundles (256 leaves)    │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *LeafBundle
                               ▼ (Stage 2: CPU Bound Mapping)
┌─────────────────────────────────────────────────────────────┐
│ Mapper Worker Pool (runtime.GOMAXPROCS(0) - 1)              │
│ • 23 parallel workers on 24-core host (~4 MB RAM / worker)  │
│ • Bundled WASM map_bundle (256 leaves/call, < 1% FFI CPU)   │
│ • Host computes KeyHash = crypto/sha256 (SHA-NI / ARM SIMD) │
│ • Emits unordered MappedBatches                             │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *MappedBatch (unordered)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Resequencer Priority Queue                                  │
│ • Min-heap / ring buffer indexed by BundleIdx               │
│ • Monotonically reorders batches into gapless sequence      │
└──────────────────────────────┬──────────────────────────────┘
                               │ chan *MappedBatch (ordered)
                               ▼ (Stage 3: Database Commit Plane)
┌─────────────────────────────────────────────────────────────┐
│ Pebble KV Committer & MPT Publisher                         │
│ • Direct streaming into inverted chunks ('c')               │
│ • MPT root computation & Tessera Output Log commitment      │
└─────────────────────────────────────────────────────────────┘
```

### Worker Allocation & Reordering Mechanics

- **Mapper Worker Pool**: Defaults to `runtime.GOMAXPROCS(0) - 1` (23 parallel workers on a 24-core host). This dedicates the remaining CPU capacity to Pebble chunk writes, MPT tree updates, and live query serving without saturating host CPU cores.
- **Monotonic Resequencing via Priority Queue**: Because variable-length leaves cause parallel map workers to complete bundles out of order, the `Resequencer` buffers completed `MappedBatch` instances in a priority queue min-heap keyed by `BundleIdx`. Batches are released to the Pebble KV committer plane in strictly ascending chronological order before being committed to Pebble.
- **Backpressure Control**: Buffered Go channels connecting pipeline stages enforce backpressure automatically, preventing unbound memory growth when downstream Pebble chunk writes or MPT publishing experience disk I/O pauses.

---

## 4. Production Zero-WAL Benchmark Results

### 4.1 Full Go SumDB Ingestion & Verification

This benchmark measures full end-to-end ingestion, indexing, publication, and cryptographic verification of the entire public Go Module Sum Database (`sum.golang.org`) across local file mirror and live remote CDN sources.

#### Summary Metrics (Live Remote Ingest)

- **Total Input Leaves**: 60,965,405 leaves (100% of live Go SumDB)
- **Total Ingestion Duration**: **8m 54s (534s)**
- **Average Ingestion Throughput**: **~114,167 leaves/sec** (peaking at ~170,000 leaves/sec)
- **CPU Utilization**: ~220–230% across parallel tile fetch and map worker pool
- **Storage Footprint on Disk**:
  - Inverted Chunk DB (Pebble): **345 MB**
  - Sparse Merkle Trie (MPT): **75 MB**
  - Output Log: **8 KB**
  - Pruned Tile Cache: **28 KB** (managed by `TileReaper`)
  - **Total Storage on Disk**: **~420 MB**
- **Client Verification**: Verified across local git checkouts and cryptographic non-inclusion proofs.

#### Pipeline Breakdown & Comparison

| Ingestion Source | Total Leaves | Elapsed Time | Effective Rate | Storage Footprint | Verification Success |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Local File Mirror (Zero-WAL)** | 54,364,768 | 3m 46.08s | 240,467 leaves/s | ~380 MB | 100% |
| **Live Remote CDN (`sum.golang.org`)** | **60,965,405** | **8m 54s (534s)** | **114,167 leaves/s** | **420 MB** | **100%** |

#### Cryptographic Verification

- **Verification Results**: **100% cryptographic verification**, 0 proof errors.
- **Proofs Validated**: Checkpoint note signatures, Output Log tile inclusion proofs, Binary MPT inclusion proofs, and RFC 6962 Compact Range mini-tree root recalculation.

---

## 5. 10 Million Entry Synthetic Load Tests

### 5.1 1-to-1 Identity Mapping Baseline

A 10,000,000 leaf synthetic dataset with 1-to-1 key-to-leaf identity mapping was evaluated across four concurrent verifying read QPS tiers (0 QPS, 1 QPS, 10 QPS, 100 QPS) generated by `vindex-hammer`.

| Read Load Profile | Duration | Write Throughput | Final Serving Size | Actual Read QPS | Read Success Rate | P50 Latency | P90 Latency | P99 Latency | Max Latency | Invariant Violations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0 QPS** (Write-Only) | 80.9s | ~123,600 leaves/s | 10,000,000 | 0.0 QPS | N/A | N/A | N/A | N/A | N/A | 0 |
| **1 QPS** | 82.4s | ~121,350 leaves/s | 10,000,000 | 1.0 QPS | 100.0% | 1.4 ms | 16.2 ms | 598.1 ms | 1.2 s | 0 |
| **10 QPS** | 88.7s | ~112,740 leaves/s | 10,000,000 | 10.0 QPS | 100.0% | 1.6 ms | 45.8 ms | 812.4 ms | 3.8 s | 0 |
| **100 QPS** | 132.2s | ~111,200 leaves/s | 10,000,000 | 99.8 QPS | 100.0% | 1.8 ms | 194.3 ms | 1,214.0 ms | 11.3 s | 0 |

---

### 5.2 CT-Style 1-to-N Multi-Domain Fanout Load Test

This test simulates Certificate Transparency (CT) workloads where each certificate leaf covers multiple Subject Alternative Names (SANs), producing a 1-to-N fanout from leaf entries to search keys.

- **Input Leaves**: 10,000,000 leaves
- **Fanout Distribution**: 1 to 50 domain names per leaf (mean: ~25 domains/leaf)
- **Total Mapped Search Keys**: ~250,000,000 indexed key entries
- **Concurrent Read Load**: 100 verifying read QPS

| Metric | 1-to-1 Identity Baseline (100 QPS) | CT-Style 1-to-N Fanout (100 QPS) |
| :--- | :--- | :--- |
| **Input Leaves** | 10,000,000 | 10,000,000 |
| **Domain Fanout per Leaf** | 1 (Fixed) | 1 to 50 (Mean: ~25) |
| **Indexed Key Entries** | 10,000,000 | ~250,000,000 |
| **Input Leaf Throughput** | ~43,820 leaves/s | 12,022 leaves/s |
| **Effective Key Indexing Rate** | ~43,820 keys/s | **~300,550 search keys/s** |
| **Read Latency P50** | 1.800 ms | 1.615 ms |
| **Read Latency P90** | 194.300 ms | 24.766 ms |
| **Read Latency P99** | 1,214.000 ms | 847.847 ms |
| **Invariant Violations** | 0 | **0** |

---

## 6. Closed-Loop MapFn Profiling & Hardware Cryptography Telemetry

During development of the V1 mapping plane, detailed CPU profiling was conducted to measure the exact breakdown of CPU cycles across WASM guest execution, FFI boundary crossings, and cryptographic hashing.

### 6.1 Telemetry Findings: Baseline vs. PoR

```text
Baseline (Per-Leaf map_leaf + WASM Software SHA-256):
  ┌─────────────────────────┬─────────────────────────┬─────────────────────────┐
  │  FFI Boundary: ~23%     │  WASM Software SHA-256: │  Business Logic /       │
  │  (768 calls / tile)     │  ~55% of CPU cycles     │  Parsing: ~22%          │
  └─────────────────────────┴─────────────────────────┴─────────────────────────┘

Production PoR (Bundled map_bundle + Host Hardware SHA-NI):
  ┌──────┬────────────────────────────────────────────┬─────────────────────────┐
  │ FFI: │ Business Logic / Parsing: ~40%             │ Host Hardware SHA-256   │
  │ < 1% │ (Runs at full guest speed in WASM)         │ (SIMD SHA-NI: < 5% CPU) │
  └──────┴────────────────────────────────────────────┴─────────────────────────┘
```

### 6.2 Architectural Breakdown Table

| Dimension | Baseline Per-Leaf Mapping | PoR Bundled Tile Mapping (`map_bundle`) | Delta / Improvement |
| :--- | :--- | :--- | :--- |
| **FFI Calls per 256-Leaf Tile** | 768 calls (`allocate`, `map_leaf`, `reset` x 256) | **2–3 calls** (`allocate`, `map_bundle`, `reset`) | **99.6% fewer FFI calls** |
| **FFI CPU Time Proportion** | ~23% of total CPU time | **< 1% of total CPU time** | ~23x reduction in FFI overhead |
| **SHA-256 Execution Domain** | In-guest WebAssembly bytecode | **Go host runtime (`crypto/sha256`)** | Delegated to host SIMD |
| **Hardware Acceleration** | None (pure software bitwise in WASM) | **x86 SHA-NI / ARMv8 Crypto** | Full hardware acceleration |
| **Crypto CPU Time Proportion** | ~55% of total CPU time | **< 5% of total CPU time** | ~11x reduction in crypto overhead |

---

## 7. Comparative Analysis: Zero-WAL vs. Retired Baseline WAL

The initial V1 implementation utilized an intermediate Write-Ahead Log staged under a transient `'w'` prefix in Pebble DB, managed by a background `WalReaper`. Removing the WAL in favor of direct chunk indexing and managed tile caching yielded major architectural and performance improvements.

### Comprehensive Performance Comparison Table

| Workload Configuration | Metric | Retired Baseline WAL Architecture | Production Zero-WAL Direct Commit | Improvement / Delta |
| :--- | :--- | :--- | :--- | :--- |
| **Full Go SumDB** | **Total Wall-Clock Time** | 4m 42.00s | **3m 46.08s** | **55.92s faster (-19.8%)** |
| | **Effective Throughput** | 192,783 leaves/s | **240,467 leaves/s** | **+24.7% throughput gain** |
| | **Warm Recovery** | Cold WAL replay overhead | **2.4 ms** | **Instant warm recovery** |
| **1-to-1 Mapping (100 Read QPS)** | **Read Latency P50** | 1.800 ms | **0.905 ms** | **~50% reduction** |
| | **Read Latency P99** | 1,214.000 ms | **11.343 ms** | **~99% tail reduction** |
| | **Pebble Compaction Churn** | Continuous WAL LSM compaction | **0%** | **100% transient WAL churn eliminated** |
| **1-to-N CT Fanout (100 Read QPS)** | **Read Latency P99** | 847.847 ms | **62.218 ms** | **~93% reduction** |
| | **Pebble DB Footprint** | 1.2 GB | **9.91 MB** | **99% space savings** |

### Architectural Rationale for WAL Retirement

1. **Throughput Gain & Elimination of Double Writes**: Ingesting the complete 54,364,768 leaf Go SumDB dataset completed in **3m 46.08s** under Zero-WAL compared to **4m 42.00s** for the baseline WAL pipeline—a **55.92s reduction (-19.8% duration)** and a **+24.7% throughput gain**.
2. **Instant Warm Startup Recovery**: With Zero-WAL, daemon restarts on an existing database achieve a time-to-first-serve of **2.4 ms**. The system eliminates the costly startup phase of scanning and replaying unindexed WAL keys.
3. **Tail Latency Eradication**: Direct chunk commits eliminate transient WAL churn entirely, reducing P99 tail latencies significantly for both 1-to-1 and CT fanout scenarios.
4. **Sub-Millisecond Serving**: Median read latencies drop to sub-millisecond levels, providing excellent query responsiveness during active write ingestion.
5. **Database Footprint & Space Savings**: Eliminating temporary WAL writes reduces total Pebble DB storage overhead from 1.2 GB down to **9.91 MB** (99% space savings) in CT fanout tests. The `ManagedTileCache` working set remains bounded to `< 1 MB` under continuous `TileReaper` pruning.
6. **Cryptographic Invariant Guarantees**: Zero invariant violations occurred across all benchmark runs, validating that the direct commit model strictly preserves all Merkle tree and MPT cryptographic invariants.
