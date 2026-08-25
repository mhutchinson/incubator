# VIndex v1 Benchmarks & Empirical Evaluation

This document details empirical benchmarks, real-world workload evaluations, comparative analysis against retired architectural baselines, and capacity sizing telemetry for **VIndex v1**.

---

## 0. Headline Metrics & Key Highlights

The production Zero-WAL direct commit pipeline streams mapped leaf entries directly into Pebble inverted chunk records (`'c'`) with synchronous durability barriers (`pebble.Sync`), backed by bundled tile WebAssembly execution (`map_bundle`), host hardware SIMD SHA-256 computation, and dynamic `TileReaper` pruning over verified input tiles.

### Production Key Performance Indicators (KPIs)

| Performance Dimension | Production Result (PoR) | Comparison vs. Baseline Architecture | Impact & Significance |
| :--- | :--- | :--- | :--- |
| **Ingestion Throughput (Go SumDB Mirror)** | **240,467 leaves/sec** | +24.7% throughput gain | 54.3M leaves indexed in 3m 46s |
| **Ingestion Throughput (Live CDN)** | **~114,167 leaves/sec** | Network-saturating ingestion | 60.9M leaves indexed in 8m 54s over HTTP |
| **MapFn FFI CPU Overhead** | **< 1% CPU** | **Down from ~23% CPU** | Boundary crossings cut from 768 to 2–3 per tile |
| **MapFn Cryptography Bottleneck** | **0% CPU in WASM** | **Down from ~55% CPU in WASM** | Leverages host x86 SHA-NI / ARMv8 Crypto SIMD |
| **Median Read Latency (P50)** | **0.780 ms** | Sub-millisecond serving | 50% lower median latency during active writes |
| **Tail Read Latency (P99, 1-to-1)** | **11.343 ms** | **~99% tail reduction** | Down from 1,214 ms under WAL compaction stalls |
| **Tail Read Latency (P99, CT Fanout)** | **62.218 ms** | **~93% tail reduction** | Down from 847.8 ms under WAL compaction stalls |
| **Warm Recovery (Time-to-First-Serve)** | **2.4 ms** | **Instant warm recovery** | Zero WAL replay or index rebuild on restart |
| **Pebble Storage Footprint (CT Fanout)** | **9.91 MB** | **99% space savings** | Eliminates temporary WAL bloat (down from 1.2 GB) |

---

## 1. Test Environment & Hardware Configuration

All benchmarks were conducted under a standardized local dual-process topology on dedicated multi-core hardware:

- **Host Operating System**: Linux
- **Processor Architecture**: 24-core host (`runtime.GOMAXPROCS(0) = 24`) with hardware SHA-NI / ARMv8 Crypto support
- **Storage Subsystem**: Dedicated local NVMe Solid State Drive
- **Dual-Process Topology**:
  - `vindex-hammer`: Tessera POSIX Input Log sequencer and Checkpoint Drip Proxy listening on `http://127.0.0.1:8085`.
  - `vindexd`: Verifiable Index Daemon (Ingestion, KV Indexer, Output Log Publisher, and HTTP Serving API) listening on `http://127.0.0.1:8088`.
- **Communication Channel**: Local loopback HTTP (`:8085` -> `:8088`).

### Concurrency Pipeline Topology

| Stage | Subsystem | Physical Role | Concurrency Allocation |
| :--- | :--- | :--- | :--- |
| **Stage 1** | `internal/ingest` | Fetches tiles over HTTP; unpacks into 256-leaf `LeafBundle`s. | I/O-bound background goroutines |
| **Stage 2** | `mapfn` | Maps bundles via Wazero `map_bundle`; Go host executes SIMD SHA-256. | `GOMAXPROCS - 1` parallel workers (23 workers) |
| **Stage 2b** | `internal/ingest` | Min-heap priority queue re-sequences finished batches. | In-memory priority queue |
| **Stage 3** | `internal/kvstore` | Batches updates into Pebble inverted chunks (`'c'`) with `pebble.Sync`. | Single sequential write committer |
| **Stage 4** | `internal/tree` | Predicts `MapRoot` lock-free; appends Output Log; ratchets trie under < 5ms lock. | Publisher goroutine |
| **Stage 5** | `internal/server` | Serves C2SP HTTP lookups under `treeMu.RLock()`. | Concurrent HTTP server threads |

---

## 2. Production End-to-End Workload Results

### 2.1 Full Go SumDB Ingestion & Verification
This benchmark evaluated end-to-end ingestion, indexing, state commitment, and cryptographic verification of the entire public Go Module Checksum Database (`sum.golang.org`):

#### Live Remote CDN Ingest:
- **Total Input Leaves**: 60,965,405 leaves (100% of live Go SumDB)
- **Total Ingestion Duration**: **8m 54s (534s)**
- **Average Ingestion Throughput**: **~114,167 leaves/sec** (peaked at ~170,000 leaves/sec)
- **CPU Utilization**: ~220–230% across parallel tile fetch and map worker pool
- **Storage Footprint on Disk**:
  - Inverted Chunk DB (Pebble): **345 MB**
  - MPT Storage (`mmap` working files): **~1.1 GB**

#### Local File Mirror Ingest:
- **Total Input Leaves**: 54,345,728 leaves
- **Total Ingestion Duration**: **3m 46s (226s)**
- **Average Ingestion Throughput**: **240,467 leaves/sec**
- **Bottleneck**: Saturated local NVMe sequential write bandwidth; zero FFI or lock contention bottlenecks.

### 2.2 Certificate Transparency (High-Fanout Stress Test)
Evaluated mapping certificates with 1-to-N fanout (average 15 SAN domains per certificate):
- **Write Throughput**: Sustained ~85,000 leaves/sec (~1,275,000 index updates/sec into Pebble DB).
- **Compaction Behavior**: 33-byte prefix Bloom filters eliminated read amplification during active chunk location.
- **P99 Read Latency**: Maintained at **62.2ms** during peak ingestion.

### 2.3 Concurrent Read-Write Latency Profile
Measured read query latency for `GET /vindex/lookup/{keyhash}` under full ingestion write load:

| Metric | Production Result | Baseline WAL Architecture | Change |
| :--- | :--- | :--- | :--- |
| **P50 Latency (Median)** | **0.780 ms** | 1.540 ms | **50% faster** |
| **P90 Latency** | **2.140 ms** | 14.200 ms | **85% faster** |
| **P99 Latency (1-to-1)** | **11.343 ms** | 1,214.000 ms | **99% tail reduction** |
| **P99 Latency (1-to-N Fanout)** | **62.218 ms** | 847.800 ms | **93% tail reduction** |

Under the baseline WAL architecture, periodic LSM level compactions caused severe disk stalls, pushing P99 read latency beyond 1.2 seconds. The Zero-WAL direct inverted commit pipeline eliminates intermediate compaction debt, keeping P99 tail latency under 12ms for 1-to-1 keys.

### 2.4 Time-to-First-Serve Crash Recovery
Tested recovery latency across clean and dirty shutdown scenarios:
- **Clean Restart (Phase 1 Instant Warm Start)**: **2.4 ms**. The coordinator verifies `mptPersistedSize == S_OUT` and opens the HTTP read server immediately.
- **Dirty Hard Kill (Phase 2 Fast-Forward Replay)**: **< 480 ms**. The coordinator replays un-synced tiles from the local disk cache, queries `store.GetSubRoot` to rebuild in-memory MPT nodes, asserts root equality, and opens the read server in under 500 milliseconds with zero network requests.

---

## 3. Empirical Architectural Comparisons

### 3.1 Zero-WAL Direct Commit vs. Intermediate WAL ('w' Prefix & WalReaper)
- **Baseline Architecture**: Staged mapped key-index updates under a temporary `'w'` prefix in Pebble DB. An asynchronous background goroutine (`WalReaper`) read `'w'` records, aggregated them, and wrote them to inverted chunk records (`'c'`).
- **Telemetry Findings**:
  1. **Double-Write Amplification**: Every entry was written twice to disk, doubling NVMe write bandwidth consumption.
  2. **Compaction Stalls**: Staging churn generated excessive small SSTable files, overwhelming Pebble's background compactor and causing periodic 1.2-second write/read stalls.
  3. **Storage Bloat**: Temporary WAL records accumulated up to 1.2 GB of disk space during catch-up before the reaper could process them.
- **Production Zero-WAL Impact**: Direct commits reduced Pebble disk footprint from 1.2 GB to **9.91 MB** during tests and slashed P99 read latency from 1,214ms to **11.3ms**.

### 3.2 Bundled FFI (`map_bundle`) vs. Per-Leaf FFI (`map_leaf`)
- **Baseline Architecture**: Invoked an exported guest function `map_leaf(ptr, len)` individually for every log leaf.
- **Telemetry Findings**:
  - Processing a 256-leaf tile generated 768 FFI calls (`alloc` + `map_leaf` + `reset` x 256).
  - CPU profiling revealed that **~23% of total host CPU time** was consumed purely by boundary crossing overhead.
- **Production `map_bundle` Impact**: Passing all 256 leaves in a single contiguous memory slab reduced FFI crossings to 2–3 per tile, dropping FFI CPU overhead to **< 1%**.

### 3.3 Host Hardware SIMD Cryptography vs. In-Guest Software Crypto
- **Baseline Architecture**: Compiled SHA-256 cryptographic hashing libraries directly into the guest WebAssembly bytecode.
- **Telemetry Findings**:
  - Software bitwise hashing inside WebAssembly bytecode consumed **~55% of all CPU cycles** during the mapping phase due to the lack of hardware vector instructions.
- **Production Host SIMD Impact**: Having the guest emit raw canonical string preimages and delegating hashing to the Go host runtime (backed by x86 SHA-NI / ARMv8 Crypto instructions) completely eliminated the 55% WASM CPU bottleneck.

### 3.4 Normal Serving Mode vs. Retired Backfill Mode
A dedicated bulk ingestion mode ("Backfill Mode") was evaluated on the full 61.7M-leaf Go SumDB dataset to test whether bypassing root prediction would accelerate genesis catch-up:

| Evaluation Metric | Normal Serving Mode (Production) | Backfill Mode (Retired) | Empirical Advantage |
| :--- | :--- | :--- | :--- |
| **Ingestion Throughput** | **90,797 leaves/sec** | 49,064 leaves/sec | **Normal Mode is 85.1% Faster** |
| **Read Availability** | **100% Available** (P50 < 2ms) | **0% Available** (100% Starvation) | Full query availability during catch-up |
| **RAM Footprint (RSS)** | ~220 MB | ~195 MB | Statistically negligible (~25 MB) |
| **Code Surface** | Unified single-pipeline | Split dual-pipeline | Eliminates redundant ingestion code |

*Conclusion*: Normal Serving Mode was 85.1% faster because streaming leaf bundles and batching storage updates amortized overhead efficiently, while Backfill Mode's un-batched in-memory trie mutations throttled ingestion while completely starving HTTP readers. Backfill Mode was permanently retired in favor of unified normal serving mode catch-up.

### 3.5 Pebble Storage Layouts (`pebble-tests` Suite)
Benchmarks from [github.com/mhutchinson/pebble-tests](https://github.com/mhutchinson/pebble-tests) across 20M entries demonstrated the superiority of bitwise key inversion (`^chunkNum`) over forward chronological ordering:

| Workload Mode (1M Entries) | Engine | Write Throughput | Write Latency (p50) | Write Latency (p99) |
| :--- | :--- | :---: | :---: | :---: |
| **Mode A** *(10 hot keys)* | `chunk_scan` | 190,912 QPS | 2.93 ms | 103.78 ms |
| | **`inverted_prefix_chunk_scan`** | 175,523 QPS | 3.37 ms | 107.45 ms |
| **Mode B** *(1M sparse keys)* | `chunk_scan` | 27,923 QPS | 35.96 ms | 105.03 ms |
| | **`inverted_prefix_chunk_scan`** | **41,431 QPS (+48.4%)** | **23.73 ms** | **45.97 ms** |
| **Mode C** *(100k mixed keys)* | `chunk_scan` | 40,144 QPS | 21.83 ms | 85.38 ms |
| | **`inverted_prefix_chunk_scan`** | **64,446 QPS (+60.5%)** | **13.66 ms** | **66.60 ms** |

---

## 4. Operational Sizing & Capacity Planning Guide

Based on production telemetry across real-world logs, hardware capacity requirements scale predictably with unique key cardinality:

| Scale (Unique Keys) | Inverted Chunk DB (Pebble) | MPT Storage (`mmap`) | Recommended System RAM | Target Hardware Spec |
| :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1 GB | ~1.04 GB | 8 GB | 2-4 vCPU, 8 GB RAM, NVMe |
| **Medium (100M)** | ~10 GB | ~10.4 GB | 64 GB | 8-16 vCPU, 64 GB RAM, NVMe |
| **Large (1B)** | ~100 GB | ~104 GB | 256 GB | 16-32 vCPU, 256 GB RAM, Dual NVMe |
| **Very Large (2B)** | ~200 GB | ~208 GB | 512+ GB | 32-64 vCPU, 512 GB RAM, Dual NVMe |

### Key Capacity Planning Rules:
1. **MPT RAM Residency**: While leaf payloads reside in `mmap` files, uniform 32-byte key hash distribution scatters lookups across trie branch nodes. Ensure sufficient host RAM to cache active branch levels.
2. **Dual NVMe Physical Separation**: For high-velocity logs (>50,000 writes/sec), deploy Pebble DB on NVMe Disk A and MPT working files on NVMe Disk B to prevent compaction I/O contention.
