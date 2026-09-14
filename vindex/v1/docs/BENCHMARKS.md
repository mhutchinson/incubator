# VIndex v1 Benchmark Suite & Performance Specification

This document defines the formal benchmark specification, testing taxonomy, standard hardware environment, Service Level Objectives (SLOs), and execution procedures for **VIndex v1**.

> [!NOTE]
> This document records both the target Service Level Objectives (SLOs) defined during the v1 design phase and the verified empirical telemetry achieved by the resulting spec-driven implementation across real-world production logs (Go SumDB and Cloudflare MTC).

---

## Executive Summary

Validating the performance, scalability, and cryptographic correctness of a verifiable index requires a principled testing taxonomy. Historical evaluations often suffered from **methodological conflation**: synthetic microbenchmarks testing isolated data structures in memory (such as raw trie insertions or byte hashing) were conflated with multi-stage, end-to-end ingestion and query serving pipelines. This conflation obscured actual hardware bottlenecks, obscured the impact of LSM-tree compaction stalls under sustained I/O, and created misleading expectations for real-world production deployments.

The VIndex v1 Benchmark Suite resolves this conflation by partitioning performance evaluation across **four strictly isolated tiers**:

1. **Tier 1: Subsystem Microbenchmarks**: Isolates individual core components (the Pebble key-value store, the WebAssembly guest mapping runtime, and the Sparse Merkle Patricia Trie engine) to establish baseline computational and algorithmic ceilings independent of inter-process communication or pipeline queueing.
2. **Tier 2: End-to-End Ingestion Pipelines**: Evaluates full-pipeline continuous ingestion and catch-up from upstream Input Logs into committed, witnessed Output Logs under the Zero-WAL direct commit architecture, measuring sustained throughput across both low-fanout (1-to-1) and high-fanout (1-to-N) data distributions.
3. **Tier 3: Query Serving Under Active Load**: Measures read query latency percentiles (P50 and P99) and request throughput (QPS) of the C2SP HTTP read server while the daemon concurrently processes and commits maximum write ingestion traffic, requiring 100% cryptographic proof verification on all responses.
4. **Tier 4: Crash Recovery**: Evaluates the time required for the coordinator and storage engine to recover, verify durability invariants, and open the HTTP serving interface following both clean process shutdowns and abrupt dirty crashes.

---

## 1. Standard Test Environment & Hardware Specification

To ensure reproducibility across benchmark executions, all standardized tests must run on a dedicated bare-metal host conforming to the following baseline:

### 1.1 Hardware Configuration

- **Host Processor**: Dedicated 24-core / 48-thread x86_64 host (or equivalent modern multi-core architecture) with physical cores pinned or scheduled via `runtime.GOMAXPROCS(24)`.
- **Cryptographic Vector Extensions**: Host hardware SIMD acceleration for SHA-256 (Intel/AMD SHA-NI extensions or ARMv8 Cryptographic Instructions). The Go runtime must utilize hardware-accelerated SHA-256 for all tile hashing and MPT commitments.
- **Storage Subsystem**: Dedicated local NVMe Solid State Drive mounted with `ext4` or `xfs` and default write barriers enabled (`discard,noatime`). Virtualized disks (e.g. network-attached cloud block storage) introduce unpredictable hypervisor flush latency and must not be used for baseline benchmark runs.
- **Durable Barrier Policy**: Pebble batch commits must execute with synchronous disk flushing enabled (`pebble.Sync`), ensuring that reported write throughput reflects true durability rather than volatile page-cache buffering.

### 1.2 Network & Communication Topology

- **Dual-Process Loopback Harness**: All integration tests execute as two distinct operating system processes communicating over local loopback TCP (`127.0.0.1`):
  - **Upstream Producer**: The [`vindex-hammer`](../hammer/README.md) test harness serves standard C2SP `tlog-tiles` endpoints on port `:8085`.
  - **System Under Test**: The `vindexd` indexing daemon serves C2SP query endpoints on port `:8088`.
- **Rationale**: The loopback topology eliminates wide-area network jitter, transit latency, and external CDN throttling while fully exercising the operating system network stack, HTTP/1.1 transport pooling, socket buffers, and connection concurrency.

### 1.3 Concurrency & Pipeline Scheduling Model

VIndex divides processing across discrete pipeline stages, allocating goroutines and CPU cores as follows:

| Stage | Subsystem | Resource Allocation & Concurrency | Role |
| :--- | :--- | :--- | :--- |
| **Stage 1** | [`internal/ingest`](../internal/ingest/README.md) | I/O-bound goroutines | Downloads 256-leaf tiles from upstream HTTP server into local tile cache. |
| **Stage 2** | [`mapfn`](../mapfn/README.md) & [`internal/ingest`](../internal/ingest/README.md) | `GOMAXPROCS - 1` worker pool | Executes WASM `map_bundle` in Wazero; offloads preimage hashing to host SIMD SHA-256. |
| **Stage 2b** | [`internal/ingest`](../internal/ingest/README.md) | Single in-memory goroutine | Min-heap priority queue re-sequences finished tile bundles into strictly monotonic order. |
| **Stage 3** | [`internal/kvstore`](../internal/kvstore/README.md) | Key-partitioned hashing pool + single committer | Concurrently evaluates mini-log compact ranges across distinct keys; sequentially commits inverted chunk records via `pebble.Sync`. |
| **Stage 4** | [`internal/tree`](../internal/tree/README.md) | Single publisher goroutine | Predicts `MapRoot` lock-free, appends to Output Log, and ratchets trie under short write lock (< 5 ms). |
| **Stage 5** | [`internal/server`](../internal/server/README.md) | Concurrent HTTP worker pool | Serves C2SP read queries under shared read lock (`treeMu.RLock()`). |

### 1.4 Standard Milestone Taxonomy (One-Shot Catch-Up Mode)

To eliminate methodological conflation during one-shot bulk indexing evaluations, benchmarks decompose end-to-end execution into five deterministic milestones corresponding to subsystem completion:

- **Milestone 1 (M1): Tile Ingestion & Mapping 100% Complete (`internal/ingest` + `mapfn`)**:
  All 256-leaf tiles are fetched from upstream, executed through `map_bundle` in Wazero, and re-sequenced into strict monotonic order. Observable when `pipeline.StreamBatches` finishes streaming all bundles and closes the reader channel (`vindex_leaves_mapped_total == Target_Size`).
- **Milestone 2 (M2): KV Store Synced & Durable (`internal/kvstore`)**:
  The dedicated committer goroutine drains all batches, updates inverted chunk records (`'c' + KeyHash + ^chunkNum`), commits atomic SSTable batches to Pebble, and executes `pebble.Sync` to persist `m_kv_size = Target_Size`. Marks the completion of the ingestion phase (`vindex_kv_committed_size == Target_Size`).
- **Milestone 3 (M3): State Commitment Predicted (`internal/tree` - Pass 1)**:
  Radix sorting of dirty key hashes completes (`SortKeyVals`), followed by speculative lock-free calculation of the Patricia Trie root hash across all accumulated mutations (`mptMgr.PredictKeyVals`, tracked by `vindex_mpt_predict_duration_seconds`).
- **Milestone 4 (M4): Output Log Appended & Witnessed (`internal/tree` + `witness`)**:
  The state commitment leaf (`MapRoot` + `InputLogCP`) is formatted, appended to POSIX storage (`outputLog.Append`), signed by remote witnesses if configured, and inclusion proof is fetched (`vindex_output_log_append_duration_seconds`).
- **Milestone 5 (M5): MPT Ratcheted & State Promoted / Time-to-Serve (`internal/tree` - Pass 2 + `server`)**:
  Under write lock (`treeMu.Lock()`), changes are applied to the trie (`CommitKeyValsLocked`), `tree.Snap` writes mmap files to disk, root hash equality is asserted, and the active serving state is ratcheted (`pub.SetServingState`). The read server is now live and serving cryptographic inclusion proofs (`vindex_serving_tree_size == Target_Size`). Wall clock from process launch to M5 defines total **Time-to-First-Serve**.

---

## 2. Standard Benchmark Matrix

The following matrix defines the standard suite of benchmarks, their component scope, workload profiles, target Service Level Objectives (SLOs), and performance budgets. All measured result fields are designated for re-evaluation under the unified test runner.

| Benchmark Tier | Benchmark Name | Subsystem Scope | Workload Profile | Target SLO / Performance Budget | Measured Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Subsystem Microbenchmarks** | Raw KV Inverted Storage | [`internal/kvstore`](../internal/kvstore/README.md) | Direct batch writes to Pebble inverted chunks (`'c' + KeyHash + ^chunkNum`); 64K-entry chunk roll-overs; 16-bit relative index encoding; `pebble.Sync` barrier. | >= 150,000 index entries/s sustained; zero compaction stalls exceeding 100 ms. | `TODO (Pending Reimplementation)` |
| **Tier 1: Subsystem Microbenchmarks** | WASM Mapping Overhead | [`mapfn`](../mapfn/README.md) | 256-leaf tile batch execution (`map_bundle`); linear memory pack-and-wipe; host SIMD SHA-256 preimage extraction; Wazero compilation mode. | Boundary crossing CPU overhead < 1% total CPU; >= 50,000 leaves/s per CPU core. | `TODO (Pending Reimplementation)` |
| **Tier 1: Subsystem Microbenchmarks** | MPT Commit Duration | [`internal/tree`](../internal/tree/README.md) | Binary Sparse Merkle Patricia Trie path mutation; lock-free root prediction (`mpt.Predict`); 4,096-leaf mutation batch commit. | Root prediction < 10 ms for 4K leaves; exclusive lock duration (`treeMu.Lock()`) < 5 ms. | `TODO (Pending Reimplementation)` |
| **Tier 2: End-to-End Ingestion Pipelines** | Go SumDB (Low-Fanout 1-to-1) | Full Engine (`ingest`, `mapfn`, `kvstore`, `tree`, `coordinator`) | Stream public Go Checksum Database mirror (54M+ leaves); 1-to-1 key-to-leaf mapping; continuous tile fetch, map, commit, and witness publishing. | Local Mirror: >= 200,000 leaves/s; Remote Loopback: >= 100,000 leaves/s; Peak RSS < 512 MB. | **Pure Go**: **295,241.2 leaves/s** (54,364,768 leaves in 3m 04.34s; total 3m 30.79s)<br>**WASM (Parallel Fetch)**: **288,589.5 leaves/s** (54,364,768 leaves in 3m 08.38s; total 4m 00.66s)<br>**WASM (Single Fetch)**: **257,985.4 leaves/s** (54,364,768 leaves in 3m 33.58s; total 3m 58.87s)<br>**MVP**: **172,193.3 leaves/s** (54,364,768 leaves in 5m 15.72s; total 6m 36.01s) |
| **Tier 2: End-to-End Ingestion Pipelines** | Merkle Tree Certificates / CT (High-Fanout 1-to-N) | Full Engine (`ingest`, `mapfn`, `kvstore`, `tree`, `coordinator`) | Stream Cloudflare MTC Shard 3 log (257.8M+ leaves, ~74 GB); ASN.1 DER X.509 certificate parsing; 1-to-N mapping (SAN domains down to eTLD+1); heavy chunk roll-overs. | >= 40,000 certs/s; 33-byte prefix Bloom filter seek efficiency >= 99%; Peak RSS < 4 GB. | **WASM (`mtc.wasm`)**: **146,214.2 leaves/s** (257,823,832 leaves in 29m 23.33s; Peak RSS 3.08 GB; Pebble DB 1.7 GB) |
| **Tier 3: Query Serving Under Active Load** | Point Lookup Latency (P50/P99) | [`internal/server`](../internal/server/README.md) & [`client`](../client/README.md) | Single-chunk lookup (`GET /vindex/v1/lookup/{keyhash}`) under 100% active ingestion write load; client verifies checkpoint, MPT proof, and mini-log. | Median (P50) < 1.0 ms; Tail (P99) < 15.0 ms; 0 cryptographic or monotonicity failures. | `TODO (Pending Reimplementation)` |
| **Tier 3: Query Serving Under Active Load** | High-Fanout Paged Lookup (P50/P99) | [`internal/server`](../internal/server/README.md) & [`client`](../client/README.md) | Backward pagination (`before=X`) across multi-chunk historical records (> 65,536 entries per key) under concurrent ingestion compaction load. | Median (P50) < 5.0 ms; Tail (P99) < 75.0 ms; 0 cryptographic or monotonicity failures. | `TODO (Pending Reimplementation)` |
| **Tier 3: Query Serving Under Active Load** | Max Read Concurrency QPS | [`internal/server`](../internal/server/README.md) | Query saturation test with concurrent HTTP workers querying static committed checkpoint across 24 cores over loopback. | >= 10,000 QPS per single node process; sub-5ms P50 latency. | `TODO (Pending Reimplementation)` |
| **Tier 4: Crash Recovery** | Warm Restart Time-to-First-Serve | [`internal/coordinator`](../internal/coordinator/README.md) | Clean process shutdown where MPT persisted size matches Output Log checkpoint size (`mptPersistedSize == S_OUT`); verify and start HTTP server. | Time-to-first-serve < 5.0 ms; zero tile replays or index rebuilds required. | `TODO (Pending Reimplementation)` |
| **Tier 4: Crash Recovery** | Dirty Crash Fast-Forward Replay | [`internal/coordinator`](../internal/coordinator/README.md) | Abrupt `SIGKILL` mid-batch; restart engine; replay uncommitted tiles from durable local cache; verify MPT subroots and ratchet state. | Time-to-first-serve < 500.0 ms; zero data loss; zero upstream network re-fetches. | `TODO (Pending Reimplementation)` |

---

## 3. Test Methodology & Execution Procedures

### 3.1 Subsystem Microbenchmark Harnesses

#### A. Inverted KV Storage Benchmark (`internal/kvstore`)
Tests the ingestion and lookup performance of the Pebble-backed inverted index without WASM or MPT overhead:

```bash
# Run raw KV inverted storage benchmarks with bitwise chunk inversion
go test -v -benchmem -run=^$ \
  -bench=^BenchmarkInvertedStorage \
  ./vindex/v1/internal/kvstore/...
```

Parameters evaluated:
- Write throughput across uniform random 32-byte keyhashes versus skewed key distributions.
- Seek latency when finding the most recent chunk (`'c' + KeyHash + 0x00...`) using the 33-byte prefix Bloom filter.
- Impact of chunk rollovers at the 65,536-entry boundary with 16-bit relative index encoding.

#### B. WASM Mapping Engine Harness (`cmd/vindex-wasm`)
Measures the pure execution latency and memory allocation overhead of guest WASM plugins:

```bash
# Benchmark WASM plugin bundle execution and memory arena reset
go run ./vindex/v1/cmd/vindex-wasm bench \
  --wasm=./vindex/v1/mapfn/examples/sumdb/sumdb.wasm \
  --iterations=10000 \
  --workers=4
```

Parameters evaluated:
- FFI boundary transitions per 256-leaf tile bundle (target: <= 3 FFI calls per tile).
- Host SIMD SHA-256 offload latency versus software in-guest hashing.
- Memory allocation rate within the guest linear memory arena (`pack-and-wipe` lifecycle).

#### C. MPT Tree Commitment Benchmark (`internal/tree`)
Evaluates Sparse Merkle Patricia Trie path mutations and root calculation:

```bash
# Benchmark lock-free root prediction and tree commitment
go test -v -benchmem -run=^$ \
  -bench=^BenchmarkMPTCommit \
  ./vindex/v1/internal/tree/...
```

Parameters evaluated:
- Duration of speculative root calculation (`mpt.Predict`) across 1,024, 2,048, and 4,096 leaf mutation batches.
- Critical section duration during write lock acquisition (`treeMu.Lock()`) when swapping the active serving root pointer.

---

### 3.2 End-to-End Pipeline & Stress Testing (`hammer`)

The primary harness for Tier 2 (Ingestion), Tier 3 (Serving under load), and Tier 4 (Recovery) is the [`vindex-hammer`](../hammer/README.md) crash test rig.

#### A. Synthetic Workload Generation (Zipfian Distribution)
Real package ecosystems and certificate transparency logs exhibit heavy key skew, where a small fraction of popular keys receive a majority of entries. To model this, the hammer generator implements a power-law Zipfian distribution:

- **Skew Parameter**: `s = 1.2` (models heavy Pareto tail).
- **Target Key Space**: 10,000 unique keys across 1,000,000 generated leaves.
- **Stress Vector**: Forces hot keys across multiple 65,536-entry chunk boundaries (`^0 -> ^1 -> ^2`), validating chunk splitting, reverse chronological ordering, and SSTable compaction under maximum write amplification.

```bash
# Start the vindex-hammer upstream producer with Zipfian skew and drip scheduling
vindex-hammer \
  --mode=producer \
  --listen=127.0.0.1:8085 \
  --num_leaves=1000000 \
  --zipf_s=1.2 \
  --drip_rate=20 \
  --checkpoint_interval=1000
```

#### B. Concurrent Ingestion and Verification Runner
While `vindexd` ingests from the hammer upstream producer, a pool of concurrent client workers issues verifying queries against `vindexd`:

```bash
# Start vindexd pointing to the hammer producer
vindexd \
  --input_log_url=http://127.0.0.1:8085 \
  --db_dir=/tmp/vindex-bench/db \
  --tile_dir=/tmp/vindex-bench/tiles \
  --listen=127.0.0.1:8088 \
  --wasm_plugin=./vindex/v1/mapfn/examples/sumdb/plugin.wasm

# Launch verifying read hammer against vindexd
vindex-hammer \
  --mode=reader \
  --vindex_url=http://127.0.0.1:8088 \
  --read_qps=500 \
  --read_workers=24 \
  --verify_proofs=true \
  --assert_monotonic=true
```

#### C. Invariant Assertion Rules
The reader worker pool enforces zero-tolerance correctness invariants on 100% of read queries:
1. **Cryptographic Proof Validity**: Every Output Log checkpoint signature, Merkle inclusion proof, MPT inclusion/non-inclusion proof, and RFC 6962 compact range root must verify cleanly using [`client.Verifier`](../client/README.md).
2. **Monotonic History Invariant**: For subsequent queries on the same key where `S_new >= S_old`, the returned index set `I_new` must be a strict superset of `I_old`, with an identical historical prefix:
   ```text
   I_new[0 : len(I_old)] == I_old
   ```
3. **Zero Read Starvation**: Point lookup latency must not drop requests or exceed timeouts during peak LSM compaction or tile commit cycles.

---

### 3.3 Real-World Ecosystem Dataset Evaluation

In addition to synthetic workloads, the benchmark suite evaluates complete mirrors of production transparency logs:

#### A. Go SumDB Mirror Dataset
- **Workload Type**: Low-fanout 1-to-1 key mapping (module path to version record).
- **Dataset Size**: Full mirror of `sum.golang.org` (> 54 million leaves, ~15 GB tile mirror).
- **Execution Commands**:
  ```bash
  # Option 1: Native Pure Go MapFn (cmd/sumdbindex)
  /usr/bin/time -v go run ./vindex/v1/cmd/sumdbindex \
    --input_override_url="file:///path/to/sumdb/mirror" \
    --storage_dir=/tmp/vindex-sumdb \
    --oneshot

  # Option 2: Isolated WASM MapFn (vindexd, Parallel Fetch)
  /usr/bin/time -v go run ./vindex/v1/cmd/vindexd \
    --mode=publisher \
    --input_log_url="file:///path/to/sumdb/mirror" \
    --input_log_origin="go.sum database tree" \
    --input_log_pubkey="sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8" \
    --wasm_path="./vindex/v1/mapfn/examples/sumdb/sumdb.wasm" \
    --output_log_signer_key="PRIVATE+KEY+SumDBIndex+a5ed0e81+AYT6tfHpqGaSoH0gYpM7fhj1tEkM3wwYR/IhtiYh1pnj" \
    --output_log_dir=/tmp/vindex-sumdb/outlog \
    --db_path=/tmp/vindex-sumdb/db \
    --mpt_dir=/tmp/vindex-sumdb/mpt \
    --tile_cache_dir=/tmp/vindex-sumdb/tiles \
    --fetch_workers=4 \
    --oneshot

  # Option 3: Isolated WASM MapFn (vindexd, Single Fetch)
  # (Identical to Option 2 with --fetch_workers=1)
  ```

- **Comparative Telemetry (54,364,768 Leaves)**:

  | Pipeline Milestone / Phase | MVP (`cmd/sumdbindex`) | v1 Streaming WASM (Single Fetch) | v1 Streaming WASM (Parallel Fetch) | v1 Pure Go (`cmd/sumdbindex`) |
  | :--- | :--- | :--- | :--- | :--- |
  | **M1/M2: Ingestion & KV Store Synced** | 5m 15.72s (315.72s) | 3m 33.58s (213.58s) | **3m 08.38s** (188.38s) | **3m 04.34s** (184.34s) |
  | **Sustained Mapping Rate** | 172,193.3 leaves/s | 257,985.4 leaves/s | **288,589.5 leaves/s** | **295,241.2 leaves/s** |
  | **M3: MPT Root Prediction (Lock-Free)** | N/A (Flat SHA-256) | ~26s *(Omitted from legacy total)* | **26.10s** (`vindex_mpt_predict_duration_seconds`) | ~26s *(Omitted from legacy total)* |
  | **M4: Output Log Append & Proof** | < 0.01s | < 0.01s | **< 0.01s** (`vindex_output_log_append_duration_seconds`) | < 0.01s |
  | **M5: MPT Commit & Snap (Write Lock)** | 1m 20.27s (80.27s) | 26.04s (`vindex_mpt_write_duration_seconds`) | **26.18s** (`vindex_mpt_write_duration_seconds`) | **26.37s** (`vindex_mpt_write_duration_seconds`) |
  | **State Commitment Wall Clock (M3+M4+M5)** | 1m 20.27s (80.27s) | 26.04s *(Omitted M3 pass)* | **52.28s** *(Full end-to-end publish)* | 26.37s *(Omitted M3 pass)* |
  | **Time-to-First-Serve (Total M1..M5)** | 6m 36.01s (396.01s) | 3m 58.87s *(Legacy M1+M2+M5)* | **4m 00.66s** (240.66s) | 3m 30.79s *(Legacy M1+M2+M5)* |
  | **Overall Ingestion Throughput** | 137,280.0 leaves/s | 227,572.2 leaves/s | **225,898.6 leaves/s** | **257,909.6 leaves/s** |
  | **Peak Resident Set Size (RSS)** | 964.3 MB (987,396 KB) | 1,227.4 MB (1,256,840 KB) | **2,862.0 MB** (2,930,680 KB) | **573.5 MB** (587,328 KB) |
  | **CPU Utilization** | 130% | 771% | **1017%** | 297% |
  | **MapRoot Value Scheme** | Flat SHA-256 concatenation | RFC 6962 mini-log Merkle sub-roots | RFC 6962 mini-log Merkle sub-roots | RFC 6962 mini-log Merkle sub-roots |
  | **MapRoot Determinism** | `ca457ef353b030ffe655818d0fdb71aea5d10cb8593123ad4cbc557701721c86` | `24357c2aa5d759b956559f32cbc9d37d7836606adce3362face32411dc076cfd` | `24357c2aa5d759b956559f32cbc9d37d7836606adce3362face32411dc076cfd` | `24357c2aa5d759b956559f32cbc9d37d7836606adce3362face32411dc076cfd` |
  | **Serving Point Lookup Latency** | < 1.0 ms | < 1.0 ms | < 1.0 ms | < 1.0 ms |

#### B. Merkle Tree Certificates (MTC) / Certificate Transparency Mirror Dataset
- **Workload Type**: High-fanout 1-to-N mapping (X.509 certificate to SAN domain names and hierarchical sub-roots down to eTLD+1).
- **Dataset Size**: Full mirror of Cloudflare MTC Shard 3 (`bootstrap-mtca.cloudflareresearch.com/logs/shard3`): **257,823,832 leaves (~74 GB)**.
- **Execution Command**:
  ```bash
  /usr/bin/time -v vindexd \
    --mode=publisher \
    --input_log_url="file:///path/to/log-clones/mtc" \
    --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
    --input_log_pubkey="mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=" \
    --wasm_path="./vindex/v1/mapfn/examples/mtc/mtc.wasm" \
    --output_log_dir="/path/to/outputlog" \
    --output_log_origin="mtc-output-log" \
    --output_log_signer_key="/path/to/signer.priv" \
    --db_path="/path/to/pebble" \
    --mpt_dir="/path/to/mpt" \
    --oneshot=true
  ```

- **Telemetry & Production Performance (257,823,832 Leaves)**:

  | Pipeline Phase / Metric | v1 Streaming WASM (`mtc.wasm`) | Production Target / SLO |
  | :--- | :--- | :--- |
  | **Total Ingestion Wall Time** | **29m 23.33s** (1,763.33s) | < 2h 00m |
  | **Overall Ingestion Throughput** | **146,214.2 leaves/s** | >= 40,000 leaves/s |
  | **Peak Leaf Ingestion Rate** | **147,403.9 leaves/s** | Sustained streaming rate |
  | **Total Processed Entries** | **257,823,832 leaves** | 100% full log coverage |
  | **Peak Resident Set Size (RSS)** | **3.08 GB** (3,227,212 KB) | < 4.0 GB |
  | **Pebble Storage Footprint** | **1.7 GB** (inverted chunks + Bloom filters) | Compact relative offsets |
  | **Sparse MPT Footprint** | **616 KB** | In-memory binary trie |
  | **CPU Utilization** | **1358%** (~13.6 cores across 24 threads) | Multi-core Wazero pool (23 workers) |
  | **User / System CPU Time** | 22,551.74s User / 1,397.21s System | High CPU efficiency |
  | **Output MapRoot** | `0f0770cf43b9f9899860a0f2b1a41104bd97497ed5bad76f9f6b1d4933a4d1e0` | Cryptographically committed |
  | **Point Lookup Latency** | **< 1.0 ms** (P50 non-inclusion) | Cryptographic proof verified |

---

## 4. Reporting & Verification Requirements

When executing benchmark runs to populate the Standard Benchmark Matrix:

1. **Hardware Telemetry**: All benchmark reports must capture CPU model, core frequency, RAM capacity, NVMe model, kernel version, and Go runtime version (`go version`).
2. **Resource Accounting**: Measurements must report wall duration, user CPU time, system CPU time, average CPU utilization percentage, peak Resident Set Size (RSS) captured via `/usr/bin/time -v`, and final on-disk database footprint.
3. **Latency Percentiles**: Read query latency must report distribution percentiles (P50, P90, P99, Max) computed from a minimum of 100,000 executed client requests under active write load.
4. **Zero-Failure Gate**: Any run encountering an invariant violation, cryptographic proof mismatch, or unhandled panics is marked invalid and fails the evaluation gate.
