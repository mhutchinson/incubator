# VIndex v1 Benchmark Suite & Performance Specification

This document defines the formal benchmark specification, testing taxonomy, standard hardware environment, Service Level Objectives (SLOs), and execution procedures for **VIndex v1**.

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
| **Stage 3** | [`internal/kvstore`](../internal/kvstore/README.md) | Single sequential committer | Appends inverted chunk records (`'c' + KeyHash + ^chunkNum`) and commits via `pebble.Sync`. |
| **Stage 4** | [`internal/tree`](../internal/tree/README.md) | Single publisher goroutine | Predicts `MapRoot` lock-free, appends to Output Log, and ratchets trie under short write lock (< 5 ms). |
| **Stage 5** | [`internal/server`](../internal/server/README.md) | Concurrent HTTP worker pool | Serves C2SP read queries under shared read lock (`treeMu.RLock()`). |

---

## 2. Standard Benchmark Matrix

The following matrix defines the standard suite of benchmarks, their component scope, workload profiles, target Service Level Objectives (SLOs), and performance budgets. All measured result fields are designated for re-evaluation under the unified test runner.

| Benchmark Tier | Benchmark Name | Subsystem Scope | Workload Profile | Target SLO / Performance Budget | Measured Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Subsystem Microbenchmarks** | Raw KV Inverted Storage | [`internal/kvstore`](../internal/kvstore/README.md) | Direct batch writes to Pebble inverted chunks (`'c' + KeyHash + ^chunkNum`); 64K-entry chunk roll-overs; 16-bit relative index encoding; `pebble.Sync` barrier. | >= 150,000 index entries/s sustained; zero compaction stalls exceeding 100 ms. | `TODO (Pending Reimplementation)` |
| **Tier 1: Subsystem Microbenchmarks** | WASM Mapping Overhead | [`mapfn`](../mapfn/README.md) | 256-leaf tile batch execution (`map_bundle`); linear memory pack-and-wipe; host SIMD SHA-256 preimage extraction; Wazero compilation mode. | Boundary crossing CPU overhead < 1% total CPU; >= 50,000 leaves/s per CPU core. | `TODO (Pending Reimplementation)` |
| **Tier 1: Subsystem Microbenchmarks** | MPT Commit Duration | [`internal/tree`](../internal/tree/README.md) | Binary Sparse Merkle Patricia Trie path mutation; lock-free root prediction (`mpt.Predict`); 4,096-leaf mutation batch commit. | Root prediction < 10 ms for 4K leaves; exclusive lock duration (`treeMu.Lock()`) < 5 ms. | `TODO (Pending Reimplementation)` |
| **Tier 2: End-to-End Ingestion Pipelines** | Go SumDB (Low-Fanout 1-to-1) | Full Engine (`ingest`, `mapfn`, `kvstore`, `tree`, `coordinator`) | Stream public Go Checksum Database mirror (54M+ leaves); 1-to-1 key-to-leaf mapping; continuous tile fetch, map, commit, and witness publishing. | Local Mirror: >= 200,000 leaves/s; Remote Loopback: >= 100,000 leaves/s; Peak RSS < 512 MB. | `TODO (Pending Reimplementation)` |
| **Tier 2: End-to-End Ingestion Pipelines** | Certificate Transparency (High-Fanout 1-to-N) | Full Engine (`ingest`, `mapfn`, `kvstore`, `tree`, `coordinator`) | Stream Certificate Transparency log tiles; X.509 ASN.1 certificate parsing; 1-to-N mapping (15 to 50 SAN domains per cert); heavy chunk roll-overs. | >= 40,000 certs/s (~600,000 index updates/s); 33-byte prefix Bloom filter seek efficiency >= 99%. | `TODO (Pending Reimplementation)` |
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
vindex-wasm bench \
  --plugin=./vindex/v1/mapfn/examples/sumdb/plugin.wasm \
  --bundle_size=256 \
  --iterations=10000 \
  --simd=true
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
- **Execution Command**:
  ```bash
  # Execute full-scale oneshot ingestion benchmark on local Go SumDB mirror
  sumdbindex \
    --input_log_dir=/path/to/sumdb/mirror \
    --db_dir=/tmp/vindex-sumdb/db \
    --wasm_plugin=./vindex/v1/mapfn/examples/sumdb/plugin.wasm \
    --oneshot=true
  ```

#### B. Certificate Transparency Mirror Dataset
- **Workload Type**: High-fanout 1-to-N mapping (X.509 certificate to 15-50 SAN domains).
- **Dataset Size**: Mirror of Certificate Transparency shards (e.g. MTC Shard3, Oak, Argon).
- **Execution Command**:
  ```bash
  # Execute oneshot ingestion benchmark on Certificate Transparency tile mirror
  mtcindex \
    --input_log_dir=/path/to/ct/mirror \
    --db_dir=/tmp/vindex-ct/db \
    --wasm_plugin=./vindex/v1/mapfn/examples/ct/plugin.wasm \
    --oneshot=true
  ```

---

## 4. Reporting & Verification Requirements

When executing benchmark runs to populate the Standard Benchmark Matrix:

1. **Hardware Telemetry**: All benchmark reports must capture CPU model, core frequency, RAM capacity, NVMe model, kernel version, and Go runtime version (`go version`).
2. **Resource Accounting**: Measurements must report wall duration, user CPU time, system CPU time, average CPU utilization percentage, peak Resident Set Size (RSS) captured via `/usr/bin/time -v`, and final on-disk database footprint.
3. **Latency Percentiles**: Read query latency must report distribution percentiles (P50, P90, P99, Max) computed from a minimum of 100,000 executed client requests under active write load.
4. **Zero-Failure Gate**: Any run encountering an invariant violation, cryptographic proof mismatch, or unhandled panics is marked invalid and fails the evaluation gate.
