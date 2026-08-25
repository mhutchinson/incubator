# VIndex Hammer: Load Testing & Verification Framework

## 1. Overview & Objectives

The **VIndex Hammer (`vindex-hammer`)** is a dedicated integration testbed, load generator, and cryptographic invariant verifier designed to simulate high-throughput transparency log ecosystems, stress test the VIndex daemon (`vindexd`), and actively detect state divergence, data loss, and race conditions under sustained concurrent load.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            vindex-hammer Process                            │
│                                                                             │
│  ┌───────────────────────┐   ┌────────────────────────┐   ┌──────────────┐  │
│  │ Synthetic Leaf        │   │ Tessera POSIX Log      │   │ Drip-Feed    │  │
│  │ Generator             ├──>│ Sequencer & Signer     ├──>│ HTTP Server  │  │
│  │ (Zipfian/Uniform/Non) │   │ (Appender + TileFiles) │   │ (:8085)      │  │
│  └───────────────────────┘   └────────────────────────┘   └──────┬───────┘  │
│                                                                  │          │
│  ┌───────────────────────────────────────────────────────────┐   │          │
│  │ Verifying Concurrent Readers (1..1000 QPS)                │<──┤          │
│  │ • Monotonic Index Growth  • Mini-Log Compact Range Roots  │   │          │
│  │ • MPT Proofs              • Checkpoint Signatures         │   │          │
│  └───────────────────────────────────────────────────────────┘   │          │
│                                │                                 │          │
│  ┌─────────────────────────────┴─────────────────────────────┐   │          │
│  │ Metrics Analyzer & Terminal Dashboard                     │   │          │
│  │ • Write/Read QPS  • Ingestion Lag  • Latency  • Invariants│   │          │
│  └───────────────────────────────────────────────────────────┘   │          │
└──────────────────────────────────────┬───────────────────────────┘          │
                                       │ HTTP                                 │
                                       ▼                                      │
                     ┌───────────────────────────────────┐                    │
                     │          vindexd Daemon           │                    │
                     │  • IngestMapper  • KVIndexer      │                    │
                     │  • OutputPublisher & MPT          │                    │
                     │  • Read Server (/vindex/lookup)   │                    │
                     └───────────────────────────────────┘                    │
```

---

## 2. Architecture & Design

`vindex-hammer` operates as an independent external process that bounds `vindexd` in a controlled "Map Sandwich" test harness:

1. **Upstream Input Log**: Hosts a local POSIX `tlog-tiles` Input Log with an automated sequencer and drip-feed proxy.
2. **Downstream Verifier**: Emits continuous concurrent query workloads against `vindexd`'s HTTP Read API and cryptographically validates all returned proofs against the witnessed Output Log checkpoints.

---

## 3. Core Components

### 3.1 Synthetic Leaf Generator (`vindex/v1/hammer/generator.go`)

Generates structured synthetic entries mimicking transparency log workloads (such as Go SumDB records: `<module> <version> h1:<hash>`):

- **Key Distributions**:
  - **Zipfian / Pareto (alpha > 1)**: Simulates realistic package ecosystem traffic where 1% of modules (e.g. `golang.org/x/sys`, `github.com/gin-gonic/gin`) account for >80% of log entries, repeatedly rolling over 64k index chunks.
  - **Uniform**: Distributes keys evenly across a bounded keyspace `[0, K)` to test wide MPT fanout and prefix Bloom filter lookups.
  - **Non-Inclusion Keys**: Keys generated with a distinct prefix (`nonexistent/<id>`) that are never submitted to the Input Log, exercising MPT non-inclusion proof generation and client verification.
- **Deterministic Key Naming**: Each key index `k` maps to `module-<k>`, enabling predictable querying and reproducible test runs from a single PRNG seed.

### 3.2 Tessera Sequencer (`vindex/v1/hammer/sequencer.go`)

Manages a real Tessera POSIX append-only log:

- Initializes `posix.New(ctx, posix.Config{Path: storageDir})` with an Ed25519 checkpoint signer.
- Configures `tessera.NewAppender` with batching and periodic checkpoint intervals.
- Uses `tessera.NewPublicationAwaiter` to detect newly signed checkpoints as leaves are integrated into the Merkle tree.
- Appends generated leaves at a rate controlled by a token-bucket rate limiter (`--write_rate`).
- As newly published checkpoints are confirmed by the awaiter, enqueues them into a thread-safe `CheckpointQueue`.

### 3.3 Drip-Feed Server (`vindex/v1/hammer/server.go`)

An HTTP server presenting the local POSIX log as a standard `tlog-tiles` Input Log to `vindexd`:

- **`GET /tile/*` & `GET /entries/*`**: Served directly from the local POSIX storage directory via `http.FileServer`.
- **`GET /checkpoint`**: Intercepted by the drip-feed scheduler. Returns the current drip-fed checkpoint rather than the latest on disk.
- **Drip Schedules**:
  - **Steady Drip**: Releases 1 queued checkpoint every delta_t seconds (or at `--drip_rate` CP/sec).
  - **Burst Mode**: Holds queued checkpoints and releases batches of size B (`--burst_size`) every interval, simulating upstream batching.
  - **Pause Mode**: Pauses checkpoint release for a given duration to allow `vindexd` to idle, followed by a large catchup burst to test ingestion recovery.

### 3.4 Verifying Concurrent Readers (`vindex/v1/hammer/reader.go`)

A pool of concurrent worker goroutines querying `vindexd` using `vindex/v1/client.Client` / `server.ClientVerifier`:

- **Workload Mix**:
  - 60% Hot key lookups (Zipfian sample).
  - 25% Uniform random lookups across known keyspace.
  - 10% Non-inclusion lookups (keys guaranteed absent).
  - 5% Paginated multi-page lookups (`LookupAll` with small page sizes).
- **Cryptographic Verification**:
  - Validates Output Log checkpoint signatures against the trusted public key.
  - Verifies Output Log Merkle inclusion proofs for the committed `MapRoot` and `InputLogSize`.
  - Verifies MPT inclusion or non-inclusion proofs against `MapRoot`.
  - Computes RFC 6962 Compact Range mini-log roots and asserts equality with the trie value.
- **Monotonicity Verification**:
  - Maintains a concurrent history map `KeyHash -> (lastInputLogSize, []uint64)`.
  - Asserts that for any subsequent lookup at S_new >= S_old, the returned index set I_new is a superset of I_old and the common prefix is identical (`I_new[:len(I_old)] == I_old`).

### 3.5 Real-Time Metrics Analyzer (`vindex/v1/hammer/analyzer.go`)

Aggregates operational metrics across all generator and reader workers:

- **Write Metrics**: Total leaves written, instantaneous write QPS, total checkpoints generated.
- **Ingestion Lag**: Difference between Sequencer log size and `vindexd` serving `InputLogSize`.
- **Read Metrics**: Total queries, successful queries, read QPS.
- **Latency Percentiles**: Tracks latency distribution (P50, P90, P99, Max) using HDR histogram buckets.
- **Invariant Assertions**:
  - `MonotonicityViolations`: Index shrank or reordered.
  - `CryptoProofFailures`: MPT, Merkle tree, or signature invalid.
  - `BoundsViolations`: Index >= `InputLogSize` or < 0.
  - `NonInclusionViolations`: Non-empty index list for non-existent key.
- **Live Terminal Dashboard**: Renders unpadded, structured ANSI status updates every second.

---

## 4. Invariant Checklist

| Invariant | Description | Failure Impact |
| :--- | :--- | :--- |
| **Monotonicity** | I_{t+1} is a superset of I_t for any key across advancing log sizes | Critical (Data loss or index rollback) |
| **Bounded Indices** | For all i in I: 0 <= i < InputLogSize | Critical (Index leakage of uncommitted data) |
| **Mini-Log Equality** | `CompactRange(I).Root() == MPT.Value(Key)` | Critical (Cryptographic map tampering) |
| **Non-Inclusion** | Key not in Log => Exists == false and len(I) == 0 | Critical (False positive index response) |
| **Output Log Inclusion** | Output leaf inclusion proof verifies against Output Log root | Critical (Uncommitted or forged state) |

---

## 5. CLI Usage & Flags

```bash
# Build the hammer
go build -o bin/hammer ./vindex/v1/cmd/hammer

# Run the hammer against a running vindexd instance
bin/hammer \
  --storage_dir=/tmp/hammer_posix \
  --vindex_url=http://localhost:8080 \
  --listen_addr=:8085 \
  --write_rate=1000 \
  --drip_rate=2 \
  --burst_size=5 \
  --num_readers=16 \
  --max_read_qps=500 \
  --key_distribution=zipf \
  --num_keys=50000 \
  --runtime=60s
```

### CLI Flag Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--storage_dir` | (required) | Local directory for Tessera POSIX input log |
| `--vindex_url` | `http://localhost:8080` | URL of target `vindexd` instance |
| `--listen_addr` | `:8085` | Address for Hammer drip-feed HTTP server |
| `--write_rate` | `500` | Target write rate (leaves/sec) |
| `--drip_rate` | `1.0` | Steady checkpoint drip rate (CP/sec) |
| `--burst_size` | `1` | Number of checkpoints released per burst |
| `--burst_interval`| `0s` | Interval between burst releases (`0s` = steady drip) |
| `--num_readers` | `8` | Number of concurrent verifying reader goroutines |
| `--max_read_qps` | `200` | Maximum total read query rate |
| `--key_distribution`| `zipf` | Key distribution (`zipf`, `pareto`, `uniform`) |
| `--num_keys` | `10000` | Active working set size of unique keys |
| `--zipf_s` | `1.2` | Zipfian skew parameter (s > 1) |
| `--runtime` | `0s` | Test duration (`0s` = run until Ctrl+C) |
| `--stats_interval`| `1s` | Terminal dashboard refresh rate |
