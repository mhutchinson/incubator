# Sub-Design: Hammer Load Testing & Verification Framework

This document defines the architecture, workload generation models, drip-feed scheduling protocols, cryptographic invariant verification rules, and operational telemetry for the **Hammer Subsystem** (`vindex/v1/hammer`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Integration Testing Dilemma
Unit tests verify software logic in isolation, but the critical failure modes of a verifiable index only emerge under **sustained, concurrent read-write load**:
1. **LSM Compaction Stalls**: Heavy write ingestion can trigger background Pebble LSM compactions that spike read latency or pause batch writes.
2. **Lock Contention & Race Conditions**: High-frequency updates to hot keys stress in-memory MPT path compression and writer lock transitions (`treeMu.Lock()`), risking deadlocks or latency degradation against concurrent read queries.
3. **Chunk Boundary Corruption**: Inverted chunks roll over every 65,536 occurrences; verifying that multi-chunk reverse scans reconstruct complete, unbroken histories requires driving individual keys past multiple 64K boundaries.

Validating that `vindexd` preserves cryptographic integrity, zero data loss, and sub-millisecond serving requires an automated adversarial testbed that simultaneously acts as the upstream log producer and the downstream verifying client.

### 1.2 The "Crash Test Rig" Harness
The **VIndex Hammer (`vindex-hammer`)** operates like an automotive crash test rig:
- **Upstream Producer (Top Bread)**: Drives a real local append-only Tessera log, synthesizing transactions across Zipfian and uniform distributions, and controls checkpoint release schedules (drip-feeding) to simulate network conditions.
- **System Under Test (The Meat)**: Runs `vindexd` as an independent external daemon, exercising its real network, storage, and commitment pipeline.
- **Downstream Verifier (Bottom Bread)**: Directs an army of concurrent worker threads querying `vindexd`'s HTTP API, cryptographically verifying every proof and asserting that history never regresses.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Stress test `vindexd` under realistic multi-million entry workloads with heavy key skew (Zipfian distributions).
  - Simulate production upstream CDN behaviors via steady, burst, and pause/catchup drip schedules.
  - Assert cryptographic invariants (signatures, MPT proofs, compact range roots, and monotonic history) on 100% of read queries.
  - Provide real-time terminal dashboards tracking throughput, latency percentiles, and invariant checks.
- **Non-Goals**:
  - **Not a Production Log Sequencer**: Designed exclusively for integration testing, benchmarking, and chaos verification.
  - **Not an In-Memory Mock**: Executes real network requests (`http://127.0.0.1:8085` -> `:8088`) against real POSIX files.

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Integrates `tessera` (POSIX storage, appender, publication awaiter) and `vindex/v1/client`.
- **Known Pain Points ("Warts and All")**:
  - **Host Core Contention**: When running both `vindex-hammer` and `vindexd` on a single developer machine, CPU-heavy leaf generation and WASM worker pools compete for physical cores.
  - **File Descriptor Saturation**: Running hundreds of concurrent verifying readers across rapid HTTP connections can exhaust OS file descriptors unless `ulimit -n` is increased.

---

## 2. Detailed Design

### 2.1 Component Architecture & Pipeline Map

| Subsystem Component | Source File | Core Responsibility |
| :--- | :--- | :--- |
| **Synthetic Leaf Generator** | `generator.go` | Emits structured synthetic leaves across Zipfian, Uniform, and Non-Inclusion distributions. |
| **Tessera Sequencer** | `sequencer.go` | Writes leaves into a real local POSIX append-only log, computes Merkle roots, and signs checkpoints. |
| **Drip-Feed HTTP Server** | `server.go` | Serves standard C2SP `tlog-tiles` endpoints (`:8085`) and schedules checkpoint releases (steady, burst, pause). |
| **Verifying Concurrent Readers** | `reader.go` | Queries `vindexd` (`:8088`) and cryptographically verifies 100% of inclusion/non-inclusion proofs. |
| **Metrics Analyzer & Dashboard** | `analyzer.go` | Aggregates latency percentiles, throughput QPS, ingestion lag, and invariant assertions. |

---

### 2.2 Synthetic Workload Distributions (`generator.go`)
The leaf generator mimics production transparency log entries (such as Go SumDB records: `<module> <version> h1:<hash>`):

1. **Zipfian / Pareto Skew (`alpha > 1`, `--zipf_s=1.2`)**:
   - Models realistic package registries where top 1% of hot keys account for >80% of all entries.
   - **Targeted Stress**: Forces individual hot keys past multiple 65,536-entry boundaries, verifying that active chunk rollovers (`^0 -> ^1`), SSTable compactions, and multi-page backward scans maintain unbroken continuity.
2. **Uniform Distribution**:
   - Spreads entries evenly across a wide keyspace (`[0, K)`) to stress binary MPT branch fanout and 33-byte prefix Bloom filter performance.
3. **Non-Inclusion Keys**:
   - Generates queries for keys prefixed with `nonexistent/<id>` that were never submitted to the Input Log, exercising cryptographic non-inclusion proofs.

---

### 2.3 Tessera Sequencer & Drip-Feed HTTP Server (`sequencer.go`, `server.go`)
To evaluate `vindexd` against realistic network conditions, the hammer controls upstream checkpoint availability:

- **POSIX Storage & Signer**: Appends generated leaves to a local directory using `tessera.NewAppender`, signing checkpoints with a test Ed25519 private key.
- **Drip-Feed Schedules**:
  - **Steady Drip**: Releases 1 queued checkpoint at fixed time intervals (or at `--drip_rate` CP/sec), simulating steady upstream log integration.
  - **Burst Mode**: Buffers generated checkpoints and releases them in sudden bursts (`--burst_size`), simulating upstream batch commits.
  - **Pause & Catchup Mode**: Halts checkpoint release for a configurable duration to allow `vindexd` to idle, then releases a large backlog of tiles to evaluate fast-forward catchup performance.

---

### 2.4 Verifying Concurrent Readers (`reader.go`)
A pool of worker goroutines issues continuous lookups against `vindexd` (`GET /vindex/lookup/{keyhash}`), validating both cryptographic truth and history monotonicity using the verification protocol specified in the public client SDK ([`client/`](../client/README.md)):

#### Query Verification Sequence:
1. **Output Log Checkpoint Verification**: Validates the Ed25519 signatures on the returned Output Log checkpoint note.
2. **Output Log Merkle Proof**: Verifies the Merkle inclusion proof committing the `MapRoot` into the Output Log.
3. **MPT Proof Verification**: Verifies the MPT inclusion or non-inclusion proof against the verified `MapRoot`.
4. **Mini-Log Compact Range Verification**: Reconstructs the RFC 6962 compact range from returned leaf indices and asserts equality with `SubRoot`.
5. **Monotonic History Assertion**: For subsequent queries on the same key where `S_new >= S_old`, asserts that `I_new` is a strict superset with an identical prefix: `I_new[:len(I_old)] == I_old`.

---

### 2.5 In-Situ Invariants & Performance Assertions

- **[Correctness Invariant] Zero-Tolerance Cryptographic Failure**:
  - *Rule*: Any cryptographic verification failure (invalid checkpoint signature, failed MPT proof, or mismatched compact range root) immediately aborts the test run with an error.
  - *Rationale*: A verifiable index must never return falsified or un-verifiable state under any load condition.
  - *Consequence ("Or Else")*: If the hammer tolerated cryptographic failures, silent race conditions or state corruption would escape into production.

- **[Correctness Invariant] Monotonic History Superset**:
  - *Rule*: For any repeated query on key K where the second query evaluates a tree size `S_new >= S_old`, the returned index set `I_new` must be a strict superset of `I_old`, and the common prefix must be bit-for-bit identical:
    ```go
    if !bytes.Equal(indicesNew[:len(indicesOld)], indicesOld) {
        t.Fatalf("history regression detected for key %s", key)
    }
    ```
  - *Rationale*: Transparency logs are strictly append-only; historical occurrences cannot be altered, re-ordered, or deleted.
  - *Consequence ("Or Else")*: A regression indicates that the storage engine dropped historical chunks or committed out-of-order batches.

---

### 2.6 CLI Usage & Configuration Parameters

```bash
# Run 100,000-leaf Zipfian stress test with 50 concurrent readers
vindex-hammer \
  --mode=hammer \
  --num_leaves=100000 \
  --zipf_s=1.2 \
  --write_rate=5000 \
  --drip_rate=10 \
  --read_qps=500 \
  --read_workers=50 \
  --vindex_url=http://127.0.0.1:8088
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 In-Process Go Unit Test Mocks vs. Out-of-Process "Map Sandwich"
- **Proposed**: Testing `vindexd` entirely in-memory using mocked interfaces and synthetic Go channels.
- **Theoretical & Practical Rejection**: In-memory mocks fail to reproduce real-world concurrency bugs (HTTP connection pooling stalls, OS thread scheduling jitter, disk fsync latency, and Pebble LSM background compaction stalls).
- **Chosen Design**: Out-of-process dual-daemon architecture communicating over loopback HTTP with real POSIX storage files.

### 3.2 Static Pre-Recorded Log Dumps vs. Dynamic Drip-Feed Sequencer
- **Proposed**: Replaying a static dump of a public log (e.g. static CT tiles).
- **Practical Rejection**: Static dumps cannot dynamically modulate write rates, generate targeted Zipfian skew, inject non-inclusion probes, or test burst/pause catchup dynamics.
- **Chosen Design**: Programmable dynamic sequencer capable of generating deterministic Zipfian workloads and custom checkpoint drip schedules.
