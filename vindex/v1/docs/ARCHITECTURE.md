# Verifiable Index (VIndex v1) Architecture

## 1. Context & Objectives

### 1.1 Problem Statement

Append-only transparency logs (e.g. Certificate Transparency, Go SumDB, Sigstore) provide robust discoverability and cryptographic tamper-evidence. However, they lack the ability to *verifiably* query log entries by their content (such as a domain name, package path, or artifact hash).

Users seeking specific records face an untenable trade-off:
1. **Full-Log Download (Inefficient)**: Downloading and processing tens of gigabytes or terabytes of irrelevant data to find a handful of relevant entries.
2. **Third-Party Indices (Unverifiable)**: Relying on centralized, unverifiable search engines that can omit records inadvertently or maliciously without detection.

### 1.2 The Solution: The "Map Sandwich"

A **Verifiable Index (VIndex)** provides efficient, trustless, and cryptographically verifiable querying over large append-only transparency logs. Informally called a "Map Sandwich", VIndex operates as a secondary overlay bounded between an **Input Log** (the source of truth being indexed) and an **Output Log** (committing to the index's cryptographic state):

- **Efficiency**: $O(1)$ point queries with $O(\log N)$ Merkle lookup and verification complexity, replacing $O(N)$ full-log scans.
- **Omission Resistance**: Every lookup response contains cryptographic inclusion or non-inclusion proofs (via an in-memory Merkle Patricia Trie and sub-log Merkle trees), mathematically guaranteeing completeness against witnessed checkpoints.
- **Decoupled Architecture**: If the VIndex service fails or goes offline, the underlying Input Log's security model, sequencing, and availability remain completely unaffected.

### 1.3 Non-Requirements & Out of Scope

- **Strictly Single-Machine Deployment**: VIndex explicitly avoids distributed consensus (e.g. Raft, Paxos), clustering, horizontal sharding, or internal replication protocols. High availability and redundancy are achieved externally: third-party monitors and mirrors run independent, standalone VIndex single-node instances indexing the same shared Input Log.
- **No Complex / Multi-Key Querying**: The service provides point lookups on exact 32-byte key hashes only (`KeyHash = SHA256(Key)`). Cross-key range scans, boolean filtering (AND/OR), substring searches, full-text search, and regular expression lookups are out of scope.
- **No Log Mutation or Tombstones**: Index state is strictly append-only. The system does not support deletion, key un-mapping, tombstones, or retrospective data modification.
- **No In-Tree Semantic Validation**: VIndex indexes raw bytes extracted deterministically by the WebAssembly `MapFn`. It does not perform semantic validation of indexed payloads (e.g. validating X.509 certificate chains, checking OCSP/CRL revocation, or verifying digital signatures).

### 1.4 Alternatives Considered

- **Authenticated Data Structure & Single-Host Coupling**:
  - *Selected*: In-memory Binary Merkle Patricia Trie (`torchwood/mpt` backed by `mmap`). Delivers ~52 bytes/node density, sub-5ms commit locks, and lock-free root prediction (`mpt.Predict`). Keeping the MPT in memory backed by local NVMe requires high-spec single-host hardware optimized for bulk log catch-up.
  - *Rejected*: Sparse Merkle Trees (SMT) were rejected due to severe memory and disk I/O overhead across 256-level trie depths. Verkle Trees were rejected due to prohibitive CPU update costs during high-throughput bulk ingestion.
- **Storage Engine**:
  - *Selected*: Embedded Pebble LSM key-value store. Provides zero network hops, single-host NVMe optimization, 33-byte prefix Bloom filters, and fast inverted chunk seeks (`^chunkNum`).
  - *Rejected*: Distributed KV stores (e.g. Cloud Bigtable, Spanner, Cassandra) were ruled out because the MPT already requires single-host deployment; remote RPC hops introduce network latency and degrade bulk catch-up throughput.
- **Commit & Durability Pipeline**:
  - *Selected*: Zero-WAL architecture. Uses the immutable Input Log tile cache as the log of record, completely eliminating write amplification and WAL tail repair during crash recovery.
  - *Rejected / Retired*: A WAL-in-Pebble design (staging index records under a transient 'w' prefix with an asynchronous WAL reaper) was initially implemented and evaluated. Removing the WAL in favor of direct chunk indexing proved measurably superior in empirical benchmarks: it increased full Go SumDB ingestion throughput by +24.7% (from ~192k to ~240k leaves/sec), reduced end-to-end build duration by ~20%, and eliminated double-write disk amplification and LSM compaction churn.

---

## 2. High-Level Architecture & Data Flow

```text
  [Input Log] (Source of Truth, e.g. CT / MTC / SumDB)
       │
       ▼ (1. Aligned Entry Bundles: tclient.GetEntryBundle [S/256 .. E/256))
┌─────────────────────────────────────────────────────────────────────────────┐
│                              vindexd Daemon                                 │
│                                                                             │
│  [Ingestion Plane]                                                          │
│  • TileFetcher & Local Cache (Direct FS / Managed Cache)                    │
│  • Parallel Wazero WASM Sandboxes (GOMAXPROCS-1 workers)                    │
│  • In-Memory Priority Resequencer (Monotonic leaf ordering)                 │
│         │                                                                   │
│         ▼ chan *MappedBatch (ordered)                                       │
│  [Data & Commitment Plane]                                                  │
│  • KVIndexer: Pebble DB Inverted Chunks ('c' + KeyHash + ^chunkNum)         │
│  • OutputPublisher: Lock-Free Root Prediction (mpt.Predict)                 │
│  • Serving MPT: In-Memory working tree (torchwood/mpt mmap, < 5ms lock)     │
│         │                                                                   │
│         ▼                                                                   │
│  [Serving Plane]                                                            │
│  • HTTP Read Server (/vindex/lookup/{keyhash}?start=N&limit=M)              │
│  • Lock-Free Reverse Scans (iter.Prev()) + Watermark Index Filtering        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (2. Append StateCommitment: hex(MapRoot) + ILCheckpoint)
                                       ▼
  [Output Log] (Tessera POSIX / Cloud Tiles + Witness Cosignatures)
```

---

## 3. Core State Progression & Serving Invariants

State progresses monotonically across the four pipeline planes:

```text
Input Log Target CP >= Cached Tile Watermark >= m_kv_size >= Output Log Size == Serving MPT
```

### Invariants:
1. **State Ratcheting**: Earlier stages (ingestion, chunk indexing) operate ahead of the serving plane to maximize throughput. Each stage processes in sub-batches, but downstream stages only expose data committed by verified checkpoints.
2. **Serving Isolation**:
   ```text
   Serving_Size == MPT_Size <= Output_Size
   ```
   Readers are strictly isolated from in-flight writes ahead of `Serving_Size` via watermark index filtering.

---

## 4. Subsystem Contract & Navigation Map

The VIndex architecture is partitioned into five modular subsystems located in [`vindex/v1/internal/`](../internal/):

| Subsystem | Location | Storage Prefix / Tech | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Ingestion Pipeline** | [`internal/ingest/`](../internal/ingest/README.md) | `vindex/input` + Wazero WASM | Native 256-leaf entry bundle fetching, sandboxed WASM `MapFn` execution, priority resequencer, and `TileReaper` cache management. |
| **KV Storage** | [`internal/kvstore/`](../internal/kvstore/README.md) | Pebble prefixes `'c'` & `'m'` | Inverted chunk numbering (`^chunkNum`), 33-byte prefix Bloom filters, delimitless value encoding, and $O(1)$ sub-root read recovery. |
| **Authenticated State** | [`internal/tree/`](../internal/tree/README.md) | `torchwood/mpt` + Tessera | In-memory MPT in `mmap`, lock-free root prediction, Tessera Output Log state commitments, and witness cosignature aggregation. |
| **Coordinator & Recovery** | [`internal/coordinator/`](../internal/coordinator/README.md) | Pebble prefix `'m'` | Moving-goalpost prevention (`m_target_checkpoint`), watermark tracking, and 3-Phase Zero-WAL startup recovery (< 500ms time-to-first-serve). |
| **Read Server & Protocol** | [`internal/server/`](../internal/server/README.md) | HTTP + C2SP `text/plain` | `GET /vindex/lookup`, lock-free Pebble reverse scans, on-the-fly RFC 6962 compact ranges, and multi-section plain-text response framing. |

---

## 5. Security & Verification Model

### 1. Threat Model & Trust Assumptions
- **Untrusted Index Operator**: The VIndex operator is assumed to be untrusted. An adversary controlling the operator cannot forge index proofs, omit valid occurrences, or equivocate state commitments without breaking SHA-256 or being detected by independent witnesses.
- **Trusted Input Log**: The Input Log is assumed to have an authentic, append-only history protected by cryptographic checkpoints. VIndex inherits the admission criteria of the Input Log without secondary filtering.
- **Immutable & Deterministic `MapFn`**: The mapping logic is compiled to WebAssembly. Any host or guest execution trap triggers a strict `HALT` policy to prevent silent state divergence across witness nodes.

### 2. Proof of Omission Resistance
When a client queries a key, the response proves completeness through two layered proofs:
1. **MPT Proof (`mpt-proof-v1`)**: Proves whether `KeyHash` exists in the MPT at `MapRoot`.
   - If **Non-Inclusion**: Cryptographically proves that no leaf in the Input Log has ever mapped to this key.
   - If **Inclusion**: Cryptographically binds `KeyHash` to its specific 32-byte `MiniLogRoot`.
2. **Sub-Log Merkle Compact Range Proof (`prefix-compact-range-v1` + `indices-v1`)**:
   - The returned indices and historical compact range hashes are hashed according to RFC 6962 (`LeafHash = SHA256(0x00 || BigEndian(idx))`).
   - The client computes `CompactRange.Root()` and asserts equality with `MiniLogRoot`.
   - Because `MapRoot` is witnessed in the Output Log, the operator cannot omit an index without causing the mini-log root to mismatch.

### 3. Equivocation Resistance via Witnessed Output Log
The Output Log uses Tessera (`tlog-tiles`) backed by independent witness cosignatures ([signed-note](https://c2sp.org/signed-note), [tlog-checkpoint](https://c2sp.org/tlog-checkpoint)). The Map Operator cannot present different views of index state to different clients without producing conflicting signed checkpoints detectable by public monitors.

---

## 6. Hardware & Operational Deployment

### 1. Dual-Disk Physical Isolation

Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is **strongly recommended**:

```text
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│       Disk A (NVMe SSD): Data        │     │       Disk B (NVMe SSD): Tree        │
│ • Pebble DB (chunks 'c', metadata 'm')│    │ • MPT mmap working tree              │
│ • Local Managed Tile Cache           │     │ • MPT append-only leaf file          │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

- **Compaction Conflict**: Periodic MPT disk compaction writes full memory images (e.g. 10 GB for 100M keys) sequentially. If sharing a disk with Pebble, this saturates disk I/O, stalls Pebble memtable flushes, and triggers LSM write stalls.
- **Durability Invariant**: `TileReaper` retains raw tiles on Disk A until Disk B's MPT compaction snapshot is durably fsync'd (`SafeWatermark = min(m_kv_size, MPT.PersistedVersion())`).

### 2. Resource Sizing & Memory Footprint

| Scale (Unique Keys) | MPT Memory (`mmap`) | MPT Leaf Disk | Pebble Disk | Recommended RAM | Recommended GCP VM |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.04 GB | ~320 MB | ~1 GB | 8 GB | `e2-standard-2` |
| **Medium (100M)** | ~10.4 GB | ~3.2 GB | ~10 GB | 64 GB | `n2-highmem-8` |
| **Large (1B)** | ~104 GB | ~32 GB | ~100 GB | 256 GB | `n2-megamem-16` |
| **Very Large (2B)** | ~208 GB | ~64 GB | ~200 GB | 512+ GB | `m4-megamem-64` |

---

## 7. Observability & Telemetry

### 7.1 Prometheus Metrics

`vindexd` exports structured Prometheus metrics:

- **Ingestion & Mapping**:
  - `vindex_ingestion_lag` (Gauge): Distance between Input Log head and `m_kv_size`.
  - `vindex_map_duration_seconds` (Histogram): Duration of WASM `MapFn` executions.
  - `vindex_map_errors_total` (Counter): Count of mapping failures by policy (`HALT`).
- **Commitment & Witnessing**:
  - `vindex_indexing_lag` (Gauge): Distance between `m_kv_size` and `Output_Size`.
  - `vindex_witness_wait_seconds` (Histogram): Time waiting for remote witness cosignatures.
  - `vindex_mpt_write_duration_seconds` (Histogram): Critical section duration under MPT write lock.
- **Serving**:
  - `vindex_lookup_latency_seconds` (Histogram): HTTP lookup endpoint latency.
  - `vindex_lookup_results_returned` (Histogram): Count of indices returned per query.

### 7.2 Service Level Objectives (SLOs) & Alerting Thresholds

- **Single-Node SLO Targets**:
  - **Read Latency**: P99 < 50ms for point lookups.
  - **Ingestion Lag**: < 60s behind published Input Log checkpoints.
  - **Availability**: 99.9% read availability.
- **Alerting Triggers**:
  - **Ingestion Lag**: Ingestion lag > 10,000 leaves for > 15 minutes.
  - **MPT Lock Contention**: MPT write lock duration > 20ms.
  - **Witness Timeout Rate**: Remote witness cosignature timeout rate > 1%.

### 7.3 Operational Probes & Health Checks

- `GET /healthz`: Liveness probe. Returns HTTP 200 if the daemon event loop is running and healthy.
- `GET /readyz`: Readiness probe. Returns HTTP 200 once 3-Phase Zero-WAL recovery completes and `ServingState` is active; returns HTTP 503 during startup recovery, active disk rebuilds, or following a fatal trap.

---

## 8. Companion Documentation

- **[BENCHMARKS.md](./BENCHMARKS.md)**: Empirical performance benchmarks (Zero-WAL vs WAL, 54M SumDB ingestion, 10M CT fanout load tests).
- **[APPLICATIONS.md](./APPLICATIONS.md)**: Ecosystem mapping guides (Certificate Transparency, Merkle Tree Certificates, Go SumDB, Sigstore, Sigsum).
- **[Hammer Design](../hammer/README.md)**: Load testing, synthetic generation, and invariant verification framework.

---

## 9. Rollout, Lifecycle & Disaster Recovery

### 1. Genesis Catch-Up Mode

High-throughput fast-forward bulk ingestion from leaf 0 to a target checkpoint. In this mode, `vindexd` maximizes parallelism across Wazero WASM sandboxes, bypasses per-batch witness roundtrips, and streams entries directly into Pebble DB and the in-memory MPT before activating serving endpoints.

### 2. Single-Host Disaster Recovery

- **Disk B (MPT) Crash**: If the disk storing MPT working files fails or corrupts, the MPT is rebuilt entirely in RAM directly from local Disk A Pebble inverted chunks (`'c' + KeyHash + ^chunkNum`) without network egress.
- **Disk A (Pebble) Crash**: If the primary storage disk fails, state is replayed directly from the local tile cache or streamed from the upstream Input Log.
- **Trap / Invariant Violation**: Any unexpected state divergence, WASM runtime fault, or invariant violation triggers a deterministic `HALT` policy. This immediately freezes the serving pointer and preserves local state on disk for post-mortem forensics.
