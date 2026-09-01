# Verifiable Index (VIndex v1) Architecture

## 1. Context & Objectives

### 1.1 Problem Statement

Append-only transparency logs (e.g. Certificate Transparency, Go SumDB, Sigstore) provide robust discoverability and cryptographic tamper-evidence. However, they lack the ability to *verifiably* query log entries by their content (such as a domain name, package path, or artifact hash).

Users seeking specific records face an untenable trade-off:
1. **Full-Log Download (Inefficient)**: Downloading and processing tens of gigabytes or terabytes of irrelevant data to find a handful of relevant entries.
2. **Third-Party Indices (Unverifiable)**: Relying on centralized, unverifiable search engines that can omit records inadvertently or maliciously without detection.

### 1.2 The Solution: The "Map Sandwich"

A **Verifiable Index (VIndex)** provides efficient, trustless, and cryptographically verifiable querying over large append-only transparency logs. Informally called a "Map Sandwich", VIndex operates as a secondary overlay bounded between an **Input Log** (the source of truth being indexed) and an **Output Log** (committing to the index's cryptographic state):

- **Efficiency**: O(1) point queries with O(log N) Merkle lookup and verification complexity, replacing O(N) full-log scans.
- **Omission Resistance**: Every lookup response contains cryptographic inclusion or non-inclusion proofs (via an in-memory Merkle Patricia Trie and sub-log Merkle trees), mathematically guaranteeing completeness against witnessed checkpoints.
- **Decoupled Architecture**: If the VIndex service fails or goes offline, the underlying Input Log's security model, sequencing, and availability remain completely unaffected.

### 1.3 Non-Requirements & Out of Scope

- **Strictly Single-Machine Deployment**: VIndex explicitly avoids distributed consensus (e.g. Raft, Paxos), clustering, horizontal sharding, or internal replication protocols. High availability and redundancy are achieved externally: third-party monitors and mirrors run independent, standalone VIndex single-node instances indexing the same shared Input Log.
- **Point Lookups by 32-Byte Key Hashes**: The production v1 service provides point lookups on exact 32-byte key hashes (`KeyHash = SHA256(CanonicalSubject)`). General cross-key range scans, boolean filtering (AND/OR), substring searches, full-text search, and arbitrary regular expressions are out of scope. (Note: Retaining raw preimages on the host enables future prefix-trie / subtree indexing without guest ABI changes; see Section 9.5).
- **No Log Mutation or Tombstones**: Index state is strictly append-only. The system does not support deletion, key un-mapping, tombstones, or retrospective data modification.
- **No In-Tree Semantic Validation**: VIndex indexes canonical Claim Subject preimages extracted deterministically by the WebAssembly `MapFn`. It does not perform semantic validation of indexed payloads (e.g. validating X.509 certificate chains, checking OCSP/CRL revocation, or verifying digital signatures).

---

## 2. System Architecture & End-to-End Data Flow

```text
  [Input Log] (Source of Truth, e.g. CT / MTC / SumDB)
       │
       ▼ (1. Authenticated Entry Bundles: torchwood.Client [S/256 .. E/256))
┌─────────────────────────────────────────────────────────────────────────────┐
│                              vindexd Daemon                                 │
│                                                                             │
│  [Ingestion Plane]                                                          │
│  • TileFetcher & Local Cache (torchwood.PermanentCache / Managed Cache)     │
│  • Parallel Wazero WASM Sandboxes (GOMAXPROCS-1 workers)                    │
│    - Bundled Tile Mapping: map_bundle (1 <= N <= 256 leaves/call, 2-3 FFI)  │
│    - Extracts Canonical Preimages (e.g. domain strings, module paths)       │
│  • Host-Side Hardware Cryptography (crypto/sha256 + SHA-NI / ARMv8 Crypto)  │
│    - KeyHash = SHA256(canonical_subject)                                   │
│    - Lexicographical sort (bytes.Compare) & deduplication (slices.Compact)  │
│  • In-Memory Priority Resequencer (Monotonic leaf ordering min-heap)        │
│         │                                                                   │
│         ▼ chan *MappedBatch (ordered)                                       │
│  [Data & Commitment Plane] (Serialized Batch Commit Loop)                   │
│  • 1. KVIndexer: Pebble DB Inverted Chunks ('c') with blocking disk sync    │
│  • 2. OutputPublisher: Lock-Free Root Prediction (mpt.Predict)              │
│  • 3. Output Log Append & Remote Witness Cosignatures                       │
│  • 4. Serving MPT: In-Memory working tree ratchet (< 5ms lock)              │
│         │                                                                   │
│         ▼                                                                   │
│  [Serving Plane]                                                            │
│  • HTTP Read Server (/vindex/lookup/{keyhash}?before=X&limit=M)             │
│  • Lock-Free Inverted Scans + Watermark Index Filtering                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (2. Append StateCommitment: hex(MapRoot) + ILCheckpoint)
                                       ▼
  [Output Log] (Tessera POSIX / Cloud Tiles + Witness Cosignatures)
```

---

## 3. Subsystem Map & Responsibilities

The VIndex architecture is partitioned into modular subsystems located in [`vindex/v1/internal/`](../internal/):

| Subsystem | Location | Storage Prefix / Tech | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Ingestion Pipeline** | [`internal/ingest/`](../internal/ingest/README.md) | `filippo.io/torchwood` + Wazero WASM | Checkpoint validation, tile/leaf Merkle authentication, native entry bundle fetching, sandboxed WASM `map_bundle` execution, host-side hardware SHA-256 hashing, priority resequencer, and `TileReaper` cache management. |
| **WASM MapFn SDK & Runtime** | [`mapfn/`](../mapfn/README.md) | Wazero (`wasip1`) + Guest SDKs | Sandboxed WebAssembly guest ABI, `map_bundle` tile/slice protocol (1 <= N <= 256 leaves), canonical preimage extraction, multi-language SDKs (Go, TinyGo, Rust), host hardware SHA-NI hashing, and offline `vindex-map` verification CLI. |
| **KV Storage** | [`internal/kvstore/`](../internal/kvstore/README.md) | Pebble prefixes `'c'` & `'m'` | Inverted chunk numbering (`^chunkNum`), 33-byte prefix Bloom filters, delimitless value encoding, and O(1) sub-root read recovery. |
| **Authenticated State** | [`internal/tree/`](../internal/tree/README.md) | `torchwood/mpt` + Tessera | In-memory MPT in `mmap`, lock-free root prediction, Tessera Output Log state commitments, and witness cosignature aggregation. |
| **Coordinator & Recovery** | [`internal/coordinator/`](../internal/coordinator/README.md) | Pebble prefix `'m'` + `tlog.CheckTree` | Checkpoint progression & Merkle consistency proofs, moving-goalpost prevention (`m_target_checkpoint`), watermark tracking, serialized batch coordination (`store.WriteBatch` -> `publisher.PublishBatch`), and Zero-WAL startup recovery (< 500ms time-to-first-serve). |
| **Read Server & Protocol** | [`internal/server/`](../internal/server/README.md) | HTTP + C2SP `text/plain` | `GET /vindex/lookup` (`before=X&limit=M`), lock-free Pebble inverted scans, on-the-fly RFC 6962 prefix compact ranges, and multi-section plain-text response framing. |

---

## 4. State Progression & Pipeline Invariants

The vast majority of the design documents across this repository describe the default **Normal Serving Mode** (Mode 1), which enforces the active serving invariant:
```text
Ingestion Checkpoint >= Pebble Checkpoint >= Output Log Checkpoint >= Merkle Tree Checkpoint
```
(with `mpt.Predict` lock-free prediction, Output Log appending, and remote witness cosigning per batch).

### 4.1 Watermark Glossary

| Watermark Symbol | Pipeline Plane | Definition & Invariant Role |
| :--- | :--- | :--- |
| `Target_CP` (Target Checkpoint) | Upstream Input Log | Latest authenticated checkpoint size discovered, verified, and locked from the upstream Input Log. |
| `Cached_Tiles` (Cached Tile Watermark) | Ingestion Plane / Local Cache | Highest contiguous leaf index downloaded, verified against the Merkle tree, and stored in `ManagedTileCache`. |
| `m_kv_size` (Committed KV Size) | KV Storage Plane (`internal/kvstore`) | Highest contiguous leaf index whose mapped search key chunks have been durably synced to Pebble DB (`pebble.Sync`). |
| `Output_Size` / `Serving_Size` / `mptDurableSize` | State Commitment Plane (`internal/tree`) | Output Log tree size committed with witness cosignatures; equals the active serving MPT size exposed to readers. |

### 4.2 Watermark Inequality Chain (Normal Serving Mode)

State progresses monotonically across the four pipeline planes in Normal Serving Mode:

```text
Input Log Target CP >= Cached Tile Watermark >= m_kv_size >= Output Log Size >= MPT_Durable_Size
```
*(Note: `Output Log Size == Serving MPT`)*

### 4.3 Invariants & Commit Barrier

1. **Synchronous Commit Barrier**:
   Output Log append and witness network calls **MUST NOT begin** until `kvstore.WriteBatch` has successfully completed and durably persisted to disk (`pebble.Sync`).
   KV storage writes and Output Log publication are not independent concurrent goroutines. The coordinator coordinates a serialized batch execution loop per batch S_k:
   `store.WriteBatch(entries, S_k)` (blocking disk persistence) -> `publisher.PublishBatch(...)` (root prediction + Output Log append + witness cosignatures + in-memory MPT ratchet).
2. **Crash Invariant Guarantee (`m_kv_size >= Output_Size`)**:
   Because storage persistence strictly precedes Output Log publication, the invariant `m_kv_size >= Output_Size` is preserved under all crash, kill, and power loss scenarios. Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted KV store chunks. If a crash occurs between storage persistence and Output Log append, `m_kv_size > S_OUT`; startup recovery safely ignores chunks beyond `S_OUT` via point-in-time `store.GetSubRoot(keyHash, S_OUT)` queries.
3. **State Ratcheting**: Earlier stages (ingestion, chunk indexing) operate ahead of the serving plane to maximize throughput. Downstream stages only expose data committed by verified checkpoints.
4. **Serving Isolation**:
   ```text
   Serving_Size == MPT_Size <= Output_Size
   ```
   Readers are strictly isolated from in-flight writes ahead of `Serving_Size` via watermark index filtering.

### 4.4 Operational Modes & Alternative Catch-Up Pipeline

#### Motivation
During initial synchronization or bulk catch-up (e.g. ingesting tens of millions of historical leaves from genesis), live read queries are inactive (`/readyz` returns HTTP 503). In this scenario, running `mpt.Predict` across tens of millions of leaves causes two severe scalability bottlenecks:
1. **Memory Accumulation**: Running `mpt.Predict` across tens of millions of leaves would accumulate massive in-memory mutation maps and incur substantial heap allocation and tree cloning overhead.
2. **Witness Roundtrip Bottleneck**: Requiring tens of thousands of slow remote witness cosignature network RPCs (one per batch) introduces unnecessary latency and throttles bulk catch-up throughput.

#### Catch-Up Ingestion Mode (Alternative Pipeline)
To maximize throughput during bulk sync, `vindexd` supports an alternative **Catch-Up Ingestion Mode**:

- **Pipeline Invariant**:
  ```text
  Ingestion Checkpoint >= Pebble Checkpoint == In-Memory MPT Checkpoint
  ```
  *(Output Log publication and remote witnessing are decoupled and disabled during catch-up).*
- **Mechanics**: Ingestion streams batches into Pebble via `store.WriteBatch` and immediately updates the in-memory working tree via direct in-place `mpt.Set(...)` and `mpt.Snap(...)`.
- **Memory Efficiency**: Working memory remains flat (O(1) heap overhead per batch in `mmap`), eliminating O(N) heap map bloat and avoiding `Predict` tree cloning overhead.
- **Read Serving**: The HTTP read server returns `HTTP 503 Service Unavailable` (`/readyz` unhealthy).

#### Mode Transition Sequence (Catch-Up Mode -> Normal Serving Mode)
Upon reaching the target synchronization point, `vindexd` transitions explicitly from Catch-Up Mode into Normal Serving Mode:

1. **Catch-Up Completion**: The catch-up loop completes all batch ingestion up to `Target_CP`.
2. **Root Availability**: The MPT root is already computed in the working tree (`mpt.Root()`).
3. **Output Log Append**: Append a single `StateCommitment` (`hex(MapRoot) + "\n" + Target_CP.Raw`) to the Output Log.
4. **Remote Witness Cosigning**: Submit the checkpoint to remote witnesses and collect a cosignature quorum.
5. **MPT Disk Fsync**: Fsync MPT working files to disk via `mptMgr.Sync()`.
6. **Atomic State Ratchet**: Set the atomic `servingState` pointer to the witnessed checkpoint.
7. **Readiness Probe Transition**: Flip `/readyz` to `HTTP 200 OK` and enter Normal Serving Mode with the active serving invariant established.

> [!NOTE]
> **Scope Note**: While this alternative Catch-Up Ingestion Mode is specified in Section 4.4, the vast majority of this documentation suite focuses on the steady-state Normal Serving Mode. The subsystem documentation will be expanded to cover catch-up pipeline variants as validated by implementation and experimentation.

---

## 5. Security, Trust & Verification Model

### 5.1 Threat Model & Trust Assumptions

- **Untrusted Index Operator**: The VIndex operator is assumed to be untrusted. An adversary controlling the operator cannot forge index proofs, omit valid occurrences, or equivocate state commitments without breaking SHA-256 or being detected by independent witnesses.
- **Trusted Input Log**: The Input Log is assumed to have an authentic, append-only history protected by cryptographic checkpoints. VIndex inherits the admission criteria of the Input Log without secondary filtering.
- **Immutable & Deterministic `MapFn`**: The mapping logic is compiled to WebAssembly. Any host or guest execution trap triggers a strict `HALT` policy to prevent silent state divergence across witness nodes.

### 5.2 Proof of Omission Resistance

When a client queries a key, the response proves completeness through two layered proofs:
1. **MPT Proof (`mpt-proof-v1`)**: Proves whether `KeyHash` exists in the MPT at `MapRoot`.
   - If **Non-Inclusion**: Cryptographically proves that no leaf in the Input Log has ever mapped to this key.
   - If **Inclusion**: Cryptographically binds `KeyHash` to its specific 32-byte `MiniLogRoot`.
2. **Sub-Log Merkle Compact Range Proof (`prefix-compact-range-v1` + `indices-v1`)**:
   - The returned indices and historical compact range hashes are hashed according to RFC 6962 (`LeafHash = SHA256(0x00 || BigEndian(idx))`).
   - The client computes `CompactRange.Root()` and asserts equality with `MiniLogRoot`.
   - Because `MapRoot` is witnessed in the Output Log, the operator cannot omit an index without causing the mini-log root to mismatch.

### 5.3 Equivocation Resistance via Witnessed Output Log

The Output Log uses Tessera (`tlog-tiles`) backed by independent witness cosignatures ([signed-note](https://c2sp.org/signed-note), [tlog-checkpoint](https://c2sp.org/tlog-checkpoint)). The Map Operator cannot present different views of index state to different clients without producing conflicting signed checkpoints detectable by public monitors.

### 5.4 Input Log Cryptographic Authentication & Verification

VIndex enforces strict, end-to-end cryptographic verification before ingesting or indexing any data from upstream Input Logs:

1. **Checkpoint Origin Signature**: Mandatory cryptographic verification of the log origin signature before accepting any target checkpoint note.
2. **Witness Policy ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy))**: Optional verification of witness cosignature quorums against the configured witness policy.
3. **Merkle Consistency Proofs**: Mandatory Merkle consistency proof verification whenever the target checkpoint advances (`CP_old` -> `CP_new`), proving that the log is an append-only progression.
4. **Tile & Leaf Merkle Tree Authentication**: All downloaded data/tree tiles and leaf entries are authenticated against the target checkpoint root before mapping or indexing.

#### Realization via `filippo.io/torchwood`
- `torchwood.VerifyCheckpoint(raw, policy)`: Parses the checkpoint note, validates the log origin signature, and verifies compliance with witness policy quorums.
- `golang.org/x/mod/sumdb/tlog.CheckTree(...)`: Verifies Merkle consistency proofs between consecutive checkpoints during target ratcheting.
- `torchwood.Client` & `torchwood.Client.Entries(ctx, tree, start)`: Fetches data and tree tiles, verifies tree tiles against `tree.Hash`, computes leaf record hashes (`tlog.RecordHash`), and verifies leaf hashes against Level-0 tree tiles prior to mapping.
- `torchwood.PermanentCache`: Caches verified non-partial tiles on disk to serve as the immutable log of record powering Zero-WAL crash recovery.
- Format adapters (`WithTilePath`, `WithCutEntry`): Configures tile paths and entry cut boundaries for standard log layouts (`tlog-tiles`, `static-ct`, `sumdb`).

### 5.5 Inductive Backward Verification Protocol

Client-side verification of paginated queries operates as an inductive backward chain:

```text
  [Client Query: Page 1 (Tip, before=nil)]
       │
       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Step 1: Base Verification (Page 1)                          │
  │ • Extract MapRoot from Output Log checkpoint & leaf         │
  │ • Verify mpt-proof-v1(KeyHash) against MapRoot -> MiniLogRoot│
  │ • Init CompactRange with prefix-compact-range-v1            │
  │ • Append LeafHash(idx) for each idx in indices-v1           │
  │ • Assert CompactRange.Root() == MiniLogRoot                 │
  │ • Retain prefix-compact-range-v1 as Target-CR-1             │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼ (Next Query: before = next_before)
  ┌─────────────────────────────────────────────────────────────┐
  │ Step 2: Inductive Verification (Page 2)                     │
  │ • Init CompactRange with Page 2 prefix-compact-range-v1     │
  │ • Append LeafHash(idx) for each idx in Page 2 indices-v1    │
  │ • Assert CompactRange.Root() matches Target-CR-1            │
  │ • Retain Page 2 prefix-compact-range-v1 as Target-CR-2      │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼ (Repeat backward...)
  ┌─────────────────────────────────────────────────────────────┐
  │ Step N: Genesis Reached                                     │
  │ • prefix-compact-range-v1 == empty (0 historical entries)   │
  │ • Entire historical sequence cryptographically verified     │
  └─────────────────────────────────────────────────────────────┘
```

1. **Base Step (Page 1 / Tip Query, `before == nil`)**:
   - Extract `MapRoot` from the verified Output Log checkpoint and leaf.
   - Verify `mpt-proof-v1` against `MapRoot` to extract `MiniLogRoot`.
   - Initialize `CompactRange` with `prefix-compact-range-v1` (commits to historical prefix `0 .. next_before-1`). If no earlier entries exist, the prefix is empty.
   - Append `LeafHash(idx) = SHA256(0x00 || BigEndian(idx))` for each index in `indices-v1`.
   - Assert `CompactRange.Root() == MiniLogRoot`.
   - Retain `prefix-compact-range-v1` as the expected target compact range for the subsequent continuation page.

2. **Inductive Step (Continuation Pages, `before != nil`)**:
   - Initialize a new `CompactRange` with the continuation page's `prefix-compact-range-v1`.
   - Append `LeafHash(idx)` for each index in the continuation page's `indices-v1`.
   - Assert that the resulting compact range state matches the prefix compact range retained from the preceding page.
   - Retain the current page's `prefix-compact-range-v1` for the next backward continuation step.
   - Repeat until genesis (empty prefix compact range) is reached.

3. **Context Dependency**:
   - Standalone continuation queries (`before != nil`) executed without prior page context cannot be verified against `MapRoot` in isolation because `MiniLogRoot` commits only to the full mini-log accumulator at the tip. Continuation pages must be verified inductively starting from Page 1 downward.

---

## 6. Storage & Physical Hardware Topology

### 6.1 Dual-Disk Physical Isolation

Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is **strongly recommended**:

```text
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│       Disk A (NVMe SSD): Data        │     │       Disk B (NVMe SSD): Tree        │
│ • Pebble DB (chunks 'c', metadata 'm')│    │ • MPT mmap working tree              │
│ • Local Managed Tile Cache           │     │ • MPT append-only leaf file          │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

- **Compaction Conflict**: Periodic MPT disk compaction writes full memory images (e.g. 10 GB for 100M keys) sequentially. If sharing a disk with Pebble, this saturates disk I/O, stalls Pebble memtable flushes, and triggers LSM write stalls.
- **Durability Invariant**: `TileReaper` remains pending during startup recovery and runs concurrently during steady-state ingestion with `SafeWatermark = mptDurableSize` (which is initialized to `S_OUT` following `mptMgr.Sync()` upon startup recovery completion). Raw tiles on Disk A are retained until Disk B's MPT working state is durably fsync'd. Because `mptDurableSize` is strictly bounded by `m_kv_size` (`Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= mptDurableSize`), `min(m_kv_size, mptDurableSize) == mptDurableSize`. Leaves below `mptDurableSize` are already committed to Pebble and durably fsync'd in MPT disk files, so crash recovery never requires raw tiles below `mptDurableSize`.

### 6.2 Resource Sizing & Memory Footprint

| Scale (Unique Keys) | MPT Memory (`mmap`) | MPT Leaf Disk | Pebble Disk | Recommended RAM | Recommended GCP VM |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.04 GB | ~320 MB | ~1 GB | 8 GB | `e2-standard-2` |
| **Medium (100M)** | ~10.4 GB | ~3.2 GB | ~10 GB | 64 GB | `n2-highmem-8` |
| **Large (1B)** | ~104 GB | ~32 GB | ~100 GB | 256 GB | `n2-megamem-16` |
| **Very Large (2B)** | ~208 GB | ~64 GB | ~200 GB | 512+ GB | `m4-megamem-64` |

---

## 7. Observability, SLOs & Disaster Recovery

### 7.1 Prometheus Metrics

`vindexd` exports structured Prometheus metrics:

- **Ingestion & Mapping**:
  - `vindex_ingestion_lag` (Gauge): Distance between Input Log head and `m_kv_size`.
  - `vindex_map_bundle_duration_seconds` (Histogram): Duration of WASM `map_bundle` tile executions.
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
- `GET /readyz`: Readiness probe. Returns HTTP 200 once Zero-WAL startup recovery completes and `ServingState` is active; returns HTTP 503 during startup recovery, active disk rebuilds, or following a fatal trap.

### 7.4 Rollout, Lifecycle & Disaster Recovery

#### 1. Genesis Catch-Up Mode

High-throughput fast-forward bulk ingestion from leaf 0 to a target checkpoint. In this mode, `vindexd` maximizes parallelism across Wazero WASM sandboxes, executes bundled tile mapping (`map_bundle`), bypasses per-batch witness roundtrips, and streams entries directly into Pebble DB and the in-memory MPT via direct `mpt.Set` and `mpt.Snap` operations before activating serving endpoints. See [Section 4.4](#44-operational-modes--alternative-catch-up-pipeline) for the complete Catch-Up Ingestion Mode pipeline invariants, memory efficiency mechanics, and atomic mode transition sequence.

#### 2. Single-Host Disaster Recovery

- **Disk B (MPT) Crash**: If the disk storing MPT working files fails or corrupts, the MPT is rebuilt entirely in RAM directly from local Disk A Pebble inverted chunks (`'c' + KeyHash + ^chunkNum`) without network egress.
- **Disk A (Pebble) Crash**: If the primary storage disk fails, state is replayed directly from the local tile cache or streamed from the upstream Input Log.
- **Trap / Invariant Violation**: Any unexpected state divergence, WASM runtime fault, or invariant violation triggers a deterministic `HALT` policy. This immediately freezes the serving pointer and preserves local state on disk for post-mortem forensics.

---

## 8. Major Design Evolutions via Closed-Loop Spec -> Implement -> Measure -> Update Cycles

The Plan of Record (PoR) for VIndex v1 was hardened through empirical, closed-loop engineering iterations where initial architectural assumptions were implemented, measured under production-scale workloads, and systematically evolved.

### 8.1 Evolution 1: MapFn Bundling & Host-Side Preimage Hashing

```text
Baseline Design (Per-Leaf Mapping + In-Guest Crypto):
  Tile (256 leaves) ──► 768 FFI Transitions (allocate, map_leaf, reset per leaf) ──► ~23% CPU in FFI
                    ──► In-Guest Software SHA-256 in WASM Bytecode                ──► ~55% CPU in Crypto

PoR Design (Bundled Tile Mapping + Host Hardware SIMD Crypto):
  Tile (256 leaves) ──► 1 allocate + 1 map_bundle + 1 reset (2-3 FFI calls)       ──► < 1% CPU in FFI
                    ──► Guest emits Raw Canonical Preimages
                    ──► Host computes Hardware SHA-256 (SHA-NI / ARMv8 Crypto)   ──► Hardware Speed (0% WASM crypto)
                    ──► Preserves Preimages for future Prefix-Trie indexing
```

- **Problem & Profiling Telemetry**:
  In the initial v1 specification, the WebAssembly interface mapped entries on a per-leaf basis (`map_leaf(ptr, len) -> (out_ptr, out_len)`), with guest bytecode computing SHA-256 hashes internally. Comprehensive CPU profiling during 54M-leaf SumDB and 10M-leaf CT ingestion runs revealed two severe bottlenecks:
  1. **FFI Boundary Overhead (~23% CPU)**: For every 256-leaf tile, the host executed 3 FFI calls per leaf (`allocate`, `map_leaf`, `reset`), totaling 768 FFI boundary crossings per tile. FFI parameter marshaling, memory boundary assertions, and context switches consumed ~23% of total CPU time.
  2. **In-Guest Software SHA-256 (~55% CPU)**: Compiling software cryptographic hashing routines into WebAssembly bytecode prevented the guest from accessing host CPU vector/SIMD cryptographic instructions. Software SHA-256 inside WASM consumed ~55% of all CPU cycles during mapping.
- **Plan of Record (PoR) Architecture**:
  1. **Bundled Tile Execution (`map_bundle`)**: Instead of 768 FFI calls per tile, the host writes bundled leaves (`1 <= N <= 256`) into guest memory in a single structured buffer and invokes `map_bundle` once. FFI transitions dropped from 768 to 2–3 per tile, reducing FFI overhead from ~23% to < 1% of CPU time, with full support for partial tiles on unaligned checkpoint boundaries or log heads.
  2. **Host-Side Hardware SHA-256**: Guest plugins extract and emit raw canonical Claim Subject preimages (e.g. lowercase Punycode domain strings, escaped Go module paths). The Go host runtime hashes preimages using standard `crypto/sha256`, which leverages hardware-accelerated SIMD instructions (Intel/AMD SHA-NI extensions or ARMv8 Crypto instructions). This eliminated the ~55% software crypto bottleneck.
  3. **Preservation of Preimages for Future Subtree / Prefix Indexing**: By returning raw preimages rather than opaque hashes, the host runtime retains the exact domain strings and module paths. This provides forward compatibility for future prefix-trie search capabilities (Section 9.5) without altering guest WASM plugin ABIs.

### 8.2 Evolution 2: Removal of the Write-Ahead Log (WAL)

```text
Baseline Design (Pebble 'w' Prefix WAL + Async WalReaper):
  Ingest ──► WriteBatch('w' WAL) ──► Disk Sync ──► Output Log ──► WalReaper Compaction ──► Inverted Chunks ('c')
  Result: Double-write disk amplification, high LSM compaction churn, P99 latency spikes (847–1,214 ms).

PoR Design (Zero-WAL Direct Commit + TileReaper):
  Ingest ──► Direct WriteBatch('c' Chunks) with pebble.Sync ──► Output Log & MPT Ratchet
  Result: +24.7% throughput (240k leaves/s), 2.4 ms warm recovery, ~93–99% P99 latency reduction.
```

- **Problem & Profiling Telemetry**:
  The prototype staged index records under a transient `'w'` prefix in Pebble DB before an asynchronous background worker (`WalReaper`) converted them into inverted chunks (`'c'`) and deleted the `'w'` keys. Telemetry revealed severe performance pathologies:
  1. **Double-Write Amplification & LSM Churn**: Every mapping was written to disk twice and then deleted, saturating NVMe write bandwidth and triggering massive Pebble LSM compaction cascades.
  2. **Severe Tail Read Latency Spikes**: LSM compaction stalls in Pebble caused P99 lookup latencies to spike to **1,214 ms** (1-to-1 mapping) and **847.8 ms** (CT fanout).
  3. **Slow Startup Recovery**: Crash recovery required scanning and replaying unindexed WAL entries from Pebble.
- **Plan of Record (PoR) Architecture**:
  1. **Direct Inverted Chunk Commits**: Mapped batches are committed directly into Pebble inverted chunk records (`'c' + KeyHash + ^chunkNum`) with a synchronous durability barrier (`pebble.Sync`).
  2. **Immutable Tile Cache as Log of Record**: Verified raw entry tiles stored by `torchwood.PermanentCache` serve as the immutable log of record. If an unclean crash occurs, Stage 1 startup recovery deterministically replays missing tiles in < 500ms using O(1) `store.GetSubRoot` point queries with **zero storage mutations**.
  3. **Empirical Results**:
     - Throughput increased by **+24.7%** (from 192k to 240,467 leaves/sec on full Go SumDB).
     - Warm recovery time-to-first-serve dropped to **2.4 ms**.
     - P99 read tail latencies dropped by **~93–99%** (to 11.3 ms for 1-to-1 and 62.2 ms for CT fanout).
     - Pebble database footprint in CT tests dropped by **99%** (from 1.2 GB down to 9.91 MB).

---

## 9. Architectural Decisions & Alternatives Considered

### 9.1 Authenticated Data Structure & Single-Host Coupling
- *Selected*: In-memory Binary Merkle Patricia Trie (`torchwood/mpt` backed by `mmap`). Delivers ~52 bytes/node density, sub-5ms commit locks, and lock-free root prediction (`mpt.Predict`). Keeping the MPT in memory backed by local NVMe requires high-spec single-host hardware optimized for bulk log catch-up.
- *Rejected*: Sparse Merkle Trees (SMT) were rejected due to severe memory and disk I/O overhead across 256-level trie depths. Verkle Trees were rejected due to prohibitive CPU update costs during high-throughput bulk ingestion.

### 9.2 Storage Engine & Encapsulation Principle
- *Selected*: Embedded Pebble LSM key-value store encapsulated behind an abstract `IndexStore` interface. Provides zero network hops, single-host NVMe optimization, 33-byte prefix Bloom filters, and fast inverted chunk seeks (`^chunkNum`).
- *Architectural Isolation Principle*: **Pebble is strictly contained within the `kvstore` subsystem**. All Pebble concepts (SSTables, memtables, iterators, batches, bitwise key inversion, and binary chunk formats) are completely hidden behind the `IndexStore` domain interface. No external subsystem (`coordinator`, `server`, `ingest`, `tree`) imports Pebble or accesses low-level iterators. This guarantees that the underlying storage implementation can be seamlessly swapped (e.g. for SQLite, DuckDB, RocksDB, or a cloud-managed KV) without affecting any other part of the system.
- *Rejected*: Distributed KV stores (e.g. Cloud Bigtable, Spanner, Cassandra) were ruled out as the default engine because the MPT already requires single-host deployment; remote RPC hops introduce network latency and degrade bulk catch-up throughput.

### 9.3 Commit & Durability Pipeline
- *Selected*: Zero-WAL architecture with a synchronous storage persistence barrier. Uses the immutable Input Log tile cache as the log of record, completely eliminating write amplification and WAL tail repair during crash recovery. Mandates strict, synchronous disk persistence of the KV store (`store.WriteBatch` with `pebble.Sync`) before Output Log publication and witness network RPCs begin.
- *Rejected / Retired*: A WAL-in-Pebble design (staging index records under a transient 'w' prefix with an asynchronous WAL reaper) was initially implemented and evaluated. Removing the WAL in favor of direct chunk indexing proved measurably superior in empirical benchmarks: it increased full Go SumDB ingestion throughput by +24.7% (from ~192k to ~240k leaves/sec), reduced end-to-end build duration by ~20%, and eliminated double-write disk amplification and LSM compaction churn.

### 9.4 Pagination Model & Traversal Direction
- *Selected - Backward Paging (`before=X&limit=M`)*:
  - **Merkle Log Prefix Property**: Merkle tree compact ranges natively commit to a contiguous prefix of history (`0 .. K-1`). Returning the latest tail entries alongside a single `prefix-compact-range-v1` allows O(log N) cryptographic verification of all prior history in a single response, without requiring complex arbitrary suffix/middle sub-tree proofs.
  - **Access Pattern & Recency Bias**: Transparency log auditing is heavily biased toward the most recent entries (new certificates, latest package releases, fresh signatures). Earlier entries are typically stale, superseded, or already observed by recurring index auditors. Backward paging delivers the freshest data on Page 1 immediately.
  - **Storage & Traversal Alignment**: Inverted chunk storage (`'c' + KeyHash + ^chunkNum`) naturally positions the active, newest chunk first, enabling O(1) seek and chronological reverse traversal.
- *Rejected - Forward Paging (`start=X&limit=M`)*: Forward paging would require either returning unverified future state, maintaining complex arbitrary suffix sub-tree proofs, or forcing clients to traverse millions of historical entries to reach the latest state.

### 9.5 Future Architectural Extensions: Prefix-Trie & Subtree Indexing

While VIndex v1 standardizes on 32-byte point lookups (`KeyHash = SHA256(canonicalSubject)`), preserving canonical preimages across `map_bundle` executions creates a clean architectural foundation for future prefix search extensions:
- **Subdomain & Path Discovery**: In CT and package repositories, querying all subdomains under `*.example.com` or all subpackages under `github.com/org/*` requires prefix-trie indexing.
- **Unified Guest Contract**: Because guest WASM modules emit canonical string preimages rather than one-way hashes, future index versions can index raw radix paths or subtree roots without modifying plugin implementations or recompiling guest modules.

---

## 10. Companion Documentation

- **[WASM MapFn Plugin SDK & Runtime](../mapfn/README.md)**: WebAssembly guest ABI, 256-leaf `map_bundle` protocol, host SHA-NI crypto, multi-language SDKs, and offline verification harness.
- **[Applications & Ecosystems](./APPLICATIONS.md)**: Ecosystem mapping guides (Certificate Transparency, Merkle Tree Certificates, Go SumDB, Sigstore, Sigsum).
- **[Benchmarks & Performance](./BENCHMARKS.md)**: Empirical performance benchmarks (Zero-WAL vs WAL, 54M local / 61M live CDN SumDB ingestion, 10M CT fanout load tests, closed-loop telemetry).
- **[Hammer Design](../hammer/README.md)**: Load testing, synthetic generation, and invariant verification framework.
