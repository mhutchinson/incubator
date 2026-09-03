# Verifiable Index (VIndex v1) Architecture

This document defines the core architecture, load-bearing invariants, verified performance optimizations, operational considerations, and retired design branches for **VIndex v1**.

---

## 0. High Level Overview

### 0.0 Architectural Context
VIndex operates as a **Map Sandwich** bounded between an **Input Log** (the immutable source of truth) and a **Witnessed Output Log** (the cryptographic state anchor). For the foundational problem statement, non-negotiable system scope (single-machine deployment, 32-byte key hashes, append-only, hermetic WASM), and development workflow, see the top-level [VIndex README](../README.md).

This document specifies the technical system architecture: the 5-stage pipeline, checkpoint promotion and ratcheting invariants, crash consistency guarantees, operational sizing, and retired design branches.

### 0.1 Primary Pipeline Flow & Subsystem Map
Data progresses sequentially through 5 modular stages, coordinated by the coordinator:

| # | Pipeline Stage | Subsystem Directory | Physical Responsibility & Transition |
| :- | :--- | :--- | :--- |
| **1** | **Ingest & Tile Cache** | [`internal/ingest/`](../internal/ingest/README.md) | Polls upstream Input Log checkpoints, downloads and authenticates 256-leaf tiles into local disk cache, and reaps tiles below `SafeWatermark`. |
| **2** | **Sandboxed Mapping** | [`mapfn/`](../mapfn/README.md) & [`internal/ingest/`](../internal/ingest/README.md) | Ingestion host worker pool executes guest WASM plugins built with the Guest SDK (`mapfn/`), extracts canonical preimages via `map_bundle`, and executes host SIMD SHA-256 hashing. |
| **3** | **Inverted Storage** | [`internal/kvstore/`](../internal/kvstore/README.md) | Batches updates into Pebble LSM inverted chunks (`'c'`), applies 16-bit relative index encoding, and executes blocking `pebble.Sync`. |
| **4** | **State Commitment** | [`internal/tree/`](../internal/tree/README.md) | Predicts future `MapRoot` lock-free (`mpt.Predict`), appends state commitment to the Tessera Output Log, collects witness cosignatures, and ratchets the in-memory trie pointer. |
| **5** | **Read Serving** | [`internal/server/`](../internal/server/README.md) | Serves multi-section C2SP HTTP lookups (`/vindex/v1/lookup/{keyhash}`), RFC 6962 prefix compact ranges, and inductive backward pagination (`before=X`), strictly isolated to witnessed checkpoints. |
| *(Orch)* | **Coordinator** | [`internal/coordinator/`](../internal/coordinator/README.md) | Drives the batch loop across stages 1–4, freezes target input checkpoint, tracks watermarks, and executes Zero-WAL startup recovery. |
| *(Client)* | **Client SDK** | [`client/`](../client/README.md) | Stateless public Go client for querying nodes and cryptographically verifying lookup responses against witnessed checkpoints. |
| *(Audit)* | **Auditor & Mirror** | [`internal/auditor/`](../internal/auditor/README.md) | Audits published Output Log roots from leaf 0, alerts on root mismatches, triggers state-preserving halts, and optionally serves verified mirror lookups. |

### 0.2 Checkpoint Promotion & Monotonic Ratcheting
VIndex operates as an asynchronous pipeline: earlier stages ingest and process new data from the Input Log while the serving plane continues serving the previously committed state. This pipelining is essential for high throughput, but introduces crash and consistency risks if transitions are ambiguous.

Progress is governed by two complementary rules: **promoting checkpoints forward** through durability boundaries, and **ratcheting them in place**:
1. **Checkpoint Promotion**: Checkpoints progress strictly down the pipeline stage by stage. An authenticated Input Log checkpoint is targeted, mapped, and committed to KV storage (`KV_CP`), unlocking lock-free root prediction and subsequent publication to the Output Log (`Output_CP`), which is finally ratcheted into memory as the active serving state (`Serving_CP`).
2. **Monotonic Ratcheting**: Once a checkpoint or watermark advances at a given stage, it is locked and can never slip backward.

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` | Durable (`pebble.Sync` in Pebble metadata) | Upstream poll & origin note verification | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (`pebble.Sync` in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | Output Log tree size (`Output_CP.Size`) committing Input Log size (`InputLogSize` in leaf) | Durable (Tessera Output Log storage) | Append commitment leaf & witness cosigning | Cryptographically commits to index root (`MapRoot` + covered Input Log checkpoint). **Size Distinction**: `Output_CP.Size` represents the tree size (number of commitment leaves) of the Output Log itself, whereas the committed Input Log size covered by the index is stored inside the Output Log leaf payload (`InputLogSize`). |
| **`Serving_CP`** | Output Log Leaf | `Serving_CP.InputLogSize` | Volatile (In-memory atomic pointer) | Pointer swap under exclusive writer lock (< 5ms) | Active state exposed to client HTTP readers. |

**The Checkpoint Monotonic Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.Leaf.InputLogSize >= Serving_CP.InputLogSize
```
Every relation in the chain is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batches accumulate and commit in discrete chunks toward the target goalpost.
- `KV_CP.Size >= Output_CP.Leaf.InputLogSize`: Inverted chunk storage writes must complete `pebble.Sync` before Output Log append begins.
- `Output_CP.Leaf.InputLogSize >= Serving_CP.InputLogSize`: Appending to the Output Log and collecting witness signatures occur outside reader locking; `Output_CP` is naturally ahead until the writer acquires the exclusive writer lock to swap the serving pointer.
Because storage persistence strictly precedes Output Log publication (`KV_CP.Size >= Output_CP.Leaf.InputLogSize`), startup recovery is mathematically guaranteed never to encounter an Output Log commitment referencing uncommitted or missing KV chunks.

---

## 1. End-to-End Pipeline & Subsystem Mechanics

### 1.1 Stage 1: Ingest & Tile Cache ([`internal/ingest/`](../internal/ingest/README.md))
The ingestion engine polls the upstream Input Log for signed checkpoints, verifies them, and streams authenticated leaf data into a local filesystem tile cache.

1. **Protocol Support & Pluggable Ingestion**: Out of the box, the fetcher supports standard tile-based log specifications—primarily [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP static-ct](https://c2sp.org/static-ct). The library encapsulates ingestion behind the `TileFetcher` interface, allowing custom log sources or adapters to be injected as long as leaves are presented in 256-entry bundles.
2. **Cryptographic Authentication**: Regardless of upstream transport, all downloaded leaves are cryptographically authenticated against the target checkpoint's Merkle tree head before being admitted into the mapping pipeline.
3. **Local Tile Cache & Retention**: Verified tiles are written directly to a local filesystem cache (`ManagedTileCache`). This cache acts as a durable staging buffer that decouples network download throughput from downstream indexing. Tiles remain cached on disk until downstream systems (KV storage and the MPT) have durably committed their changes. Once data is durably persisted beyond a safe watermark, tiles may optionally be reaped by an asynchronous garbage collector (`TileReaper`) to bound disk usage.

- **[Correctness Invariant] Target Checkpoint Note Verification**:
  - *Rule*: Checkpoint notes must be cryptographically validated against configured origin verifier keys before the coordinator accepts the size advancement.
  - *Rationale*: Protects the indexer against man-in-the-middle attacks or malicious upstream proxies serving forged checkpoints.
  - *Consequence ("Or Else")*: If an unauthenticated checkpoint were accepted, the indexer would ingest and commit phantom leaves, poisoning the local index and causing independent verifiers to detect permanent root divergence.

- **[Correctness Invariant] Crash Recovery Tile Retention**:
  - *Rule*: The `TileReaper` must only prune tiles where no leaf contained in the tile will ever be required for crash recovery. The authoritative pruning boundary is calculated and governed by the Coordinator ([`internal/coordinator/`](../internal/coordinator/README.md)).
  - *Rationale*: Guarantees that startup recovery can fast-forward lagging state directly from local disk with zero external network requests.
  - *Consequence ("Or Else")*: If uncommitted tiles were prematurely pruned, a crash would force the node into expensive network egress to re-download historical tiles, violating the sub-500ms startup recovery SLO.

- **[Performance Optimization] Native 256-Leaf Tile Bundling**:
  - *Mechanism*: Ingests leaves exclusively in native 256-leaf bundles matching the upstream log's tile structure, dispatching each bundle directly as a discrete unit of work to the WASM worker pool.
  - *Impact*: Reduces upstream network requests by 256x compared to per-leaf REST endpoints, and eliminates memory slicing/repackaging overhead by aligning the network ingest unit directly with the `map_bundle` FFI execution boundary.

### 1.2 Stage 2: Sandboxed Mapping ([`mapfn/`](../mapfn/README.md) & [`internal/ingest/`](../internal/ingest/README.md))
The mapping pipeline extracts search keys from raw verified log leaves while preserving absolute node isolation and cross-toolchain determinism. Ecosystem developers write a pure mapping function (`type MapFn func([]byte) []string`) using the WASM Guest SDK (`mapfn/sdk`). The compiled `.wasm` plugin is executed by the Ingestion subsystem's host Wazero worker pool:

1. **Sandboxed Worker Pool**: A pool of Wazero sandboxes managed by `internal/ingest` executes the guest plugin's exported `map_bundle` function concurrently across 256-leaf bundles. The in-guest SDK unpacks the leaf crate, loops over leaves, and invokes the user's `MapFn`.
2. **Host Cryptographic Hashing**: To preserve security and performance, the guest SDK returns raw, un-hashed canonical preimages. The host runtime hashes these preimages into 32-byte search keys using native CPU hardware vector instructions.
3. **Chronological Resequencer**: Because parallel workers complete batches at variable rates, finished batches enter an in-memory resequencer that emits them in strictly ascending leaf order before downstream storage handoff.

- **[Correctness Invariant] Deterministic Halt on Execution Trap**:
  - *Rule*: Sandboxes execute with zero host I/O, zero network access, and deterministic clocks. If a guest module encounters an unhandled panic, memory violation, or runtime trap, the host executes an immediate, fatal process halt.
  - *Rationale*: Guarantees 100% deterministic reproducibility across independent nodes and verifiers.
  - *Consequence ("Or Else")*: Silently swallowing guest errors or generating fallback keys would create divergent index state, resulting in false non-inclusion proofs and permanent state divergence.

- **[Correctness Invariant] Monotonic Chronological Resequencing**:
  - *Rule*: Batches delivered to downstream storage and tree stages must be strictly ordered by leaf index in monotonic ascending sequence with zero gaps.
  - *Rationale*: Search key mini-logs rely on strictly sequential leaf order to construct valid Merkle compact ranges.
  - *Consequence ("Or Else")*: Out-of-order writes would corrupt the compact range Merkle structure, producing invalid mini-log roots that fail client verification.

- **[Performance Optimization] Bundled WebAssembly Execution**:
  - *Mechanism*: Transfers an entire 256-leaf tile into shared memory and executes a single boundary call per tile, rather than invoking the guest once per leaf.
  - *Impact*: Slashes foreign-function interface (FFI) boundary crossings by >99%, dropping FFI CPU overhead from ~23% of total CPU time to < 1%.

- **[Performance Optimization] Host Hardware SIMD Cryptography**:
  - *Mechanism*: Delegates SHA-256 hashing to host CPU vector instructions (such as x86 SHA-NI or ARMv8 Crypto extensions) rather than compiling cryptographic routines into WebAssembly bytecode.
  - *Impact*: Eliminates the ~55% CPU software crypto bottleneck inside WebAssembly.

### 1.3 Stage 3: Inverted Storage Commit ([`internal/kvstore/`](../internal/kvstore/README.md))
The KV storage engine persists search keys and their occurrence lists into an embedded Pebble LSM database.

1. **Inverted Chunk Mini-Logs**: Each search key's occurrences in the Input Log are stored as an append-only mini-log partitioned into bounded chunks (64K entries). Chunks are indexed so that the latest, active chunk can be located in O(1) time without scanning historical records.
2. **Compact Binary Encoding**: Chunk values store a cumulative Merkle compact range covering all prior chunks, plus a dense sequence of 16-bit relative index offsets for the active chunk, eliminating delimiter overhead.
3. **Synchronous Commit Barrier**: Batches are committed to disk using synchronous writes before notifying the coordinator.

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: Storage writes must durably flush all modified chunk records and the updated `KV_CP` to disk before the Output Log publication phase is permitted to begin (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees that the physical database never lags behind publicly published commitments across crashes or power loss.
  - *Consequence ("Or Else")*: If the node published a state commitment to the Output Log but crashed before storage was synced, the published root would reference missing KV chunks, permanently breaking proof generation for witnessed checkpoints.

- **[Correctness Invariant] Point-in-Time Sub-Root Isolation**:
  - *Rule*: When calculating or reconstructing sub-roots for a target Input Log size, the storage engine strictly evaluates records committed up to that size, ignoring any newer chunks written ahead of it.
  - *Rationale*: Enables startup recovery and reader lookups to safely inspect the database even if storage contains batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak un-witnessed or in-flight entries, violating reader snapshot isolation.

- **[Performance Optimization] Inverted Key Indexing & Prefix Bloom Filters**:
  - *Mechanism*: Orders chunk keys such that the active chunk is positioned first under the key prefix, and evaluates full-table prefix Bloom filters on seeks.
  - *Impact*: Locates active chunks in O(1) time without iterating through historical records, eliminating a 7.5x latency penalty on deep keys, while bypassing disk I/O entirely for non-existent keys.

- **[Performance Optimization] 16-Bit Relative Offsets**:
  - *Mechanism*: Stores index offsets as 2-byte relative offsets within each 64K chunk rather than 8-byte absolute integers.
  - *Impact*: Saves 75% disk storage on occurrence lists within each chunk.

- **[Performance Optimization] Two-Generational Active Chunk Cache**:
  - *Mechanism*: Retains hot chunk descriptors across sequential batches using a bounded in-memory cache.
  - *Impact*: Eliminates >90% of Pebble block cache read I/O during high-throughput ingestion.

### 1.4 Stage 4: State Commitment ([`internal/tree/`](../internal/tree/README.md))
The commitment plane anchors the updated search index in an append-only Output Log. As data preparation, each search key's occurrences in the Input Log form an append-only mini-log where each absolute occurrence index is encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00, producing a mini-log sub-root committing to the complete historical sequence of occurrences.

Following data preparation, the commitment plane executes a 3-step atomic commitment sequence (Prediction -> Immutable Output Log Append -> Atomic State Ratchet):

1. **Prediction (Lock-Free Prediction)**: The publisher pre-computes the future `MapRoot` in memory across modified mini-log sub-roots without acquiring reader locks or blocking concurrent HTTP lookups.
2. **Immutable Output Log Append & Witnessing**: The state commitment binding the predicted `MapRoot` to the Input Log checkpoint is appended to the append-only Output Log (advancing the Output Log's own tree size `Output_CP.Size`, while committing the Input Log size `InputLogSize` inside the leaf payload) and submitted to external witnesses to collect cryptographic cosignatures.
3. **Atomic State Ratchet**: The publisher briefly acquires the exclusive publisher lock, confirms that the actual computed root matches the prediction, swaps the active serving state pointer, and releases the lock (< 5ms critical section).

- **[Correctness Invariant] Fatal Halt on Root Prediction Divergence**:
  - *Rule*: When the writer lock is acquired to commit in-memory mutations, the actual computed tree root must strictly match the predicted root previously committed to the Output Log. If any divergence is detected, the daemon halts immediately with a fatal panic.
  - *Rationale*: Output Log entries are immutable. Once a root commitment is published and witnessed, the node must never serve an internal state that diverges from it.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal commitment to the Output Log that cannot be proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published state commitment leaf binds the exact `MapRoot` to the exact signed Input Log checkpoint.
  - *Rationale*: Independent witnesses sign the Output Log checkpoint note, preventing the operator from presenting conflicting views of index state to different clients without producing split-view evidence detectable by public monitors.
  - *Consequence ("Or Else")*: An operator attempting to selectively hide records would be mathematically detected by any monitor cross-checking witness cosignatures.

- **[Performance Optimization] Lock-Free Prediction & Split-Locking**:
  - *Mechanism*: Separates slow disk persistence (mmap page fsyncs) from in-memory lookup reads. Disk operations run in the background outside the reader lock; the exclusive writer lock is held solely for the in-memory pointer swap (< 5ms).
  - *Impact*: HTTP lookup throughput sustains over 670,000 reads/second during active disk commits, compared to severe stalls under coarse global locking.

### 1.5 Stage 5: Read Serving ([`internal/server/`](../internal/server/README.md))
The HTTP read server exposes verifiable point lookups adhering to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions.

1. **Lookup Routing**: Serves point queries by key hash (`GET /vindex/v1/lookup/{keyhash}`) and publishes current index checkpoints (`GET /vindex/v1/checkpoint`).
2. **Cryptographic Proof Packaging**: Packages an authenticated Merkle non-inclusion or inclusion proof against the active `MapRoot`, reads matching leaf indices from storage, and includes prefix compact ranges for client verification.

- **[Correctness Invariant] Serving Isolation Invariant**:
  - *Rule*: Client queries are strictly isolated to data committed by the active serving checkpoint (`Serving_CP.InputLogSize <= Output_CP.Leaf.InputLogSize`). Any in-flight storage writes ahead of `Serving_CP` must be invisible to readers.
  - *Rationale*: Ensures that every response returned by the server can be mathematically proven against the currently witnessed checkpoint.
  - *Consequence ("Or Else")*: Readers would observe un-witnessed or uncommitted future entries, causing client-side Merkle proof verification to fail.

- **[Correctness Invariant] Inductive Backward Verification Protocol**:
  - *Rule*: Multi-page query pagination progresses backward in time (`before=X`). Page 1 verifies the mini-log root directly against `MapRoot`; continuation pages inductively verify their index slice against the preceding page's compact range.
  - *Rationale*: Proves completeness across high-cardinality keys without requiring the server to construct expensive consistency proofs or return millions of historical indices in a single response.
  - *Consequence ("Or Else")*: Forward pagination would require either returning unverified future state or forcing clients to scan from leaf 0, degrading lookup latency.

- **[Performance Optimization] Direct Plaintext Streaming**:
  - *Mechanism*: Streams standardized multi-section plaintext responses directly to network sockets without intermediate JSON marshalling or reflection.
  - *Impact*: Maintains sub-millisecond median read latency (< 1ms P50, < 15ms P99) during heavy concurrent ingestion.

---

## 2. System-Wide Invariants & Crash Consistency

### 2.1 The Universal Crash Invariant
Because storage persistence strictly precedes Output Log publication:
```text
KV_CP.Size >= Output_CP.Leaf.InputLogSize   (persisted KV storage watermark >= Output_Leaf.InputLogSize)
```
This invariant holds under all crash, kill, and power loss scenarios. Note the distinction between the Output Log's own Merkle tree size (`Output_CP.Size`) and the committed Input Log size inside each Output Log leaf payload (`Output_CP.Leaf.InputLogSize`). Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted or missing KV store chunks. If a crash occurs after storage sync but before Output Log publishing, `KV_CP.Size > Output_CP.Leaf.InputLogSize`; startup recovery safely ignores chunks beyond `Output_CP.Leaf.InputLogSize` via point-in-time `store.GetSubRoot(keyHash, Output_CP.Leaf.InputLogSize)` queries.

### 2.2 Zero-WAL Startup Recovery Sequence
On daemon launch, the coordinator executes a 3-phase Zero-WAL recovery sequence before opening read and write interfaces:

1. **Phase 1: Instant Warm Start (< 5ms)**:
   - Evaluates whether the persisted MPT size equals the latest committed Output Log state (`Output_CP.Leaf.InputLogSize`) and the trie root matches the published leaf commitment (`MapRoot`).
   - If true, clean shutdown is verified. Activates the latest published checkpoint as `Serving_CP`, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms)**:
   - If the persisted MPT lags behind the latest Output Log commitment (dirty crash recovery):
     - Streams missing historical tiles across the lag window directly from the local disk cache.
     - Maps replayed tiles identify modified search keys.
     - Reconstructs mini-log sub-roots for modified keys up to `Output_CP.Leaf.InputLogSize` (where each occurrence leaf is an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00) with **zero database writes**.
     - Updates in-memory trie nodes, asserts that the resulting root strictly matches the Output Log commitment, flushes trie persistence to disk, activates `Serving_CP`, and **opens the Read Server (< 500ms)**.
3. **Phase 3: Background Catchup**:
   - Resumes forward ingestion from `KV_CP` toward `Target_CP`.

### 2.3 Moving-Goalpost Prevention & Mini-Log Determinism
When indexing high-velocity logs, the upstream log head advances continuously. Polling unverified checkpoints on every batch risks synchronization starvation. The coordinator freezes verified target sync checkpoints into durable database metadata prior to batch processing, ensuring that the ingestion pipeline processes fixed ranges to completion before advancing to a new target.

Mini-log sub-roots within the target boundary are computed deterministically by encoding each occurrence index as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00. This deterministic leaf hashing guarantees that independent indexer replicas and client verifiers compute identical mini-log roots for any given Input Log prefix.

---

## 3. Independent Auditor & Verified Mirror Architecture ([`internal/auditor/`](../internal/auditor/README.md))

The auditor subsystem audits the VIndex operator's published Output Log roots from genesis, detects equivocation, and optionally serves verified mirror lookups.

### 3.1 Verification Boundaries
1. **Client / Query Verification (`client/`)**: Evaluates individual query responses (`mpt-proof-v1` + `prefix-compact-range-v1`) against witnessed Output Log checkpoints via the public, stateless client SDK ([`client/`](../client/README.md)).
2. **Full-Log Independent Auditor (`internal/auditor/`)**: A standalone daemon (`vindex-audit`) that continuously tails both the Input Log and Output Log. It downloads verified Input Log tiles from leaf 0, executes mapping independently, reconstructs its own local MPT, and asserts that its locally computed `MapRoot` strictly matches the published `MapRoot` in each Output Log commitment.

### 3.2 Root Mismatch Alerting & State-Preserving Halt
If the locally computed `MapRoot` diverges from the published Output Log commitment, or an upstream sync divergence occurs, the auditor executes a coordinated containment response:
1. **Sync Engine Halt**: The background audit sync engine immediately halts forward sync. Watermarks are not advanced in Pebble DB.
2. **Forensic State Freeze**: Database files and MPT state are frozen on disk in-place, preserving uncorrupted cryptographic evidence for root-cause analysis and public equivocation disclosure.
3. **Metrics & Structured Logging**: Increments `vindex_verifier_root_mismatches_total`, sets alert gauge `vindex_verifier_root_mismatch = 1`, and emits a critical error log containing the divergent leaf index, target input size, locally computed root, and committed root.
4. **Serving Engine (Default Pinned Behavior)**: In mirror mode (`--serve_mirror=true`), the serving engine does **not** revoke serving state (does not set serving state to nil, does not fail lookups with HTTP 503). Instead, it remains pinned to the last known good verified Output Log checkpoint (`Serving_CP`), continuing to serve point lookups backed by cryptographically valid Merkle proofs up to that verified checkpoint. This preserves read availability and partition resilience: downstream readers continue receiving consistent, authentic responses rather than experiencing an immediate denial-of-service outage caused by an upstream index bug or signer divergence.
5. **Fail-Closed Mode (Opt-In)**: For operational environments requiring an absolute hard cutoff over stale serving, the optional flag `--fail_closed=true` is provided. When enabled, root divergence triggers immediate serving state revocation, causing all incoming lookup requests to return **HTTP 503 Service Unavailable**.
6. **Health and Readiness Probes**:
   - `/healthz`: Remains **HTTP 200 OK** as long as the process is alive and serving authentic, cryptographically valid state. This prevents container orchestrators (such as Kubernetes liveness probes) and upstream load balancers from prematurely terminating or de-routing traffic from a healthy mirror node.
   - `/readyz` or `/syncz`: Returns **HTTP 503 Service Unavailable** (or degraded sync status) with structured JSON diagnostics once sync halts, alerting traffic routers and monitoring systems that background auditing has stalled.

### 3.3 Verified Mirror Serving Engine
When `--serve_mirror=true` is enabled on the auditor:
- Evaluates lookups against the locally verified MPT and storage database under reader snapshot isolation.
- Guarantees readers only observe data that has been completely re-indexed and cryptographically verified against the Output Log.
- Enforces serving bounded strictly by `Serving_CP.InputSize`. Any uncommitted or divergent writes are completely isolated from readers.
- On upstream divergence, the mirror prioritizes client availability without compromising cryptographic integrity: by continuing to serve the pinned `Serving_CP`, it guarantees that every returned proof remains authentic and witnessed. If operators demand zero tolerance for stale checkpoints, enabling `--fail_closed=true` enforces immediate revocation.

### 3.4 Adversarial Threat Vector Matrix

| Threat Vector | Adversary Action | Detection Mechanism | System Action |
| :--- | :--- | :--- | :--- |
| **Publisher Equivocation** | Publisher serves conflicting Output Log checkpoints to different nodes. | Witness signature verification; Merkle consistency proofs between checkpoints. | Background sync halts immediately; alert logged; database frozen; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`). |
| **Log Rollback / Regression** | Publisher serves an Output Log checkpoint with `outCP.Size < verifiedOutputSize`. | Strict monotonic tree size assertions in `VerifyOnce`. | Sync halts; watermarks frozen; `/healthz` remains HTTP 200; `/readyz`/`/syncz` reports degraded sync; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`). |
| **Forged Map Root** | Publisher commits to an invalid or falsified `MapRoot` in an Output Log leaf. | Local MPT re-computation from input leaves; assertion `localMapRoot == committedMapRoot`. | Sets `vindex_verifier_root_mismatch = 1`; freezes disk state; `/readyz`/`/syncz` reports degraded sync; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`); alerts witnesses. |
| **Corrupted Input Leaves** | Network attacker or corrupted storage alters raw log entries. | Upstream tile Merkle verification fails against verified checkpoint root. | Pipeline aborts tile ingestion; retries from alternative mirrors. |
| **Omission Attack** | Publisher selectively drops a certificate or package from the index. | Local MPT computation includes the missing key; computed root mismatches published root. | Instant root mismatch alert (`vindex_verifier_root_mismatch = 1`); sync engine halts and freezes disk state; forensic bundle generated for public disclosure; mirror continues serving authentic proofs up to `Serving_CP` (or revokes serving if `--fail_closed=true`). |

### 3.5 Operational Runbook: Responding to Mismatches
When a root mismatch alert fires (`vindex_verifier_root_mismatch == 1` or `/readyz`/`/syncz` returning degraded sync status):
1. **Triage & Containment**: The auditor has already frozen disk state and halted forward sync, while safely continuing to serve cryptographically valid proofs pinned to `Serving_CP` (unless `--fail_closed=true` was specified). Do not restart the auditor process with cleared storage, as the disk contains crucial forensic data.
2. **Inspect Structured Logs**: Examine the auditor logs for the `CRITICAL ROOT MISMATCH DETECTED` entry to identify the divergent `output_leaf_index`, `target_input_size`, `local_map_root`, and `committed_map_root`.
3. **Forensic State Extraction**: Inspect local Pebble DB inverted chunks (`'c'`) and compare against raw Input Log leaves in the window `[verifiedInputSize .. targetInputSize)` to determine whether the publisher omitted leaves, altered keys, or encountered a non-deterministic `MapFn` bug.
4. **Reproduce via Standalone CLI**: Run `vindex-audit --oneshot` with an isolated temporary directory against the target checkpoint to confirm the mismatch is 100% reproducible.
5. **Publish Equivocation Bundle**: If the MapFn and input log entries are valid, publish the cryptographic proof bundle (signed Output Log checkpoint, leaf inclusion proof, raw leaf payload, signed Input Log checkpoint) to transparency witnesses and public coordination channels.

---

## 4. Operational Considerations & Hardware Sizing

### 4.1 Dual-Disk Physical NVMe Isolation
Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is recommended for high-velocity installations:
- **Disk A (NVMe SSD)**: Pebble DB (`'c'` chunks, `'m'` metadata) and local managed tile cache.
- **Disk B (NVMe SSD)**: MPT `mmap` working tree and append-only leaf files.

Physical separation isolates heavy sequential MPT compaction writes from Pebble LSM memtable flushes, preventing write stalls during sustained bulk ingestion.

### 4.2 Resource Sizing & Memory Footprint Scaling Matrix
Because key hashes are uniformly distributed, MPT updates touch scattered trie branches. Active MPT nodes must remain resident in RAM/mmap:

| Scale (Unique Keys) | MPT Memory (`mmap`) | MPT Leaf Disk | Pebble Disk | Recommended RAM | Recommended GCP VM |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.04 GB | ~320 MB | ~1 GB | 8 GB | `e2-standard-2` |
| **Medium (100M)** | ~10.4 GB | ~3.2 GB | ~10 GB | 64 GB | `n2-highmem-8` |
| **Large (1B)** | ~104 GB | ~32 GB | ~100 GB | 256 GB | `n2-megamem-16` |
| **Very Large (2B)** | ~208 GB | ~64 GB | ~200 GB | 512+ GB | `m4-megamem-64` |

### 4.3 Forward-Compatibility: Prefix-Trie & Subtree Indexing
While VIndex v1 provides point lookups by 32-byte key hashes, guest plugins emit raw canonical Claim Subject preimages (e.g. domain names, package paths). This allows future VIndex versions to construct auxiliary prefix-trie indices (for `*.example.com` or `github.com/org/*` subtree queries) without altering guest WASM ABIs.

### 4.4 Prometheus Metrics & SLO Thresholds
The daemon exports Prometheus metrics covering the entire lifecycle:
- Ingestion Lag: `vindex_ingestion_lag` (Target: < 60s)
- Mapping Latency: `vindex_map_bundle_duration_seconds` (Target: < 50ms/bundle)
- MPT Write Lock Duration: `vindex_mpt_write_duration_seconds` (Target: < 5ms)
- HTTP Lookup Latency: `vindex_lookup_latency_seconds` (Target: P99 < 50ms, P50 < 1ms)
- Read Availability: Target >= 99.9% uptime.

### 4.5 Single-Host Disaster Recovery Procedures
- **MPT Disk Corruption**: Rebuilt entirely in RAM from Pebble inverted chunks (`'c'`) via `store.GetSubRoot` point queries without network egress.
- **Pebble Storage Corruption**: Replayed from local tile cache or streamed from upstream Input Log.
- **Runtime Trap / Invariant Divergence**: Deterministic `HALT` policy freezes state and preserves disk data for post-mortem forensics.

---

## 5. Retired Ideas & Alternatives Considered

### 5.1 Backfill Mode (Genesis Catch-Up Mode) Retirement
- **Proposed**: A dedicated bulk ingestion mode ("Backfill Mode") that streamed leaves into Pebble and applied direct `mpt.SetBatch` mutations to in-memory MPT nodes, completely bypassing per-batch `mpt.Predict` root prediction and Output Log publishing.
- **Why Investigated**: Theoretical concern that running `mpt.Predict` and publishing Output Log commitments per batch would bottleneck catch-up from leaf 0.
- **Empirical Rejection Findings**:
  1. **Normal Mode is 85.1% Faster on Go SumDB**: Normal Serving Mode achieved **90,797 leaves/sec** vs. Backfill Mode's **49,064 leaves/sec**. Normal Mode batches storage updates and streams leaf bundles efficiently without the per-batch in-memory MPT mutation overhead that throttled Backfill Mode.
  2. **100% Read Starvation in Backfill Mode**: Backfill Mode shut down the HTTP read server, causing 0% query availability during catch-up. Normal Mode sustained sub-2ms P50 latency with 100% availability under concurrent queries.
  3. **Identical Memory Footprint**: Backfill Mode saved only 20–30 MB out of a 220 MB working set.
  4. **Production Personalities Never Adopted Backfill**: `cmd/sumdbindex` and `cmd/mtcindex` achieved headline rates (240,467 leaves/sec) using Normal Serving Mode (`SyncOnce`).
- **Resolution**: Permanently retired in favor of unified normal serving mode catch-up.

### 5.2 Intermediate Write-Ahead Log in Storage ('w' Prefix & WalReaper)
- **Proposed**: Staging mapped records under a transient `'w'` prefix in Pebble DB before an asynchronous background worker (`WalReaper`) converted them into inverted chunks (`'c'`).
- **Empirical Rejection**: Caused double-write disk amplification, massive LSM compaction churn, and severe P99 read latency spikes (up to 1,214 ms).
- **Resolution**: Retired in favor of the Zero-WAL direct inverted chunk commit architecture.

### 5.3 Per-Leaf WebAssembly Invocation (`map_leaf`)
- **Proposed**: Invoking WASM `map_leaf` individually for every leaf entry.
- **Empirical Rejection**: Generated 768 FFI boundary crossings per 256-leaf tile, consuming ~23% of total host CPU time in FFI overhead.
- **Resolution**: Replaced with bundled tile mapping (`map_bundle`), reducing FFI transitions to 2–3 per tile (< 1% CPU).

### 5.4 In-Guest Software Cryptographic Hashing
- **Proposed**: Compiling SHA-256 cryptographic hashing into guest WebAssembly bytecode.
- **Empirical Rejection**: Consumed ~55% of all CPU cycles during mapping due to lack of SIMD vector instructions inside WASM.
- **Resolution**: Delegated hashing to the host, leveraging hardware vector instructions (SHA-NI / ARMv8 Crypto).

### 5.5 Sparse Merkle Trees (SMT) & Verkle Trees
- **SMT**: Rejected due to prohibitive memory and disk I/O across 256-level tree depths.
- **Verkle Trees**: Rejected due to high CPU polynomial commitment generation costs during high-throughput ingestion.
- **Resolution**: Standardized on binary Sparse Merkle Patricia Trie in `mmap` (`torchwood/mpt`).

### 5.6 Forward Paging (`start=X&limit=M`)
- **Proposed**: Returning indices in ascending chronological order from a start cursor.
- **Theoretical Rejection**: Requires either returning unverified future state, maintaining complex arbitrary suffix subtree proofs, or forcing clients to scan millions of historical entries to reach the latest state.
- **Resolution**: Standardized on backward paging (`before=X&limit=M`), leveraging the natural prefix property of Merkle compact ranges.

### 5.7 Distributed Key-Value Engines (Cloud Bigtable, Spanner, Cassandra)
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL database.
- **Theoretical Rejection**: The authenticated MPT already requires single-host physical RAM/mmap locality; remote RPC hops degrade bulk ingestion throughput by orders of magnitude without solving tree state replication.
- **Resolution**: Embedded Pebble LSM engine encapsulated behind the `IndexStore` interface.
