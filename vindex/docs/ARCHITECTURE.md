# Verifiable Index (VIndex v1) Architecture

This document defines the core architecture, load-bearing invariants, verified performance optimizations, operational considerations, and retired design branches for **VIndex v1**.

---

## 0. High Level Overview

### 0.0 Architectural Context
VIndex operates as a **Map Sandwich** bounded between an **Input Log** (the immutable source of truth) and a **Witnessed Output Log** (the cryptographic state anchor). For the foundational problem statement, non-negotiable system scope (single-machine deployment, canonical key & bounded prefix lookups, append-only, hermetic WASM), and development workflow, see the top-level [VIndex README](../README.md) and [Prefix Lookups Specification](./PREFIX_LOOKUPS.md).

This document specifies the technical system architecture: the 5-stage pipeline, checkpoint promotion and ratcheting invariants, crash consistency guarantees, operational sizing, and retired design branches.

### 0.1 Primary Pipeline Flow & Subsystem Map
Data progresses sequentially through 5 modular stages, coordinated by the coordinator:

| # | Pipeline Stage | Subsystem Directory | Physical Responsibility & Transition |
| :- | :--- | :--- | :--- |
| **1** | **Ingest & Tile Cache** | [`internal/ingest/`](../internal/ingest/README.md) | Polls upstream Input Log checkpoints, downloads and authenticates 256-leaf tiles into local disk cache, and reaps tiles below the safe pruning watermark. |
| **2** | **Sandboxed Mapping** | [`mapfn/`](../mapfn/README.md), [`mapfn/host/`](../mapfn/host/), & [`internal/ingest/`](../internal/ingest/README.md) | WASI-free Wazero sandbox pool (`mapfn/host`) executes guest WASM plugins built with the Guest SDK (`mapfn/sdk`), extracts canonical keys via `map_bundle`, and computes host SIMD SHA-256 key hashes for Pebble storage. |
| **3** | **Inverted Storage** | [`internal/kvstore/`](../internal/kvstore/README.md) | Computes mini-log sub-roots across key partitions in memory, batches updates into Pebble LSM inverted chunks (`'c'`), and executes a blocking disk sync at the target checkpoint barrier. |
| **4** | **State Commitment** | [`internal/mpt/`](../internal/mpt/) & [`internal/tree/`](../internal/tree/README.md) | Predicts candidate `MapRoot` over variable-length canonical keys in the MPT (`internal/mpt`) under a shared read lock, appends state commitment to the Tessera Output Log (`internal/tree`), collects witness cosignatures, and ratchets the in-memory trie pointer. |
| **5** | **Read Serving** | [`internal/server/`](../internal/server/README.md) & [`wire/`](../wire/) | Serves two-endpoint C2SP HTTP lookups (`GET /vindex/v1/keys/{key...}[?prefix=true]` and lock-free `GET /vindex/v1/entries/{key...}?before=X`), legacy `/vindex/v1/lookup/{keyhash}`, RFC 6962 prefix compact ranges, and inductive backward pagination (`before=X`), strictly isolated to witnessed checkpoints. |
| *(Orch)* | **Coordinator & Resource Budget** | [`internal/coordinator/`](../internal/coordinator/README.md) & [`internal/budget/`](../internal/budget/) | Drives the batch loop across stages 1–4, freezes target input checkpoint, tracks watermarks, resolves host RAM/CPU resource budgets (`internal/budget`), and executes Zero-WAL startup recovery. |
| *(Client)* | **Client SDK & Verifiers** | [`client/`](../client/README.md) & [`internal/verifier/`](../internal/verifier/) | Stateless public Go client (`client/`) and checkpoint verifier parsers (`internal/verifier/`) for querying nodes and cryptographically verifying point, non-inclusion, and two-sided prefix proofs against witnessed checkpoints. |
| *(Audit)* | **Auditor & Mirror** | [`internal/auditor/`](../internal/auditor/README.md) | Audits published Output Log roots from leaf 0, alerts on root mismatches, triggers state-preserving halts, and optionally serves verified mirror lookups. |

### 0.2 Checkpoint Promotion & Monotonic Ratcheting
VIndex operates as an asynchronous pipeline: earlier stages ingest and process new data from the Input Log while the serving plane continues serving the previously committed state. This pipelining is essential for high throughput, but introduces crash and consistency risks if transitions are ambiguous.

Progress is governed by two complementary rules: **promoting checkpoints forward** through durability boundaries, and **ratcheting them in place**:
1. **Checkpoint Promotion**: Checkpoints progress strictly down the pipeline stage by stage. An authenticated Input Log checkpoint is targeted, mapped, and committed to KV storage (`KV_CP`), unlocking non-blocking root prediction and subsequent publication to the Output Log (`Output_CP`), which is finally ratcheted into memory as the active serving state (`Serving_CP`).
2. **Monotonic Ratcheting**: Once a checkpoint or watermark advances at a given stage, it is locked and can never slip backward.

#### The 4 Authoritative Checkpoints

| Checkpoint | Log Type | Committed Size | Persistence | Advancement Mechanism | Role in Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Target_CP`** | Input Log | `Target_CP.Size` | Durable (synced in Pebble metadata) | Upstream poll & origin note verification | Upper goalpost for current sync cycle; prevents moving-goalpost starvation. |
| **`KV_CP`** | Input Log | `KV_CP.Size` | Durable (synced in Pebble LSM) | Atomic flush of `'c'` chunk records | Durably binds indexed `'c'` chunk records to the verified Input Log state they cover. |
| **`Output_CP`** | Output Log | Output Log tree size (`Output_CP.Size`) committing Input Log size (`Output_CP.InputSize` in leaf) | Durable (Tessera Output Log storage) | Append commitment leaf & witness cosigning | Cryptographically commits to index root (`MapRoot` + covered Input Log checkpoint). **Size Distinction**: `Output_CP.Size` represents the tree size (number of commitment leaves) of the Output Log itself, whereas the committed Input Log size covered by the index is stored inside the Output Log leaf payload (`Output_CP.InputSize`). |
| **`Serving_CP`** | Output Log Leaf | `Serving_CP.InputSize` | Volatile (In-memory atomic pointer) | Pointer swap under exclusive writer lock (< 5ms) | Active state exposed to client HTTP readers. |

**The Checkpoint Monotonic Progression Invariant**:
```text
Target_CP.Size >= KV_CP.Size >= Output_CP.InputSize >= Serving_CP.InputSize
```
Every relation in the chain is `>=`:
- `Target_CP.Size >= KV_CP.Size`: Batches accumulate and commit in discrete chunks toward the target goalpost.
- `KV_CP.Size >= Output_CP.InputSize`: Inverted chunk storage writes must complete a durable disk sync before Output Log append begins.
- `Output_CP.InputSize >= Serving_CP.InputSize`: Appending to the Output Log and collecting witness signatures occur outside reader locking; `Output_CP` is naturally ahead until the writer acquires the exclusive writer lock to swap the serving pointer.
Because storage persistence strictly precedes Output Log publication (`KV_CP.Size >= Output_CP.InputSize`), startup recovery is mathematically guaranteed never to encounter an Output Log commitment referencing uncommitted or missing KV chunks.

### 0.3 Concurrency Architecture: Competing Pressures & Dynamic Backpressure

VIndex pipelines multiple concurrent stages that contend for shared host resources. Efficient throughput requires balancing three competing architectural pressures:

1. **Compute Contention (Mapping vs. Indexing)**:
   - *Pressure*: Stage 2 (WASM guest mapping) and Stage 3 (Merkle mini-log hashing) are both CPU-bound. If both stages scale independently to host concurrency, runnable threads double, causing OS thread preemption, L1/L2 cache invalidation, and starvation of Pebble compactions and read serving.
   - *Consideration*: Compute allocation must be asymmetric. WASM mapping scales across available cores because tile mapping is embarrassingly parallel. Key indexing is capped at modest concurrency because mini-log hashing exhibits diminishing returns due to the serial costs of database batching and memtable commits (Amdahl's Law).

2. **Decoupling vs. Garbage Collection Pressure**:
   - *Pressure*: Inter-stage channel buffers decouple throughput jitter between parallel mapping, sequential indexing, and disk syncs. However, deep buffers allow hundreds of uncommitted leaf batches to accumulate in memory, creating multi-gigabyte heap graphs that trigger expensive Go runtime GC mark-assist pauses and inflate queueing delay.
   - *Consideration*: Keep channel buffers strictly bounded. The buffer must be large enough to absorb transient disk flush latency, but tight enough that memory stays flat and backpressure engages before heap growth impacts the Go collector.

3. **Dynamic Backpressure via Runtime Scheduling**:
   - *Pressure*: Statically partitioning CPU cores between stages leaves host capacity idle whenever the workload bottleneck shifts (e.g. lightweight vs. expensive WASM mappers, or fast NVMe vs. slow disk syncs).
   - *Consideration*: Use bounded channels as self-regulating scheduler governors. When downstream indexing or disk sync slows, channels fill rapidly, causing the Go runtime to park upstream mapping goroutines. Parked workers yield their OS threads and CPU cores entirely to the storage engine. When storage catches up, channels drain and mapping workers immediately resume.

*Note: Specific worker pool sizes and channel capacities are implementation defaults calibrated by empirical benchmarks, and exposed as runtime configuration flags for operator tuning.*

---

## 1. End-to-End Pipeline & Subsystem Mechanics

### 1.1 Stage 1: Ingest & Tile Cache ([`internal/ingest/`](../internal/ingest/README.md))
The ingestion engine polls the upstream Input Log for signed checkpoints, verifies them, and streams authenticated leaf data into a local filesystem tile cache.

1. **Protocol Support & Pluggable Ingestion**: Out of the box, the fetcher supports standard tile-based log specifications—primarily [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP static-ct](https://c2sp.org/static-ct). Pluggable log adapters can also supply leaves in 256-entry bundles.
2. **Cryptographic Authentication**: Regardless of upstream transport, all downloaded leaves are cryptographically authenticated against the target checkpoint's Merkle tree head before being admitted into the mapping pipeline.
3. **Local Tile Cache & Retention**: Verified tiles are written directly to a local filesystem cache. This cache acts as a durable staging buffer that decouples network download throughput from downstream indexing. Tiles remain cached on disk until downstream systems (KV storage and the MPT) have durably committed their changes. Once data is durably persisted beyond the safe pruning watermark, superseded tiles are reaped by an asynchronous background pruner to bound disk usage.

- **[Correctness Invariant] Target Checkpoint Note Verification**:
  - *Rule*: Checkpoint notes must be cryptographically validated against configured origin verifier keys before the coordinator accepts the size advancement.
  - *Rationale*: Protects the indexer against man-in-the-middle attacks or malicious upstream proxies serving forged checkpoints.
  - *Consequence ("Or Else")*: If an unauthenticated checkpoint were accepted, the indexer would ingest and commit phantom leaves, poisoning the local index and causing independent verifiers to detect permanent root divergence.

- **[Correctness Invariant] Crash Recovery Tile Retention**:
  - *Rule*: The tile cache pruner must only delete tiles where no leaf contained in the tile will ever be required for crash recovery. The authoritative pruning boundary is calculated and governed by the Coordinator ([`internal/coordinator/`](../internal/coordinator/README.md)).
  - *Rationale*: Guarantees that startup recovery can fast-forward lagging state directly from local disk with zero external network requests.
  - *Consequence ("Or Else")*: If uncommitted tiles were prematurely pruned, a crash would force the node into expensive network egress to re-download historical tiles, violating the sub-500ms startup recovery SLO.

- **[Performance Optimization] Native 256-Leaf Tile Bundling**:
  - *Mechanism*: Ingests leaves exclusively in native 256-leaf bundles matching the upstream log's tile structure, dispatching each bundle directly as a discrete unit of work to the WASM worker pool.
  - *Impact*: Reduces upstream network requests by 256x compared to per-leaf REST endpoints, and eliminates memory slicing/repackaging overhead by aligning the network ingest unit directly with the `map_bundle` FFI execution boundary.

### 1.2 Stage 2: Sandboxed Mapping ([`mapfn/`](../mapfn/README.md) & [`internal/ingest/`](../internal/ingest/README.md))
The mapping pipeline extracts search keys from raw verified log leaves while preserving absolute node isolation and cross-toolchain determinism. Ecosystem developers write a pure mapping function using a streaming `emit` callback (`type EmitMapFunc func(leaf []byte, emit func(key []byte))`) via the WASM Guest SDK (`mapfn/sdk`). The compiled `.wasm` plugin is executed by the Ingestion subsystem's host Wazero worker pool:

1. **Sandboxed Worker Pool**: A pool of Wazero sandboxes managed by `internal/ingest` executes the guest plugin's exported `map_bundle` function concurrently across 256-leaf bundles. The in-guest SDK unpacks the leaf crate, loops over leaves, and invokes the user's `MapFn`. Extracted preimages are streamed via `emit` directly into the pre-allocated output memory slab, eliminating intermediate collection allocations.
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
The KV storage engine persists search keys and their occurrence lists efficiently in an embedded Pebble LSM database.

1. **Inverted Chunk Mini-Logs**: Each search key's occurrences in the Input Log are stored as an append-only mini-log partitioned by fixed 64K global Input Log leaf index windows. Chunks are indexed in reverse chronological order so that the latest chunk for any key can be located in O(1) time without scanning historical records.
2. **Compact Binary Encoding**: Chunk values store a cumulative Merkle compact range covering all occurrences of that key in prior chunks, plus a dense sequence of relative index offsets within the current 64K leaf window.
3. **Synchronous Commit Barrier**: Storage updates across a target sync cycle are durably flushed to disk before the coordinator publishes the new state commitment to the Output Log.

- **[Correctness Invariant] Synchronous Persistence Barrier**:
  - *Rule*: Storage writes must durably flush all modified chunk records and the updated `KV_CP` to disk before the Output Log publication phase is permitted to begin (`KV_CP.Size >= Output_CP.InputSize`).
  - *Rationale*: Guarantees that the physical database never lags behind publicly published commitments across crashes or power loss.
  - *Consequence ("Or Else")*: If the node published a state commitment to the Output Log but crashed before storage was synced, the published root would reference missing KV chunks, permanently breaking proof generation for witnessed checkpoints.

- **[Correctness Invariant] Point-in-Time Sub-Root Isolation**:
  - *Rule*: When calculating or reconstructing sub-roots for a target Input Log size, the storage engine strictly evaluates records committed up to that size, ignoring any newer entries written ahead of it.
  - *Rationale*: Enables startup recovery and reader lookups to safely inspect the database even if storage contains batches ahead of the active serving state.
  - *Consequence ("Or Else")*: Query responses would leak unwitnessed or in-flight entries, violating reader snapshot isolation.

- **[Performance Optimization] Inverted Key Indexing & Prefix Bloom Filters**:
  - *Mechanism*: Orders chunk keys such that the newest chunk is positioned first under the key prefix, and evaluates full-table prefix Bloom filters on seeks.
  - *Impact*: Locates active chunks in O(1) time without iterating through historical records, while bypassing disk I/O for non-existent keys.

- **[Performance Optimization] Window-Relative Offset Encoding**:
  - *Mechanism*: Partitions occurrences by 64K Input Log leaf windows so each occurrence inside a chunk is stored as a compact relative offset rather than a full 8-byte absolute index.
  - *Impact*: Reduces per-occurrence storage footprint by 75% within each chunk.

- **[Performance Optimization] Active Chunk Caching & Parallel In-Memory Mini-Log Hashing**:
  - *Mechanism*: Retains hot chunk state across consecutive batches in a bounded in-memory cache and evaluates RFC 6962 compact ranges across distinct keys concurrently in memory before sequentially applying chunk writes to Pebble.
  - *Impact*: Eliminates repeated block cache reads on hot keys and prevents single-thread CPU bottlenecks on Merkle hashing during high-fanout ingestion.

### 1.4 Stage 4: State Commitment ([`internal/tree/`](../internal/tree/README.md))
The commitment plane anchors the updated search index in an append-only Output Log. Each search key's mini-log commits to the strictly increasing sequence of Input Log leaf indices matching that key, where each occurrence is encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00, producing a mini-log sub-root committing to the complete historical sequence of occurrences.

Following data preparation, the commitment plane executes a 3-step atomic commitment sequence (Prediction -> Immutable Output Log Append -> Atomic State Ratchet):

1. **Prediction (Non-Blocking Prediction)**: The publisher pre-computes the candidate `MapRoot` in memory across modified mini-log sub-roots under a shared read lock without blocking concurrent HTTP lookups.
2. **Immutable Output Log Append & Witnessing**: The state commitment binding the predicted `MapRoot` to the Input Log checkpoint is appended to the append-only Output Log (advancing the Output Log's own tree size `Output_CP.Size`, while committing the Input Log size `InputLogSize` inside the leaf payload) and submitted to external witnesses to collect cryptographic cosignatures.
3. **Atomic State Ratchet**: The publisher briefly acquires the exclusive tree lock, confirms that the actual computed root matches the prediction, swaps the active serving state pointer, and releases the lock (< 5ms critical section).

- **[Correctness Invariant] Fatal Halt on Root Prediction Divergence**:
  - *Rule*: When the writer lock is acquired to commit in-memory mutations, the actual computed tree root must strictly match the predicted root previously committed to the Output Log. If any divergence is detected, the daemon halts immediately.
  - *Rationale*: Output Log entries are immutable. Once a root commitment is published and witnessed, the node must never serve an internal state that diverges from it.
  - *Consequence ("Or Else")*: Continuing execution would publish an equivocal commitment to the Output Log that cannot be proven by the node's internal state.

- **[Correctness Invariant] Single-Timeline Equivocation Resistance**:
  - *Rule*: Every published state commitment leaf binds the exact `MapRoot` to the exact signed Input Log checkpoint.
  - *Rationale*: Independent witnesses sign the Output Log checkpoint note, preventing the operator from presenting conflicting views of index state to different clients without producing split-view evidence detectable by public monitors.
  - *Consequence ("Or Else")*: An operator attempting to selectively hide records would be mathematically detected by any monitor cross-checking witness cosignatures.

- **[Performance Optimization] Non-Blocking Prediction & Split-Locking**:
  - *Mechanism*: Separates slow disk persistence (mmap page `fsync`s) from in-memory lookup reads. Disk operations run in the background outside the exclusive tree lock; the exclusive lock is held solely for the in-memory commit and pointer swap (< 5ms).
  - *Impact*: HTTP lookup throughput sustains over 670,000 reads/second during active disk commits, compared to severe stalls under coarse global locking.

### 1.5 Stage 5: Read Serving ([`internal/server/`](../internal/server/README.md))
The HTTP read server exposes verifiable point and prefix lookups adhering to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions (see [`docs/PREFIX_LOOKUPS.md`](./PREFIX_LOOKUPS.md) for the full wire specification):

1. **Two-Endpoint Read Protocol**:
   - **Key Discovery & State Commitment (`GET /vindex/v1/keys/{key...}[?prefix=true]`)**: Acquires a brief shared read lock on the MPT (`internal/mpt`), evaluates point inclusion/non-inclusion (`ProveKey`) or prefix subtree scans (`ProvePrefix`), and returns the state commitment (`vindex/v1`, `output-log-leaf-v1`, `output-log-proof-v1`), `mpt-proof-v1 <inclusion|non-inclusion|prefix>`, and `keys-v1` (`<canonical_key> <subRootHex>`).
   - **Lock-Free Entry Pagination (`GET /vindex/v1/entries/{key...}?before=X[&limit=Y]`)**: Evaluates `KeyHash = SHA256(key)` directly against Pebble inverted chunks (`'c'`) with **zero MPT lock acquisition**, returning `prefix-compact-range-v1` and `indices-v1`.
   - **Legacy Point Lookup (`GET /vindex/v1/lookup/{keyhash}`)**: Combined single-request point lookup for 64-character hex key hashes.
2. **Prefix Policy Guardrails**: Prefix queries (`?prefix=true`) are validated against an optional `PrefixPolicy` (such as `DomainETLDP1PrefixPolicy`, rejecting bare TLD/public-suffix scans with `HTTP 400`) and bounded by `--max_prefix_keys` (default `1000`, returning `HTTP 413 Content Too Large` if exceeded).

- **[Correctness Invariant] Serving Isolation Invariant**:
  - *Rule*: Client queries are strictly isolated to data committed by the active serving checkpoint (`Serving_CP.InputSize <= Output_CP.InputSize`). Any in-flight storage writes ahead of `Serving_CP` must be invisible to readers.
  - *Rationale*: Ensures that every response returned by the server can be mathematically proven against the currently witnessed checkpoint.
  - *Consequence ("Or Else")*: Readers would observe unwitnessed or uncommitted future entries, causing client-side Merkle proof verification to fail.

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
KV_CP.Size >= Output_CP.InputSize   (persisted KV storage watermark >= Output_CP.InputSize)
```
This invariant holds under all crash, kill, and power loss scenarios. Note the distinction between the Output Log's own Merkle tree size (`Output_CP.Size`) and the committed Input Log size inside each Output Log leaf payload (`Output_CP.InputSize`). Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted or missing KV store chunks. If a crash occurs after storage sync but before Output Log publishing, `KV_CP.Size > Output_CP.InputSize`; startup recovery safely ignores chunks beyond `Output_CP.InputSize` using point-in-time sub-root reconstruction bounded at `Output_CP.InputSize`.

### 2.2 Zero-WAL Startup Recovery Sequence
On daemon launch, `vindexd` binds the HTTP listener immediately so `/healthz` returns `200 OK` and `/readyz` + lookup endpoints return `503 Service Unavailable` (`Retry-After: 30`, `"status": "mpt_initializing"`) while `mpt.Open()` replays any uncompacted `torchwood/mpt` journal frames on disk (see [`docs/BENCHMARKS.md §5`](./BENCHMARKS.md#5-post-run-empirical-evaluation--cold-startup-investigation-2026-09-22) for cold-start journal replay telemetry). Once `mpt.Open()` completes, the coordinator executes a 3-phase Zero-WAL recovery sequence (`coord.Recover()`) before promoting the read server to `200 OK`:

1. **Phase 1: Instant Warm Start (< 5ms after `mpt.Open`)**:
   - Evaluates whether the durable MPT watermark (`MPT_Durable_Size` with `IsExact() == true`) equals the latest committed Output Log state (`Output_CP.InputSize`) and the trie root matches the published leaf commitment (`MapRoot`).
   - If true, clean shutdown is verified. Activates the latest published checkpoint as `Serving_CP`, and **opens the HTTP Read Server immediately (< 5ms)**.
2. **Phase 2: Fast-Forward Tile Replay (< 500ms after `mpt.Open`)**:
   - If the persisted MPT lags behind the latest Output Log commitment (dirty crash recovery):
     - Streams missing historical tiles across the lag window directly from the local disk cache.
     - Maps replayed tiles to identify modified search keys.
     - Reconstructs mini-log sub-roots for modified keys up to `Output_CP.InputSize` (where each occurrence leaf is an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00) with **zero database writes**.
     - Updates in-memory trie nodes, asserts that the resulting root strictly matches the Output Log commitment, flushes trie persistence to disk, activates `Serving_CP`, and **opens the Read Server (< 500ms)**.
3. **Phase 3: Background Catchup**:
   - Resumes forward ingestion from `Serving_CP.InputSize` toward `Target_CP`.

### 2.3 Moving-Goalpost Prevention & Mini-Log Determinism
When indexing high-velocity logs, the upstream log head advances continuously. Polling unverified checkpoints on every batch risks synchronization starvation. The coordinator freezes verified target sync checkpoints into durable database metadata prior to batch processing, ensuring that the ingestion pipeline processes fixed ranges to completion before advancing to a new target.

Mini-log sub-roots within the target boundary are computed deterministically by encoding each occurrence index as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00. This deterministic leaf hashing guarantees that independent indexer replicas and client verifiers compute identical mini-log roots for any given Input Log prefix.

### 2.4 Genesis Backfill Lifecycle (Unserved Bootstrap)

When bootstrapping from leaf 0 on large, high-cardinality logs, accumulating every modified key's sub-root across the entire log in memory before publishing a single initial Output Log commitment would consume excessive heap memory or incur unnecessary intermediate witnessing overhead.

To resolve this without complicating the live serving state machine, VIndex executes an automated **Genesis Backfill** lifecycle during initial unserved bootstrap (`Output_CP.Size == 0`):

| State / Phase | Entry Condition | Operations | Exit Transition |
| :--- | :--- | :--- | :--- |
| **Mode Selection** | Daemon startup / sync cycle start | Inspects Output Log tree size (`Output_CP.Size`). | `Output_CP.Size == 0` -> **Genesis Backfill**<br>`Output_CP.Size > 0` -> **Normal Serving** |
| **Stream & Coalesce** | `Output_CP.Size == 0` and `KV_CP.Size < Target_CP.Size` | Streams tiles, writes KV chunks without per-slab `fsync`, and coalesces modified sub-roots in a bounded in-memory double buffer. | Buffer reaches flush threshold / coarse leaf interval -> **Coarse Checkpoint**<br>Reaches `Target_CP.Size` -> **Genesis Finalization** |
| **Coarse Checkpoint** | Active key buffer full or coarse leaf interval reached | 1. Executes synchronous KV flush (`KV_CP`).<br>2. Applies coalesced sub-roots and snapshots MPT.<br>3. Flushes MPT `mmap` pages to disk (`MPT_Durable_Size`). | Returns to **Stream & Coalesce** |
| **Genesis Finalization** | Reached `Target_CP.Size` | Flushes remaining buffered sub-roots, syncs KV and MPT to disk, appends Leaf 0 to the Output Log, collects witness cosignatures, and promotes `Serving_CP`. | Permanent one-way transition to **Normal Serving** (`Output_CP.Size > 0`) |

1. **Activation & Serving Plane Isolation**:
   - Activated automatically if and only if the Output Log has zero commitment leaves (`Output_CP.Size == 0`).
   - Because no checkpoint has ever been published, `/lookup` endpoints return `503 Service Unavailable`, `/healthz` returns `200 OK`, and `/readyz` / `/syncz` return `503 Service Unavailable` with structured bootstrap progress diagnostics.
2. **Bounded Coalescing & Coarse Checkpointing**:
   - Intermediate root predictions, Output Log appends, and external witness roundtrips are bypassed until the initial `Target_CP.Size` is reached.
   - Modified key sub-roots are coalesced in bounded memory and periodically flushed to the MPT under a coarse checkpoint sequence that strictly enforces `KV_CP.Size >= MPT_Durable_Size` (syncing KV storage before snapshotting and syncing the MPT).
   - The tile cache pruner retains cached tiles above `min(KV_CP.Size, MPT_Durable_Size)`, ensuring any interrupted bootstrap recovers locally without re-downloading tiles or duplicating KV writes.
3. **Permanent One-Way Transition**:
   - Upon reaching `Target_CP.Size`, the final MPT root is synced, published as Leaf 0 of the Output Log, witnessed, and promoted to `Serving_CP`. From that point forward (`Output_CP.Size > 0`), the node runs permanently in Normal Serving Mode. See [`internal/coordinator/README.md`](../internal/coordinator/README.md) for detailed mechanics.

---

## 3. Independent Auditor & Verified Mirror Architecture ([`internal/auditor/`](../internal/auditor/README.md))

The auditor subsystem audits the VIndex operator's published Output Log roots from genesis, detects equivocation, and optionally serves verified mirror lookups. For the full continuous audit loop, threat vector matrix, forensic state-freeze mechanics, and operational mismatch runbook, see the [`internal/auditor/` Type B Specification](../internal/auditor/README.md).

### 3.1 Verification Boundaries
1. **Client / Query Verification (`client/`)**: Evaluates individual query responses (`mpt-proof-v1` + `prefix-compact-range-v1`) against witnessed Output Log checkpoints via the public, stateless client SDK ([`client/`](../client/README.md)).
2. **Full-Log Independent Auditor (`internal/auditor/`)**: A standalone daemon (`vindex-auditor`) that continuously tails the Output Log, extracts the committed Input Log checkpoint from each Output Log commitment leaf, downloads and authenticates the corresponding Input Log tiles from leaf 0, executes mapping independently, reconstructs its own local MPT, and asserts that its locally computed `MapRoot` strictly matches the published `MapRoot` in each Output Log commitment.

### 3.2 State-Preserving Forensic Halt & Verified Mirror Serving
- **Atomic Staging & Forensic State Freeze**: Each Output Log leaf is staged via `KVIndexer.StageMappedBatch` before predicting the candidate `MapRoot`. If the candidate `MapRoot` diverges from the published Output Log commitment, the auditor closes the unapplied Pebble batch without committing, clears the in-memory chunk cache, halts forward sync (`vindex_verifier_root_mismatch = 1`), and freezes database/MPT files on disk in-place to preserve uncorrupted forensic evidence.
- **Verified Mirror Serving (`--serve_mirror=true`)**: Evaluates two-endpoint (`/vindex/v1/keys/`, `/vindex/v1/entries/`) and legacy (`/vindex/v1/lookup/`) queries against the locally verified MPT and Pebble database under reader snapshot isolation (`Serving_CP.InputSize`).
- **Pinned Last-Known-Good vs. Fail-Closed**: On upstream divergence, `/healthz` remains `HTTP 200 OK` (preventing orchestrator liveness kills), `/readyz` and `/syncz` return `HTTP 503` with structured JSON diagnostics, and the mirror remains pinned to the last verified checkpoint (`Serving_CP`) by default so downstream readers continue receiving authentic proofs. Operators requiring an immediate hard cutoff can pass `--fail_closed=true` to revoke `Serving_CP` and return `HTTP 503` on all lookups. See [`internal/auditor/README.md §2.3–2.7`](../internal/auditor/README.md) for the complete threat matrix and 5-step incident response runbook.

---

## 4. Operational Considerations & Hardware Sizing

### 4.1 Dual-Disk Physical NVMe Isolation
Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is recommended for high-velocity installations:
- **Disk A (NVMe SSD)**: Pebble DB (`'c'` chunks, `'m'` metadata) and local managed tile cache.
- **Disk B (NVMe SSD)**: MPT `mmap` working tree and append-only leaf files.

Physical separation isolates heavy sequential MPT compaction writes from Pebble LSM memtable flushes, preventing write stalls during sustained bulk ingestion.

### 4.2 Resource Sizing & Memory Footprint Scaling Matrix
`filippo.io/torchwood/mpt` (`v0.10.1+`) reserves a 16 TiB virtual address space (`mmap` with `PROT_NONE`, zero physical RAM overhead) and commits physical pages on demand using fixed-size 32-byte node records (`nodeSize = 32`) plus append-only variable-length key/value leaf logs (`leaves` file). Active MPT internal and leaf nodes remain resident in the OS page cache:

| Scale (Unique Keys) | MPT Node Working Set (`nodes` + `leaves`) | Pebble Disk (`'c'` chunks) | Recommended Host RAM | Recommended GCP VM |
| :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.0 – 1.5 GB | ~1 GB | 8 GB | `e2-standard-2` |
| **Medium (100M)** | ~10 – 15 GB | ~10 GB | 64 GB | `n2-highmem-8` |
| **Large (1B)** | ~100 – 150 GB | ~100 GB | 256 GB | `n2-megamem-16` |
| **Very Large (2B)** | ~200 – 300 GB | ~200 GB | 512+ GB | `m4-megamem-64` |

### 4.3 Variable-Length Canonical Keys & Two-Sided Prefix Proofs (`internal/mpt`)

VIndex v1 indexes variable-length canonical keys (`1..1024` printable ASCII bytes `0x21..0x7E`, validated via `mpt.ValidateCanonicalKey`) directly in a single unified Sparse Merkle Patricia Trie (`filippo.io/torchwood/mpt`):
- **Hybrid Keying**: The MPT stores raw variable-length canonical keys (`mpt.Key`) so common string prefixes share a dedicated subtrie, while Pebble DB (`internal/kvstore`) keys inverted chunks by fixed 32-byte `SHA256(key)` hashes to preserve 41-byte LSM keys and 33-byte prefix Bloom filters.
- **Two-Sided Prefix Proofs**: `GET /vindex/v1/keys/{prefix...}?prefix=true` scans the MPT subtree via `Tree.Scan(prefix)`, proves the subtree boundary via `mpt.ProvePrefix`, and allows clients (`mpt.VerifyPrefix`) to verify both **soundness** (every returned key has `prefix` and maps to its authenticated `SubRoot`) and **completeness** (zero matching keys in the global trie were omitted). See [`docs/PREFIX_LOOKUPS.md`](./PREFIX_LOOKUPS.md) for full details.

### 4.4 Prometheus Metrics & SLO Thresholds
The daemon exports Prometheus metrics covering the entire lifecycle:
- Ingestion Lag: `vindex_ingestion_lag` (Target: < 60s)
- Mapping Latency: `vindex_map_bundle_duration_seconds` (Target: < 50ms/bundle)
- MPT Write Lock Duration: `vindex_mpt_write_duration_seconds` (Target: < 5ms)
- HTTP Lookup Latency: `vindex_lookup_latency_seconds` (Target: P99 < 50ms, P50 < 1ms)
- Read Availability: Target >= 99.9% uptime.

### 4.5 Single-Host Disaster Recovery Procedures
- **MPT Disk Corruption**: Rebuilt entirely in RAM from Pebble inverted chunks (`'c'`) via point-in-time sub-root reconstruction without network egress.
- **Pebble Storage Corruption**: Replayed from local tile cache or streamed from upstream Input Log.
- **Runtime Trap / Invariant Divergence**: Deterministic `HALT` policy freezes state and preserves disk data for post-mortem forensics.

---

## 5. Retired Ideas & Alternatives Considered

### 5.1 Arbitrary Runtime Backfill Mode Switching (Retired)
- **Proposed**: Allowing running daemons to switch dynamically between a bulk ingestion mode ("Backfill Mode") and Normal Serving Mode during live catch-up operations.
- **Empirical Rejection Findings**:
  1. **Read Starvation on Live Nodes**: Shutting down the HTTP read server during live catch-up breaks availability for active readers.
  2. **State Machine Complexity**: Dynamic mode switching introduced edge cases around checkpoint continuity, witness synchronization, and reader lock handoffs.
- **Resolution**: Arbitrary runtime switching was permanently retired. Live serving nodes always operate in Normal Serving Mode. However, for unserved logs bootstrapping from leaf 0 (`Output_CP.Size == 0`), an automated, bounded-memory **Genesis Backfill** lifecycle is retained (§2.4) to avoid unbounded in-memory sub-root accumulation on billion-scale logs.

### 5.2 Intermediate Write-Ahead Log in Storage ('w' Prefix)
- **Proposed**: Staging mapped records under a transient `'w'` prefix in Pebble DB before an asynchronous background worker converted them into inverted chunks (`'c'`).
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
- **Resolution**: Embedded Pebble LSM storage engine.

---

## 6. Verification Gate

All architectural invariants, package dependency boundaries, and end-to-end pipeline flows are verified via:

```bash
go test -race ./vindex/...
```

---

## 7. Design Log

| Date | Milestone | Summary |
| :--- | :--- | :--- |
| 2026-09-22 | v1 Initial | Established 5-stage Map Sandwich architecture, Zero-WAL recovery, and Genesis Backfill lifecycle. |
| 2026-10-14 | M1–M3 | Hardened storage/ingestion/recovery invariants (M1), added variable-length canonical keys & two-endpoint prefix lookups (M2), and decoupled `wire`, `internal/mpt`, `mapfn/host`, and `internal/verifier` packages (M3). |
