# Sub-Design: HTTP Read Server API & C2SP Wire Protocol

This document defines the HTTP serving plane, C2SP multi-section wire protocol, load-bearing invariants, verified performance optimizations, operational endpoints, and retired design branches for the **Read Server Subsystem** (`vindex/v1/internal/server`).

---

## 1. Core Load-Bearing Invariants

### 1.1 C2SP Multi-Section Wire Protocol Compliance
The Read Server serves verifiable lookup responses over HTTP adhering to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions:
- **Content-Type**: `text/plain; charset=utf-8`.
- **Framing**: Sections delimited by `— <section-name>[ <arguments>] —` (Unicode U+2014 em dash or ASCII `---`).
- **Strict Section Order**:
  1. `— vindex/v1 —` (Mandatory): Output Log checkpoint signed note.
  2. `— output-log-leaf-v1 <leaf_index> —` (Mandatory): `MapRoot` (hex) + raw Input Log checkpoint note.
  3. `— output-log-proof-v1 —` (Mandatory): RFC 6962 audit path hashes.
  4. `— mpt-proof-v1 <inclusion|non-inclusion> —` (Mandatory): Sparse binary MPT proof.
  5. `— prefix-compact-range-v1 <covered_size> —` (Optional: present when earlier occurrences exist prior to this page).
  6. `— indices-v1 [next_before] —` (Mandatory): Ascending leaf indices.

### 1.2 Read Isolation & Snapshot Consistency
To guarantee consistency without blocking concurrent writers or storage compactions:
- **Sub-Millisecond Snapshot**: `ServingState` pointer and binary MPT proof for `keyhash` are retrieved under `treeMu.RLock()` (< 1ms).
- **Lock Release**: The read lock is released immediately. All subsequent storage queries (`store.Lookup`) and response streaming execute completely lock-free.
- **Watermark Filtering**: Readers are strictly isolated from in-flight writes ahead of `serving_state.InputLogSize` via index filtering.

### 1.3 Inductive Backward Verification Protocol
Clients verify paginated responses inductively starting from Page 1 downward:
- **Base Step (Page 1 / Tip Query, `before == nil`)**:
  * Extract `MapRoot` from the verified Output Log checkpoint and leaf.
  * Verify `mpt-proof-v1` against `MapRoot` to extract `MiniLogRoot`.
  * Initialize `compact.Range` with `prefix-compact-range-v1` (commits to prefix `0 .. next_before-1`).
  * Append `LeafHash(idx) = SHA256(0x00 || BigEndian(idx))` for each index in `indices-v1`.
  * Assert `CompactRange.Root() == MiniLogRoot`.
  * Retain `prefix-compact-range-v1` as the expected target compact range for the subsequent continuation page.
- **Inductive Step (Continuation Pages, `before != nil`)**:
  * Initialize a fresh `compact.Range` with the continuation page's `prefix-compact-range-v1`.
  * Append `LeafHash(idx)` for each index in the continuation page's `indices-v1`.
  * Assert that the resulting compact range matches the prefix compact range retained from the preceding page.
  * Retain the current page's `prefix-compact-range-v1` for the next backward query.
  * Repeat until genesis (`prefix-compact-range-v1` empty) is reached.
- **Context Dependency**: Standalone continuation queries (`before != nil`) executed without prior page context cannot be verified against `MapRoot` in isolation because `MiniLogRoot` commits only to the full mini-log accumulator at the tip. Continuation pages must be verified inductively starting from Page 1 downward.

### 1.4 Read-Only Safety Constraints
- **Strictly Read-Only**: The server handles `GET` methods exclusively; any `POST`, `PUT`, or mutation request is rejected with HTTP 405 Method Not Allowed.
- **Hex Sanitization**: Enforces strict validation on `{keyhash}` (`^[0-9a-f]{64}$`), returning HTTP 400 Bad Request immediately before touching the trie or disk.

---

## 2. Verified Performance Optimizations

### 2.1 Sub-Millisecond Read Lock Critical Section
The MPT read lock (`treeMu.RLock()`) is held exclusively for retrieving the atomic `ServingState` pointer and calling `mpt.ProveLocked(keyHash)`:
- Critical section duration completes in microseconds (< 1ms).
- Disk I/O during Pebble lookup and HTTP streaming runs completely outside the lock, sustaining over 678,000 reads/sec in microbenchmarks.

### 2.2 Direct Stream Serialization
The server formats and streams multi-section response lines directly to `http.ResponseWriter`:
- Bypasses intermediate string or buffer allocations.
- Emits RFC 4648 Base64 hashes and decimal indices via streaming writers.

### 2.3 Hot-Key Backward Pagination & Parameter Clamping
- Supporting backward paging via `before` and `limit` query parameters with continuation headers (`indices-v1 [next_before]`) bounds response latency and memory on deep keys.
- Query parameter `limit` is strictly clamped (`1 <= limit <= 1000`, default `100`), preventing unbounded disk scans and memory exhaustion.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Embedded Single-Page Web UI
The server embeds an interactive single-page HTML interface (`index.html`) via Go's `embed.FS`:
- Served at `/` and `/index.html` (toggleable via `SetEnableUI`).
- Allows operators and auditors to perform interactive browser lookups and inspect raw multi-section cryptographic proofs directly.

### 3.2 Operational Probes & Checkpoint Endpoints
- `GET /healthz`: Process liveness (returns HTTP 200).
- `GET /readyz`: Readiness probe (returns HTTP 200 once `ServingState` is active; returns HTTP 503 during startup recovery or unready states).
- `GET /vindex/v1/checkpoint`: Returns the latest witnessed Output Log checkpoint note.
- `GET /vindex/v1/inputlog_checkpoint`: Returns the latest witnessed Input Log checkpoint note.
- `GET /metrics`: Exports standard Prometheus metrics covering request counts, latencies, and status codes.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode Retirement in Read Serving
- **What Was Proposed & Investigated**:
  In Backfill Mode, the HTTP read server was held offline (`/readyz` returning HTTP 503 Service Unavailable) for the entire duration of bulk ingestion from genesis.
- **Why It Was Investigated**:
  Theoretical hypothesis that disabling query serving during bulk sync would maximize CPU and disk bandwidth for ingestion.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  1. **100% Read Starvation**: Backfill Mode denied all read lookups (0 QPS, 0% availability) to clients and monitors for the entire duration of ingestion.
  2. **Zero Ingestion Benefit**: Normal Serving Mode (`SyncOnce`) was **85.1% faster** on real Go SumDB logs (90,797 vs 49,064 leaves/sec) while simultaneously serving concurrent queries at sub-2ms P50 latency with 100% availability.
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode caused complete read starvation with zero throughput benefit. It was permanently pruned from the codebase in Milestone M3.

### 4.2 REST / JSON Wire Protocol
- Storing and transmitting cryptographic proofs in JSON format introduced Base64 serialization bloat on hashes and required JSON schema parsers on clients.
- Replaced by C2SP multi-section `text/plain` framing, which is human-readable, curl-friendly, and natively aligned with transparency ecosystem conventions.

### 4.3 Forward Paging (`start=X&limit=M`)
- Returning indices in ascending order from genesis required either returning unverified future state, maintaining complex arbitrary suffix subtree proofs, or forcing clients to traverse millions of historical entries to reach the latest state.
- Replaced by backward paging (`before=X&limit=M`), leveraging the natural prefix property of Merkle compact ranges and recency bias in transparency log monitoring.

### 4.4 gRPC / Protobuf Transport
- Rejected because it requires compiled client SDKs and protocol buffer tooling, conflicting with lightweight curl-based inspection and transparent web auditing.
