# Sub-Design: Read Serving & C2SP Query Protocol

This document defines the HTTP serving architecture, wire protocol specifications, inductive backward verification mechanics, load-bearing invariants, and verified performance optimizations for the **Serving Subsystem** (`vindex/internal/server`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & Verifiable Pagination Dilemma
The read serving engine exposes HTTP endpoints for point lookups over 32-byte key hashes (`KeyHash = SHA256(ClaimSubject)`). In a verifiable index, serving search results is fundamentally different from a traditional database:
1. **Omission Resistance**: Clients cannot trust the server. Every query response must deliver cryptographic inclusion or non-inclusion proofs, mathematically proving that no matching records were omitted.
2. **Cardinality Skew & Pagination**: When a key accumulates tens of thousands of occurrences (e.g. popular cloud domains in Certificate Transparency), returning all indices in a single HTTP response causes memory exhaustion, serialization stalls, and vulnerability to denial-of-service.
3. **The Forward Pagination Trap**: If the server paginates forward in time (`start=X`), proving that an intermediate page did not omit records requires computing complex, expensive Merkle consistency proofs across arbitrary subtrees.

### 1.2 The Inverted Filing Drawer Analogy (Read Path)
The serving engine mirrors the inverted storage structure established in the KV store:
- **Opening the Front Drawer**: The client auditor approaches the inverted filing cabinet and immediately pulls the folder at the very front of the drawer (`^chunkNum`), representing the latest active chunk.
- **The Witnessed Seal**: That front folder carries the official witnessed seal (`MapRoot`) from the latest Output Log checkpoint.
- **Flipping Backwards**: If the client requires deeper history for a deep key, they simply reach for the folders stacked immediately behind the front folder (`before=X`).
- **The Cryptographic Wax Seal**: Each folder contains an embedded compact range (`prefix-compact-range-v1`) certifying all folders that lie behind it. By reading backwards, the client verifies each folder inductively against the seal of the folder ahead of it, proving unbroken completeness without consistency proofs.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide a two-endpoint C2SP read protocol separating key/prefix proof generation (`GET /vindex/v1/keys/{key...}[?prefix=true]`) from lock-free Pebble entry pagination (`GET /vindex/v1/entries/{key...}?before=X[&limit=Y]`), alongside legacy single-request point lookups (`GET /vindex/v1/lookup/{keyhash}`).
  - Return verifiable point inclusion proofs, non-inclusion proofs, and two-sided prefix proofs (`mpt-proof-v1 <inclusion|non-inclusion|prefix>`) with `keys-v1` mappings.
  - Enforce configurable prefix policies (`PrefixPolicy` such as `DomainETLDP1PrefixPolicy` -> `HTTP 400`) and key-count caps (`--max_prefix_keys` -> `HTTP 413`).
  - Enforce strict reader snapshot isolation: readers observe state strictly bounded by witnessed Output Log checkpoints.
  - Stream responses using direct plaintext formatting (`vindex/wire`) without JSON reflection or intermediate heap allocations.
- **Non-Goals**:
  - **No Unbounded Full-Tree Scans**: Prefix scans are guarded by `PrefixPolicy` and `--max_prefix_keys`.
  - **No Uncommitted / Read-Uncommitted Mode**: Lookups never observe un-witnessed or in-flight entries ahead of the latest published checkpoint.
  - **No In-Server Client Verification**: The server generates proofs; cryptographic verification is executed exclusively by the client SDK ([`client/`](../../client/README.md)).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Protocol Standards**: Adheres to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions.
- **Dependencies**: Reads from the Pebble inverted chunk store, the in-memory Sparse Merkle Patricia Trie, and the active serving state snapshot published by the tree subsystem.
- **Known Pain Points ("Warts and All")**:
  - **Backward Cursor Friction**: Developers accustomed to conventional REST APIs (`page=2`, `start=X`) are often surprised by backward pagination (`before=X`). Client SDKs must abstract this traversal to present a standard forward iterator.
  - **Sequential Roundtrips for Deep Keys**: Hot keys with 100,000+ entries require multiple sequential HTTP requests to retrieve complete historical logs.
  - **Checkpoint Boundary Latency**: HTTP queries evaluate the latest committed checkpoint (`Serving_CP`). Records in the active ingestion batch are invisible until the next commit cycle completes.

---

## 2. Detailed Design

### 2.1 C2SP HTTP REST Endpoints
The server exposes the following HTTP endpoints:

| Endpoint | Method | Purpose & Parameters |
| :--- | :--- | :--- |
| `/vindex/v1/keys/{key...}` | `GET` | Point or prefix key lookup over variable-length canonical keys (`1..1024` printable ASCII bytes).<br>Query params: `prefix=true` (optional boolean). Returns `vindex/v1`, `output-log-leaf-v1`, `output-log-proof-v1`, `mpt-proof-v1 <inclusion\|non-inclusion\|prefix>`, and `keys-v1`. Returns `HTTP 400` if `PrefixPolicy` rejects the prefix, or `HTTP 413` if matched keys exceed `--max_prefix_keys`. Aliases: `/vindex/keys/{key...}`, `/keys/{key...}`. |
| `/vindex/v1/entries/{key...}` | `GET` | Lock-free mini-log entry pagination for `{key...}` (`KeyHash = SHA256(key)`).<br>Query params: `before` (**required** `uint64` > 0), `limit` (optional `uint64`, default 100, max 1000). Acquires **zero MPT locks**; returns `prefix-compact-range-v1` (if `covered_size > 0`) and `indices-v1 [<next_before>]`. Aliases: `/vindex/entries/{key...}`, `/entries/{key...}`. |
| `/vindex/v1/lookup/{keyhash}` | `GET` | Legacy combined point lookup for a 32-byte hex-encoded key hash.<br>Query params: `before` (optional `uint64`), `limit` (optional `uint64`, default 100, max 1000). Evaluated against `Serving_CP`. Aliases: `/vindex/lookup/{keyhash}` and `/lookup/{keyhash}`. |
| `/vindex/v1/checkpoint` | `GET` | Returns the latest signed, witnessed Output Log checkpoint note from `Serving_CP`. Supported backward compatibility alias: `/checkpoint`. |
| `/vindex/v1/inputlog_checkpoint` | `GET` | Returns the raw signed Input Log checkpoint note from `Serving_CP`. Supported backward compatibility alias: `/inputlog_checkpoint`. |
| `/healthz` | `GET` | Liveness probe. Returns **HTTP 200 OK** (`ok\n`) as long as the process is alive. |
| `/readyz` | `GET` | Readiness probe. Returns **HTTP 200 OK** (`ok\n`) when serving state is initialized, or **HTTP 503** if serving state is not yet ready. |
| `/metrics` | `GET` | Exposes standard Prometheus telemetry metrics. |

### 2.2 Multi-Section Plaintext Response Wire Format

Responses use the C2SP multi-section plaintext format (`vindex/wire`), where sections are delimited by blank lines (`\n\n`) and framed by section headers `— <section-name>[ <args>] —`.

#### A. `/vindex/v1/keys/{key...}[?prefix=true]` Response:
```text
— vindex/v1 —
origin example.com/vindex
123456
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
— example.com/witness-1 p7c...

— output-log-leaf-v1 42 —
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
origin example.com/inputlog
98765
k2g...

— output-log-proof-v1 —
MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=

— mpt-proof-v1 prefix —
AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=

— keys-v1 —
com.google. 8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4
com.google.*. 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
com.google.mail. 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
```

#### B. `/vindex/v1/entries/{key...}?before=98765&limit=100` Response:
```text
— prefix-compact-range-v1 65536 —
MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=

— indices-v1 1042 —
1042
1089
1150
```

#### C. Legacy `/vindex/v1/lookup/{keyhash}` Response:
Combines `vindex/v1`, `output-log-leaf-v1`, `output-log-proof-v1`, `mpt-proof-v1 <inclusion|non-inclusion>`, optional `prefix-compact-range-v1`, and `indices-v1` in a single payload.

#### Section Breakdown:
1. `— vindex/v1 —`: Raw signed Output Log checkpoint note from `Serving_CP`, containing tree size, root hash, and witness cosignatures.
2. `— output-log-leaf-v1 <leaf_index> —`: Output Log leaf data at `<leaf_index>` (with trailing newlines trimmed for multi-section wire framing):
   - Line 1: Lowercase hexadecimal-encoded 32-byte `MapRoot` (64 characters).
   - Line 2+: Raw signed Input Log checkpoint note (right-trimmed of trailing newlines in section framing; canonical leaf bytes hashed into the Output Log are `"<64-char-lowercase-hex-mapRoot>\n<right-newline-trimmed-rawInputLogCP>\n"`).
3. `— output-log-proof-v1 —`: Output Log Merkle inclusion proof hashes, one base64-encoded SHA-256 hash per line.
4. `— mpt-proof-v1 <inclusion|non-inclusion> —`: Base64-encoded binary Sparse Merkle Patricia Trie proof:
   - `inclusion`: Proves that `SubRoot` exists at `KeyHash` within `MapRoot`.
   - `non-inclusion`: Proves that `KeyHash` does not exist in the trie.
5. `— prefix-compact-range-v1 <covered_size> —`: Base64-encoded compact hashes committing to the prior `<covered_size>` occurrences, one per line. Omitted entirely if `covered_size == 0`.
6. `— indices-v1 [<next_before>] —`: Decimal ASCII occurrence indices matching the search key in the Input Log, one per line. If older occurrences remain, `<next_before>` indicates the continuation cursor.

For non-inclusion responses, sections 4 and 6 are formatted as:
```text
— mpt-proof-v1 non-inclusion —
AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=

— indices-v1 —
```

### 2.3 The Inductive Backward Verification Protocol
To prove completeness across paginated responses without expensive consistency proofs, pagination proceeds backwards:

#### Step 1: Initial Query (Tip / Page 1)
1. The client queries `GET /vindex/v1/lookup/{KeyHash}?limit=100` (default limit 100, max 1000, no `before` cursor).
2. The server acquires reader snapshot isolation under `Serving_CP`:
   - Generates the MPT inclusion/non-inclusion proof under a shared read lock.
   - Reads matching occurrence indices from Pebble DB strictly below `Serving_CP.InputSize`.
3. The client receives Page 1 and verifies:
   - Verifies the Output Log checkpoint note (`— vindex/v1 —`) against trusted witness keys.
   - Reconstructs the canonical Output Log commitment leaf bytes (`"<64-char-lowercase-hex-mapRoot>\n<right-newline-trimmed-rawInputLogCP>\n"`) from `— output-log-leaf-v1 <leaf_index> —`, hashes the leaf with RFC 6962 leaf domain separator `0x00`, and verifies the inclusion proof (`— output-log-proof-v1 —`) against the Output Log checkpoint root.
   - Verifies the raw Input Log checkpoint note signature from the leaf data.
   - Verifies `— mpt-proof-v1 inclusion —` against `MapRoot`.
   - Reconstructs the mini-log compact range from `— prefix-compact-range-v1 <covered_size> —` (if present) and `— indices-v1 —` decimal indices (each encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator `0x00`), asserting equality with `SubRoot`.
   - **Page 1 is now cryptographically authenticated.**

#### Step 2: Continuation Queries (Page 2..N)
1. If `indices-v1` contains `<next_before>` (or if `prefix-compact-range-v1` indicates unread historical occurrences):
2. The client queries `GET /vindex/v1/lookup/{KeyHash}?before=<next_before>&limit=100`.
3. The server queries earlier entries from Pebble DB strictly before `before` and generates an updated `prefix-compact-range-v1`.
4. The client verifies:
   - Reconstructs the compact range for the page using the updated prefix range and page indices.
   - Asserts inductive backward continuity: each page's indices and prefix range strictly precede the next page.
5. This process repeats inductively until `prefix-compact-range-v1` is empty, proving that every historical leaf has been retrieved without gaps or omissions.

### 2.4 Reader Snapshot Isolation
To ensure readers never observe uncommitted or unwitnessed records, the serving engine enforces strict watermark filtering (`Serving_CP.InputSize <= Output_CP.InputSize`):

1. Every incoming lookup captures an atomic snapshot of `Serving_CP` along with the MPT proof under a shared read lock.
2. When querying Pebble DB, the storage engine ignores any occurrence index `>= Serving_CP.InputSize`, ensuring uncommitted entries from in-flight batches are invisible to readers.
3. Lookups are completely decoupled from concurrent background ingestion.
4. **Resilience Under Divergence (Pinned Last Known Good State)**: If the background auditor detects an upstream Output Log root mismatch or sync divergence, forward sync halts and freezes database files on disk, but the serving pointer remains pinned to the last verified checkpoint (`Serving_CP`). Readers continue receiving valid, witnessed cryptographic proofs evaluated at `Serving_CP` without interruption.
5. **Fail-Closed Mode (Opt-In)**: If the server is explicitly launched with `--fail_closed=true` (e.g. in mirror mode), a detected root mismatch or divergence causes the auditor to clear the active serving state, causing subsequent lookup requests to return `HTTP 503 Service Unavailable` immediately.

### 2.5 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Serving Snapshot Isolation**:
  - *Rule*: Query responses must evaluate state strictly bounded by the latest witnessed checkpoint (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: Guarantees that readers only observe data committed in the Output Log and witnessed by public monitors.
  - *Consequence ("Or Else")*: Readers would observe uncommitted, unwitnessed entries, causing client-side Merkle proof verification to fail against witnessed checkpoints.

- **[Correctness Invariant] Inductive Backward Verification Completeness**:
  - *Rule*: For any continuation query where `before` precedes the latest occurrence, the server must return a valid `prefix-compact-range-v1` committing to all occurrences strictly below the oldest index in the returned page.
  - *Rationale*: Enables the client to inductively link historical pages back to the witnessed `SubRoot`.
  - *Consequence ("Or Else")*: An adversary operating the server could omit historical entries during pagination without detection.

- **[Performance Optimization] Zero-Reflection Plaintext Streaming**:
  - *Mechanism*: Serializes C2SP multi-section responses directly to the HTTP response stream using buffered I/O, avoiding JSON reflection and heap marshalling.
  - *Impact*: Delivers sub-millisecond P50 read latency (< 1ms) and sustains high lookup throughput under concurrent ingestion.

### 2.6 Serving Contract

The read serving subsystem exposes point lookups and checkpoint retrieval over HTTP:

- **Non-Blocking Read Path**: The read path is completely non-blocking with respect to ingestion and Output Log `fsync`. Requests capture immutable serving state snapshots under a shared read lock without contending with background storage writes.
- **Request Validation & Limits**: Requests strictly validate key hash format (requiring a 64-character lowercase hexadecimal string representing the 32-byte hash) and clamp query limits (default 100, maximum 1000).

---

## 3. Alternatives Considered (or Tried)

### 3.1 Forward Paging (`start=X`) vs. Backward Paging (`before=X`)
- **Proposed**: Returning occurrence indices in ascending chronological order starting from an offset cursor (`start=X`).
- **Theoretical Rejection**:
  - Merkle trees naturally compute compact ranges over prefixes (`0..K`), not suffixes (`K..N`).
  - Forward pagination requires either:
    1. Returning unverified future state that cannot be anchored to the witnessed `MapRoot`.
    2. Computing complex, custom consistency proofs across arbitrary subtrees for every page.
    3. Forcing the client to download millions of historical entries starting from leaf 0 to reach current state.
- **Chosen Design**: Standardized on backward pagination (`before=X`), leveraging the prefix compact range property to provide inductive, zero-overhead verification.

### 3.2 JSON / Protobuf API vs. C2SP Plaintext Wire Format
- **Proposed**: Serving responses formatted as JSON (`{"checkpoint": "...", "indices": [...]}`) or binary Protobufs.
- **Theoretical & Architectural Rejection**:
  - Standard transparency ecosystem tooling (e.g. `sumdb`, `tessera`, `static-ct`) standardized on plain-text C2SP formats for transparency notes and checkpoints.
  - JSON reflection adds significant GC and CPU overhead during high-throughput point queries.
- **Chosen Design**: C2SP multi-section plaintext wire format with direct streaming.

### 3.3 Server-Side Proof Verification vs. Client-Side Cryptographic Verification
- **Proposed**: Having the server evaluate and verify Merkle proofs internally before returning results.
- **Theoretical Rejection**:
  - Server-side verification wastes CPU without providing trust guarantees; a compromised server can lie about its own internal checks.
  - Verifiable computing requires the client SDK to execute cryptographic assertions against independent witness signatures.
- **Chosen Design**: Server produces raw proofs; client SDK verifies them locally.

### 3.4 Aggressive 503 Circuit-Breaking vs. Pinned Last-Known-Good Serving
- **Proposed**: Immediately clearing the active serving state and returning HTTP 503 on all lookup queries the moment the background auditor detects an Output Log root mismatch or sync divergence.
- **Operational & Availability Rejection**:
  - In mirror deployments, an upstream publisher bug, temporary network inconsistency, or signer mismatch instantly caused a total denial-of-service outage for downstream query clients. Downstream systems were starved of verified answers despite holding thousands of previously authenticated entries.
  - Tying liveness health probes (`/healthz`) to upstream sync status caused Kubernetes and cloud load balancers to prematurely kill or de-route healthy mirror replicas, exacerbating outages.
- **Chosen Design**: Decouple sync auditing from read serving:
  - Background sync halts immediately, freezes database files, and raises alerts (`vindex_verifier_root_mismatch = 1`).
  - Readiness and sync status probes (`/readyz` or `/syncz`) report degraded status.
  - Liveness probe (`/healthz`) remains HTTP 200, and the serving engine continues serving lookups pinned to the last verified checkpoint (`Serving_CP`), preserving read availability and partition resilience.
  - Operators strictly preferring total downtime over serving stale state can opt in via `--fail_closed=true`.

---

## 4. Verification Gate

All server endpoint, prefix policy, and C2SP wire response tests are verified via:

```bash
go test -race ./vindex/internal/server/...
```

---

## 5. Design Log

| Date | Milestone | Summary |
| :--- | :--- | :--- |
| 2026-09-22 | v1 Initial | Defined C2SP plaintext wire format, backward pagination, and reader snapshot isolation. |
| 2026-10-14 | M1–M3 | Added asynchronous startup (`mpt_initializing` `503` on `/readyz`), two-endpoint protocol (`/vindex/v1/keys/` and lock-free `/vindex/v1/entries/`), `DomainETLDP1PrefixPolicy` (`400`), `--max_prefix_keys` (`413`), and shared `vindex/wire` formatting. |
