# Sub-Design: Read Serving & C2SP Query Protocol

This document defines the HTTP serving architecture, wire protocol specifications, inductive backward verification mechanics, load-bearing invariants, and verified performance optimizations for the **Serving Subsystem** (`vindex/v1/internal/server`).

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
  - Provide constant-time point lookups over exact 32-byte key hashes.
  - Return verifiable inclusion proofs for existing keys and cryptographic non-inclusion proofs for absent keys.
  - Enforce strict reader snapshot isolation: readers observe state strictly bounded by witnessed Output Log checkpoints.
  - Stream responses using direct plaintext formatting without JSON reflection or intermediate heap allocations.
- **Non-Goals**:
  - **No Cross-Key Prefix Scans**: Lexical scanning across different key prefixes is out of scope.
  - **No Uncommitted / Read-Uncommitted Mode**: Lookups never observe un-witnessed or in-flight entries ahead of the latest published checkpoint.
  - **No In-Server Client Verification**: The server generates proofs; cryptographic verification is executed exclusively by the client SDK ([`client/`](../../client/README.md)).

### 1.4 Requirements, Dependencies & Known Pain Points
- **Protocol Standards**: Adheres to Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions.
- **Dependencies**: Pebble `IndexStore`, `MPTManager`, and `Publisher.GetServingState()`.
- **Known Pain Points ("Warts and All")**:
  - **Backward Cursor Friction**: Developers accustomed to conventional REST APIs (`page=2`, `start=X`) are often surprised by backward pagination (`before=X`). Client SDKs must abstract this traversal to present a standard forward iterator.
  - **Sequential Roundtrips for Deep Keys**: Hot keys with 100,000+ entries require multiple sequential HTTP requests (e.g. 100 roundtrips at `limit=1000`) to retrieve complete historical logs.
  - **Checkpoint Boundary Latency**: HTTP queries evaluate the latest committed checkpoint. Records in the active ingestion batch are invisible until the next commit cycle completes.

---

## 2. Detailed Design

### 2.1 C2SP HTTP REST Endpoints
The server exposes three primary HTTP endpoints:

| Endpoint | Method | Purpose & Parameters |
| :--- | :--- | :--- |
| `/vindex/lookup/{keyhash}` | `GET` | Look up occurrences for a 32-byte hex-encoded key hash.<br>Query params: `before` (optional `uint64`), `limit` (optional `int`, default 1000, max 10000). Evaluated against `Serving_CP`. On upstream divergence, defaults to serving pinned `Serving_CP`; returns HTTP 503 only if `--fail_closed=true`. |
| `/checkpoint` | `GET` | Returns the latest signed, witnessed Output Log checkpoint note (`Serving_CP`). |
| `/healthz` | `GET` | Liveness probe. Returns **HTTP 200 OK** as long as the process is alive and serving authentic verified state (including during sync halt), preventing load balancers and orchestrators from killing the replica. |
| `/readyz` / `/syncz` | `GET` | Readiness & sync probe. Returns HTTP 200 during normal operation, or **HTTP 503** (with diagnostic JSON) if the background auditor detects a root mismatch or sync halt. |

### 2.2 Multi-Section Plaintext Response Wire Format
Responses use the C2SP multi-section plaintext format, where sections are delimited by blank lines (`\n\n`) and identified by headers:

```text
— checkpoint —
origin example.com/vindex
123456
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=

— mpt-proof-v1 —
0102a3b4...

— prefix-compact-range-v1 —
c8a3f120...

— entries —
1042
1089
1150
```

#### Section Breakdown:
1. **Checkpoint**: The latest signed Output Log checkpoint note, containing tree size, root hash, and witness signatures.
2. **`mpt-proof-v1`**: A binary Merkle Patricia Trie proof:
   - If the key exists: an inclusion proof authenticating the key's 32-byte `SubRoot` against `MapRoot`.
   - If the key does not exist: a non-inclusion proof proving the absence of the key in the trie.
3. **`prefix-compact-range-v1`**: The RFC 6962 compact range root committing to all historical occurrences preceding the earliest index returned in the current page.
4. **`entries`**: Newline-delimited list of decimal `uint64` leaf indices matching the search key in the Input Log.

### 2.3 The Inductive Backward Verification Protocol
To prove completeness across paginated responses without expensive consistency proofs, pagination proceeds backwards:

#### Step 1: Initial Query (Page 1)
1. The client queries `GET /vindex/lookup/{KeyHash}?limit=1000` (no `before` cursor).
2. The server pulls the front folder from the inverted drawer:
   - Evaluates `mpt.Prove(keyHash)` under reader snapshot isolation.
   - Reads the latest chunk's entries from Pebble DB.
3. The client receives Page 1 and verifies:
   - Verifies the Output Log checkpoint note against trusted witness keys.
   - Verifies `mpt-proof-v1` against `MapRoot`, proving `SubRoot`.
   - Hashes the returned indices and `prefix-compact-range-v1` according to RFC 6962 rules to reconstruct the candidate mini-log root, asserting equality with `SubRoot`.
   - **Page 1 is now cryptographically authenticated.**

#### Step 2: Continuation Queries (Page 2..N)
1. If `prefix-compact-range-v1` is non-empty, historical occurrences remain unread.
2. The client sets `before = min(seen_indices)` and queries `GET /vindex/lookup/{KeyHash}?before=1042&limit=1000`.
3. The server reaches for the folder immediately behind the active chunk, returning older entries and an updated `prefix-compact-range-v1`.
4. The client verifies:
   - Hashes the new entries against the new `prefix-compact-range-v1`.
   - Asserts that the computed root matches the **`prefix-compact-range-v1` root from Page 1**.
5. This process repeats inductively until `prefix-compact-range-v1` is empty, proving that every historical leaf has been retrieved without gaps or omissions.

### 2.4 Reader Snapshot Isolation
To ensure readers never observe uncommitted or un-witnessed records, the serving engine enforces strict watermark filtering:

```text
Serving_CP.InputSize <= Output_CP.InputSize
```

1. Every incoming lookup acquires an immutable snapshot of `ServingState`:
   ```go
   state := p.publisher.GetServingState()
   ```
2. When querying Pebble DB, the storage engine applies a strict filter:
   ```go
   if index >= state.InputLogSize {
       // Ignore entry; uncommitted in current serving checkpoint
   }
   ```
3. Lookups are completely decoupled from concurrent background ingestion; in-flight writes ahead of `state.InputLogSize` are invisible to readers.
4. **Resilience Under Divergence (Pinned Last Known Good State)**: If the background auditor detects an upstream Output Log root mismatch or sync divergence, forward sync halts and freezes database files on disk, but the serving pointer remains pinned to the last verified checkpoint (`Serving_CP`). Readers continue receiving valid, witnessed cryptographic proofs evaluated at `Serving_CP` without interruption.
5. **Fail-Closed Mode (Opt-In)**: If the server is explicitly launched with `--fail_closed=true` (e.g. in mirror mode), a detected root mismatch or divergence causes the auditor to revoke the serving state (`SetServingState(nil)`), causing subsequent lookup requests to return HTTP 503 Service Unavailable immediately.

### 2.5 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Serving Snapshot Isolation**:
  - *Rule*: Query responses must evaluate state strictly bounded by the latest witnessed checkpoint (`Serving_CP.InputSize <= Output_CP.InputSize`).
  - *Rationale*: Guarantees that readers only observe data committed in the Output Log and witnessed by public monitors.
  - *Consequence ("Or Else")*: Readers would observe uncommitted, un-witnessed entries, causing client-side Merkle proof verification to fail against witnessed checkpoints.

- **[Correctness Invariant] Inductive Backward Verification Completeness**:
  - *Rule*: For any continuation query where `before < latest_index`, the server must return a valid `prefix-compact-range-v1` committing to all occurrences with `index < min(page_indices)`.
  - *Rationale*: Enables the client to inductively link historical pages back to the witnessed `SubRoot`.
  - *Consequence ("Or Else")*: An adversary operating the server could omit historical entries during pagination without detection.

- **[Performance Optimization] Zero-Reflection Plaintext Streaming**:
  - *Mechanism*: Serializes C2SP multi-section responses directly into the `http.ResponseWriter` using buffered I/O, avoiding JSON reflection and heap marshalling.
  - *Impact*: Delivers sub-millisecond P50 read latency (< 1ms) and sustains high lookup throughput under concurrent ingestion.

### 2.6 Go Interfaces & Public Types

```go
package server

import (
	"context"
	"crypto/sha256"
	"net/http"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
)

// Server coordinates HTTP endpoints for VIndex lookups and checkpoints.
type Server struct {
	httpServer *http.Server
	store      IndexStore
	mptMgr     MPTManager
	publisher  Publisher
}

// LookupResponse captures the multi-section verifiable response.
type LookupResponse struct {
	Checkpoint   *log.Checkpoint
	MPTProof     []byte
	SubRoot      [sha256.Size]byte
	Exists       bool
	CompactRange *compact.Range
	Indices      []uint64
}

// IndexStore defines the storage query subset required by the server.
type IndexStore interface {
	Lookup(keyHash [sha256.Size]byte, before uint64, limit int) (indices []uint64, compactRange *compact.Range, err error)
}
```

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
- **Proposed**: Immediately revoking `ServingState` (setting it to nil) and returning HTTP 503 on all lookup queries the moment the background auditor detects an Output Log root mismatch or sync divergence.
- **Operational & Availability Rejection**:
  - In mirror deployments, an upstream publisher bug, temporary network inconsistency, or signer mismatch instantly caused a total denial-of-service outage for downstream query clients. Downstream systems were starved of verified answers despite holding thousands of previously authenticated entries.
  - Tying liveness health probes (`/healthz`) to upstream sync status caused Kubernetes and cloud load balancers to prematurely kill or de-route healthy mirror replicas, exacerbating outages.
- **Chosen Design**: Decouple sync auditing from read serving:
  - Background sync halts immediately, freezes database files, and raises alerts (`vindex_verifier_root_mismatch = 1`).
  - Readiness and sync status probes (`/readyz` or `/syncz`) report degraded status.
  - Liveness probe (`/healthz`) remains HTTP 200, and the serving engine continues serving lookups pinned to the last verified checkpoint (`Serving_CP`), preserving read availability and partition resilience.
  - Operators strictly preferring total downtime over serving stale state can opt in via `--fail_closed=true`.
