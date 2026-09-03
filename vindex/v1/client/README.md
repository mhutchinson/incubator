# Sub-Design: Client SDK & Query Proof Verification

This document defines the public, stateless Go client SDK (`vindex/v1/client`) for querying VIndex nodes and cryptographically verifying lookup responses.

---

## 1. Context & Objectives

### 1.1 Problem Statement: Zero-Trust Light Clients
In verifiable transparency systems, a client querying an index cannot trust the server's response. A compromised, coerced, or malfunctioning server could return falsified occurrence lists, omit records, or present stale data.

To achieve cryptographic security without requiring clients to download entire databases or execute WebAssembly indexing pipelines, VIndex provides a **stateless light client library**. The client consumes point lookup responses from any VIndex server or mirror, evaluating cryptographic proofs directly on the client machine against independent witness signatures.

### 1.2 The Independent Receipt Verifier Analogy
The client SDK functions like a bank customer verifying an itemized transaction receipt:
- The receipt contains the merchant's signature and independent notary stamps (Output Log checkpoint note cosigned by witnesses).
- The receipt contains a tamper-evident chain linking this specific item to the bank's central registry (Merkle inclusion proof committing the `MapRoot`).
- The receipt proves whether the account exists and lists all historical transactions (Sparse Merkle Tree inclusion/non-inclusion proof and mini-log compact range).
- The customer never needs to audit the entire bank; they verify the mathematical proofs attached to their own receipt in under one millisecond.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Provide a lightweight, zero-dependency public Go package (`vindex/v1/client`) usable by external applications, CLIs, and monitoring services.
  - Implement strict cryptographic verification for all query responses (`/vindex/v1/lookup/{keyhash}` and `/vindex/v1/checkpoint`).
  - Verify Output Log checkpoint note signatures against configured witness public keys.
  - Verify Output Log Merkle inclusion proofs for the committed `MapRoot`.
  - Verify MPT inclusion and non-inclusion proofs for requested 32-byte key hashes.
  - Reconstruct and assert RFC 6962 compact ranges for mini-log sub-roots against returned occurrence indices.
  - Verify history monotonicity across paginated and consecutive queries on identical keys.
  - Zero heavy dependencies: completely decoupled from storage engines (`pebble`), WebAssembly runtimes (`wazero`), and local tile caches.
- **Non-Goals**:
  - **No Full Log Auditing**: The client does not re-index raw Input Log leaves or reconstruct global MPT state; full audits are delegated to `internal/auditor`.
  - **No Storage Mutations**: The client is 100% stateless and executes strictly in memory.

### 1.4 Known Constraints & Trade-Offs
- **Witness Trust Floor**: The client's security is bounded by the integrity of the witness signatures on the Output Log checkpoint. If witnesses equivocate or cosign fraudulent checkpoints without detection, the client will accept proofs consistent with that checkpoint until an independent auditor detects the fraud.
- **CPU Overhead of Cryptographic Verification**: Verifying RSA/Ed25519 signatures, Merkle paths, MPT bitwise nodes, and compact ranges adds approximately 0.5 to 1.5 milliseconds of CPU time per lookup on the client machine. This trade-off is fundamental to zero-trust verifiable computing.

---

## 2. Detailed Design

### 2.1 Public Architecture & Package Decoupling

The client library is completely decoupled from the indexing and audit subsystems:

| Component | Responsibility | External Dependencies |
| :--- | :--- | :--- |
| `client.Client` | HTTP communication with VIndex nodes (`GET /vindex/v1/lookup/{keyhash}`, `GET /vindex/v1/checkpoint`). | Go standard library (`net/http`, `context`). |
| `client.Parser` | Parses C2SP multi-section plaintext wire format into structured proof objects. | Go standard library (`bufio`, `bytes`, `strconv`). |
| `client.Verifier` | Executes pure cryptographic assertions on parsed proof structures. | Standard `crypto/sha256`, `github.com/transparency-dev/formats/log`. |

### 2.2 The 5-Step Query Verification Sequence

For every lookup request, the client SDK executes the following deterministic 5-step verification sequence:

| Step | Phase | Operations | Mathematical Assertion |
| :--- | :--- | :--- | :--- |
| **1** | **Checkpoint Authentication** | Verifies note format and cryptographic signatures on the Output Log checkpoint. | Number of valid witness cosignatures >= configured threshold `MinWitnessSignatures`. |
| **2** | **Output Log Merkle Proof** | Verifies the Merkle inclusion proof committing `MapRoot` into the Output Log. | `proof.VerifyInclusion(OutputTreeSize, LeafIndex, MapRootCommitment) == OutputTreeRoot`. |
| **3** | **MPT Proof Verification** | Evaluates the bitwise Sparse Merkle Tree path traversal against `MapRoot`. | **Inclusion**: Proves `SubRoot` exists at `KeyHash`.<br>**Non-Inclusion**: Proves path terminates in empty node or mismatched prefix. |
| **4** | **Mini-Log Compact Range** | Reconstructs RFC 6962 compact range from returned leaf indices and prefix compact range. | `CompactRange.GetRootHash() == SubRoot`. |
| **5** | **Monotonic History Check** | When evaluating consecutive queries on key K where S_new >= S_old: | `I_new[:len(I_old)] == I_old` (historical indices cannot mutate or disappear). |

#### Step Details:
1. **Checkpoint Authentication**: Fetches and parses the checkpoint note. Asserts that the origin string matches expectations and verifies cryptographic signatures against the configured trusted witness keys.
2. **Output Log Merkle Inclusion**: Parses the inclusion proof for the Output Log leaf containing the state commitment. Recomputes the audit path and asserts equality with the authenticated Output Log root.
3. **Sparse Merkle Tree Verification**: Evaluates the 256-bit path for the 32-byte key hash:
   - For an **inclusion proof**, asserts that hashing up the provided sibling nodes reproduces the committed `MapRoot`, proving that the returned `SubRoot` is authentically bound to the key.
   - For a **non-inclusion proof**, asserts that the trie path terminates at a nil leaf or a conflicting prefix node, mathematically proving that no records exist for the key hash at this checkpoint.
4. **Mini-Log Compact Range Reconstruction**: Reconstructs the mini-log root using RFC 6962 tree hashing:
   - Mini-log leaf hashing: each absolute occurrence index is encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00.
   - The client uses `compact.RangeFactory` (or `Range.Append`) to incrementally accumulate leaf hashes over the returned `IndexValue` occurrence indices.
   - If paginating, it initializes the range from the `prefix-compact-range-v1` compact hashes committing to all preceding historical occurrences (`prefixCoveredSize`), then appends the page's indices.
   - The resulting compact range root is asserted to match the authenticated MPT `SubRoot`.
5. **Monotonic History Assertion**: If the client maintains historical query cache for key K, it asserts that subsequent queries at larger checkpoints contain the previous indices as an exact prefix.

### 2.3 Backward Pagination Protocol

When a key has more occurrence records than fit in a single response (or when paginating using `?before={cursor}`):
1. **Initial Tip Query**: The client queries `GET /vindex/v1/lookup/{keyhash}` without a cursor.
   - Response contains the latest page of occurrence indices, the MPT proof against `MapRoot`, and an optional `prefix-compact-range-v1` section if older entries exist.
   - If more historical occurrences exist, the response includes a `next_before` cursor argument on `indices-v1`.
2. **Backward Continuation Query**: The client queries `GET /vindex/v1/lookup/{keyhash}?before={cursor}`.
   - Response contains earlier occurrences and an updated `prefix-compact-range-v1` committing to records preceding this page.
3. **Incremental Compact Range Accumulation**:
   - Rather than relying on a separate hash chain, verification uses incremental RFC 6962 compact range accumulation.
   - The client constructs a compact range from `prefix-compact-range-v1` (covering `prefixCoveredSize`) via `compact.RangeFactory`, then appends the returned `IndexValue` indices (each encoded as an 8-byte big-endian absolute leaf index hashed with RFC 6962 leaf domain separator 0x00).
   - For tip queries (`before == nil`), the accumulated compact range root is directly asserted against the authenticated MPT `SubRoot`.
   - For backward pagination, continuity is verified inductively by ensuring each page's indices and prefix range strictly precede the next page.
4. **Integrity Guarantee**: Inductive compact range accumulation guarantees that historical pages cannot be altered, reordered, or truncated by the server across multiple HTTP requests.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Client-Side Cryptographic Assertion**:
  - *Rule*: The client SDK must never expose search results to calling applications without first executing all 5 cryptographic verification checks to completion.
  - *Rationale*: Server responses are untrusted input; treating an unverified response as authentic re-introduces the operator trust dependency that verifiable logs exist to eliminate.
  - *Consequence ("Or Else")*: A compromised server could return fraudulent search results or hide critical security revocations from applications without detection.

- **[Correctness Invariant] Monotonic History Invariant**:
  - *Rule*: For any series of queries on key hash K where checkpoint size increases (S_new >= S_old), the client must assert that the newly returned indices contain the previously verified indices as an identical prefix:
    ```text
    indices_new[:len(indices_old)] == indices_old
    ```
  - *Rationale*: Inverted indices are append-only; historical occurrences cannot be deleted or reordered.
  - *Consequence ("Or Else")*: An operator could selectively delete historical associations, concealing past malicious activities.

- **[Performance Optimization] Stateless Streaming Proof Verification**:
  - *Mechanism*: Proof verification operations operate strictly over byte slices in linear memory with zero heap allocations for intermediate tree nodes.
  - *Impact*: Client verification completes in under 1.2 ms per query, enabling high-throughput client validation exceeding 800 queries/sec per client CPU core.

### 2.5 Error Taxonomy & Failure Handling

| Error Code | Root Cause | Client Action |
| :--- | :--- | :--- |
| `ErrUntrustedCheckpoint` | Checkpoint note missing required witness signatures or invalid origin. | Reject response immediately; abort query. |
| `ErrOutputInclusionFailed` | Output Log Merkle inclusion proof does not evaluate to the checkpoint root. | Security alert; abort query (possible server equivocation). |
| `ErrMPTProofInvalid` | Sparse Merkle Tree bitwise path does not match the committed `MapRoot`. | Security alert; abort query (server attempted to forge trie state). |
| `ErrSubRootMismatch` | Reconstructed compact range does not match the verified `SubRoot`. | Security alert; abort query (server altered or truncated occurrences). |
| `ErrHistoryRegression` | Returned occurrences omit or mutate indices present in earlier queries. | Security alert; abort query (server executed an index rollback). |
| `ErrServerDegraded` | Server returned HTTP 503 (mirror in fail-closed mode or syncing). | Retry with exponential backoff or query an alternative mirror. |

### 2.6 Client Contract & API Requirements

The client library provides a stateless query interface implementing strict zero-trust verification:

- **Inputs**:
  - VIndex service URL.
  - 32-byte search key hash (`KeyHash = SHA256(ClaimSubject)`).
  - Input Log verifier.
  - Output Log verifier.
  - Optional `before` pagination cursor.
  - Optional `limit`.
- **Outputs**:
  - Ordered list of uint64 Input Log occurrence indices.
  - Raw signed Input Log checkpoint.
- **Guarantees**:
  - Client unconditionally rejects unverified or cryptographically inconsistent responses. Any invalid checkpoint signature, Merkle inclusion proof failure, trie path defect, or compact range mismatch triggers an immediate verification error.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Server-Side Proof Verification vs. Client-Side Verification
- **Proposed**: Having the VIndex server execute cryptographic proof checks and return a simple boolean `"verified": true` in a JSON response.
- **Security Rejection**: Defeats the foundational premise of verifiable computing. A compromised, coerced, or buggy server can easily lie and claim its own output is verified. Trust must terminate on the client device through local mathematical assertion against witness cosignatures.
- **Chosen Design**: The server returns raw proofs; the client SDK executes all cryptographic assertions locally.

### 3.2 Monolithic Verifier Package vs. Decoupled Client SDK
- **Proposed**: Housing client verification in `internal/verifier/` alongside the full-log auditor and mirror engine.
- **Architectural Rejection**:
  - `internal/` packages cannot be imported by external Go applications.
  - The full-log auditor requires heavy storage engines (`pebble`), WebAssembly runtimes (`wazero`), and multi-gigabyte disk caches. Forcing client applications to import these heavy dependencies violates lightweight client architecture.
- **Chosen Design**: Decouple completely: a public, zero-dependency `client` package for query proof verification, and an `internal/auditor` package for full-log background auditing.
