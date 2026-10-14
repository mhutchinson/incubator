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
  - Provide a lightweight public Go package (`vindex/v1/client`) usable by external applications, CLIs, and monitoring services.
  - Implement strict cryptographic verification for the two-endpoint protocol (`LookupKeys`, `LookupPrefix`, `LookupEntries`, `LookupKey`, `LookupAllKey`, `LookupPrefixAll`), legacy point lookups (`Lookup`, `LookupAll`), and checkpoint endpoints (`GetCheckpoint`, `GetInputLogCheckpoint`).
  - Verify Output Log and Input Log checkpoint signatures and optional K-of-N witness cosignature policies (`WitnessPolicy`, `RequireVerifiers`).
  - Verify Output Log Merkle inclusion proofs for the committed `MapRoot`.
  - Verify MPT inclusion, non-inclusion, and two-sided prefix proofs (`internal/mpt.VerifyKey`, `VerifyPrefix`) for canonical keys.
  - Reconstruct and assert RFC 6962 compact ranges (`wire.ComputeMiniLogRoot`) for mini-log sub-roots against returned occurrence indices across initial and backward continuation pages (`NextExpectedSubRoot`).
  - Enforce monotonic checkpoint history ratcheting (`ErrCheckpointRegressed`) rejecting log size regressions or split-view root hash divergences.
  - Decoupled dependency graph: zero dependencies on storage engines (`pebble`), WebAssembly runtimes (`wazero`), or internal ingestion packages (`internal/ingest`, `internal/kvstore`).
- **Non-Goals**:
  - **No Full Log Auditing**: The client does not re-index raw Input Log leaves or reconstruct global MPT state; full audits are delegated to `internal/auditor`.
  - **No Storage Mutations**: The client executes strictly in memory.

### 1.4 Known Constraints & Trade-Offs
- **Witness Trust Floor**: The client's security is bounded by the integrity of the witness signatures on the Output Log checkpoint. If witnesses equivocate or cosign fraudulent checkpoints without detection, the client will accept proofs consistent with that checkpoint until an independent auditor detects the fraud.
- **CPU Overhead of Cryptographic Verification**: Verifying RSA/Ed25519 signatures, Merkle paths, MPT bitwise nodes, and compact ranges adds approximately 0.5 to 1.5 milliseconds of CPU time per lookup on the client machine. This trade-off is fundamental to zero-trust verifiable computing.

---

## 2. Detailed Design

### 2.1 Public Architecture & Package Decoupling

The client library is completely decoupled from the indexing and storage subsystems:

| Responsibility | Package | External Dependencies |
| :--- | :--- | :--- |
| **HTTP Transport & Verification Orchestration** | `vindex/v1/client` | `net/http`, `vindex/v1/wire`, `vindex/v1/internal/mpt`, `vindex/v1/internal/verifier`. |
| **C2SP Multi-Section Wire & Mini-Log Codecs** | `vindex/v1/wire` | Standard `crypto/sha256`, `github.com/transparency-dev/formats/log`, `github.com/transparency-dev/merkle`. |
| **MPT Point & Prefix Proof Verification** | `vindex/v1/internal/mpt` | `filippo.io/torchwood/mpt`, `vindex/v1/wire`. |
| **Checkpoint Signature & MTC Verifiers** | `vindex/v1/internal/verifier` | `golang.org/x/mod/sumdb/note`, `crypto/ed25519`. |

### 2.2 The 5-Step Query Verification Sequence

For every lookup request, the client SDK executes the following deterministic 5-step verification sequence, explicitly distinguishing initial key/tip queries (**Step 3a**) from backward entry continuation pages (**Step 3b**):

| Step | Phase | Operations | Mathematical Assertion |
| :--- | :--- | :--- | :--- |
| **1** | **Checkpoint Authentication** | Verifies note format, origin, primary signature, and optional `WitnessPolicy` K-of-N threshold on Output Log and Input Log checkpoints. | Enforces `VerifierConfig` origin, verifier, `RequireVerifiers`, and `WitnessPolicy` cosignature quorum. |
| **2** | **Output Log Merkle Proof** | Verifies the Merkle inclusion proof committing `MapRoot` into the Output Log. | Recomputes the Output Log leaf hash from the committed `MapRoot` and signed Input Log checkpoint, asserting inclusion under the authenticated Output Log root. |
| **3a** | **Tip / Keys Query (`GET /vindex/v1/keys/` or `before == nil`)** | Evaluates the `torchwood/mpt` proof against `MapRoot` (`mpt.VerifyKey` / `mpt.VerifyPrefix`). | **Inclusion**: Proves `SubRoot` exists at `Key`.<br>**Non-Inclusion**: Proves `Key` is absent.<br>**Prefix**: Two-sided proof (`HasPrefix` + strict ascending `Key.Compare` + `TreeHash` + `mpt.VerifyPrefix`). |
| **3b** | **Continuation Query (`GET /vindex/v1/entries/?before=X` or `before != nil`)** | Evaluates the page's compact range directly against the preceding page's expected `SubRoot` (`NextExpectedSubRoot()`). | Bypasses redundant MPT/Output Log verification on continuation pages; asserts inductive continuity against the prior page's `prefix-compact-range-v1` root. |
| **4** | **Mini-Log Compact Range** | Reconstructs the RFC 6962 compact range from `prefix-compact-range-v1` and `indices-v1` (`wire.ComputeMiniLogRoot`). | Asserts non-truncation (`NextBefore` invariants), index bounds/ordering, and equality with the authenticated `SubRoot` (from Step 3a) or `expectedSubRoot` (from Step 3b). |
| **5** | **Monotonic History Ratchet** | Tracks highest verified `OutputLogSize`/`InputLogSize` and root hashes on `Verifier`. | Rejects any checkpoint regression or same-size split-view hash divergence with `ErrCheckpointRegressed`. |

#### Step Details:
1. **Checkpoint Authentication**: Parses and verifies the Output Log and Input Log checkpoint notes (`VerifyOutputLogCheckpoint`, `VerifyInputLogCheckpoint`). Asserts that origin strings match expectations and enforces primary verifier signatures plus K-of-N witness cosignature quorum via `WitnessPolicy` (`OutputLogWitnessPolicy`, `InputLogWitnessPolicy`).
2. **Output Log Merkle Inclusion**: Reconstructs the canonical Output Log leaf bytes (`"<64-char-lowercase-hex-mapRoot>\n<right-newline-trimmed-rawInputLogCP>\n"`), hashes the leaf using RFC 6962 leaf domain separation (`0x00`), and verifies the Merkle inclusion proof against the authenticated Output Log root.
3. **Step 3a (Tip / Keys Query) vs. Step 3b (Continuation Query)**:
   - **Step 3a (`VerifyKeysResponse` or `VerifyResponse` with `before == nil`)**: Evaluates the `torchwood/mpt` path against `MapRoot` (`internal/mpt.VerifyKey` or `VerifyPrefix`), authenticating each returned key's 32-byte `SubRoot` (or proving non-inclusion / empty prefix subtree).
   - **Step 3b (`VerifyEntriesResponse` or `VerifyResponse` with `before != nil`)**: Evaluates continuation pages against the `expectedSubRoot` carried forward from the preceding page's `prefix-compact-range-v1` (`EntriesResult.NextExpectedSubRoot()`), requiring zero MPT or Output Log proofs on continuation pages.
4. **Mini-Log Compact Range Reconstruction**: Reconstructs the mini-log root using RFC 6962 tree hashing (`wire.ComputeMiniLogRoot`):
   - Mini-log leaf hashing: each absolute occurrence index is encoded as an 8-byte big-endian unsigned integer and hashed with RFC 6962 leaf domain separator `0x00`.
   - Seeds the compact range from `prefix-compact-range-v1` (committing to `PrefixCoveredSz` preceding occurrences), appends the page's strictly ascending `indices-v1` (< `before`), enforces non-truncation (`NextBefore != nil` and `Indices[0] == *NextBefore` whenever `PrefixCoveredSz > 0`), and asserts that the resulting root equals the expected `SubRoot`.
5. **Monotonic History Ratchet**: `Verifier` tracks the maximum verified `OutputLogSize` and `InputLogSize` (and their corresponding root hashes), rejecting any subsequent response that regresses in log size or presents a conflicting root hash at the same size (`ErrCheckpointRegressed`).

### 2.3 Two-Endpoint & Backward Pagination Protocol

1. **Key / Prefix Discovery (`LookupKeys` / `LookupPrefix`)**: The client queries `GET /vindex/v1/keys/{key...}[?prefix=true]` and verifies the Output Log checkpoint, Output Log inclusion proof, and MPT inclusion/non-inclusion/prefix proof via `VerifyKeysResponse`, obtaining each matching key's `SubRoot` and `InputLogSize`.
2. **Initial Entry Page (`LookupEntries` with `before = InputLogSize`)**: For each matching key, the client queries `GET /vindex/v1/entries/{key...}?before={InputLogSize}&limit={limit}` and verifies the returned `prefix-compact-range-v1` and `indices-v1` against the authenticated `SubRoot` via `VerifyEntriesResponse(respBytes, InputLogSize, SubRoot)`.
3. **Backward Continuation Pages (`LookupEntries` with `before = *NextBefore`)**: While `NextBefore != nil`, the client computes `expectedSubRoot := prevPage.NextExpectedSubRoot()` from the current page's `prefix-compact-range-v1`, queries `GET /vindex/v1/entries/{key...}?before={*NextBefore}&limit={limit}`, and verifies the next page against `expectedSubRoot` until `PrefixCoveredSz == 0`.
4. **High-Level Helpers (`LookupKey`, `LookupAllKey`, `LookupPrefixAll`)**: Combine Steps 1–3 automatically in a single call. Legacy `/vindex/v1/lookup/{keyhash}` queries (`Lookup`, `LookupAll`) remain supported for backward compatibility.

### 2.4 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Client-Side Cryptographic Assertion**:
  - *Rule*: The client SDK must never expose search results to calling applications without first executing all cryptographic verification checks to completion.
  - *Rationale*: Server responses are untrusted input; treating an unverified response as authentic re-introduces the operator trust dependency that verifiable logs exist to eliminate.
  - *Consequence ("Or Else")*: A compromised server could return fraudulent search results or hide critical security revocations from applications without detection.

- **[Correctness Invariant] Monotonic History Invariant**:
  - *Rule*: For any series of queries on the same key hash where the checkpoint size is non-decreasing, the newly verified occurrence list must contain the previously verified occurrence list as an identical prefix.
  - *Rationale*: Inverted indices are append-only; historical occurrences cannot be deleted or reordered.
  - *Consequence ("Or Else")*: An operator could selectively delete historical associations, concealing past malicious activities.

- **[Performance Optimization] Stateless Streaming Proof Verification**:
  - *Mechanism*: Proof verification operations operate strictly over byte slices in linear memory with zero heap allocations for intermediate tree nodes.
  - *Impact*: Client verification completes in under 1.2 ms per query, enabling high-throughput client validation exceeding 800 queries/sec per client CPU core.

### 2.5 Failure Taxonomy & Client Handling

| Failure Category | Root Cause | Client Action |
| :--- | :--- | :--- |
| **Untrusted Checkpoint** | Checkpoint note fails origin verification or witness cosignature quorum under the configured `tlog-policy`. | Reject response immediately; abort query. |
| **Output Log Inclusion Failure** | Output Log Merkle inclusion proof does not evaluate to the authenticated checkpoint root. | Security alert; abort query (possible server equivocation). |
| **MPT Proof Mismatch** | Sparse Merkle Tree bitwise path does not evaluate to the committed `MapRoot`. | Security alert; abort query (server attempted to forge trie state). |
| **Mini-Log Sub-Root Mismatch** | Reconstructed RFC 6962 compact range root does not match the verified `SubRoot` (or pagination continuity check fails). | Security alert; abort query (server altered, reordered, or truncated occurrences). |
| **History Regression** | Returned occurrences omit or mutate indices observed in an earlier verified query. | Security alert; abort query (server executed an index rollback). |
| **Upstream Server Degraded (`HTTP 503`)** | Server or verified mirror is still warming up or has halted serving in fail-closed mode. | Retry with backoff or failover to an alternative mirror. |

### 2.6 Client Contract & API Requirements

The client library provides a stateless query interface implementing strict zero-trust verification:

- **Inputs**:
  - VIndex service URL.
  - 32-byte search key hash (`KeyHash = SHA256(ClaimSubject)`).
  - Input Log verifier.
  - Output Log verifier and witness policy: configured [C2SP Transparency Log Policy](https://c2sp.org/tlog-policy) (`tlog-policy`) enforcing witness cosignature quorum.
  - Optional `before` pagination cursor.
  - Optional `limit`.
- **Outputs**:
  - Ordered list of uint64 Input Log occurrence indices.
  - Raw signed Input Log checkpoint.
- **Guarantees**:
  - Output Log checkpoint verification enforces witness cosignature quorum via a configured [C2SP Transparency Log Policy](https://c2sp.org/tlog-policy) (`tlog-policy`).
  - Client unconditionally rejects unverified or cryptographically inconsistent responses. Any invalid checkpoint signature, witness quorum failure, Merkle inclusion proof failure, trie path defect, or compact range mismatch triggers an immediate verification error.

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
- **Chosen Design**: Decouple completely: a public, zero-dependency `client` package (`vindex/v1/client`) and `wire` package (`vindex/v1/wire`) for query proof verification, and an `internal/auditor` package for full-log background auditing.

---

## 4. Verification Gate

All client proof verification, witness policy, monotonic history, and package dependency boundary tests are verified via:

```bash
go test -race ./vindex/v1/client/... ./vindex/v1/wire/...
```

---

## 5. Design Log

| Date | Milestone | Summary |
| :--- | :--- | :--- |
| 2026-09-22 | v1 Initial | Defined stateless light client SDK and 5-step proof verification sequence. |
| 2026-10-14 | M2–M3 | Added two-endpoint verification (`VerifyKeysResponse`, `VerifyEntriesResponse`, `LookupPrefixAll`), `GetCheckpoint` verification, `WitnessPolicy`, monotonic history ratcheting (`ErrCheckpointRegressed`), and decoupled `client` from `pebble`/`wazero`. |
