# Sub-Design: Independent Log Auditor & Verified Mirror

This document defines the architecture, continuous audit loop, root mismatch alerting, state-preserving halt protocols, adversarial threat model, and verified mirror serving engine for the **Auditor Subsystem** (`vindex/v1/internal/auditor`).

---

## 1. Context & Objectives

### 1.1 Problem Statement & The Operator Trust Dilemma
The primary VIndex operator publishes an Output Log asserting that their search index accurately, completely, and deterministically represents the underlying Input Log.

However, in a verifiable transparency architecture, clients cannot simply trust the operator's claims. A compromised, coerced, or buggy index operator could:
1. **Targeted Omission Attacks**: Commit an invalid `MapRoot` that silently conceals specific certificates, packages, or identities, while still returning valid-looking proofs to unsuspecting users.
2. **Equivocation & Split-Views**: Present conflicting Output Log checkpoints to different monitors or clients.
3. **Historical Rollbacks**: Rewrite or regress historical index states.

To enforce cryptographic integrity, independent third parties must be able to audit the operator's commitments from genesis to log head without placing trust in the operator. Furthermore, organizations requiring high query availability need to run **verified mirror instances** that serve local lookups with absolute authenticity. If the upstream operator cheats or divergence is detected, the mirror halts forward sync and alerts operators while safely continuing to serve from the last known good verified checkpoint (`Serving_CP`), preserving read availability without sacrificing cryptographic integrity (or optionally revoking serving via `--fail_closed=true`).

### 1.2 The Independent Auditor & Safe Freeze Analogy
The verifier operates as an independent external auditor paired with a safe forensic freeze:
- **The Audit**: Like a forensic auditor re-running a company's general ledger from raw bank statements (Input Log) and calculating whether the published balance sheet (`MapRoot`) matches down to the exact cent. If the calculated root matches the published root, the auditor certifies the ledger.
- **The Safe Freeze**: If the calculated root diverges by even a single bit, the auditor sounds the alarm (`vindex_verifier_root_mismatch = 1`), freezes the physical books on disk to preserve uncorrupted evidence for forensic analysis, halts further forward sync, but keeps the branch doors open to continue serving customers from the last certified audit snapshot (`Serving_CP`). Downstream readers continue to get consistent, authentic answers up to that checkpoint rather than suffering immediate denial of service. Operators requiring total immediate shutdown can opt into hard serving revocation via `--fail_closed=true`.

### 1.3 Goals & Non-Goals
- **Goals**:
  - Continuously audit published Output Log leaves against Input Log entries from leaf 0.
  - Assert cryptographic equality between the independently reconstructed `localMapRoot` and the operator's `committedMapRoot`.
  - Provide immediate mismatch signaling via Prometheus metrics (`vindex_verifier_root_mismatch = 1`), structured logs, and sync status probe degradation (`/readyz` or `/syncz`).
  - Freeze physical database state on root mismatch to preserve forensic post-mortem evidence.
  - Serve verifiable read queries (`--serve_mirror=true`) pinned to the last verified checkpoint (`Serving_CP`) during sync halt, preserving read availability and partition resilience.
  - Support an opt-in fail-closed mode (`--fail_closed=true`) for deployments requiring immediate serving revocation (HTTP 503).
- **Non-Goals**:
  - **No Automatic Retry / Self-Healing on Root Mismatch**: If a root mismatch occurs, the verifier does not guess or retry; it halts immediately to preserve evidence of operator fraud or software bug.
  - **No Operator Checkpoint Generation**: The verifier does not sign Output Log checkpoints; it is strictly an independent auditor and consumer.

### 1.4 Requirements, Dependencies & Known Pain Points
- **Dependencies**: Integrates `TileFetcher`, `ManagedTileCache`, `IndexStore`, `MPTManager`, and `Publisher`.
- **Known Pain Points ("Warts and All")**:
  - **Hardware Sizing Parity**: Running a full-log verifier mirror requires the same RAM and disk capacity as the primary indexer to maintain the local MPT in memory.
  - **Audit Catch-Up vs. Issuance Velocity**: When catching up from leaf 0, the verifier experiences initial sync lag. However, because VIndex's indexing engine achieves 90,000 to 240,000+ leaves/sec—several orders of magnitude faster than steady-state log issuance rates (50 to 500 entries/sec)—catch-up over tens of millions of entries completes in hours rather than months, provided the upstream log's historical entry tiles remain resolvable over HTTP/CDN.
  - **Stale Serving During Sync Halt**: By default, when an upstream root mismatch or sync divergence halts background sync, the mirror remains pinned to `Serving_CP`. While queries return cryptographically authentic proofs, index coverage remains frozen until human operators triage and resolve the divergence. Deployments requiring immediate cutoff can enable `--fail_closed=true` to fail lookups with HTTP 503 instead.

---

## 2. Detailed Design

### 2.1 Ecosystem Audit Architecture: Client SDK vs. Log Auditor

VIndex verification operates across two distinct, complementary boundaries:

| Role & Component | Execution Scope | Target Consumer | Threat Coverage |
| :--- | :--- | :--- | :--- |
| **Client Query Verification** (`vindex/v1/client`) | Evaluates individual query responses against witnessed Output Log checkpoints. | End-user apps, CLIs, light clients. | Verifies inclusion/non-inclusion of queried key; verifies witness signatures; verifies backward pagination chain. |
| **Full-Log Independent Auditor** (`vindex/v1/internal/auditor`) | Independently re-indexes all Input Log leaves from leaf 0 and reconstructs the full MPT. | Standalone monitoring daemon (`vindex-audit`). | Detects operator equivocation, forged map roots, targeted omission of unqueried keys, and log rollbacks. |

### 2.2 The Continuous Audit Loop (`AuditOnce`)
The standalone auditor daemon continuously polls both logs, executing the following 5-step audit loop:

| Step | Phase | Action & Operations | Verification Check |
| :--- | :--- | :--- | :--- |
| **1** | **Poll Output Checkpoint** | Fetches latest Output Log `/checkpoint`. | Verifies origin note signatures and witness cosignatures. |
| **2** | **Stream Output Leaves** | Streams Output Log leaves in the range `[verifiedOutputWatermark .. targetOutputSize)`. | Asserts Merkle inclusion proof against the verified Output Log root. |
| **3** | **Fetch & Map Input Tiles** | Downloads missing Input Log tiles up to `targetInputSize`. | Authenticates tiles against Input Log root and runs sandboxed mapping. |
| **4** | **Reconstruct Local MPT** | Reconstructs mini-log sub-roots for all modified search keys. | Computes candidate `localMapRoot` in local memory. |
| **5** | **Assert Root Equality** | Asserts `localMapRoot == committedMapRoot`. | **Match**: Ratchets verified watermarks.<br>**Mismatch**: Triggers state-preserving halt, freezes database files, emits alerts, and pins serving to `Serving_CP` (or revokes serving if `--fail_closed=true`). |

#### Step Details:
1. **Discover & Authenticate Output Checkpoint**: Polls the Output Log's `/checkpoint` endpoint, verifies origin note signatures and witness cosignatures using configured public keys.
2. **Stream State Commitments**: Downloads new Output Log leaves using standard Merkle tile fetching. Verifies inclusion proofs for each leaf against the Output Log checkpoint root (`proof.VerifyInclusion`).
3. **Fetch & Map Input Tiles**: For each state commitment leaf specifying `targetInputSize`:
   - Validates monotonic progression: `targetInputSize >= verifiedInputWatermark`.
   - Downloads missing Input Log tiles from the upstream log.
   - Evaluates the WASM `MapFn` on input leaves and appends occurrence indices to the local Pebble DB (`store.WriteBatch`).
4. **Reconstruct Local MPT**: Queries `store.GetSubRoot(keyHash, targetInputSize)` for all modified keys and computes the local candidate root:
   ```go
   localMapRoot, err := v.mptMgr.CommitWithVersionLocked(modifiedSubRoots, int64(targetInputSize))
   ```
5. **Root Equality Assertion**: Asserts `localMapRoot == committedMapRoot`.
   - If equal: advances verifier metadata watermarks in Pebble (`KeyVerifierOutputWatermark`, `KeyVerifierInputWatermark`, `KeyVerifierLastRoot`) and updates the mirror serving state.
   - If divergent: enters the state-preserving halt protocol.

### 2.3 Root Mismatch Alerting & State-Preserving Halt
If `localMapRoot != committedMapRoot`, or upstream sync divergence occurs, the verifier immediately executes a coordinated containment response:

1. **Sync Engine Halt**:
   - The background audit sync loop terminates immediately.
   - Watermarks are **not** advanced in Pebble DB (`KeyVerifierOutputWatermark`, `KeyVerifierInputWatermark`).
2. **Forensic State Freeze**:
   - The database files and MPT state are left intact on disk, freezing the exact divergent state for forensic triage and public equivocation reporting.
3. **Metrics & Structured Logging**:
   - Increments `vindex_verifier_root_mismatches_total`.
   - Sets gauge `vindex_verifier_root_mismatch = 1`.
   - Emits structured error logs containing the divergent `output_leaf_index`, `target_input_size`, `local_map_root`, and `committed_map_root`.
4. **Serving Engine (Default Pinned Behavior)**:
   - In mirror mode (`--serve_mirror=true`), the serving engine does **not** revoke serving state (`publisher.GetServingState()` remains populated with the last verified `Serving_CP`).
   - The server remains pinned to the last verified Output Log checkpoint (`Serving_CP`), continuing to serve lookups with cryptographically valid proofs up to that verified checkpoint.
   - This avoids turning an upstream bug or index corruption into an instant denial of service for downstream readers, preserving read availability and partition resilience.
5. **Fail-Closed Mode (Opt-In)**:
   - If configured with `--fail_closed=true`, the verifier immediately revokes serving state via `publisher.SetServingState(nil)`.
   - Subsequent HTTP lookup requests immediately receive **HTTP 503 Service Unavailable**.
6. **Health and Status Probes**:
   - `/healthz`: Remains **HTTP 200 OK** as long as the serving replica is alive and serving authentic verified state, preventing external load balancers and Kubernetes container orchestrators from prematurely terminating or de-routing traffic.
   - `/readyz` or `/syncz`: Returns **HTTP 503 Service Unavailable** (or degraded sync status) with structured JSON diagnostics:
     ```json
     {
       "status": "degraded",
       "error": "verifier root hash mismatch",
       "output_index": 12480,
       "input_size": 3194880,
       "local_root": "a4f1...",
       "committed_root": "b7c2..."
     }
     ```

### 2.4 Verified Mirror Serving Engine (`--serve_mirror`)
When deployed with `--serve_mirror=true`, the verifier acts as a production-grade read replica:
- Exposes standard C2SP query endpoints (`/vindex/lookup/{keyhash}`, `/checkpoint`).
- Lookups are evaluated against the locally verified MPT and Pebble database under reader snapshot isolation.
- Guarantees that clients querying the mirror never observe unverified data or commitments from an untrusted operator.
- If upstream divergence occurs, the mirror freezes forward sync but continues serving valid proofs pinned to the last verified Output Log checkpoint (`Serving_CP`), protecting downstream clients from an immediate denial of service while ensuring they never consume unverified or fraudulent results. If the operator configures `--fail_closed=true`, the server instead immediately revokes serving state and returns HTTP 503.

### 2.5 Adversarial Threat Vector Matrix

| Threat Vector | Adversary Action | Detection Mechanism | Verifier Action |
| :--- | :--- | :--- | :--- |
| **Publisher Equivocation** | Operator serves conflicting Output Log checkpoints to different mirrors. | Witness signature verification; Merkle consistency proofs between checkpoints. | Background sync halts immediately; alert logged; database frozen; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`). |
| **Tree Size Rollback** | Operator serves an Output Log checkpoint with `Size < verifiedOutputWatermark`. | Monotonic tree size assertions in `VerifyOnce`. | Sync halts; watermarks frozen; `/healthz` remains HTTP 200; `/readyz`/`/syncz` reports degraded sync; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`). |
| **Forged Map Root (Omission)** | Operator commits to an invalid `MapRoot` to hide specific records. | Local MPT re-computation from Input Log leaves; assertion `localMapRoot == committedMapRoot`. | Increments mismatch alert (`vindex_verifier_root_mismatch = 1`); freezes disk state; `/readyz`/`/syncz` reports degraded sync; continues serving pinned `Serving_CP` (or revokes serving if `--fail_closed=true`); alerts witnesses. |
| **Corrupted Input Leaves** | Network attacker or corrupted CDN alters raw log entries. | Upstream tile Merkle verification fails against signed Input Log checkpoint root. | Pipeline aborts tile ingestion; retries from alternative mirrors. |
| **Invalid Leaf Inclusion** | Operator publishes an Output Log leaf that is not part of the Output Log tree. | `proof.VerifyInclusion` fails against Output Log tree root. | Leaf rejected; sync terminates with `ErrInclusionFailed`. |

### 2.6 In-Situ Invariants & Performance Optimizations

- **[Correctness Invariant] Strict Root Equality Assertion**:
  - *Rule*: For every processed Output Log leaf, `localMapRoot` computed from raw Input Log leaves must strictly equal `committedMapRoot` committed in the Output Log leaf payload.
  - *Rationale*: Guarantees that the operator's index state is 100% faithful to the Input Log.
  - *Consequence ("Or Else")*: Accepting mismatched roots allows an adversary to execute omission attacks or publish fabricated search states without detection.

- **[Correctness Invariant] Non-Monotonic Size Rejection**:
  - *Rule*: The target Input Log size specified in Output Log leaf N must strictly satisfy:
    ```text
    leaf[N].InputLogSize >= leaf[N-1].InputLogSize
    ```
  - *Rationale*: Transparency logs are strictly append-only; historical input tree size cannot shrink.
  - *Consequence ("Or Else")*: An operator could rollback historical entries, truncating index coverage.

- **[Performance Optimization] High-Throughput Catch-Up Architecture**:
  - *Mechanism*: Reuses the core batching pipeline (256-leaf tile bundling, Wazero worker pool, host SIMD hashing, and Pebble batch commits).
  - *Impact*: Ingestion throughput operates at 90,000 to 240,000+ leaves/sec, allowing a newly provisioned verifier to catch up over tens of millions of historical leaves in hours.

### 2.7 Operational Runbook: Responding to Mismatches
When a root mismatch alert fires (`vindex_verifier_root_mismatch == 1` or `/readyz`/`/syncz` returning degraded sync status):
1. **Triage & Containment**: The auditor sync engine has automatically halted forward sync and frozen database state on disk, while safely continuing to serve cryptographically authentic proofs pinned to `Serving_CP` (unless `--fail_closed=true` was specified). Do not restart the auditor process with cleared storage, as the disk contains crucial forensic data.
2. **Inspect Structured Logs**: Examine the auditor logs for the `CRITICAL ROOT MISMATCH DETECTED` entry to identify the divergent `output_leaf_index`, `target_input_size`, `local_map_root`, and `committed_map_root`.
3. **Forensic State Extraction**: Inspect local Pebble DB inverted chunks (`'c'`) and compare against raw Input Log leaves in the window `[verifiedInputSize .. targetInputSize)` to determine whether the publisher omitted leaves, altered keys, or encountered a non-deterministic `MapFn` bug.
4. **Reproduce via Standalone CLI**: Run `vindex-audit --oneshot` with an isolated temporary directory against the target checkpoint to confirm the mismatch is 100% reproducible.
5. **Publish Equivocation Bundle**: If the MapFn and input log entries are valid, publish the cryptographic proof bundle (signed Output Log checkpoint, leaf inclusion proof, raw leaf payload, signed Input Log checkpoint) to transparency witnesses and public coordination channels.

### 2.8 Go Interfaces & Public Types

```go
package auditor

import (
	"context"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

// Auditor audits the Output Log against the Input Log and optionally serves verified lookups.
type Auditor struct {
	cfg        *AuditorConfig
	inputLog   TesseraClient
	outputLog  TesseraClient
	store      IndexStore
	mptMgr     MPTManager
	publisher  Publisher
	httpServer *http.Server
}

// AuditorConfig configures auditor and mirror parameters.
type AuditorConfig struct {
	InputLogURL       string
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
	OutputLogURL      string
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	MapWasmPath       string
	DataDir           string
	ServeMirror       bool
	FailClosed        bool
	ListenAddr        string
	PollInterval      time.Duration
}

// RootMismatchError provides structured diagnostics when verification fails.
type RootMismatchError struct {
	OutputIndex   uint64
	InputSize     uint64
	LocalRoot     [sha256.Size]byte
	CommittedRoot [sha256.Size]byte
}
```

---

## 3. Alternatives Considered (or Tried)

### 3.1 Client-Side Query Verification vs. Full-Log Independent Auditing
- **Proposed**: Relying exclusively on the client SDK to verify individual query responses, omitting a standalone auditor daemon.
- **Theoretical Rejection**: Client verification proves inclusion or non-inclusion for queried keys only. It cannot detect targeted omission of unqueried keys or silent operator divergence across long-tail records.
- **Chosen Design**: Complementary architecture: lightweight, stateless client SDK (`vindex/v1/client`) for query-level proof verification, paired with the stateful `internal/auditor` daemon for full-log state auditing and optional mirror serving.

### 3.2 Ephemeral In-Memory Verification vs. State-Preserving Forensic Freezing
- **Proposed**: Storing verifier state ephemerally in RAM or dropping database files on error.
- **Operational Rejection**: If an operator attempts a malicious attack or a severe bug triggers a mismatch, dropping state destroys the evidence needed to file public cryptographic equivocation reports against the operator.
- **Chosen Design**: State-preserving halt: the verifier freezes all Pebble DB and MPT files in-place, writes structured diagnostics to `/readyz` (or `/syncz`), keeps `/healthz` HTTP 200, and halts forward sync while continuing to serve pinned `Serving_CP`.

### 3.3 Aggressive 503 Circuit-Breaking vs. Pinned Last-Known-Good Serving
- **Proposed**: Having the verifier immediately revoke serving state (`SetServingState(nil)`) and return HTTP 503 on all queries upon encountering a root mismatch or sync divergence.
- **Operational & Availability Rejection**: In production mirror deployments, upstream glitches, signer delays, or isolated bugs converted immediately into total denial of service for all downstream applications. Downstream systems were starved of verified answers despite holding thousands of previously authenticated entries. Furthermore, load balancers de-routed or killed healthy mirrors due to failing health checks.
- **Chosen Design**: Safe state-preserving halt with pinned last-known-good serving: background sync halts immediately, disk state is frozen for forensic triage, and alerts fire, while the serving engine safely continues answering lookups pinned to the last verified checkpoint (`Serving_CP`). Deployments strictly requiring total shutdown can opt into hard revocation via `--fail_closed=true`.
