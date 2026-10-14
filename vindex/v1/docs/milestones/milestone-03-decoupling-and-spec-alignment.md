# Milestone 03: Package Decoupling & C2SP `tlog-vindex` Spec Alignment

**Status**: ✅ **Completed**  
**Target Completion**: 2026-W42  
**Epic**: Decouple core VIndex v1 packages (`internal/mpt` vs `internal/tree`, `mapfn/host` vs `internal/ingest`, shared `wire/`, and isolated `internal/verifier`), sever `client`'s transitive dependency on `cockroachdb/pebble` and `tetratelabs/wazero`, harden client checkpoint signature/witness/monotonicity verification (`2.6.4`), and align all Type A and Type B documentation with the M1 + M2 architecture (`1.3.1`–`1.3.7`).

---

## 1. Objectives & Success Criteria
1. **Pure State Trie & Shared Wire Package (`1.2.1`, `1.2.3`)**: Extract the stateless/pure Sparse Merkle Patricia Trie into `internal/mpt` and shared C2SP section/leaf/compact-range primitives into `wire/`, severing `client`'s transitive dependency on `internal/kvstore` (`cockroachdb/pebble`) and `tessera/storage/posix`.
2. **Host WASM Sandbox & Verifier Isolation (`1.2.2`, `1.2.4`)**: Extract the Wazero `input_buffer` / `map_bundle` host runtime into `mapfn/host` alongside `mapfn/sdk` (so `cmd/vindex-wasm` does not import the network tile-fetching stack) and isolate `MTCVerifier` inside `internal/verifier` (so `internal/verifier` does not import `internal/mtc` or `internal/ingest`).
3. **Client Checkpoint Verification, Witness Policy, & Monotonic History (`2.6.4`)**: Verify checkpoint signatures in `Client.GetCheckpoint` and `Client.GetInputLogCheckpoint`, support witness cosignature policies (`torchwood/tlog` or `tessera.WitnessGroup`) in `VerifierConfig`, and enforce monotonic Output Log and Input Log checkpoint ratcheting across sequential client operations.
4. **Type A & Type B Documentation Alignment (`1.3.1`–`1.3.7`)**: Align `README.md`, `docs/ARCHITECTURE.md`, `docs/APPLICATIONS.md`, `internal/server/README.md`, `client/README.md`, `internal/tree/README.md`, `internal/coordinator/README.md`, `hammer/README.md`, and `mapfn/examples/README.md` with the M1 + M2 implementation, standardized checkpoint field names, and executable verification gates.

---

## 2. Actionable Task Breakdown

### Phase 03.1: Package Decoupling & Dependency Hygiene (`internal/mpt/`, `wire/`, `mapfn/host/`, `internal/verifier/`, `internal/tree/`, `internal/ingest/`, `internal/mtc/`)
- [x] **03.1.1 Split `internal/tree` into Pure State Trie (`internal/mpt`) and Output Log Publisher (`1.2.1`)**: Move pure Sparse Merkle Patricia Trie types and proof verification (`Manager`, `Open`, `NewMem`, `VerifyKey`, `VerifyPrefix`, `PrefixKeyVal`, `ValidateCanonicalKey`) into `vindex/v1/internal/mpt` with zero dependency on `internal/kvstore` or `cockroachdb/pebble`, keeping re-exports in `internal/tree` alongside `OutputPublisher` and `POSIXOutputLog`.
- [x] **03.1.2 Extract Shared C2SP Wire Format & Proof Primitives (`wire/`) (`1.2.3`)**: Create `vindex/v1/wire` consolidating C2SP section parsing/formatting (`Section`, `ParseSections`, `FormatKeysResponse`, `FormatEntriesResponse`, `FormatResponse`), Output Log leaf formatting/parsing (`FormatOutputLogLeaf`, `ParseOutputLogLeaf`, `ParseCheckpointHeader`), and RFC 6962 mini-log leaf/compact-range hashing (`LeafHash`, `HashChildren`, `ComputeMiniLogRoot`).
- [x] **03.1.3 Extract Host WASM Sandbox into `mapfn/host` (`1.2.2`)**: Move `WASMHost`, `WASMRunner`, `LeafMapper`, `BundleMapper`, `MappedEntry`, and `ValidatePreimageKey` into `vindex/v1/mapfn/host` with type aliases in `internal/ingest`, and update `cmd/vindex-wasm` to import `mapfn/host` directly.
- [x] **03.1.4 Isolate `MTCVerifier` in `internal/verifier` (`1.2.4`)**: Move `MTCVerifier` (`NewMTCVerifier`) into `internal/verifier` (re-exported in `internal/mtc`) so `internal/verifier` and `client/` have zero dependency on `internal/mtc` or `internal/ingest`. Verify via `go list -deps ./vindex/v1/client` that `cockroachdb/pebble` and `tetratelabs/wazero` are no longer in `client`'s dependency graph.

### Phase 03.2: Client Checkpoint Verification, Witness Policy, & Monotonic History (`client/`)
- [x] **03.2.1 Verified `GetCheckpoint` / `GetInputLogCheckpoint` & Strict Verifier Enforcement (`2.6.4`)**: Verify checkpoint signatures and origins in `Client.GetCheckpoint` and `Client.GetInputLogCheckpoint` when verifiers are configured, and add `RequireVerifiers` / witness policy checks (`OutputLogWitnessPolicy`, `InputLogWitnessPolicy`) to `VerifierConfig`.
- [x] **03.2.2 Monotonic History Ratchet (`2.6.4`)**: Track the highest verified `(OutputLogSize, InputLogSize)` watermark on `Verifier` / `Client` and reject any server response whose `OutputLogSize` or `InputLogSize` regresses (`ErrCheckpointRegressed`).

### Phase 03.3: Type A & Type B Documentation Alignment (`1.3.1`–`1.3.7`)
- [x] **03.3.1 Architecture & Subsystem Spec Hygiene (`1.3.1`–`1.3.7`)**:
  - Condense duplicated Auditor runbook in `docs/ARCHITECTURE.md §3` (`1.3.1`).
  - Qualify cold-start MPT replay latency and link to `docs/BENCHMARKS.md §5` in `docs/ARCHITECTURE.md`, `internal/coordinator/README.md`, and `internal/tree/README.md` (`1.3.2`).
  - Standardize checkpoint field names (`Output_CP.InputSize`, `Serving_CP.InputSize`) across all docs (`1.3.3`).
  - Document the two-endpoint protocol (`/vindex/v1/keys/` + `/vindex/v1/entries/`), Tip vs. Continuation verification (`1.3.4`), reversed-label trailing-dot domain keys, `internal/budget`, `internal/verifier`, `internal/mpt`, `mapfn/host`, and `wire/` across `README.md`, `docs/ARCHITECTURE.md`, `docs/APPLICATIONS.md`, `client/README.md`, `internal/server/README.md`, `hammer/README.md`, and `mapfn/examples/README.md` (`1.3.5`, `1.3.6`).
  - Add executable verification gates (`go test -race ./vindex/v1/...`) and `Design Log` sections (`1.3.7`).

### Phase 03.4: Verification Gate & Critical Review
- [x] **03.4.1 Automated Test & Dependency Verification Suite**: `go test -race ./vindex/v1/...` passes cleanly and `client` / `cmd/vindex-wasm` dependency graphs are verified.
- [x] **03.4.2 Independent Critical Subagent Review**: Run adversarial review across all Milestone 03 commits, fix and squash findings, and log snippets.
