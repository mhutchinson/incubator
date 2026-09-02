# VIndex v1 Deep Review & Discrepancy Audit Report

- **Date**: 2026-09-02
- **Milestone**: M1 (Requirement R1)
- **Status**: Complete
- **Scope**: Full VIndex v1 codebase (`vindex/v1/...`), specifications (`vindex/v1/docs/...`), subsystem design documents (`vindex/v1/internal/*/README.md`), CLI commands (`vindex/v1/cmd/...`), WASM runtime (`vindex/v1/mapfn/...`), and benchmark/stress harness (`vindex/v1/hammer/...`).

---

## 1. Executive Summary

This audit establishes the ground truth between the documented design specifications of VIndex v1 and its actual Go implementation.

### 1.1 Key Audit Findings

1. **Architectural Viability**: The core production architecture—comprising the Zero-WAL direct inverted chunk pipeline (`internal/kvstore`), lock-free MPT root prediction (`internal/tree`), bundled WebAssembly execution (`internal/ingest`), and inductive C2SP multi-section HTTP serving (`internal/server`)—is functionally sound, robustly tested (27 test suites), and correctly enforces cryptographic commitments.
2. **Terminology Inversion**: Documentation across `docs/ARCHITECTURE.md` defines "Genesis Catch-Up Mode" or "Catch-Up Ingestion Mode", whereas the Go codebase uniformly implements this feature as "Backfill Mode" (`vindex.Backfill`, `Coordinator.Backfill`, `--backfill`).
3. **Over-Specified Spec Fantasies**: Specifications document cryptographic mechanisms that are absent in code:
   - Checkpoint consistency proofs (`golang.org/x/mod/sumdb/tlog.CheckTree`) and witness policy quorums (`torchwood.VerifyCheckpoint`) in the coordinator.
   - A 2x2 startup recovery matrix predicated on a two-value MPT disk header return `(version int64, exact bool)`; the implementation relies solely on single-version equality checks.
   - `torchwood.Client` and `torchwood.PermanentCache` in the ingestion fetcher; the implementation directly uses Tessera client libraries and a bespoke filesystem cache.
4. **Stale Design Signatures**: Multiple subsystem READMEs contain outdated type names, method signatures, and package locations:
   - `MPTManager` instead of `Manager` in `internal/tree/README.md`.
   - `GetKVSize()` / `SetKVSize()` instead of `GetUint64()` / `SetUint64()` in `internal/kvstore/README.md`.
   - `ClientVerifier` residing in `internal/server` rather than `client/client.go`.
   - Undocumented `ReadServer` constructor parameters and embedded HTML UI.
5. **Backfill Mode Dead Branch & Complexity**: Backfill Mode is an isolated, redundant ingestion path. Production personality binaries (`cmd/sumdbindex`, `cmd/mtcindex`) do not expose or call Backfill Mode; their `--oneshot` execution uses `SyncOnce` (Normal Serving Mode). The documented headline throughput of 240,467 leaves/sec was achieved in Normal Serving Mode. Backfill Mode introduces dead code and architectural bifurcation across 6 source files and 3 test files without delivering utility.
6. **Undocumented Invariants**: Several mission-critical invariants—including immediate panic on MPT root prediction mismatch, bitwise inverted chunk key ordering (`^chunkNum`) for LSM Bloom filter alignment, and strict lexicographical deduplication—are implemented in code but omitted or only partially framed in design documents.

---

## 2. Subsystem-by-Subsystem Alignment Analysis

### 2.1 Root Embedder API (`vindex`)

#### Primary Artifacts
- Source: `vindex/v1/vindex.go` (653 lines)
- Tests: `vindex/v1/vindex_test.go`
- Specifications: `vindex/v1/docs/ARCHITECTURE.md` §1, §4, §7

#### Alignment Assessment
- **Engine Lifecycle (`Engine`)**: Correctly orchestrates all child subsystems (`db`, `mptMgr`, `cache`, `indexer`, `outLog`, `pub`, `fetcher`, `mapper`, `pipeline`, `coord`, `server`, `reaper`). Lifecycle transitions (`New`, `Start`, `Stop`, `Close`) match the top-level specification.
- **Mapping Interfaces**: Exposes `MappedEntry`, `LeafMapper`, `IdentityMapper()`, and `FuncMapper()`. Fully aligned with the claimant model in `docs/APPLICATIONS.md`.
- **Configuration Contract (`Config`)**: Holds paths, chunk/bundle dimensions, worker pool size, input log verifiers, and output log signing parameters.
- **Discrepancy - Backfill Infiltration**: `Config` contains `BackfillSnapInterval uint64` and `BackfillSyncInterval time.Duration`. A top-level function `Backfill(ctx, cfg, mapper, targetCP)` encapsulates standalone bulk ingestion, duplicating subsystem initialization logic from `New()`.
- **Discrepancy - Error Wrapping**: `vindex.go` relies on `errors.Join` during teardown, whereas design docs specify strict atomic rollbacks.

### 2.2 Ingestion Pipeline & Tile Cache (`internal/ingest`)

#### Primary Artifacts
- Source: `vindex/v1/internal/ingest/{types.go,pipeline.go,fetcher.go,cache.go,reaper.go,wasm.go}`
- Tests: `vindex/v1/internal/ingest/{ingest_test.go,wasm_test.go,reaper_test.go}`
- Specifications: `vindex/v1/internal/ingest/README.md` (320 lines)

#### Alignment Assessment
- **256-Leaf Entry Bundling**: Implemented in `LeafBundle` and `pipeline.go`. Upstream log leaves are fetched and processed in native Tessera 256-leaf bundles, eliminating per-leaf request overhead.
- **Bundled WebAssembly Mapping (`map_bundle`)**: Implemented in `WasmMapper` (`wasm.go`). Wazero executes `map_bundle(ptr, len)` passing up to 256 leaves per invocation. FFI crossings are reduced to 2-3 per tile.
- **Host SIMD SHA-256**: Implemented in `wasm.go`. Guest modules emit raw Claim Subject preimages; the Go host computes `KeyHash = sha256.Sum256(preimage)` leveraging CPU hardware acceleration (SHA-NI / ARMv8 Crypto).
- **In-Memory Priority Resequencer**: Implemented in `pipeline.go` (`resequencer`). A min-heap keyed by `BundleIdx = StartLeafIdx / 256` re-orders parallel mapper completions into strictly ascending chronological sequence.
- **Cache Pruning (`TileReaper`)**: Implemented in `reaper.go`. Evaluates `SafeWatermark = min(m_kv_size, mptDurableSize)` and removes tiles strictly satisfying `(tileIdx + 1) * 256 <= SafeWatermark`.
- **Discrepancy - Over-Specified Dependencies**: `internal/ingest/README.md:35-38` states that `TileFetcher` uses `torchwood.Client`, `torchwood.PermanentCache`, and `torchwood.VerifyCheckpoint`. The implementation does NOT import `torchwood` in `fetcher.go`. It imports `github.com/transparency-dev/tessera/client` and `golang.org/x/mod/sumdb/note`.
- **Discrepancy - Checkpoint Verification Scope**: `TiledFetcher.Checkpoint()` parses notes via `log.ParseCheckpoint` using a single `note.Verifier`. It does not execute Merkle consistency checks against prior checkpoints or evaluate witness quorum policies.

### 2.3 Inverted Chunk Storage Engine (`internal/kvstore`)

#### Primary Artifacts
- Source: `vindex/v1/internal/kvstore/{types.go,store.go,writer.go,reader.go,chunk.go,compact.go,recovery.go}`
- Tests: `vindex/v1/internal/kvstore/{chunk_test.go,compact_test.go,reader_test.go,store_test.go,writer_test.go}`
- Specifications: `vindex/v1/internal/kvstore/README.md` (342 lines)

#### Alignment Assessment
- **Pedagogical Inverted Chunk Keys**: Implemented in `chunk.go`. Keys are formatted as `'c' + KeyHash (32B) + ^chunkNum (8B BigEndian)`. Active chunks sort first lexicographically under the prefix.
- **Prefix Extractor & Bloom Filter**: Implemented in `store.go`. Uses `InvertedPrefixChunkComparer` with a 33-byte prefix (`'c' + KeyHash`) and 10-bit Bloom filters, achieving O(1) active chunk discovery via `SeekPrefixGE`.
- **16-bit Relative Index Offsets**: Implemented in `chunk.go`. Indices within a 65,536-leaf chunk are encoded as `uint16(index % 65536)`, saving 75% storage versus 8-byte integers.
- **RFC 6962 Compact Ranges**: Implemented in `compact.go` and `chunk.go`. Chunk values store covered leaf counts, intermediate compact sub-roots, and relative indices without delimiters.
- **Two-Generational Active Chunk Cache**: Implemented in `writer.go` (`KVIndexer`). Uses `currentCache` and `previousCache` (capped at 32,768 entries) to avoid Pebble block cache reads on active chunks.
- **Point-in-Time Sub-Root Recovery (`GetSubRoot`)**: Implemented in `reader.go`. Evaluates inverted keys to reconstruct mini-log roots up to `maxInputLogSize` without issuing storage mutations.
- **Discrepancy - Stale Metadata Accessor Signatures**:
  - `internal/kvstore/README.md:88-89` documents `GetKVSize() (uint64, error)` and `SetKVSize(size uint64) error`.
  - Actual code in `types.go:69-70` defines generic helpers: `GetUint64(key []byte) (uint64, error)` and `SetUint64(key []byte, val uint64) error`.
- **Discrepancy - Constructor Return Type**:
  - `internal/kvstore/README.md:96` specifies `Open(dir string, opts *pebble.Options) (IndexStore, error)`.
  - Actual code in `store.go:36` returns `(*DB, error)`.
- **Discrepancy - Missing Interface Methods in Spec**: `IndexStore` in `types.go:71-72` includes `SetChunkSize(chunkSize uint64)` and `ChunkSize() uint64`, which are omitted from `internal/kvstore/README.md`.

### 2.4 Authenticated State & Publisher (`internal/tree`)

#### Primary Artifacts
- Source: `vindex/v1/internal/tree/{types.go,mpt.go,publisher.go,posix.go}`
- Tests: `vindex/v1/internal/tree/{mpt_test.go,publisher_test.go,posix_test.go}`
- Specifications: `vindex/v1/internal/tree/README.md` (293 lines)

#### Alignment Assessment
- **Sparse Merkle Patricia Trie in `mmap`**: Implemented in `mpt.go`. Integrates `filippo.io/torchwood/mpt`, storing nodes in memory-mapped files without Go GC overhead.
- **Lock-Free Root Prediction (`mpt.Predict`)**: Implemented in `mpt.go`. Computes the post-mutation `MapRoot` across modified sub-roots before acquiring exclusive writer locks.
- **Split-Locking (`writeMu` vs `treeMu`)**: Implemented in `mpt.go`. Read queries (`Prove`, `ProveLocked`) run under `treeMu.RLock()`. Disk persistence (`Sync`, `Persist`) runs under `writeMu`, allowing concurrent lookups during disk fsync operations.
- **Output Log Commitments**: Implemented in `publisher.go`. State commitments format `hex(MapRoot) + "\n" + rawInputLogCP` and append to the Tessera Output Log.
- **Atomic Serving State Ratchet**: Implemented in `publisher.go`. An `atomic.Pointer[ServingState]` ratchets the reader-visible state atomically after write lock verification.
- **Discrepancy - Type Name Divergence**:
  - `internal/tree/README.md:45` specifies `type MPTManager struct`.
  - Actual code in `mpt.go:31` defines `type Manager struct`.
- **Discrepancy - Constructor Divergence**:
  - `internal/tree/README.md:52` specifies `func OpenMPT(mmapDir string) (*MPTManager, error)`.
  - Actual code in `mpt.go:41` defines `func Open(mmapDir string) (*Manager, error)` with alias `func NewManager(...)`.
  - `internal/tree/README.md:93` specifies `NewOutputPublisher(mptMgr, outputLog, witness)`.
  - Actual code in `publisher.go:43` requires `NewOutputPublisher(db kvstore.IndexStore, mptMgr *Manager, outputLog OutputLogClient, witness WitnessClient)`.
- **Discrepancy - Missing `exact` Flag in MPT Versioning**:
  - `internal/tree/README.md:53` specifies `Version() (version int64, exact bool)`.
  - Actual code in `mpt.go:275-289` implements `PersistedVersion() int64` and `PersistedSize() uint64`. The boolean return from `torchmpt.Tree.Version()` is ignored (`v, _ := m.tree.Version()`).
- **Discrepancy - Direct Publishing API**: `publisher.go:158-222` implements `PublishDirect(ctx, mapRoot, inputLogCP, rawInputLogCP)` exclusively to serve Backfill Mode. This method bypasses prediction checks.

### 2.5 Coordinator & Recovery (`internal/coordinator`)

#### Primary Artifacts
- Source: `vindex/v1/internal/coordinator/{coordinator.go,recovery.go}`
- Tests: `vindex/v1/internal/coordinator/recovery_test.go`
- Specifications: `vindex/v1/internal/coordinator/README.md` (341 lines)

#### Alignment Assessment
- **3-Phase Zero-WAL Recovery**:
  - Phase 1 (`Phase1` in `coordinator.go:161-214`): Instant Warm Start (< 5ms) when `inCP.Size == mptPersistedSize && MPT.Root() == tipMapRoot`.
  - Phase 2 (`Phase2` in `coordinator.go:217-331`): Fast-Forward Tile Replay (< 500ms) streaming tiles from cache, computing sub-roots via `store.GetSubRoot`, and updating MPT in RAM with zero Pebble writes.
  - Phase 3 (`Phase3` in `coordinator.go:334-388`): Resumes background catchup from `m_kv_size` to `m_target_checkpoint`.
- **Synchronous Commit Barrier**: Implemented in `coordinator.go:645-709` (`SyncOnce`). `store.WriteBatch` with `pebble.Sync` completes before `pub.PublishBatch` begins.
- **Moving-Goalpost Prevention**: Implemented in `coordinator.go:419, 608`. Target checkpoint raw bytes are frozen in Pebble metadata (`m_target_checkpoint`) prior to batch processing.
- **Commit Batch Aggregation**: Aggregates 256-leaf mapper batches into `DefaultCommitBatchSize = 4096` before committing to storage.
- **Discrepancy - Over-Specified Cryptographic Ratcheting**:
  - `internal/coordinator/README.md:12, 54` claims the coordinator executes Merkle consistency proofs via `golang.org/x/mod/sumdb/tlog.CheckTree` and validates witness quorums via `torchwood.VerifyCheckpoint` on target checkpoint transitions.
  - Reality in code: `SyncOnce` (`coordinator.go:598-610`) simply fetches `c.fetcher.Checkpoint(ctx)` and writes it to `m_target_checkpoint`. No `tlog.CheckTree` or `torchwood.VerifyCheckpoint` calls exist in the coordinator package.
- **Discrepancy - Fictional 2x2 Header Matrix**:
  - `internal/coordinator/README.md:29, 67-99` defines a 2x2 decision matrix based on `exact == true/false` in the on-disk MPT header.
  - Reality in code: Phase 1 evaluates `if inCP.Size == mptPersistedSize && c.mptMgr.Root() == mapRoot`. The `exact` flag is never inspected.
- **Discrepancy - Terminology Divergence**: Coordinator comments reference "Catch-Up Ingestion Mode", but method and variable identifiers use `Backfill` (`Backfill`, `backfillSnapInterval`, `backfillSyncInterval`).

### 2.6 Read Serving Plane (`internal/server`)

#### Primary Artifacts
- Source: `vindex/v1/internal/server/{server.go,format.go,index.html}`
- Tests: `vindex/v1/internal/server/server_test.go`
- Specifications: `vindex/v1/internal/server/README.md` (450 lines)

#### Alignment Assessment
- **Endpoint Routing**: Serves `GET /vindex/v1/lookup/{keyhash}?before=X&limit=M` and alias `GET /lookup/{keyhash}`.
- **C2SP Multi-Section Wire Format**: Implemented in `format.go`. Emits sections delimited by `— <section-name>[ <args>] —`:
  - `— vindex/v1 —`
  - `— output-log-leaf-v1 <index> —`
  - `— output-log-proof-v1 —`
  - `— mpt-proof-v1 <inclusion|non-inclusion> —`
  - `— prefix-compact-range-v1 <covered_size> —`
  - `— indices-v1 [<next_before>] —`
- **Sub-Millisecond Snapshot Isolation**: Captures `ServingState` and MPT proof under `treeMu.RLock()` (< 1ms), then releases lock before querying Pebble.
- **Health & Readiness Probes**: Implemented in `server.go`. Exposes `/healthz` (200 OK) and `/readyz` (503 during startup/catchup, 200 once serving state is active).
- **Discrepancy - Misplaced ClientVerifier in Spec**:
  - `internal/server/README.md:61-79` defines `ClientVerifier` and `VerifiedLookupResult` as types in `package server`.
  - Reality in code: Client verification is decoupled into `vindex/v1/client/client.go` (`Verifier`, `LookupResponse`). `internal/server` contains zero client verification code.
- **Discrepancy - Constructor Signature**:
  - `internal/server/README.md:55` documents `NewReadServer(store, mptMgr, pub)`.
  - Reality in code: `server.go:50` defines `NewReadServer(store kvstore.IndexStore, mptMgr *tree.Manager, pub *tree.OutputPublisher, chunkSize uint64)`.
- **Discrepancy - Undocumented Interactive Web UI**: `server.go:32, 81-84` embeds `index.html` and serves an interactive web lookup interface at `/` and `/index.html` (toggleable via `SetEnableUI`). This feature is completely absent from `internal/server/README.md`.
- **Discrepancy - Additional Endpoints**: Code exposes `/vindex/v1/checkpoint`, `/vindex/v1/inputlog_checkpoint`, and `/metrics` (Prometheus), which are not documented in `internal/server/README.md`.

### 2.7 Client, Personalities & Tooling (`client/`, `cmd/`, `hammer/`)

#### Primary Artifacts
- Client: `vindex/v1/client/client.go`, `client/client_test.go`
- Personalities: `cmd/{sumdbindex,sumdbverify,mtcindex,mtcverify,clonelog,vindex-map,vindexd,vindex}`
- Hammer: `vindex/v1/hammer/{analyzer.go,fetcher.go,generator.go,reader.go,sequencer.go,server.go,hammer_test.go,benchmarks_test.go}`
- Specifications: `vindex/v1/docs/APPLICATIONS.md`, `cmd/*/README.md`, `hammer/README.md`

#### Alignment Assessment
- **Client Verification Engine**: `client/client.go` implements strict cryptographic validation: Output Log checkpoint note verification, inclusion proof verification, MPT root proof verification, RFC 6962 compact range accumulation, and inductive backward pagination continuity checks.
- **Synthetic Load Harness (`hammer`)**: Closed-loop testing framework generating configurable leaf traffic distributions (Zipfian, Pareto, Uniform), synthetic checkpoints, drip feeding, and real-time invariant assertions.
- **Personality Decoupling from Backfill Mode**:
  - Neither `cmd/sumdbindex` nor `cmd/mtcindex` defines or binds a `--backfill` flag.
  - Both commands implement `--oneshot` using `coord.SyncOnce(ctx)` (Normal Serving Mode).
  - The headline benchmark of 240,467 leaves/sec in `docs/BENCHMARKS.md` was obtained via `sumdbindex --oneshot`.
- **Discrepancy - Legacy JSON Verification**: `client/client.go:63-69` maintains legacy JSON parsing structs (`LegacyLookupResponse`) alongside C2SP text parsing, an artifact of pre-C2SP prototypes.

---

## 3. Comprehensive Inventory of Technical Discrepancies

### 3.1 Naming Inversions & Terminology Divergences

| Subsystem | Specification Term | Codebase Implementation | Location in Code | Impact |
| :--- | :--- | :--- | :--- | :--- |
| Core / Coordinator | Catch-Up Ingestion Mode / Genesis Catch-Up Mode | Backfill Mode | `vindex.go:268`, `coordinator.go:393`, `vindexd/main.go:70` | Causes cognitive dissonance between high-level architecture docs and operator CLI flags. |
| Tree / MPT | `MPTManager` | `Manager` | `vindex/v1/internal/tree/mpt.go:31` | Outdated documentation snippets fail compilation if copied into embedder code. |
| Tree / MPT | `OpenMPT` | `Open` / `NewManager` | `vindex/v1/internal/tree/mpt.go:41, 87` | API mismatch in documentation. |
| Server / Client | `server.ClientVerifier` | `client.Verifier` | `vindex/v1/client/client.go:95` | Architectural misattribution: verifier belongs in client library, not server package. |
| Server / Client | `server.VerifiedLookupResult` | `client.LookupResponse` | `vindex/v1/client/client.go:80` | Naming discrepancy between spec and client library. |

### 3.2 Stale Method Signatures & Struct Definitions

| Package | Documented Signature / Struct | Actual Code Signature / Struct | Location in Docs vs Code |
| :--- | :--- | :--- | :--- |
| `kvstore` | `GetKVSize() (uint64, error)`<br>`SetKVSize(size uint64) error` | `GetUint64(key []byte) (uint64, error)`<br>`SetUint64(key []byte, val uint64) error` | `internal/kvstore/README.md:88-89`<br>`internal/kvstore/types.go:69-70` |
| `kvstore` | `Open(dir string, opts *pebble.Options) (IndexStore, error)` | `Open(dir string, opts *pebble.Options) (*DB, error)` | `internal/kvstore/README.md:96`<br>`internal/kvstore/store.go:36` |
| `tree` | `Version() (version int64, exact bool)` | `PersistedVersion() int64`<br>`PersistedSize() uint64` | `internal/tree/README.md:53`<br>`internal/tree/mpt.go:275, 283` |
| `tree` | `Commit(mutations, inputLogSize uint64) ([32]byte, error)` | `CommitWithVersion(mutations, int64(inputLogSize))` | `internal/tree/README.md:55`<br>`internal/tree/mpt.go:122` |
| `tree` | `NewOutputPublisher(mptMgr, outputLog, witness)` | `NewOutputPublisher(db, mptMgr, outputLog, witness)` | `internal/tree/README.md:93`<br>`internal/tree/publisher.go:43` |
| `server` | `NewReadServer(store, mptMgr, pub)` | `NewReadServer(store, mptMgr, pub, chunkSize)` | `internal/server/README.md:55`<br>`internal/server/server.go:50` |

### 3.3 Missing or Unimplemented CLI Flags

| Binary | Documented CLI Flag | Actual Status in Code | Detail |
| :--- | :--- | :--- | :--- |
| `sumdbindex` | `--backfill` | Missing | Command only supports `--oneshot` via `SyncOnce`. |
| `mtcindex` | `--backfill` | Missing | Command only supports `--oneshot` via `SyncOnce`. |
| `vindexd` | `-catchup_mode` | Implemented as `-backfill` | Flag naming diverges from `ARCHITECTURE.md`. |
| `vindexd` | `-enable_ui` | Implemented, Undocumented | Serves embedded HTML UI at `/`; omitted from docs. |

---

## 4. Inventory of Over-Specified / Unimplemented Mechanisms in Specs

The following mechanisms are documented in specifications as load-bearing requirements, but are completely absent from the actual implementation:

### 4.1 Checkpoint Origin & Policy Verification via `torchwood.VerifyCheckpoint`
- **Specification Claim**: `ARCHITECTURE.md` §5.4, `internal/ingest/README.md` §4.1, and `internal/coordinator/README.md` §1.1 claim that incoming checkpoints must be cryptographically verified against origin keys and witness policy quorums ([c2sp.org/tlog-policy](https://c2sp.org/tlog-policy)) using `torchwood.VerifyCheckpoint`.
- **Reality in Code**: `torchwood` is not imported by `internal/ingest/fetcher.go` or `internal/coordinator/coordinator.go`. Checkpoint signatures are verified solely via `golang.org/x/mod/sumdb/note` against a single public key. No witness policy or quorum evaluation is performed.

### 4.2 Merkle Consistency Proof Verification (`tlog.CheckTree`) in Coordinator
- **Specification Claim**: `internal/coordinator/README.md` §1.1, §6.3 asserts that the coordinator verifies append-only Merkle tree consistency proofs (`CP_old` -> `CP_new`) using `golang.org/x/mod/sumdb/tlog.CheckTree` before freezing a target checkpoint.
- **Reality in Code**: In `coordinator.go:598-610`, `SyncOnce` queries `c.fetcher.Checkpoint(ctx)` and immediately writes the raw bytes into `m_target_checkpoint`. It performs zero consistency proof checks between successive checkpoints.

### 4.3 MPT Disk Header `exact` Boolean Durability Flag
- **Specification Claim**: `internal/tree/README.md` §4.4 and `internal/coordinator/README.md` §2.1 detail an MPT disk header flag (`exact bool`) that indicates whether the on-disk trie is clean or dirty. A 2x2 decision matrix selects Instant Warm Start vs. Fast-Forward Tile Replay based on `exact`.
- **Reality in Code**: In `internal/tree/mpt.go:278`, the second return value of `m.tree.Version()` is ignored (`v, _ := m.tree.Version()`). `PersistedVersion()` returns only `int64`. In `coordinator.go:182`, Phase 1 evaluates `inCP.Size == mptPersistedSize && c.mptMgr.Root() == mapRoot`. The `exact` flag is an unimplemented specification artifact.

### 4.4 `torchwood.Client` & `torchwood.PermanentCache` in Ingest
- **Specification Claim**: `internal/ingest/README.md` §2, §3 states that tile fetching is performed by `torchwood.Client` backed by `torchwood.PermanentCache`.
- **Reality in Code**: `internal/ingest/fetcher.go` uses `github.com/transparency-dev/tessera/client` (`TiledReader`) and a bespoke on-disk bundle cache (`ManagedTileCache` in `cache.go`).

### 4.5 Standalone Continuation Traversal
- **Specification Claim**: `internal/server/README.md` §5 implies clients can query arbitrary continuation pages (`before != nil`) directly.
- **Reality in Code**: `client/client.go:174-210` correctly enforces that continuation pages cannot be verified in isolation; inductive backward verification requires the prefix compact range established on Page 1.

---

## 5. Inventory of Undocumented Load-Bearing Invariants in Code

The following invariants are implemented in the Go source code and are critical for correctness, crash safety, and cryptographic integrity, but are omitted or under-specified in design documentation:

### 5.1 Fatal Panic on Prediction Mismatch (`internal/tree/publisher.go:134-137`)
```go
if actualRoot != predictedMapRoot {
    p.mptMgr.Unlock()
    panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", actualRoot, predictedMapRoot))
}
```
- **Mechanism**: In `PublishBatch`, the MPT root is predicted lock-free (`mpt.Predict`), and the state commitment is appended to the Tessera Output Log. When writer lock `treeMu` is acquired and mutations are committed (`CommitWithVersionLocked`), the actual computed root is asserted against `predictedMapRoot`.
- **Invariant**: If `actualRoot != predictedMapRoot`, the node must terminate immediately with a fatal panic. Continuing execution would publish an equivocal commitment to the Output Log.

### 5.2 Bitwise Chunk Key Inversion (`internal/kvstore/chunk.go`)
```text
Key = 'c' (1B) + KeyHash (32B) + ^chunkNum (8B BigEndian)
```
- **Mechanism**: Chunk numbers are inverted using bitwise NOT: `^chunkNum = math.MaxUint64 - chunkNum`.
- **Invariant**: Inverted ordering places chunk N before chunk 0 lexicographically. Because Pebble Bloom filters operate exclusively during forward prefix seeks (`SeekPrefixGE`), this guarantees that `SeekPrefixGE('c' + KeyHash)` lands directly on the newest active chunk in O(1) time without scanning historical chunks.

### 5.3 Lexicographical Sorting & Deduplication per Leaf (`internal/kvstore/writer.go:108-115`)
```go
slices.SortFunc(uniqueKeys, func(a, b [sha256.Size]byte) int {
    return bytes.Compare(a[:], b[:])
})
```
- **Mechanism**: In `KVIndexer.IndexMappedBatch`, search key hashes within each leaf are sorted via `bytes.Compare` and deduplicated via `slices.Compact`.
- **Invariant**: Guarantees deterministic mini-log sub-root generation, optimizes LSM SSTable sequential writes, and prevents duplicate relative index insertions in chunk records.

### 5.4 Terminal Batch Fsync Barrier (`internal/kvstore/writer.go:281-282`)
```go
syncOpt := pebble.NoSync
if targetSize > 0 && newKVSize == targetSize {
    syncOpt = pebble.Sync
}
```
- **Mechanism**: During multi-batch ingestion up to `targetSize`, intermediate batches use `pebble.NoSync`. Only the terminal batch reaching `targetSize` triggers a blocking `pebble.Sync`.
- **Invariant**: Ingestion throughput is maximized by avoiding intermediate fsyncs while ensuring that `m_kv_size` is fully durable before Output Log publishing begins.

### 5.5 Checkpoint Clamping (`internal/ingest/pipeline.go:121-135`)
- **Mechanism**: When an upstream Input Log checkpoint size is not an exact multiple of 256 (e.g. size 500), the final bundle is truncated to `min(256, targetSize - currIdx)` (244 leaves).
- **Invariant**: Processing must halt at the exact target boundary; leaves beyond `targetSize` must not be ingested or committed to storage.

### 5.6 SafeWatermark Bounded Tile Reaper (`internal/ingest/reaper.go:48-52`)
```text
SafeWatermark = min(m_kv_size, mptDurableSize)
```
- **Mechanism**: Cached tile files are pruned only if `(tileIdx + 1) * 256 <= SafeWatermark`.
- **Invariant**: Tiles in the window `[mptDurableSize .. m_kv_size)` must never be pruned, guaranteeing that Fast-Forward Tile Replay during dirty crash recovery can always read missing tiles from local disk without network egress.

---

## 6. Dead Design Branches & Unneeded Complexity Analysis

### 6.1 Backfill Mode: Coupling and Redundancy Assessment

A codebase-wide scan reveals that Backfill Mode exists in **exactly 6 Go source files and 3 test files**:

```text
vindex/v1/
├── vindex.go                                  # Config fields (65-66), Backfill() function (268-387)
├── vindex_test.go                             # TestBackfill_StandaloneIngestion_ThenStartEngine (287-453)
├── cmd/
│   └── vindexd/
│       ├── main.go                            # Flags -backfill, -backfill_checkpoint (70-71), dispatch (214-247)
│       └── main_test.go                       # TestBackfillExecution (52-168)
└── internal/
    ├── coordinator/
    │   ├── coordinator.go                     # Backfill() (390-589), constants (36-41), intervals (104-128)
    │   └── recovery_test.go                   # TestCoordinator_Backfill_* (971-1141)
    └── tree/
        └── publisher.go                       # PublishDirect() (156-222)
```

#### Where Backfill Mode Does NOT Exist (Decoupled Subsystems):
- `internal/ingest`: 0 references. `IngestionPipeline.StreamBatches` is shared identically.
- `internal/kvstore`: 0 references. `KVIndexer.IndexBatch` is shared identically.
- `internal/server`: 0 references. ReadServer has no knowledge of Backfill Mode.
- `cmd/sumdbindex`: 0 references. Does not expose `--backfill`. Uses `coord.SyncOnce(ctx)`.
- `cmd/mtcindex`: 0 references. Does not expose `--backfill`. Uses `coord.SyncOnce(ctx)`.
- `hammer/`: 0 references. Benchmarks exclusively test Normal Serving Mode (`pub.PublishBatch`).

#### Redundancy Arguments
1. **Unused by Production Demonstrators**: Neither `sumdbindex` nor `mtcindex` calls `coord.Backfill`. Both use `coord.SyncOnce` for bulk indexing.
2. **Normal Mode Achieves Headline Throughput**: In `docs/BENCHMARKS.md`, the headline ingestion rate of 240,467 leaves/sec on Go SumDB (54.3M leaves in 3m 46s) was achieved with `sumdbindex --oneshot`, which runs Normal Serving Mode (`SyncOnce`).
3. **Architectural Duplication**: `Coordinator.Backfill` duplicates batch channel streaming, pending batch aggregation, progress reporting, and checkpoint persistence from `SyncOnce`, differing only in calling `mptMgr.SetBatch` instead of accumulating modified sub-roots for `pub.PublishBatch`.
4. **Complexity Cost**: Requires maintaining `PublishDirect` in `publisher.go`, custom configuration fields in `vindex.Config`, custom CLI flags in `vindexd`, and dedicated unit tests.

### 6.2 Speculative Prefix-Trie & Subtree Preimage Indexing
- **Documentation Framing**: `docs/APPLICATIONS.md` §1.4 and `mapfn/README.md` §1.1 describe preserving canonical Claim Subject preimages across the guest-host boundary to enable future "prefix-trie and subtree indexing" (e.g. `*.example.com` or `github.com/org/*`).
- **Audit Assessment**: VIndex v1 implements strictly point lookups over 32-byte `KeyHash` values. No prefix-trie structures exist in `internal/tree` or `internal/kvstore`. This forward-looking design should be quarantined in Tier 3 (Optional / Future Considerations) to avoid confusing users about current capabilities.

### 6.3 Abstract Storage Engine Generalization
- **Documentation Framing**: `internal/kvstore/README.md` frames `IndexStore` as an engine-agnostic abstraction permitting drop-in replacement with SQLite, DuckDB, or cloud KV.
- **Audit Assessment**: The `IndexStore` interface is heavily specialized for Pebble idioms (prefix split comparers, inverted chunk encoding, Bloom filter constraints). No second storage engine exists. The abstraction adds value by decoupling storage from ingestion and serving, but claims of multi-database portability are speculative.

### 6.4 Legacy JSON Wire Protocols
- **Audit Assessment**: `client/client.go:63-69` maintains `LegacyLookupResponse` for pre-C2SP JSON responses. All active servers emit C2SP plain-text framing. The JSON path is dead legacy code.

---

## 7. Recommendation for R4 Specification Consolidation Structure

To eliminate specification drift and establish clear boundaries between load-bearing guarantees and optional features, all design documents across `vindex/v1/docs/` and `vindex/v1/internal/*/README.md` must be restructured into a uniform three-tier hierarchy:

### 7.1 Uniform Three-Tier Hierarchy Template

```markdown
# [Subsystem Name] Specification

## 1. Core Load-Bearing Invariants
Cryptographic commitments, crash safety guarantees, and ordering constraints
required for correctness. Violations cause data corruption, security failures,
or fatal node halts.

## 2. Verified Performance Optimizations
Mechanisms empirically proven to yield measurable throughput, latency, or
storage efficiency gains. Altering these affects performance but not correctness.

## 3. Optional Considerations & Speculative Branches
Ecosystem-specific personalities, speculative future designs, and deferred
features quarantined from core architecture.

## 4. Retired Ideas & Alternatives Considered
Archived record of designs, mechanisms, or modes evaluated and set aside,
preserving engineering rationale without polluting active operational documentation.
```

### 7.2 Mandatory Historical Preservation Policy for Backfill Mode
Per explicit project requirements, if Backfill Mode is eliminated from the codebase during Milestone M3, **it must NOT be expunged from the project documentation history**. Instead, it must be permanently documented under a dedicated **"Retired Ideas & Alternatives Considered"** section in `docs/ARCHITECTURE.md` and `internal/coordinator/README.md`.

This archived record must document:
1. **Original Hypothesis & Motivation**: The theoretical concern that running `mpt.Predict` across tens of millions of historical leaves would cause excessive heap memory bloat and witness roundtrip latency during genesis bulk sync.
2. **Implemented Mechanism**: The direct in-memory MPT mutation pathway (`mptMgr.SetBatch`), intermediate snapshotting/syncing (`backfillSnapInterval`, `backfillSyncInterval`), and post-catchup commitment (`pub.PublishDirect`).
3. **Empirical Evaluation Findings**: Documenting that Normal Serving Mode (`SyncOnce`) achieved identical high-throughput bulk catch-up (240,467 leaves/sec on SumDB) using standard batching, rendering the separate mode functionally redundant.
4. **Rationale for Retirement**: Removal of code bifurcation, elimination of unneeded CLI flags and tests, and reduction of architectural attack surface.

### 7.3 Subsystem-by-Subsystem Restructuring Roadmap

#### A. `docs/ARCHITECTURE.md`
- **Tier 1 (Invariants)**:
  - Universal Crash Invariant (`m_kv_size >= Output_Size`).
  - Synchronous Commit Barrier (`pebble.Sync` prior to Output Log append).
  - Watermark Inequality Chain (`Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= MPT_Durable_Size`).
  - Inductive Backward Verification Protocol (Page 1 anchor + backward traversal).
  - Fatal panic on MPT root prediction divergence.
- **Tier 2 (Optimizations)**:
  - Zero-WAL direct inverted chunk commits.
  - Bundled WASM execution (`map_bundle`, 256 leaves/call).
  - Host SIMD hardware SHA-256 (SHA-NI / ARMv8 Crypto).
  - Bitwise inverted chunk keys (`'c' + KeyHash + ^chunkNum`) for O(1) Bloom filter seeks.
  - 16-bit relative index offsets within 64K chunks.
  - Split-locking (`writeMu` vs `treeMu`) for sub-5ms write critical sections.
  - Two-generational active chunk caching.
- **Tier 3 (Optional / Speculative)**:
  - Catch-Up / Backfill Mode evaluation and status.
  - Forward-compatibility prefix-trie search.
  - Pluggable adaptive HTTP transport.

#### B. `docs/BENCHMARKS.md`
- **Tier 1 (Methodology & Baseline Invariants)**:
  - Closed-loop dual-process benchmark topology.
  - Cryptographic verification during read benchmarks.
- **Tier 2 (Verified Empirical Results)**:
  - Zero-WAL vs. WAL comparative results (+24.7% throughput, ~99% P99 tail reduction).
  - Bundled WASM FFI overhead reduction (< 1% CPU).
  - Host hardware SIMD crypto performance.
  - Empirical Backfill Mode vs. Normal Mode benchmark evaluation.
- **Tier 3 (Hardware Scenarios & Scaling Models)**:
  - Cloud disk (EBS / Persistent Disk) vs NVMe profiles.
  - Distributed witness network latency simulations.

#### C. `docs/APPLICATIONS.md`
- **Tier 1 (Claimant Model Invariants)**:
  - Unambiguous canonical preimage deterministic agreement.
  - 1-to-1 vs. 1-to-N identity mapping rules.
- **Tier 2 (Ecosystem Performance Profiles)**:
  - Go SumDB byte scanner optimization.
  - CT domain fanout batch compaction.
  - MTC certificate pruning lifecycle.
- **Tier 3 (Future Applications & Ecosystems)**:
  - Sigstore dual-claim mapping.
  - Sigsum submitter key mapping.
  - Prefix-trie subdomain and path matching.

#### D. `internal/ingest/README.md`
- **Tier 1 (Invariants)**:
  - Strictly monotonic ascending batch delivery via min-heap resequencer.
  - Checkpoint clamping at exact unaligned target sizes.
  - `TileReaper` preservation of uncommitted tiles: `SafeWatermark = min(m_kv_size, mptDurableSize)`.
  - Hermetic sandboxed execution (zero host I/O, zero network, deterministic clocks).
- **Tier 2 (Optimizations)**:
  - Native 256-leaf entry bundling.
  - Bundled WASM execution (`map_bundle`).
  - Host SIMD hardware SHA-256.
  - In-memory key sorting and deduplication.
- **Tier 3 (Optional / Config)**:
  - Custom bundle size configuration.
  - Alternative guest runtime engines.

#### E. `internal/kvstore/README.md`
- **Tier 1 (Invariants)**:
  - Inverted chunk key structure (`'c' + KeyHash + ^chunkNum`).
  - RFC 6962 delimitless chunk schema with compact ranges.
  - Synchronous write persistence (`pebble.Sync`) on terminal batches.
  - Point-in-time sub-root reconstruction (`GetSubRoot`) ignoring uncommitted chunks.
- **Tier 2 (Optimizations)**:
  - Pebble 33-byte prefix extractor with 10-bit Bloom filter.
  - 16-bit relative index encoding.
  - Two-generational active chunk cache (32,768 entries).
  - Active chunk first placement avoiding LSM scan penalties.
- **Tier 3 (Optional / Abstraction)**:
  - Pluggable storage engine abstraction (`IndexStore`).

#### F. `internal/tree/README.md`
- **Tier 1 (Invariants)**:
  - State commitment schema (`hex(MapRoot) + "\n" + rawInputLogCP`).
  - Lock-free MPT root prediction (`mpt.Predict`).
  - Fatal panic on root prediction divergence.
  - Semantic MPT versioning bound to Input Log size (`mpt.Snap(inputLogSize)`).
  - Split-locking (`writeMu` vs `treeMu`) read isolation.
- **Tier 2 (Optimizations)**:
  - Binary Sparse MPT in `mmap` via `torchwood/mpt` (zero Go GC overhead).
  - Sub-5ms `treeMu` write critical section.
  - Lock-free reader lookup (`treeMu.RLock`).
- **Tier 3 (Optional / Modes)**:
  - `PublishDirect` (Backfill Mode publishing) if retained.
  - Hybrid sync triggers (time, leaf count, idle).

#### G. `internal/coordinator/README.md`
- **Tier 1 (Invariants)**:
  - 3-Phase Zero-WAL recovery sequence.
  - Phase 1 Instant Warm Start (< 5ms) equality condition.
  - Phase 2 Fast-Forward Tile Replay (< 500ms) with zero storage mutations.
  - Universal Crash Invariant enforcement (`m_kv_size >= Output_Size`).
  - Moving-goalpost prevention (`m_target_checkpoint`).
- **Tier 2 (Optimizations)**:
  - Commit batch aggregation (`DefaultCommitBatchSize = 4096`).
  - Tile cache pre-warming during replay.
- **Tier 3 (Optional / Modes)**:
  - Backfill Mode lifecycle and CLI flags if retained.

#### H. `internal/server/README.md`
- **Tier 1 (Invariants)**:
  - C2SP multi-section wire format compliance.
  - Read isolation: snapshotting `ServingState` and MPT proof under `treeMu.RLock()`.
  - Inductive backward pagination continuity semantics.
- **Tier 2 (Optimizations)**:
  - Zero-alloc stream formatting.
  - Limit clamping (`1 <= limit <= 1000`, default 100).
- **Tier 3 (Optional / Extras)**:
  - Embedded single-page HTML UI (`/`, `/index.html`).
  - Prometheus metrics exporter (`/metrics`).

---

## 8. Verification & Traceability Matrix

Every finding in this report is independently verifiable in the repository using the exact line references below:

| Finding | File Path | Line References | Verification Command |
| :--- | :--- | :--- | :--- |
| Prediction Mismatch Panic | `vindex/v1/internal/tree/publisher.go` | Lines 134-137 | `view_file` |
| Bitwise Inverted Chunk Key | `vindex/v1/internal/kvstore/chunk.go` | Lines 25-45 | `view_file` |
| Lexicographical Key Sorting | `vindex/v1/internal/kvstore/writer.go` | Lines 108-115 | `view_file` |
| Terminal Batch Fsync Barrier | `vindex/v1/internal/kvstore/writer.go` | Lines 281-282 | `view_file` |
| Phase 1 & 2 Crash Recovery | `vindex/v1/internal/coordinator/coordinator.go` | Lines 161-331 | `view_file` |
| Moving-Goalpost Freezing | `vindex/v1/internal/coordinator/coordinator.go` | Lines 419, 608 | `view_file` |
| Normal Mode `SyncOnce` Loop | `vindex/v1/internal/coordinator/coordinator.go` | Lines 593-712 | `view_file` |
| Backfill Mode Implementation | `vindex/v1/internal/coordinator/coordinator.go` | Lines 390-589 | `view_file` |
| Backfill CLI Flags in `vindexd` | `vindex/v1/cmd/vindexd/main.go` | Lines 70-71, 214-247 | `view_file` |
| `sumdbindex` Uses `SyncOnce` | `vindex/v1/cmd/sumdbindex/main.go` | Lines 62, 206-212 | `view_file` |
| `mtcindex` Uses `SyncOnce` | `vindex/v1/cmd/mtcindex/main.go` | Lines 65, 228-234 | `view_file` |
| MPT Manager Name & Versioning | `vindex/v1/internal/tree/mpt.go` | Lines 31, 275-289 | `view_file` |
| PublishDirect Backfill Path | `vindex/v1/internal/tree/publisher.go` | Lines 156-222 | `view_file` |
| Stale Metadata Signatures | `vindex/v1/internal/kvstore/types.go` | Lines 69-70 | `view_file` |
| Client Verifier Location | `vindex/v1/client/client.go` | Lines 95-120 | `view_file` |
| Embedded Server Web UI | `vindex/v1/internal/server/server.go` | Lines 32-34, 81-84 | `view_file` |
| Headline Benchmark Claims | `vindex/v1/docs/BENCHMARKS.md` | Lines 13-23, 199-217 | `view_file` |
| Catch-Up Mode Specification | `vindex/v1/docs/ARCHITECTURE.md` | Lines 124-156 | `view_file` |
