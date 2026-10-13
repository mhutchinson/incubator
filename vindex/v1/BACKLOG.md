# VIndex v1 Engineering Backlog

This backlog consolidates open architectural refinements, documentation alignment tasks, implementation bugs, and upstream library investigations for **VIndex v1**.

It is organized into three categories:
1. [**Architectural & Documentation Issues**](#1-architectural--documentation-issues)
2. [**VIndex Code Issues (Implementation Bugs)**](#2-vindex-code-issues-implementation-bugs)
3. [**Upstream Library Issues to Raise / Investigate**](#3-upstream-library-issues-to-raise--investigate)

---

## 1. Architectural & Documentation Issues

### 1.1 Protocol & Read-Path Architecture Refinements

- [ ] **1.1.1 Zero-MPT Continuation & The "Map of Logs" API (`before != nil`)**
  - **Affected Components**: [`internal/server`](internal/server/README.md), [`client`](client/README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
  - **Current Behavior**: Every query to `/vindex/v1/lookup/{keyhash}` acquires an MPT read lock (`mptMgr.RLock()`), retrieves serving state, and formats an Output Log checkpoint, Output Log leaf, Output Log inclusion proof, and MPT inclusion/non-inclusion proof alongside returned indices.
  - **Problem**: VIndex is a **Map of Logs** where `Map` commits to `KeyHash -> MiniLogRoot` at tip and `MiniLog` is an append-only RFC 6962 Merkle log of occurrence indices. On Page 1 (`before == nil`), the client authenticates `MiniLogRoot` against `MapRoot` via the MPT proof and computes `expectedMiniLogRoot` for the remaining prefix from `prefix-compact-range-v1`. On Page 2+ (`before = next_before`), the client verifies continuity purely against the previous page's `expectedMiniLogRoot`:
    ```text
    NewRange(Page_N.PrefixCR).Append(Page_N.Indices).GetRootHash() == Page_(N-1).expectedMiniLogRoot
    ```
    Continuation pages never need the MPT or Output Log, and a mid-log mini-log root cannot match the tip `MapRoot`. Returning MPT/Output Log proofs on `before != nil` wastes lock acquisitions, trie traversal CPU, and wire bandwidth.
  - **Candidate Directions**:
    - *Option A (Smart Tip with Zero-MPT Continuations)*: Keep combined proof + Page 1 data in 1 RTT when `before == nil`; when `before != nil`, skip `mptMgr.RLock()` and `ProveLocked()`, query Pebble directly, and omit Output Log / MPT sections.
    - *Option B (Pure 2-Phase Split `/proof` vs. `/entries`)*: Expose `GET /vindex/v1/proof/{keyhash}` (MPT only) and `GET /vindex/v1/entries/{keyhash}?before=X` (Pebble only, requiring `before=InputLogSize` from the proof to prevent write-skew races).

- [ ] **1.1.2 Chunk-Aligned Paging (Eliminating Dynamic Read-Path Merkle Hashing)**
  - **Affected Components**: [`internal/kvstore`](internal/kvstore/README.md), [`internal/server`](internal/server/README.md)
  - **Current Behavior**: When an inverted chunk (`^chunkNum`) contains more matching indices than the requested `limit`, `internal/kvstore/reader.go` splits the chunk and loops over `rec.RelativeIndices[:splitIdx]`, computing on-the-fly SHA-256 leaf and interior node hashes (`cr.Append(LeafHash(b[:]))`) to synthesize a mid-chunk `prefix-compact-range-v1`. For a hot chunk with 5,000 occurrences and `limit=100`, the server performs 4,900 SHA-256 computations per HTTP request.
  - **Proposed Refinement**: Treat the client's `limit` parameter as an advisory hint and align page boundaries to whole inverted chunks. Each stored chunk already contains precomputed `rec.CompactHashes` and `rec.CoveredSize` committing to all prior chunks. Returning whole chunks allows `CompactHashes` and `CoveredSize` to be copied in O(1) time with **zero dynamic SHA-256 hashing on the read path** (worst-case 65,536 `uint16` offsets is ~100 KB gzipped).

- [ ] **1.1.3 Bounded Chunk Visitation for Sparse Keys (`maxChunksPerRequest` P99 Guardrail)**
  - **Affected Components**: [`internal/kvstore`](internal/kvstore/README.md), [`internal/server`](internal/server/README.md)
  - **Current Behavior**: `DB.Lookup` seeks to `maxChunkNum` and iterates backwards until `totalMatched == limit` or the key prefix is exhausted.
  - **Problem**: If a key appears once every 65,536 leaves across a 1B-leaf log (~15,000 chunks) and a client requests `limit=1000`, a single HTTP request executes 1,000 random SSTable seeks and unmarshals across cold disk levels, spiking P99 latency.
  - **Proposed Refinement**: Enforce a dual termination condition in the Pebble reader loop: `totalMatched >= limitHint` **OR** `chunksVisited >= maxChunksPerRequest` (e.g., 8–16 chunks). Because compact ranges authenticate arbitrarily small pages, halting early and returning the oldest visited chunk's `CompactHashes` with `next_before` bounds worst-case server I/O per HTTP request while preserving 100% verifiability.

- [ ] **1.1.4 Decoupled & Asynchronous Serving Startup (`vindexd`)**
  - **Affected Components**: [`cmd/vindexd`](cmd/vindexd/main.go), [`internal/coordinator`](internal/coordinator/README.md), [`internal/server`](internal/server/README.md)
  - **Current Behavior**: `vindexd/main.go` synchronously blocks on `tree.Open(*mptDir)` before binding `:8080`, causing `/healthz`, `/readyz`, and `/checkpoint` to fail with `Connection refused` during large MPT journal replays.
  - **Proposed Refinement**: Bind `:8080` and start the HTTP server immediately so `/healthz` returns `200 OK` and `/readyz` + `/vindex/v1/lookup/*` return `503 Service Unavailable` (`Retry-After: 30`, `"status": "mpt_initializing"`) while `tree.Open()` and `coord.Recover(ctx)` run asynchronously in the background.

---

### 1.2 Subcomponent Splitting & Package Decoupling

- [ ] **1.2.1 Split `internal/tree` into Pure State Trie (`internal/mpt`) and Output Log Publisher (`internal/publish`)**
  - **Problem**: `internal/tree` currently bundles the pure Sparse Merkle Patricia Trie wrapper (`mpt.go`) with the stateful `OutputPublisher` and `POSIXOutputLog` (`publisher.go`, `posix.go`, `outputlog.go`). Because `OutputPublisher` imports `internal/kvstore` (`cockroachdb/pebble`) and `tessera`, any package importing `internal/tree` for stateless MPT proof verification (`tree.Verify`)—including [`client/client.go`](client/client.go)—transitively drags in `pebble` and `tessera`.
  - **Action**: Split `internal/tree` into a pure trie package (`internal/mpt`) and a stateful publication package (`internal/publish`), severing `client`'s transitive dependency on `pebble`.

- [ ] **1.2.2 Split `internal/ingest` into Upstream Tile Ingestion (`internal/ingest`) and Host WASM Sandbox (`mapfn/host` or `internal/wasmhost`)**
  - **Problem**: `internal/ingest` (2,648 non-test lines) combines HTTP/file tile fetching and disk caching (`fetcher.go`, `cache.go`, `reaper.go`) with the 923-line Wazero host sandbox and `map_bundle` slab ABI unpacker (`wasm.go`). Tools like `cmd/vindex-wasm` that only test `.wasm` plugins must import the entire network tile-fetching stack.
  - **Action**: Extract `wasm.go` into `mapfn/host` (or `internal/wasmhost`) alongside `mapfn/sdk` so both sides of the `input_buffer` / `map_bundle` binary slab contract live together.

- [ ] **1.2.3 Extract Shared C2SP Wire Format & Proof Primitives (`wire/` or `internal/wire`)**
  - **Problem**: C2SP multi-section response serialization (`internal/server/format.go`) and parsing (`client/client.go`), Output Log leaf formatting/parsing (`internal/tree/outputlog.go`), and RFC 6962 mini-log leaf/interior hashing (`internal/kvstore/compact.go` vs `client/client.go`) are duplicated or scattered across 4 packages.
  - **Action**: Extract a zero-dependency wire/proof package shared by `server`, `client`, and `auditor`.

- [ ] **1.2.4 Isolate Ecosystem-Specific `internal/mtc` Leaf Mapping Out of Core Engine Internals**
  - **Problem**: [`internal/mtc/mtc.go`](internal/mtc/mtc.go) combines MTC checkpoint signature verification (`MTCVerifier`) with ASN.1 DER certificate domain mapping (`MTCLeafMapper`, which imports `internal/ingest` and duplicates `mapfn/examples/mtc`).
  - **Action**: Move `MTCLeafMapper` to the MTC personality (`cmd/mtcindex` / `mapfn/examples/mtc`) and keep only checkpoint signature verification in `internal/verifier`.

---

### 1.3 Design Document Alignment & Hygiene

- [ ] **1.3.1 Deduplicate Auditor Section in `docs/ARCHITECTURE.md`**
  - [`docs/ARCHITECTURE.md §3`](docs/ARCHITECTURE.md) duplicates the threat vector matrix, mismatch halt sequence, and 5-step operational runbook from [`internal/auditor/README.md §2.3–2.7`](internal/auditor/README.md) almost verbatim. Condense `ARCHITECTURE.md §3` to a high-level architectural summary and link to `internal/auditor/README.md`.

- [ ] **1.3.2 Qualify Cold-Start Recovery SLO in `ARCHITECTURE.md`, `coordinator/README.md`, and `tree/README.md`**
  - [`docs/ARCHITECTURE.md §2.2`](docs/ARCHITECTURE.md) and [`internal/coordinator/README.md §1.3 & §2.5`](internal/coordinator/README.md) claim `< 5ms` warm start and `< 500ms` dirty recovery without noting that `tree.Open()` currently replays uncompacted `torchwood/mpt` journal frames before `coord.Recover()` runs (see [3.1](#31-filippoiotorchwoodmpt--redundant-synchronous-disk-writes-on-journal-replay-22m-pwrite-syscalls)). Document this constraint and link to [`docs/BENCHMARKS.md §5`](docs/BENCHMARKS.md#5-post-run-empirical-evaluation--cold-startup-investigation-2026-09-22).

- [ ] **1.3.3 Standardize Checkpoint Field Names Across All Design Docs**
  - [`docs/ARCHITECTURE.md §0.2`](docs/ARCHITECTURE.md) uses `Output_CP.Leaf.InputLogSize` and `Serving_CP.InputLogSize`, whereas [`coordinator/README.md`](internal/coordinator/README.md), [`kvstore/README.md`](internal/kvstore/README.md), [`tree/README.md`](internal/tree/README.md), [`server/README.md`](internal/server/README.md), and `ARCHITECTURE.md §3.3` use `Output_CP.InputSize` and `Serving_CP.InputSize`. Standardize on one naming convention across all docs.

- [ ] **1.3.4 Clarify Tip vs. Continuation Verification in `client/README.md §2.2`**
  - Explicitly distinguish Step 3a (Tip query `before == nil`: verify `SubRoot` against `MapRoot` via MPT proof) from Step 3b (Continuation query `before != nil`: verify reconstructed page compact range root against the prior page's `prefix-compact-range-v1` root).

- [ ] **1.3.5 Document `internal/budget` and `internal/verifier` in Architecture & Repository Map**
  - Add [`internal/budget`](internal/budget/budget.go) (resource budget resolution across RAM/CPUs) and [`internal/verifier`](internal/verifier/verifier.go) to [`README.md §8`](README.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

- [ ] **1.3.6 Clean Up Legacy Route and Internal Symbol References in `hammer/README.md`**
  - Update `GET /vindex/lookup/{keyhash}` in [`hammer/README.md §2.4`](hammer/README.md) to `GET /vindex/v1/lookup/{keyhash}`, and replace internal mutex/code snippets (`treeMu.Lock()`) with prose contract descriptions.

- [ ] **1.3.7 Add Executable Verification Gates and Design Logs to Type A/B Specs**
  - Add explicit exit-0 CLI verification gate commands (`go test -race ./...`) and a bottom `Design Log` section to the canonical Type A and Type B design documents.

---

## 2. VIndex Code Issues (Implementation Bugs)

### 2.1 Ingestion & Tile Cache (`internal/ingest/`)

- [ ] **2.1.1 Missing Merkle Tree Root Verification on Downloaded Tiles**
  - **Location**: [`internal/ingest/fetcher.go:395-531`](internal/ingest/fetcher.go#L395-L531) (`TiledFetcher.FetchTiles`), [`fetcher.go:334-393`](internal/ingest/fetcher.go#L334-L393) (`TiledFetcher.Leaf`), [`fetcher.go:688-708`](internal/ingest/fetcher.go#L688-L708) (`verifyBundleWithTile`), [`fetcher.go:657-684`](internal/ingest/fetcher.go#L657-L684) (`parseAndVerifyStaticCTBundle`)
  - **Bug**: `FetchTiles` and `Leaf` only verify that entry bundle leaf hashes match the 32-byte entries in the downloaded Level-0 hash tile (`tile/0/...`). Neither `TiledFetcher` nor any caller fetches upper tree tiles (`level > 0`) or verifies an inclusion proof chaining the Level-0 tile to the signed `Checkpoint.Hash`. A MITM or malicious mirror serving a mutually consistent forged `(entryBundle, level0Tile)` pair passes ingestion undetected.
  - **Fix**: Verify Level-0 tile hashes against the target `Checkpoint.Hash` (e.g., via `tessera/client.ProofBuilder` or parent tile chain verification) before admitting bundles into the pipeline.

- [ ] **2.1.2 Truncated Static-CT Tile Bypasses Leaf Hash Verification**
  - **Location**: [`internal/ingest/fetcher.go:667`](internal/ingest/fetcher.go#L667) (`parseAndVerifyStaticCTBundle`)
  - **Bug**: Leaf hash comparison is guarded by `if len(treeTile) >= (idx+1)*32`. If the downloaded Static-CT Level-0 tile is truncated or empty, hash verification is silently skipped for all remaining leaves in the bundle.
  - **Fix**: Reject the bundle with an error if `len(treeTile) != len(leaves)*32` (matching `verifyBundleWithTile` at [`fetcher.go:689-692`](internal/ingest/fetcher.go#L689-L692)).

- [ ] **2.1.3 Optional Checkpoint Signature Verification Bypass**
  - **Location**: [`internal/ingest/fetcher.go:301-316`](internal/ingest/fetcher.go#L301-L316), [`fetcher.go:710-729`](internal/ingest/fetcher.go#L710-L729) (`TiledFetcher.Checkpoint`), [`cmd/vindexd/main.go:296-305`](cmd/vindexd/main.go#L296-L305)
  - **Bug**: When `--input_log_pubkey` is omitted (`f.verifier == nil`), `TiledFetcher.Checkpoint` silently falls back to `parseCheckpointHeaderOnly(rawCP)`, accepting unverified checkpoints without validating any origin signature.
  - **Fix**: Require a non-nil `note.Verifier` for upstream checkpoint ingestion (or require an explicit `--insecure_skip_verify` flag for local testing).

- [ ] **2.1.4 Fire-and-Forget Asynchronous Tile Caching**
  - **Location**: [`internal/ingest/pipeline.go:196-216`](internal/ingest/pipeline.go#L196-L216), [`pipeline.go:279-288`](internal/ingest/pipeline.go#L279-L288) (`IngestionPipeline.StreamBatches`)
  - **Bug**: Downloaded bundles are sent directly in-memory to `leafBundleChan` for WASM mapping while queued asynchronously to `cacheBundleChan`, where background workers ignore disk write errors (`_ = p.cache.PutBundle(b)` at `pipeline.go:205`). If a crash occurs after Pebble commit or if disk writes fail silently, Phase 2 crash recovery cannot replay from local disk.
  - **Fix**: Check and surface `PutBundle` errors, and ensure tiles required for recovery are durably written before advancing `KV_CP` / `Output_CP`.

- [ ] **2.1.5 Premature In-Memory Partial-Bundle Pruning in `ManagedTileCache`**
  - **Location**: [`internal/ingest/cache.go:179-185`](internal/ingest/cache.go#L179-L185) (`ManagedTileCache.PruneBefore`)
  - **Bug**: In-memory cache entries are evicted when `b.StartLeafIdx + uint64(len(b.Leaves)) <= watermark`, which evicts a partial bundle (e.g., 100 leaves) as soon as `watermark >= StartLeafIdx + 100`, even though subsequent syncs for `StartLeafIdx + 100 .. StartLeafIdx + 255` still require that bundle.
  - **Fix**: Align in-memory pruning with disk pruning (`(bIdx + 1) * c.bundleSz <= watermark` at [`cache.go:213-216`](internal/ingest/cache.go#L213-L216)).

---

### 2.2 Sandboxed Mapping & Guest SDK (`mapfn/` & `internal/ingest/wasm.go`)

- [ ] **2.2.1 Silent Key Loss on 4 MB Slab Overflow or Dynamically Allocated Input Bundle**
  - **Location**: [`mapfn/sdk/arena.go:36-46`](mapfn/sdk/arena.go#L36-L46) (`emitKey`), [`arena.go:63-76`](mapfn/sdk/arena.go#L63-L76) (`GetInputSlice`), [`arena.go:121-167`](mapfn/sdk/arena.go#L121-L167) (`ExecuteBundle`), [`internal/ingest/wasm.go:257`](internal/ingest/wasm.go#L257), [`wasm.go:280-294`](internal/ingest/wasm.go#L280-L294), [`wasm.go:311-322`](internal/ingest/wasm.go#L311-L322) (`wasmInstance.executeBundle`)
  - **Bug**:
    1. When emitted preimages for a 256-leaf bundle exceed the static 4 MB `outputBuf`, `emitKey` sets `emitOverflow = true` and `ExecuteBundle` returns `(0, 0)`.
    2. When an input bundle exceeds 4 MB, `wasm.go:257` allocates a dynamic buffer via `allocate`/`malloc` outside `inputBuf`, causing `GetInputSlice` (`arena.go:63-76`) to return `nil` and `ExecuteBundle` to return `(0, 0)`.
    3. In `wasm.go:317`, `if outLen == 0` is treated as a valid empty key set (`return make([][]MappedEntry, len(leaves)), nil`), silently dropping 100% of keys for the 256-leaf bundle instead of raising a fatal error.
  - **Fix**: Use distinct non-zero error sentinel return codes (or trap/panic in the guest) on input/output slab overflow, and treat `(outPtr == 0, outLen == 0)` in `wasm.go` as a fatal execution error (since a valid 0-key response still has a `4 + 4*LeafCount` header where `outLen >= 8`).

- [ ] **2.2.2 WASM Runtime Traps Leak Pool Slots / Respawn Instead of Triggering Fatal Halt**
  - **Location**: [`internal/ingest/wasm.go:841-860`](internal/ingest/wasm.go#L841-L860), [`wasm.go:895-899`](internal/ingest/wasm.go#L895-L899) (`WASMRunner.MapBundle`, `WASMRunner.Close`), [`wasm.go:558-574`](internal/ingest/wasm.go#L558-L574) (`WASMHost.MapLeaf`), [`wasm.go:637-653`](internal/ingest/wasm.go#L637-L653) (`WASMHost.MapBundle`), [`internal/coordinator/coordinator.go:1027-1044`](internal/coordinator/coordinator.go#L1027-L1044) (`Coordinator.Run`), [`vindex.go:302-304`](vindex.go#L302-L304), [`vindex.go:328-330`](vindex.go#L328-L330) (`Engine.Start`)
  - **Bug**: When a WASM guest traps or faults during pipeline ingestion (`WASMRunner.MapBundle`), `r.hadErr` is set to `true` and `WASMRunner.Close` destroys the faulted instance without returning a replacement to `h.pool` (permanently depleting a worker slot from the pool on each fault), while direct `WASMHost.MapLeaf`/`MapBundle` calls respawn a fresh replacement instance. Above the pipeline, `Coordinator.Run` and `Engine.Start` log a warning and retry on the next tick instead of halting the daemon.
  - **Fix**: Propagate a fatal/unrecoverable error sentinel on WASM execution traps and terminate the daemon to uphold the deterministic `HALT` invariant (and ensure pool capacity is never silently leaked).

- [ ] **2.2.3 Ecosystem WASM Plugin Bugs (`ct`, `mtc`, `sumdb`)**
  - **Location**: [`mapfn/examples/ct/main.go`](mapfn/examples/ct/main.go), [`mapfn/examples/mtc/main.go`](mapfn/examples/mtc/main.go), [`mapfn/examples/sumdb/main.go`](mapfn/examples/sumdb/main.go)
  - **Bugs**:
    1. **Missing IDNA Punycode Conversion (`ct/main.go:102-111`, `mtc/main.go:221-241`)**: Neither plugin converts IDNs to Punycode (`idna.Lookup.ToASCII`); non-ASCII labels are emitted as raw bytes.
    2. **MTC Missing Subject Common Name, Missing Trailing-Dot Strip, & Silent Truncation (`mtc/main.go:110-171, 186-187, 221-254`)**: `extractDNSNamesFromDER` only extracts SAN `dNSName` (`2.5.29.17`), ignoring Subject CN (`2.5.4.3`); `MapMTCLeaf` does not strip trailing dots (`.`); and domains beyond `leafSpans` (`64`) or `leafStorage` (`2048` bytes) per leaf are silently dropped.
    3. **CT Plaintext Fallback (`ct/main.go:377-386`)**: When ASN.1 parsing extracts 0 domains, `ct/main.go` treats the raw binary leaf as a newline-delimited list of plaintext domain strings.
    4. **SumDB Missing `module.EscapePath` (`sumdb/main.go:58, 78-91`)**: Emits the raw `modPath` token (`line[:modEnd]`) directly without canonicalizing or validating via `golang.org/x/mod/module.EscapePath` (which encodes uppercase characters as `!` followed by lowercase).
  - **Fix**: Implement `idna.Lookup.ToASCII` (or reject non-ASCII per RFC 5280), add Subject CN extraction and trailing-dot stripping and remove silent span truncation in `mtc`, remove the plaintext fallback on binary CT leaves, and enforce `module.EscapePath` canonicalization in `sumdb`.

- [ ] **2.2.4 `cmd/vindex-wasm` Subcommands Only Test Single-Leaf `MapLeaf` Instead of 256-Leaf `MapBundle`**
  - **Location**: [`cmd/vindex-wasm/bench_cmd.go:76, 110`](cmd/vindex-wasm/bench_cmd.go#L76), [`cmd/vindex-wasm/determinism_cmd.go:75, 109`](cmd/vindex-wasm/determinism_cmd.go#L75), [`cmd/vindex-wasm/test_cmd.go:105`](cmd/vindex-wasm/test_cmd.go#L105), [`cmd/vindex-wasm/inspect_cmd.go:63, 72-79, 103`](cmd/vindex-wasm/inspect_cmd.go#L63)
  - **Bug**: `bench`, `determinism`, and `test` call `host.MapLeaf` (1-leaf bundle) rather than `host.MapBundle` (256-leaf bundle), and `inspect` fails if a `map_bundle` module omits legacy `allocate`/`malloc` exports.
  - **Fix**: Update `bench`, `determinism`, and `test` to exercise 256-leaf `MapBundle` calls, and accept `input_buffer` + `map_bundle` in `inspect`.

---

### 2.3 Inverted Storage Engine (`internal/kvstore/`)

- [ ] **2.3.1 Phantom Empty Chunk 0 Written for Every Key First Seen at `leafIdx >= 65536`**
  - **Location**: [`internal/kvstore/writer.go:484-504`](internal/kvstore/writer.go#L484-L504) (`KVIndexer.processKey`)
  - **Bug**: When a key is not present in cache or Pebble, `currChunkNum` is initialized to `0` with an empty `ChunkRecord`. Immediately afterward in the `for _, leafIdx := range unpersisted` loop (`writer.go:496-504`), if `targetChunkNum > currChunkNum` (`leafIdx >= 65536`), it marshals and writes an empty chunk `0` record (`'c' + keyHash + ^uint64(0)`) to Pebble before setting `currChunkNum = targetChunkNum`. This doubles the KV record count for every sparse key first appearing after leaf 65,535.
  - **Fix**: When initializing a brand-new key (`!iter.SeekPrefixGE`), initialize `currChunkNum = unpersisted[0] / idx.chunkSize` (or skip sealing `rec` when `len(rec.RelativeIndices) == 0`).

- [ ] **2.3.2 Prefix Bloom Filter Bypassed on `DB.Lookup` via `SeekGE`**
  - **Location**: [`internal/kvstore/reader.go:102`](internal/kvstore/reader.go#L102) (`DB.Lookup`)
  - **Bug**: `DB.Lookup` calls `iter.SeekGE(seekKey)`. Because Pebble is configured with a 33-byte prefix split (`'c' + KeyHash` in `store.go:77-82`), Pebble constructs *prefix* Bloom filters, which are only consulted on `SeekPrefixGE`. Calling `SeekGE` bypasses the Bloom filter on every point lookup and forces SSTable disk reads for non-existent keys.
  - **Fix**: Replace `iter.SeekGE(seekKey)` with `iter.SeekPrefixGE(seekKey)` (or `iter.SeekPrefixGE(prefix)` followed by positioning at `seekKey` within the prefix).

- [ ] **2.3.3 `GetSubRoot` Scans All Historical Chunks and Re-Hashes from Leaf 0 in O(N)**
  - **Location**: [`internal/kvstore/writer.go:545-605`](internal/kvstore/writer.go#L545-L605) (`KVIndexer.getSubRootWithIter`)
  - **Bug**: `getSubRootWithIter` iterates over and unmarshals *every* historical chunk for `keyHash`, calls `slices.Reverse(chunks)` (`writer.go:568`) to order them from chunk 0 ascending, and loops from chunk 0 forward. Because chunk 0 populates `cr.CoveredSize > 0` via `cr.Append`, `if cr.CoveredSize == 0 && len(rec.CompactHashes) > 0` (`writer.go:581`) is false for all subsequent chunks. All precomputed `CompactHashes` are ignored, and 100% of historical occurrences are read and re-hashed from leaf 0.
  - **Fix**: Seek directly to the newest chunk with `cNum * idx.chunkSize < maxInputLogSize` using inverted key ordering, seed `cr` with that single chunk's `rec.CoveredSize` and `rec.CompactHashes`, and append only the entries in that chunk with `absIdx < maxInputLogSize` in O(1) chunk reads (matching `DB.Lookup` in [`reader.go:93-170`](internal/kvstore/reader.go#L93-L170)).

---

### 2.4 State Commitment (MPT & Publisher) (`internal/tree/`)

- [ ] **2.4.1 Missing MPT Disk `Persist()` (`tree.Sync()`) in `PublishBatch` and `Phase2` & Premature `PersistedSize()`**
  - **Location**: [`internal/tree/publisher.go:138-170`](internal/tree/publisher.go#L138-L170) (`OutputPublisher.PublishBatch`), [`internal/coordinator/coordinator.go:471`](internal/coordinator/coordinator.go#L471) (`Coordinator.Phase2`), [`internal/tree/mpt.go:70, 302-315, 368-389`](internal/tree/mpt.go#L70) (`Manager`)
  - **Bug**:
    1. Neither `PublishBatch` nor `Coordinator.Phase2` ever calls `mptMgr.Persist()` (`m.tree.Sync()`), so dirty MPT `mmap` pages are never explicitly `fsync`-ed to disk during normal serving or after Phase 2 recovery.
    2. `mptMgr.PersistedSize()` (`mpt.go:375-381`) returns `m.tree.Version()`, which advances as soon as `m.tree.Snap(version)` runs in memory—before `m.tree.Sync()` has flushed to disk. Consequently, `TileReaper` (`internal/ingest/reaper.go:72`) treats un-synced in-memory snapshots as durable on disk and prunes cached tiles prematurely.
    3. `tree.Open` (`mpt.go:70`) immediately calls `tree.Snap(-1)` on startup and `PersistedVersion()` (`mpt.go:370`) discards the `exact` boolean from `m.tree.Version()`, erasing dirty-crash detection (`exact == false`).
  - **Fix**: Track a dedicated `durableSize atomic.Uint64` on `tree.Manager` that only advances after `m.tree.Sync()` completes; trigger `mptMgr.Persist()` after `PublishBatch` and `Phase2`; and inspect `m.tree.Version()` `(version, exact)` in `tree.Open` *before* calling `Snap(-1)`.

- [ ] **2.4.2 Unwired Witness Client in `cmd/vindexd` and `vindex.New`**
  - **Location**: [`vindex.go:65-66, 197, 213`](vindex.go#L65-L66), [`cmd/vindexd/main.go:267, 273`](cmd/vindexd/main.go#L267)
  - **Bug**: `vindex.Config` defines `WitnessURLs` and `WitnessPubKeys`, but `vindex.New` ignores them and passes `nil` to `tree.NewOutputPublisher(db, mptMgr, outLog, nil)`. `cmd/vindexd/main.go` has no witness flags and also passes `nil`.
  - **Fix**: Wire witness configuration flags and pass configured `tessera.WitnessGroup` / `WitnessClient` to `NewPOSIXOutputLog` / `NewOutputPublisher`.

---

### 2.5 Coordinator & Top-Level Wiring (`internal/coordinator/`, `vindex.go`, `cmd/vindexd/`)

- [ ] **2.5.1 Phase 3 Recovery Advances `m_kv_size` Without Updating MPT/Output Log, Causing Duplicate Replay in `SyncOnce`**
  - **Location**: [`internal/coordinator/coordinator.go:236-238, 512-580`](internal/coordinator/coordinator.go#L512-L580) (`Coordinator.Phase3`), [`coordinator.go:613-680`](internal/coordinator/coordinator.go#L613-L680) (`Coordinator.SyncOnce`), [`cmd/vindexd/main.go:355-381`](cmd/vindexd/main.go#L355-L381)
  - **Bug**:
    1. `cmd/vindexd/main.go:357` starts the HTTP Read Server *before* `coord.Recover(ctx)` (`main.go:378`).
    2. Inside `Recover`, `Phase3` streams `[kvSize, targetCP.Size)`, commits chunks and `m_kv_size` to Pebble via `IndexMappedBatch`, **discards `res.ModifiedSubRoots`**, and never updates the MPT or calls `PublishBatch`.
    3. When `SyncOnce` runs next (`coordinator.go:614`), `startLogSize` is still `ServingState.InputLogSize` (`<= old kvSize < targetCP.Size`), forcing `SyncOnce` to re-stream and re-map the entire `[ServingState.InputLogSize, targetCP.Size)` range a second time.
  - **Fix**: Remove the redundant `Phase3` KV-only streaming loop (letting `SyncOnce` handle catch-up from `ServingState.InputLogSize` in a single pass after `Phase1`/`Phase2`), and open the Read Server after `Phase1`/`Phase2` completes.

- [ ] **2.5.2 Genesis Backfill Non-Durable `pebble.NoSync` Watermark Writes & Unupdated `lastCheckpointLeaf` on Cancellation**
  - **Location**: [`internal/coordinator/coordinator.go:750-782, 813-893`](internal/coordinator/coordinator.go#L750-L782) (`Coordinator.syncGenesisBackfill`), [`internal/kvstore/writer.go:336-352`](internal/kvstore/writer.go#L336-L352) (`IndexMappedBatchWithOptions`), [`cmd/vindexd/main.go:86, 368-370`](cmd/vindexd/main.go#L86)
  - **Bug**:
    1. During Genesis Backfill, `IndexMappedBatchWithOptions` writes `m_kv_size` inside `batch.Set` (`writer.go:336`) *before* the chunk-writing loop (`writer.go:341-351`) and commits every batch with `pebble.NoSync`, while `c.db.Sync()` (`d.db.Flush()`) is deferred to the asynchronous background flush worker. If the process crashes between `c.db.Sync()` calls, un-flushed memtable writes for `m_kv_size` and chunks are lost; furthermore, while the background worker runs `c.db.Sync()`, the foreground goroutine concurrently commits subsequent `pebble.NoSync` batches into the same memtable being flushed.
    2. When `streamAndIndex` exits with `streamErr != nil` (`coordinator.go:872-880`), `workerWg.Wait()` finishes any in-flight `currentJob` without updating `lastCheckpointLeaf = currentJob.watermark`.
    3. In `cmd/vindexd/main.go:86, 368`, `--backfill_max_pending_keys` defaults to `50000000`, so `if *backfillMaxPendingKeys > 0` is always true and unconditionally overwrites `resBudget.GenesisKeyBufferSize`.
  - **Fix**: Execute `c.db.Sync()` synchronously in `dispatchFlush` *before* handing the buffer off to the background MPT worker, guard `isFlagPassed("backfill_max_pending_keys")` in `main.go`, and update `lastCheckpointLeaf` after `workerWg.Wait()`.

- [ ] **2.5.3 Decentralized `TileReaper` Polling Instead of Coordinator-Governed Pruning**
  - **Location**: [`internal/coordinator/coordinator.go:144-151`](internal/coordinator/coordinator.go#L144-L151) (`Coordinator.SafeWatermark`), [`internal/ingest/reaper.go:40-133`](internal/ingest/reaper.go#L40-L133), [`cmd/vindexd/main.go:384-388`](cmd/vindexd/main.go#L384-L388), [`vindex.go:264, 337-343`](vindex.go#L264)
  - **Bug**: `Coordinator.SafeWatermark` has zero callers; `TileReaper` runs on an independent 60s ticker reading `m_kv_size` and `mptMgr.PersistedSize()` directly.
  - **Fix**: Have `Coordinator` govern `SafeWatermark` (or ensure `TileReaper` only reads the fsync-durable MPT watermark).

- [ ] **2.5.4 Top-Level `vindex.go` Duplicate Pipeline & Ephemeral `memoryOutputLog` Fallback**
  - **Location**: [`vindex.go:204-210, 240-258`](vindex.go#L204-L210) (`vindex.New`)
  - **Bug**:
    1. `vindex.New` constructs `e.pipeline` with `cfg.Workers` (`vindex.go:242`), which is never used; `coordinator.NewCoordinator` (`vindex.go:252`) constructs a second internal pipeline with `workers = 0` (`GOMAXPROCS - 1`), dropping `cfg.Workers`.
    2. When `cfg.OutputLogDir` is unset, `vindex.New` silently falls back to an in-memory `memoryOutputLog` even if `DBPath` and `MPTDir` are on disk; on restart, `outputLog.Size() == 0` while `m_kv_size > 0`, corrupting recovery state.
  - **Fix**: Pass `cfg.Workers` (or `pipeline`) into `Coordinator`, and reject mixing persistent `DBPath`/`MPTDir` with an ephemeral in-memory Output Log.

---

### 2.6 Read Serving & Client SDK (`internal/server/` & `client/`)

- [ ] **2.6.1 Unverified MPT Proof & SubRoot When Calling `Client.Lookup` / `Verifier.VerifyResponse` with `before != nil`**
  - **Location**: [`client/client.go:318-323`](client/client.go#L318-L323) (`Verifier.VerifyResponse`), [`client/client.go:475-507`](client/client.go#L475-L507) (`Client.Lookup`)
  - **Bug**: `VerifyResponse` only calls `tree.Verify(mapRoot, keyHash, computedMiniLogRoot, true, mptProofBytes)` when `before == nil`. Direct calls to `Client.Lookup` or `VerifyResponse` with `before != nil` perform **neither** MPT verification nor compact-range continuity verification against a preceding page, accepting arbitrary fabricated `indices-v1` and `prefix-compact-range-v1` payloads.
  - **Fix**: Require callers of paginated verification to supply the expected `MiniLogRoot` from the prior page's prefix compact range (or verify `expectedMiniLogRoot` inside `VerifyResponse` when `before != nil`).

- [ ] **2.6.2 Truncation / Omission Vulnerability in `Client.LookupAll` and `computeMiniLogRoot`**
  - **Location**: [`client/client.go:538-567`](client/client.go#L538-L567) (`Client.LookupAll`), [`client/client.go:364-376`](client/client.go#L364-L376) (`computeMiniLogRoot`)
  - **Bug**:
    1. `LookupAll` breaks out of the backward pagination loop as soon as `resp.NextBefore == nil` (`client.go:564`) without asserting `resp.PrefixCoveredSz == 0 && len(resp.PrefixHashes) == 0`. A malicious server can return a valid `prefix-compact-range-v1` (passing `MiniLogRoot` verification) while omitting `<next_before>` from `— indices-v1 —`, causing `LookupAll` to return truncated history without error.
    2. In `computeMiniLogRoot` (`client.go:364-376`), if `prefixCoveredSize > 0` with `len(prefixHashes) == 0` (or `prefixCoveredSize == 0` with `len(prefixHashes) > 0`), it silently falls back to `rf.NewEmptyRange(0)` instead of returning a malformed proof error.
  - **Fix**: In `LookupAll`, return an error if `resp.NextBefore == nil && (resp.PrefixCoveredSz > 0 || len(resp.PrefixHashes) > 0)`, and require `resp.Indices[0] == *resp.NextBefore` when `NextBefore != nil`. In `computeMiniLogRoot`, reject mismatched `(prefixCoveredSize == 0) != (len(prefixHashes) == 0)`.

- [ ] **2.6.3 Unverified Fallback & Linear SHA-256 Acceptance in `VIndexClient.Lookup`**
  - **Location**: [`client/client.go:679-690`](client/client.go#L679-L690) (`VerifyLookupResponse`), [`client/client.go:726-738`](client/client.go#L726-L738) (`VIndexClient.Lookup`)
  - **Bug**: On *any* error from `c.client.Lookup`—including a cryptographic proof failure—`VIndexClient.Lookup` falls back to `GET /lookup/{keyhash}` (legacy JSON) and `VerifyLookupResponse`, which further falls back to accepting a plain linear `sha256` hash over raw 8-byte indices if RFC 6962 compact range verification fails.
  - **Fix**: Remove the legacy JSON endpoint fallback and linear SHA-256 hash fallback from `client/client.go`, and have `VIndexClient.Lookup` call `c.client.LookupAll`.

- [ ] **2.6.4 Missing Checkpoint Signature Verification, Witness Quorum (`tlog-policy`), & Step 5 History Check in `client/`**
  - **Location**: [`client/client.go:73-78, 135-147, 190-202, 581-631`](client/client.go#L73-L78)
  - **Bug**:
    1. If `OutputLogVerifier == nil` or `InputLogVerifier == nil`, `VerifyResponse` silently skips signature verification (`tree.ParseCheckpointHeader`).
    2. `Client.GetCheckpoint` and `Client.GetInputLogCheckpoint` return raw HTTP response bytes with zero signature verification.
    3. Witness cosignature verification (`tlog-policy`) and Step 5 (`Monotonic History Check`) are unimplemented.
    4. `client/client.go` imports `internal/tree` and `internal/verifier`, transitively pulling `internal/kvstore` and `github.com/cockroachdb/pebble` into the public client SDK.
  - **Fix**: Enforce non-nil verifiers (and optional witness policy), verify checkpoints in `GetCheckpoint`/`GetInputLogCheckpoint`, implement monotonic history verification, and decouple `client/` from `internal/kvstore`/`pebble`.

- [ ] **2.6.5 Missing Genesis Backfill Structured JSON on `/readyz` and `/syncz`**
  - **Location**: [`internal/server/server.go:266-300`](internal/server/server.go#L266-L300) (`HandleReadyz`), [`cmd/vindexd/main.go:344-354`](cmd/vindexd/main.go#L344-L354)
  - **Bug**: During Genesis Backfill (`Output_CP.Size == 0`), `GET /readyz` and `GET /syncz` return plain text `503 Service Unavailable` (`"serving state not ready\n"`) instead of the documented structured JSON (`{"genesis_backfill": true, "leaves_indexed": X, "target_leaves": Y}`).
  - **Fix**: Wire a readiness status provider from `Coordinator` to `ReadServer` that emits the Genesis Backfill progress JSON when `outputLog.Size == 0`.

---

### 2.7 Independent Auditor & Verified Mirror (`internal/auditor/`)

- [ ] **2.7.1 Reader Snapshot Isolation Race in Verified Mirror Mode (`--serve_mirror=true`)**
  - **Location**: [`internal/auditor/auditor.go:758-808`](internal/auditor/auditor.go#L758-L808) (`Auditor.VerifyOnce`), [`internal/server/server.go:344-352`](internal/server/server.go#L344-L352) (`ReadServer.HandleLookup`)
  - **Bug**: In `VerifyOnce`, `v.mptMgr.CommitWithVersion` mutates the in-memory MPT and releases `treeMu` at `auditor.go:758`, then performs synchronous Pebble watermark writes (`pebble.Sync` at `auditor.go:779`) and MPT disk `Persist()` (`fsync` at `auditor.go:784`), and only calls `v.publisher.SetServingState` at `auditor.go:797`. During that entire disk-sync window, concurrent `HandleLookup` requests on the mirror read the **old** `ServingState` (`MapRoot`, `InputLogSize`) while `s.mptMgr.ProveLocked` generates proofs from the **new** MPT state, returning corrupted responses that fail client verification.
  - **Fix**: Hold `v.mptMgr.Lock()` across `CommitKeyValsLocked` and `v.publisher.SetServingState(newState)` (matching `OutputPublisher.PublishBatch` in [`internal/tree/publisher.go:140-168`](internal/tree/publisher.go#L140-L168)), and run `v.mptMgr.Persist()` under `writeMu` outside `treeMu`.

- [ ] **2.7.2 Premature Pebble Mutation Before Root Equality Assertion on Mismatch**
  - **Location**: [`internal/auditor/auditor.go:696-781`](internal/auditor/auditor.go#L696-L781) (`Auditor.VerifyOnce`)
  - **Bug**: `v.indexer.IndexMappedBatch` writes the new `'c'` chunks and updates `m_kv_size = targetInputSize` in Pebble at `auditor.go:696` **before** `v.mptMgr.Predict` (`auditor.go:742`) and the root equality assertion `localMapRoot != committedMapRoot` (`auditor.go:752`). When a root mismatch is detected, Pebble DB has already been mutated with the unverified batch's chunks and `m_kv_size`, violating the forensic state freeze invariant.
  - **Fix**: Keep `m_kv_size` aligned with `KeyVerifierInputWatermark`, or stage/verify predicted sub-roots before committing the watermark advancement in Pebble so a root mismatch leaves the verified database state intact.

- [ ] **2.7.3 `--fail_closed=true` Fails `/healthz` Liveness Probe with HTTP 503**
  - **Location**: [`internal/auditor/auditor.go:468-473`](internal/auditor/auditor.go#L468-L473) (`auditor.New`)
  - **Bug**: When `FailClosed` is true, `auditor.New` registers `v.HealthCheck()` on `SetHealthChecker`, causing `GET /healthz` to return `HTTP 503 Service Unavailable` when halted. This causes container orchestrators (e.g. Kubernetes liveness probes) to kill and restart the halted forensic container, whereas `/healthz` should remain `HTTP 200 OK` and only `/readyz`, `/syncz`, and `/lookup` (via `SetServingState(nil)`) should return `503`.
  - **Fix**: Do not wire `v.HealthCheck()` to `SetHealthChecker` on `/healthz`; rely on `SetReadyChecker` (`/readyz`, `/syncz`) and `SetServingState(nil)` (`/lookup`).

- [ ] **2.7.4 Missing `ManagedTileCache` & Miswired `CommitBatchSize` in Auditor**
  - **Location**: [`internal/auditor/auditor.go:457`](internal/auditor/auditor.go#L457), [`cmd/vindexd/main.go:473`](cmd/vindexd/main.go#L473), [`cmd/vindex-auditor/main.go:117`](cmd/vindex-auditor/main.go#L117)
  - **Bug**: `auditor.New` passes `nil` for the tile cache to `ingest.NewPipeline`, and both `cmd/vindexd` and `cmd/vindex-auditor` wire `CommitBatchSize: *chunkSize` (passing the 65,536 KV chunk size as the commit batch size instead of 4,096) without calling `db.SetChunkSize(*chunkSize)`.
  - **Fix**: Wire `ManagedTileCache` in `auditor.New`, separate `--commit_batch_size` (4,096) from `--chunk_size` (65,536), and call `db.SetChunkSize` on the auditor DB.

---

## 3. Upstream Library Issues to Raise / Investigate

### 3.1 `filippo.io/torchwood/mpt` — Redundant Synchronous Disk Writes on Journal Replay (`22M pwrite syscalls`)

- [ ] **Suppress Redundant `m.disk.WriteAt` Calls During `pmem.Open` Replay When `mpt.disk` Is Clean**
  - **Library Location**: `filippo.io/torchwood/mpt/internal/pmem/pmem.go` (`readFile` / `replay`)
  - **Empirical Finding**: On a cold restart of the completed 926M-leaf Sycamore 2026h1 CT log index (861M unique keys, 52 GB `mpt.disk`, 89 GB `mpt.tree1`), `tree.Open()` blocked for **~55 minutes** before returning. Profiling (`/proc/<PID>/io`, `wchan`, `vmstat`) showed that leaf insertions record disk-backed leaf values with an odd offset tag (`off&1 != 0`) and execute:
    ```go
    if isDisk && count > 0 {
        m.disk.WriteAt(patch[:count], m.diskOff+int64(off))
    }
    ```
    During `pmem.Open`, `replay` executed **over 22 million synchronous POSIX `pwrite` syscalls** to rewrite 52 GB of leaf data back into `mpt.disk`, even though `mpt.disk` was already durably synced before shutdown. User-space CPU (SHA-256 and varint decoding) accounted for only ~18% (~9.5 minutes) of wall time; the remaining **~82% (~45 minutes)** was spent blocked in kernel sleep (`ext4_block_write_beg`) saturating disk queues with redundant rewrites.
  - **Upstream Proposal**: If `mpt.disk` byte size already covers the target offset (or matches the watermark in the journal trailer), skip redundant `m.disk.WriteAt` calls during journal replay.

### 3.2 `filippo.io/torchwood/mpt` — Missing Explicit Final Compaction API (`tree.Compact()`)

- [ ] **Expose an Explicit `Compact()` Method on `mpt.Tree` / `pmem.Mem`**
  - **Library Location**: `filippo.io/torchwood/mpt/disk.go`, `internal/pmem/pmem.go`
  - **Empirical Finding**: `torchwood/mpt` persists an initial base snapshot (48 KB) followed by an append-only sequence of up to 8 MB mutation patch frames. Because `maybeCompact()` only compacts passively as a fraction of ongoing writes (`2 * len(patch)` bytes per write), compaction ceases the moment bulk backfill reaches log tip. Across 35 hours of CT backfill, `mpt.tree1` accumulated **89 GB (~11,000 frames)** with no way to trigger a final compaction on backfill completion or clean `SIGINT`/`SIGTERM` shutdown.
  - **Upstream Proposal**: Expose an explicit `Compact()` API on `mpt.Tree` that writes a single contiguous memory snapshot (`memLen = len(tree)`) to the alternate file (`mpt.tree2`), flushes `mpt.disk`, and swaps active files—reducing subsequent cold-start `pmem.Open` from 55 minutes to a single sequential frame read (seconds).

### 3.3 `filippo.io/torchwood/mpt` — Single-Threaded Journal Frame Checksumming & Replay

- [ ] **Investigate Pipelined Frame I/O and Multi-Core SHA-256 Verification in `pmem.readFile`**
  - **Library Location**: `filippo.io/torchwood/mpt/internal/pmem/pmem.go` (`readFile`)
  - **Empirical Finding**: When opening an uncompacted journal (`89 GB`, ~11,000 frames), `readFile()` reads each 8 MB frame from disk, verifies its SHA-256 checksum, and decodes varint patches serially on a single OS thread (~9.5 minutes of single-core CPU time).
  - **Upstream Proposal**: Decouple sequential frame reading (I/O goroutine), parallel SHA-256 frame verification (worker pool), and ordered memory mutation apply (state-machine thread).

### 3.4 `github.com/transparency-dev/merkle` — Per-Hash Heap Allocations in `rfc6962.DefaultHasher`

- [ ] **Upstream Zero-Allocation Stack-Buffered `HashLeaf` and `HashChildren` into `merkle/rfc6962`**
  - **Library Location**: `github.com/transparency-dev/merkle/rfc6962` (currently worked around locally in [`internal/kvstore/compact.go:27-66`](internal/kvstore/compact.go#L27-L66))
  - **Empirical Finding**: `rfc6962.DefaultHasher.HashLeaf` (161 B/op, 3 allocs/op) and `HashChildren` (240 B/op, 3 allocs/op) instantiate a new `sha256.New()` digest and allocate temporary slices on every call. During MTC batch ingestion, `HashChildren` alone accounted for **3.70 GB (24.1%)** of total heap allocation churn. Replacing them locally in `kvstore/compact.go` with inline stack buffers (`[512]byte` for small leaves, `[65]byte` for `0x01 || left || right`) and `sha256.Sum256` reduced allocations to `0 B/op, 0 allocs/op` and lowered hashing latency by ~33–35%.
  - **Upstream Proposal**: Upstream the stack-buffered `sha256.Sum256` fast path into `github.com/transparency-dev/merkle/rfc6962`.
