# Milestone 01: Core Storage, Recovery & Pipeline Hardening

**Status**: 🏃 **Mid-Sprint (Active)**  
**Target Completion**: 2026-W42  
**Epic**: Resolve all storage, ingestion, crash-recovery, and auditor correctness and performance bugs in [`BACKLOG.md`](../../BACKLOG.md) that are orthogonal to the [`PREFIX_LOOKUPS.md`](../PREFIX_LOOKUPS.md) key-format and two-endpoint overhaul, establishing a rock-solid, benchmark-verified engine baseline before Milestone 02.

---

## 1. Objectives & Success Criteria
1. **Zero-Allocation Read Path & O(1) Pebble Seeks**: Eliminate phantom chunk-0 writes (`2.3.1`), consult 33-byte prefix Bloom filters on point lookups (`2.3.2`), reconstruct `GetSubRoot` in O(1) chunk reads (`2.3.3`), align paging to whole chunks (`1.1.2`), and bound sparse-key SSTable seeks via `maxChunksPerRequest` (`1.1.3`).
2. **Benchmark-Verified Performance Commits**: Every performance optimization in Phase 01.1 includes dedicated unit tests and `testing.B` (`b.Loop()`) microbenchmarks (`-benchmem`), with **before/after performance scores (`ns/op`, `B/op`, `allocs/op`) cited directly in the commit message**.
3. **Hermetic Ingest & WASM Failure Safety**: Authenticate Level-0 hash tiles against signed checkpoint roots (`2.1.1`–`2.1.3`), enforce durable tile caching and partial-bundle retention (`2.1.4`–`2.1.5`), and convert WASM 4 MB slab overflows (`2.2.1`) and runtime traps (`2.2.2`) into deterministic fatal halts.
4. **Crash-Consistent Recovery & Mirror Isolation**: Enforce `m.tree.Sync()` durability watermarks (`2.4.1`, `2.5.3`), eliminate redundant `Phase3` recovery replay (`2.5.1`), make Genesis Backfill flushes crash-safe (`2.5.2`), and guarantee reader snapshot isolation and forensic state freeze in `vindex-auditor` (`2.7.1`–`2.7.4`).

---

## 2. Actionable Task Breakdown

### Phase 01.1: Pebble Storage & Read-Path Performance (`internal/kvstore/`)
> **Mandatory Rule for Phase 01.1**: Every item below must include a reproducible `Benchmark*` in `internal/kvstore/` (using `b.Loop()` and `b.ReportAllocs()`) alongside unit tests, and its commit message must include the exact `go test -bench=... -benchmem` before/after table.

- [x] **01.1.1 Eliminate Phantom Empty Chunk 0 (`2.3.1`)**: In [`internal/kvstore/writer.go`](../../internal/kvstore/writer.go), initialize `currChunkNum = unpersisted[0] / idx.chunkSize` when a key is not present in cache or Pebble so keys first appearing at `leafIdx >= 65536` do not write an empty chunk `0` record (`'c' + keyHash + ^uint64(0)`). Add unit test verifying exact `'c'` record count in Pebble for sparse keys (`leafIdx >= 65536`) and benchmark measuring batch indexing throughput/bytes written before vs. after.
- [x] **01.1.2 Enable Prefix Bloom Filters via `SeekPrefixGE` (`2.3.2`)**: In [`internal/kvstore/reader.go`](../../internal/kvstore/reader.go), replace `iter.SeekGE(seekKey)` with `iter.SeekPrefixGE(prefix)` (positioned at `seekKey` within the 33-byte `'c' + KeyHash` prefix) so Pebble's 33-byte prefix Bloom filters are consulted on point lookups. Add benchmark measuring non-existent key lookup latency (`ns/op`, SSTable block reads) across flushed SSTables before vs. after.
- [x] **01.1.3 O(1) `GetSubRoot` Reconstruction (`2.3.3`)**: In [`internal/kvstore/writer.go`](../../internal/kvstore/writer.go) (`getSubRootWithIter`), replace the full historical chunk scan and `slices.Reverse` re-hash from leaf 0 with a direct inverted seek to the newest chunk `< maxInputLogSize`, seeding `cr` from `rec.CoveredSize` and `rec.CompactHashes` and appending only entries in that chunk with `absIdx < maxInputLogSize`. Add unit test asserting identical sub-roots across multi-chunk histories and benchmark comparing 100-chunk `GetSubRoot` latency (`ns/op`, `B/op`, `allocs/op`) before vs. after.
- [x] **01.1.4 Chunk-Aligned Paging & Bounded Chunk Visitation (`1.1.2`, `1.1.3`)**: In [`internal/kvstore/reader.go`](../../internal/kvstore/reader.go), treat `limit` as an advisory hint and align page boundaries to whole inverted chunks so `rec.CompactHashes` and `rec.CoveredSize` are copied in O(1) with zero read-path SHA-256 hashing; enforce a dual loop termination condition (`totalMatched >= limitHint || chunksVisited >= maxChunksPerRequest`). Add unit tests for multi-chunk pagination and sparse-key early termination, plus a read-path benchmark (`limit=100` on a 5,000-entry chunk and sparse multi-chunk seeks) citing before/after `ns/op` and `allocs/op`.

### Phase 01.2: Ingest Verification & WASM Slab Safety (`internal/ingest/`, `mapfn/sdk/`, `cmd/vindex-wasm/`)
- [x] **01.2.1 Upstream Tile Cryptographic Root Verification (`2.1.1`, `2.1.2`)**: In [`internal/ingest/fetcher.go`](../../internal/ingest/fetcher.go), verify Level-0 hash tiles against the target `Checkpoint.Hash` via upper tree tiles / inclusion proof verification, and reject Static-CT bundles when `len(treeTile) != len(leaves)*32`. Add unit tests covering tampered `(entryBundle, level0Tile)` pairs and truncated Static-CT tiles.
- [x] **01.2.2 Mandatory Checkpoint Signature Verifier (`2.1.3`)**: In [`internal/ingest/fetcher.go`](../../internal/ingest/fetcher.go) and [`cmd/vindexd/main.go`](../../cmd/vindexd/main.go), require a non-nil `note.Verifier` (rejecting unverified checkpoints unless an explicit local-test opt-out is set).
- [x] **01.2.3 Durable Tile Caching & Partial-Bundle Retention (`2.1.4`, `2.1.5`)**: In [`internal/ingest/pipeline.go`](../../internal/ingest/pipeline.go), check and surface `cache.PutBundle` errors before advancing `KV_CP`; in [`internal/ingest/cache.go`](../../internal/ingest/cache.go) (`ManagedTileCache.PruneBefore`), align in-memory eviction with disk eviction (`(bIdx + 1) * c.bundleSz <= watermark`) so partial bundles are retained until full.
- [x] **01.2.4 WASM 4 MB Slab Overflow & Fatal Trap Handling (`2.2.1`, `2.2.2`, `2.2.4`)**: In [`mapfn/sdk/arena.go`](../../mapfn/sdk/arena.go) and [`internal/ingest/wasm.go`](../../internal/ingest/wasm.go), fail fast with a non-zero error sentinel when input or output slabs exceed 4 MB (`outPtr == 0, outLen == 0`), propagate fatal errors on WASM guest traps without leaking worker pool slots, and update [`cmd/vindex-wasm`](../../cmd/vindex-wasm/bench_cmd.go) (`bench`, `determinism`, `test`, `inspect`) to exercise 256-leaf `MapBundle`.

### Phase 01.3: State Durability, Recovery & Startup (`internal/tree/`, `internal/coordinator/`, `cmd/vindexd/`, `vindex.go`)
- [ ] **01.3.1 MPT Disk `Persist()` & Durable Watermark (`2.4.1`, `2.5.3`)**: In [`internal/tree/mpt.go`](../../internal/tree/mpt.go) and [`internal/tree/publisher.go`](../../internal/tree/publisher.go), track `durableSize atomic.Uint64` that only advances after `m.tree.Sync()` completes, call `mptMgr.Persist()` after `PublishBatch` and `Coordinator.Phase2`, inspect `m.tree.Version()` `(version, exact)` in `tree.Open` before calling `Snap(-1)`, and wire `TileReaper` through `Coordinator.SafeWatermark`.
- [ ] **01.3.2 Remove Redundant Recovery `Phase3` (`2.5.1`)**: In [`internal/coordinator/coordinator.go`](../../internal/coordinator/coordinator.go), remove the KV-only `Phase3` streaming pass that discards `ModifiedSubRoots` and causes `SyncOnce` to re-index `[ServingState.InputLogSize, targetCP.Size)` twice.
- [ ] **01.3.3 Synchronous Genesis Backfill Flush Barrier (`2.5.2`)**: In [`internal/coordinator/coordinator.go`](../../internal/coordinator/coordinator.go) and [`internal/kvstore/writer.go`](../../internal/kvstore/writer.go), write `m_kv_size` after chunk mutations in the batch, execute `c.db.Sync()` synchronously in `dispatchFlush` before handing buffers to the background MPT worker, update `lastCheckpointLeaf` after `workerWg.Wait()`, and guard `--backfill_max_pending_keys` with `isFlagPassed` in [`cmd/vindexd/main.go`](../../cmd/vindexd/main.go).
- [ ] **01.3.4 Async Daemon Startup, Readiness JSON & Top-Level Wiring (`1.1.4`, `2.6.5`, `2.4.2`, `2.5.4`)**: Bind `:8080` immediately in `cmd/vindexd/main.go` before `tree.Open()` and `coord.Recover(ctx)`, serve structured status JSON on `/readyz` and `/syncz` during MPT initialization and Genesis Backfill, wire witness clients in `vindex.New` and `cmd/vindexd`, and eliminate the duplicate pipeline / ephemeral `memoryOutputLog` fallback in [`vindex.go`](../../vindex.go).

### Phase 01.4: Auditor & Verified Mirror Correctness (`internal/auditor/`, `cmd/vindex-auditor/`)
- [ ] **01.4.1 Mirror Reader Snapshot Isolation (`2.7.1`)**: In [`internal/auditor/auditor.go`](../../internal/auditor/auditor.go) (`VerifyOnce`), hold `v.mptMgr.Lock()` across `CommitKeyValsLocked` and `v.publisher.SetServingState(newState)`, running `v.mptMgr.Persist()` outside `treeMu` so `--serve_mirror=true` readers never pair a stale `ServingState` with a mutated MPT.
- [ ] **01.4.2 Forensic State Freeze on Root Mismatch (`2.7.2`)**: In [`internal/auditor/auditor.go`](../../internal/auditor/auditor.go), verify `localMapRoot == committedMapRoot` before advancing the verified Pebble watermark so a root mismatch leaves the verified database state untouched on disk.
- [ ] **01.4.3 Liveness Probe & Cache/Batch Wiring (`2.7.3`, `2.7.4`)**: Keep `/healthz` returning `HTTP 200 OK` when halted under `--fail_closed=true` (returning `503` on `/readyz`, `/syncz`, and lookups), wire `ManagedTileCache` in `auditor.New`, and separate `--commit_batch_size` (`4096`) from `--chunk_size` (`65536`) in `cmd/vindexd` and `cmd/vindex-auditor`.

### Phase 01.5: Verification Gate
- [ ] **01.5.1 Automated Test Suite**: `go test -race ./...` passes cleanly across `vindex/v1/...`.
- [ ] **01.5.2 Benchmark Suite Verification**: `go test -bench=. -benchmem ./internal/kvstore/...` passes with all before/after metrics recorded in commit messages.

---

## 3. Retrospective & Deliverables
*(Populated upon milestone completion)*
* **Shipped Commit**: TBD
* **Completed Date**: TBD
* **Key Wins & Deviations**: TBD
