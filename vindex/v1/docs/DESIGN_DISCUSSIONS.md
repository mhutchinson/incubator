# VIndex Design Discussions & Open Frontiers

> [!NOTE]
> **Status: Active Research / Not Yet Implemented**
> This document captures bleeding-edge architectural insights, performance discoveries, and protocol refinements identified during VIndex v1 scale testing and production benchmarking. These items are deliberately documented here as an **open invitation for community collaboration, RFC critique, and joint implementation**.

---

## Subsystem Index & Design Cross-References

| Section | Topic | Primary Subcomponents | Base Design Documents |
| :--- | :--- | :--- | :--- |
| **§1** | [Zero-MPT Continuation & "Map of Logs" API](#1-zero-mpt-continuation--the-map-of-logs-api) | Read Serving, Client SDK, Architecture | [`internal/server`](../internal/server/README.md), [`client`](../client/README.md), [`docs/ARCHITECTURE`](./ARCHITECTURE.md) |
| **§2** | [Chunk-Aligned Paging (Zero Dynamic Hashing)](#2-chunk-aligned-paging-eliminating-dynamic-merkle-hashing) | Inverted Storage, Read Serving | [`internal/kvstore`](../internal/kvstore/README.md), [`internal/server`](../internal/server/README.md) |
| **§3** | [Bounded Chunk Visitation for Sparse Keys](#3-bounded-chunk-visitation-for-sparse-keys-p99-guardrail) | Inverted Storage, Read Serving | [`internal/kvstore`](../internal/kvstore/README.md), [`internal/server`](../internal/server/README.md) |

---

## 1. Zero-MPT Continuation & The "Map of Logs" API

### 1.1 Base Design Context
- **Base Design Reference**: [`internal/server/README.md §2.1–§2.2`](../internal/server/README.md#21-c2sp-http-rest-endpoints), [`client/README.md §2.2`](../client/README.md#22-the-5-step-query-verification-sequence), and [`docs/ARCHITECTURE.md §2.5`](./ARCHITECTURE.md#25-stage-5-read-serving-internal-server).
- **Current Behavior**: Every query to `/vindex/v1/lookup/{keyhash}` acquires an MPT read lock (`mptMgr.RLock()`), retrieves serving state, and formats an Output Log checkpoint, an Output Log leaf, an Output Log inclusion proof, and an MPT inclusion/non-inclusion proof alongside returned indices.

### 1.2 The Realization: MPT Is Irrelevant on Backward Continuations
VIndex is fundamentally a **Map of Logs**:
- The **Map** commits to `KeyHash -> MiniLogRoot` at a given Input Log checkpoint.
- The **Mini-Log** is an independent, append-only Merkle log storing the occurrence indices for that key.

When a client paginates backwards through history:
1. **Page 1 (`before == nil`)**: The client uses the MPT proof to authenticate `MiniLogRoot` against the witnessed `MapRoot`. It also receives a `prefix-compact-range-v1` representing all preceding occurrences and collapses it into an authenticated `expectedMiniLogRoot`.
2. **Page 2+ (`before = next_before`)**: The client verifies subsequent indices purely by checking compact range continuity:
   ```text
   NewRange(Page_N.PrefixCR).Append(Page_N.Indices).GetRootHash() == Page_(N-1).expectedMiniLogRoot
   ```
3. Because the mini-log is self-authenticating via RFC 6962 Merkle tree hashing, **continuation requests never need the MPT or Output Log**.
4. In fact, [`client.go`](../client/client.go) already skips MPT verification when `before != nil` because a mid-log mini-log root cannot match the current tip `MapRoot`. The MPT proof returned on continuation pages is currently dead payload.

### 1.3 Proposed Architectural Directions

#### Option A: Pure 2-Phase Split (`/proof` vs. `/entries`)
Decouple the endpoints explicitly:
- `GET /vindex/v1/proof/{keyhash}`: Queries the MPT under `RLock()`. Returns Checkpoint + Output Log proof + MPT proof (`MiniLogRoot`). Bypasses Pebble entirely.
- `GET /vindex/v1/entries/{keyhash}?before=X`: Queries Pebble directly. Returns `indices-v1` + `prefix-compact-range-v1`. Completely eliminates MPT lock acquisition.

*Trade-off & Write-Skew Race*:
If a client fires both requests concurrently without an upper bound, a commit between the two requests causes the Pebble read to observe a newer `InputLogSize` than the MPT proof, leading to a spurious root mismatch. Safe execution requires either:
- A serial 2-RTT sequence (fetch proof first, then query entries `before=InputLogSize`), or
- Passing a pre-witnessed Input Log checkpoint boundary known to the client.

#### Option B: Smart Tip with Zero-MPT Continuations
- **Tip query (`before == nil`)**: Retains combined proof + Page 1 data in 1 RTT (optimal for the 95%+ of keys with few occurrences).
- **Continuation query (`before != nil`)**: Server automatically skips `s.mptMgr.RLock()`, skips `s.mptMgr.ProveLocked()`, queries Pebble directly, and strips Output Log and MPT sections from the response.

### 1.4 Collaboration & Research Frontiers
- Designing benchmark harnesses to quantify lock contention reduction on `mptMgr` during concurrent bulk historical queries.
- Evaluating whether a standalone `/entries` or `/minilog` endpoint should be formalized in the C2SP specification for clients that already track log state out-of-band.

---

## 2. Chunk-Aligned Paging (Eliminating Dynamic Merkle Hashing)

### 2.1 Base Design Context
- **Base Design Reference**: [`internal/kvstore/README.md §2.2`](../internal/kvstore/README.md#22-delimitless-binary-chunk-serialization--compact-ranges) and [`internal/server/README.md §2.2`](../internal/server/README.md#22-multi-section-plaintext-response-wire-format).
- **Current Behavior**: When an inverted chunk (`^chunkNum`) has more matching indices than the requested query limit (`validCount > needed`), the server splits the chunk.

### 2.2 The Bottleneck: Mid-Chunk On-the-Fly Merkle Hashing
When splitting a chunk, the server must construct a valid `prefix-compact-range` for the leftover prefix:
```go
// Current implementation in internal/kvstore/reader.go
for _, rel := range rec.RelativeIndices[:splitIdx] {
    var b [8]byte
    binary.BigEndian.PutUint64(b[:], chunkBase+uint64(rel))
    cr.Append(LeafHash(b[:]))
}
```
If a key appears 5,000 times in an active chunk and the client requests `limit=100`, the server executes **4,900 SHA-256 leaf and node hashes on every request** just to synthesize an arbitrary mid-chunk compact range.

### 2.3 The Realization: Chunks Already Store Boundary Compact Ranges
Each stored inverted chunk record already contains `rec.CompactHashes` and `rec.CoveredSize` committing to all entries prior to that chunk:
- If the server **never splits a chunk** and instead aligns pagination to chunk boundaries:
  1. `rec.CompactHashes` and `rec.CoveredSize` are returned in **O(1) time** via direct memory copy from the Pebble value buffer.
  2. Dynamic, on-the-fly Merkle hashing on the read path drops to **zero**.
  3. The worst-case chunk size is 65,536 indices (`uint16` offsets) = ~524 KB uncompressed (~100 KB gzipped). Transmitting this payload over HTTP is orders of magnitude cheaper than burning host CPU on tens of thousands of SHA-256 computations.

### 2.4 Proposed Architectural Direction
- Treat the client's `limit` parameter as an advisory hint rather than an exact quota.
- When an inverted chunk is read, return all of its valid entries and output the chunk's precomputed `CompactHashes` as the `prefix-compact-range`.
- Client verification in `client.Verifier` is completely invariant to page size; it simply appends whatever indices are returned to the prefix compact range and verifies the root.

### 2.5 Collaboration & Research Frontiers
- Benchmarking read throughput improvements in `internal/kvstore/reader.go` when removing the inner `cr.Append` loop.
- Measuring payload size distributions across diverse real-world logs (e.g. Certificate Transparency vs. Go SumDB vs. MTC).

---

## 3. Bounded Chunk Visitation for Sparse Keys (P99 Guardrail)

### 3.1 Base Design Context
- **Base Design Reference**: [`internal/kvstore/README.md §2.1`](../internal/kvstore/README.md#21-logical-model--inverted-chunk-key-layout) and [`internal/server/README.md §2.1`](../internal/server/README.md#21-c2sp-http-rest-endpoints).
- **Current Behavior**: The read path seeks to `maxChunkNum` and iterates backwards until `totalMatched == limit` or the prefix is exhausted.

### 3.2 The Bottleneck: Pathological Sparse Key Scans
Consider a key that appears once every 65,536 entries across a 1-billion-entry log (~15,000 chunks):
- If a client requests `limit=1000`, the storage engine must seek, read, and unmarshal **1,000 separate Pebble chunk records** scattered across cold SSTables.
- A single client query can trigger thousands of random disk I/O reads, stalling Pebble's background compactions and causing severe P99 latency spikes.

### 3.3 The Discovery: Compact Ranges Allow Arbitrarily Small Pages
In an authenticated mini-log, a page containing only 1 or 2 entries is 100% cryptographically verifiable, provided the `prefix-compact-range` commits to the boundary where iteration stopped.

### 3.4 Proposed Architectural Direction
Introduce a dual termination condition in the Pebble reader loop:
1. `totalMatched >= limitHint` (after completing the active chunk), **OR**
2. `chunksVisited >= maxChunksPerRequest` (e.g. hard cap of 8–16 chunks).

If `maxChunksPerRequest` is reached:
- Halt iteration immediately.
- Yield whatever matches were gathered.
- Return the compact range committing to all preceding chunks (`rec.CompactHashes` of the oldest visited chunk).
- Set `next_before` to the oldest index returned.
- Binds worst-case server execution time and disk I/O per HTTP request.

### 3.5 Collaboration & Research Frontiers
- Determining optimal dynamic chunk visitation budgets based on server load or SSTable cache hit ratios.
- Standardizing C2SP response headers for pagination budget exhaustion.
