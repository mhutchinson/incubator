# Verifiable Index (VIndex v1) Architecture

This document defines the core architecture, non-negotiable invariants, verified performance optimizations, operational considerations, and retired design branches for **VIndex v1**.

---

## 1. Core Load-Bearing Invariants

### 1.1 Context, Problem Statement & The Map Sandwich
Append-only transparency logs (e.g., Certificate Transparency, Go SumDB, Merkle Tree Certificates, Sigstore) provide tamper-evident discoverability. However, finding records by content (e.g., domain name, module path, public key hash) historically required full-log scans or trusting centralized, unverifiable third-party indexers that could silently omit records.

A **Verifiable Index (VIndex)** operates as an authenticated search overlay bounded between an **Input Log** (the source of truth being indexed) and an **Output Log** (committing to the index's cryptographic state)—informally known as the **"Map Sandwich"**:
- **O(1) Point Queries**: Constant-time key lookups with logarithmic Merkle inclusion proofs.
- **Omission Resistance**: Every query response delivers cryptographic inclusion or non-inclusion proofs, mathematically guaranteeing completeness against witnessed checkpoints.
- **Decoupled Security**: If VIndex halts or fails, the underlying Input Log's sequencing, consensus, and security model remain unaffected.

```text
  [Input Log] (Source of Truth, e.g. CT / MTC / SumDB)
       │
       ▼ (1. Authenticated Entry Bundles)
┌─────────────────────────────────────────────────────────────────────────────┐
│                              vindexd Daemon                                 │
│                                                                             │
│  [Ingestion Plane]                                                          │
│  • TileFetcher & ManagedTileCache                                           │
│  • Parallel Wazero WASM Sandboxes (max(1, GOMAXPROCS-1) workers)            │
│    - Bundled Tile Mapping: map_bundle (1 <= N <= 256 leaves/call, 2-3 FFI)  │
│    - Extracts Canonical Preimages (e.g. domain strings, module paths)       │
│  • Host-Side Hardware Cryptography (crypto/sha256 + SHA-NI / ARMv8 Crypto)  │
│    - KeyHash = SHA256(canonical_subject)                                    │
│    - Lexicographical sort (bytes.Compare) & deduplication (slices.Compact)  │
│  • In-Memory Priority Resequencer (Monotonic leaf ordering min-heap)        │
│         │                                                                   │
│         ▼ chan *MappedBatch (ordered)                                       │
│  [Data & Commitment Plane] (Serialized Batch Commit Loop)                   │
│  • 1. KVIndexer: Pebble DB Inverted Chunks ('c') with blocking disk sync    │
│  • 2. OutputPublisher: Lock-Free Root Prediction (mpt.Predict)              │
│  • 3. Output Log Append & Remote Witness Cosignatures                       │
│  • 4. Serving MPT: In-Memory working tree ratchet (< 5ms lock)              │
│         │                                                                   │
│         ▼                                                                   │
│  [Serving Plane]                                                            │
│  • HTTP Read Server (/vindex/lookup/{keyhash}?before=X&limit=M)             │
│  • Lock-Free Inverted Scans + Watermark Index Filtering                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (2. Append StateCommitment: hex(MapRoot) + ILCheckpoint)
                                       ▼
  [Output Log] (Tessera POSIX / Cloud Tiles + Witness Cosignatures)
```

### 1.2 Non-Negotiable System Scope & Invariants
1. **Strictly Single-Machine Deployment**: VIndex operates strictly within a single process on a single host. It avoids internal clustering, distributed consensus (Raft/Paxos), or multi-node replication. High availability is achieved externally: independent monitors and mirrors run standalone VIndex instances against the shared Input Log.
2. **Point Lookups by 32-Byte Key Hashes**: The production serving plane provides point queries exclusively over exact 32-byte key hashes (`KeyHash = SHA256(CanonicalSubject)`). General cross-key scans, substring matches, full-text queries, and arbitrary regex searches are out of scope.
3. **Strictly Append-Only (Zero Tombstones)**: The index state progresses strictly forward. The system supports no deletions, key un-mappings, rollbacks, or tombstones.
4. **Hermetic, Deterministic Mapping**: The WebAssembly `MapFn` operates in a restricted sandbox with zero host I/O, zero network access, and deterministic clocks. Any runtime trap, memory fault, or unhandled exception triggers an immediate `HALT` to prevent unverified state divergence across nodes.

### 1.3 Watermark Glossary & Progression Inequality Chain
VIndex coordinates state progression monotonically across four distinct pipeline planes:

| Watermark Symbol | Pipeline Plane | Definition & Invariant Role |
| :--- | :--- | :--- |
| `Target_CP` | Upstream Input Log | Latest authenticated checkpoint size discovered, verified, and frozen in Pebble (`m_target_checkpoint`). |
| `Cached_Tiles` | Ingestion Plane / Local Cache | Highest contiguous leaf index downloaded, verified against the Merkle tree, and stored in `ManagedTileCache`. |
| `m_kv_size` | Storage Plane (`internal/kvstore`) | Highest contiguous leaf index whose inverted chunk records have been durably synced to Pebble DB (`pebble.Sync`). |
| `Output_Size` | Commitment Plane (`internal/tree`) | Input Log tree size committed with witness cosignatures in the Output Log (`StateCommitment`). |
| `MPT_Durable_Size` | Tree Disk Plane (`internal/tree`) | Durably fsync'd MPT Input Log size on disk (`mptMgr.Sync()`). |

In steady-state serving, these watermarks strictly satisfy the **Watermark Progression Inequality Chain**:
```text
Target_CP >= Cached_Tiles >= m_kv_size >= Output_Size >= MPT_Durable_Size
```
*(Note: Active Serving MPT Size == Output_Size)*.

### 1.4 Synchronous Commit Barrier
To guarantee crash consistency without distributed transactions or complex WAL rollback mechanics, the coordinator enforces a strict, synchronous commit barrier during batch processing:
1. **Blocking Storage Persistence**: `store.WriteBatch(entries, S_k)` executes `pebble.Sync`, blocking until all inverted chunk mutations (`'c'`) and `m_kv_size` are durably persisted to disk.
2. **Output Log Publication Gating**: Output Log append and remote witness network RPCs **MUST NOT begin** until `store.WriteBatch` has successfully returned.
3. **Serialized Batch Loop**: Each batch progresses sequentially through:
   `store.WriteBatch(entries, S_k)` (blocking disk sync) -> `publisher.PublishBatch(...)` (root prediction -> Output Log append -> witness cosigning -> in-memory MPT ratchet).

### 1.5 Universal Crash Invariant Guarantee
Because storage persistence strictly precedes Output Log publication:
```text
m_kv_size >= Output_Size
```
This invariant holds under all crash, kill, and power loss scenarios. Startup recovery is mathematically guaranteed never to encounter an Output Log entry referencing uncommitted or missing KV store chunks. If a crash occurs after storage sync but before Output Log publishing, `m_kv_size > Output_Size`; startup recovery safely ignores chunks beyond `Output_Size` via point-in-time `store.GetSubRoot(keyHash, Output_Size)` queries.

### 1.6 Fatal Panic on Root Prediction Divergence
In `publisher.PublishBatch`, the future `MapRoot` is pre-calculated lock-free via `mptMgr.Predict`. The state commitment (`hex(predictedMapRoot) + "\n" + rawInputLogCP`) is appended to the Tessera Output Log. When writer lock `treeMu` is acquired and mutations are committed (`CommitWithVersionLocked`), the actual computed root is asserted against `predictedMapRoot`:
```go
if actualRoot != predictedMapRoot {
    p.mptMgr.Unlock()
    panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", actualRoot, predictedMapRoot))
}
```
If `actualRoot != predictedMapRoot`, the node must terminate immediately with a fatal panic. Continuing execution would publish an equivocal commitment to the Output Log.

### 1.7 Serving Isolation Invariant
```text
Serving_Size == MPT_Size <= Output_Size
```
Readers are strictly isolated from in-flight writes ahead of `Serving_Size`. HTTP queries snapshot `ServingState` and generate MPT proofs under `treeMu.RLock()`. All subsequent storage reads filter indices to satisfy `idx < Serving_Size`, ensuring readers never observe uncommitted or un-witnessed records.

### 1.8 Threat Model & Omission Resistance
- **Untrusted Index Operator**: The VIndex operator is untrusted. An adversary cannot forge proofs, omit occurrences, or equivocate state commitments without breaking SHA-256 or being detected by independent witnesses.
- **Trusted Input Log**: The Input Log is assumed to have an authentic, append-only history protected by cryptographic checkpoints.
- **Proof of Completeness**: Every lookup response combines two cryptographic proofs:
  1. **MPT Proof (`mpt-proof-v1`)**: Proves whether `KeyHash` exists in `MapRoot`. Non-inclusion proves key absence across the entire log history. Inclusion proves the key maps to a specific 32-byte `MiniLogRoot`.
  2. **RFC 6962 Compact Range Proof (`prefix-compact-range-v1` + `indices-v1`)**: Proves that the returned leaf indices, when accumulated with the prefix compact range, hash to `MiniLogRoot`.

### 1.9 Inductive Backward Verification Protocol
Client-side verification of paginated queries operates as an inductive backward chain:

1. **Base Step (Page 1 / Tip Query, `before == nil`)**:
   - Extract `MapRoot` from the verified Output Log checkpoint and leaf.
   - Verify `mpt-proof-v1` against `MapRoot` to extract `MiniLogRoot`.
   - Initialize `compact.Range` with `prefix-compact-range-v1` (commits to historical prefix `0 .. next_before-1`). If no earlier entries exist, the prefix is empty.
   - Append `LeafHash(idx) = SHA256(0x00 || BigEndian(idx))` for each index in `indices-v1`.
   - Assert `CompactRange.Root() == MiniLogRoot`.
   - Retain `prefix-compact-range-v1` as the expected target compact range for the subsequent continuation page.
2. **Inductive Step (Continuation Pages, `before != nil`)**:
   - Initialize a new `compact.Range` with the continuation page's `prefix-compact-range-v1`.
   - Append `LeafHash(idx)` for each index in the continuation page's `indices-v1`.
   - Assert that the resulting compact range state matches the prefix compact range retained from the preceding page.
   - Retain the current page's `prefix-compact-range-v1` for the next backward continuation step.
   - Repeat until genesis (empty prefix compact range) is reached.
3. **Context Dependency**: Standalone continuation queries (`before != nil`) executed without prior page context cannot be verified against `MapRoot` in isolation because `MiniLogRoot` commits only to the full mini-log accumulator at the tip. Continuation pages must be verified inductively starting from Page 1 downward.

### 1.10 Moving-Goalpost Prevention
When indexing high-velocity logs, the log head advances continuously. Polling unverified checkpoints risks synchronization starvation. The coordinator freezes verified target sync checkpoints into Pebble metadata (`m_target_checkpoint`) prior to batch processing, ensuring that the ingestion pipeline processes fixed ranges to completion before advancing.

---

## 2. Verified Performance Optimizations

### 2.1 Zero-WAL Direct Inverted Chunk Commits
Rather than staging entries in a transient Write-Ahead Log, VIndex streams mapped batches directly into Pebble inverted chunk records (`'c' + KeyHash + ^chunkNum`) with a synchronous durability barrier (`pebble.Sync`).
- **Throughput Advantage**: Full Go SumDB ingestion throughput increased by **+24.7%** (from 192,783 to 240,467 leaves/sec), indexing 54.3M leaves in 3m 46s.
- **Tail Latency Eradication**: P99 read latencies dropped by **~93–99%** (down from 1,214 ms under WAL compaction to 11.3 ms for 1-to-1 workloads, and down from 847.8 ms to 62.2 ms for CT fanout).
- **Instant Warm Recovery**: Restart time-to-first-serve dropped to **2.4 ms**, eliminating WAL scanning and replay.
- **Storage Footprint**: Pebble database size in CT fanout tests dropped by **99%** (from 1.2 GB to 9.91 MB).

### 2.2 Bundled WebAssembly Execution (`map_bundle`)
The host passes up to 256 contiguous leaves to the guest WASM sandbox in a single invocation (`map_bundle`), slashing FFI boundary crossings from 768 per tile (in per-leaf mapping) to 2–3 per tile. FFI CPU overhead dropped from **~23% of total CPU time to < 1%**.

### 2.3 Host Hardware SIMD Cryptography
WASM guest plugins extract and emit raw canonical Claim Subject preimages (e.g. lowercase Punycode domain strings, escaped Go module paths). The Go host hashes preimages using standard `crypto/sha256`, which leverages hardware vector instructions (**x86 SHA-NI** or **ARMv8 Crypto**). This eliminated the **~55% CPU software crypto bottleneck** inside WebAssembly bytecode.

### 2.4 Bitwise Inverted Chunk Keys & 33-Byte Prefix Bloom Filters
Index records use the key encoding:
```text
Key = 'c' (1B) + KeyHash (32B) + BigEndian(^chunkNum) (8B)
```
where `^chunkNum = math.MaxUint64 - chunkNum`.
Because Pebble Bloom filters evaluate exclusively during forward prefix seeks (`SeekPrefixGE`), inverting chunk numbers places the newest active chunk lexicographically first. A single `SeekPrefixGE('c' + KeyHash)` checks the 33-byte Bloom filter and lands directly on the active chunk in O(1) time without scanning historical chunks, eliminating up to 7.5x append latency penalties on deep keys.

### 2.5 16-Bit Relative Index Offsets & Delimitless Binary Chunk Schema
Within each 65,536-leaf chunk, indices are stored as 2-byte offsets `uint16(index % 65536)`, saving 75% storage compared to 8-byte integers. Chunks serialize `CoveredSize` (8B), `bits.OnesCount64(CoveredSize)` compact hashes (32B each), and relative indices (2B each) without internal delimiters, enabling exact boundary slicing.

### 2.6 Split-Locking for Sub-5ms MPT Write Critical Section
The authenticated trie subsystem isolates background disk persistence (`writeMu`) from in-memory lookup reads (`treeMu.RLock()`):
- Disk fsync operations (`Sync()`, taking 5–20ms) run under `writeMu` and never acquire `treeMu`.
- HTTP lookup handlers calling `Prove()` execute under `treeMu.RLock()` without blocking.
- The exclusive write lock (`treeMu.Lock()`) is held strictly for in-memory node updates and pointer ratcheting, completing in microseconds (< 5ms).
- Benchmark telemetry showed 12.8x higher lookup throughput under disk sync (678,000 vs 53,000 reads/sec) compared to coarse global locking.

### 2.7 Two-Generational Active Chunk Cache
The storage engine maintains a bounded 2-generational cache (`currentCache` and `previousCache` in `KVIndexer`, capped at 32,768 entries). This eliminates more than 90% of Pebble block cache read I/O on active chunks during sequential batching without coarse full-cache invalidation freezes.

### 2.8 Pipelined Concurrency with Resequencer Min-Heap
CPU-bound mapping runs across a parallel worker pool (`max(1, GOMAXPROCS - 1)` workers, ~4 MB RAM/worker). Completed batches are buffered in a priority queue min-heap keyed by `BundleIdx = StartLeafIdx / 256`, re-serializing out-of-order completions into strictly ascending chronological sequence before delivery to the serialized commit plane.

### 2.9 SafeWatermark Bounded Tile Reaper
The local tile cache serves as the immutable log of record. `TileReaper` prunes cached tiles strictly below:
```text
SafeWatermark = min(m_kv_size, MPT_Durable_Size) == MPT_Durable_Size
```
Tiles in the window `[MPT_Durable_Size .. m_kv_size)` are preserved, guaranteeing that dirty crash recovery replays missing MPT state directly from local disk without network egress.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Dual-Disk Physical NVMe Isolation
Deploying MPT working files and Pebble DB on separate physical NVMe SSDs is recommended for large installations:
- **Disk A (NVMe SSD)**: Pebble DB (`'c'` chunks, `'m'` metadata) and local managed tile cache.
- **Disk B (NVMe SSD)**: MPT `mmap` working tree and append-only leaf files.
Physical separation isolates heavy sequential MPT compaction writes from Pebble LSM memtable flushes, preventing compaction write stalls.

### 3.2 Resource Sizing & Memory Footprint Scaling Matrix
Because key hashes are uniformly distributed, MPT batch updates touch scattered nodes. Sufficient RAM must be provisioned to keep active MPT nodes resident:

| Scale (Unique Keys) | MPT Memory (`mmap`) | MPT Leaf Disk | Pebble Disk | Recommended RAM | Recommended GCP VM |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (10M)** | ~1.04 GB | ~320 MB | ~1 GB | 8 GB | `e2-standard-2` |
| **Medium (100M)** | ~10.4 GB | ~3.2 GB | ~10 GB | 64 GB | `n2-highmem-8` |
| **Large (1B)** | ~104 GB | ~32 GB | ~100 GB | 256 GB | `n2-megamem-16` |
| **Very Large (2B)** | ~208 GB | ~64 GB | ~200 GB | 512+ GB | `m4-megamem-64` |

### 3.3 Forward-Compatibility: Prefix-Trie & Subtree Indexing
While VIndex v1 provides point lookups by 32-byte key hashes, guest plugins emit raw canonical Claim Subject preimages (e.g. domain names, package paths). This allows future VIndex versions to construct auxiliary prefix-trie indices (for `*.example.com` or `github.com/org/*` subtree queries) without altering guest WASM ABIs.

### 3.4 Pluggable Adaptive HTTP Transport
For initial log catchup against rate-limited CDNs, `TileFetcher` can accept custom `http.RoundTripper` implementations providing token-bucket rate limiting or AIMD adaptive concurrency.

### 3.5 Operational Observability, Prometheus Metrics & SLO Thresholds
The daemon exports Prometheus metrics covering ingestion lag (`vindex_ingestion_lag`), mapping latency (`vindex_map_bundle_duration_seconds`), commit lock durations (`vindex_mpt_write_duration_seconds`), and read latencies (`vindex_lookup_latency_seconds`). Standard SLO targets: P99 read latency < 50ms, ingestion lag < 60s, read availability >= 99.9%.

### 3.6 Single-Host Disaster Recovery Procedures
- **MPT Disk Corruption**: Rebuilt entirely in RAM from Pebble inverted chunks (`'c'`) via `store.GetSubRoot` point queries without network egress.
- **Pebble Storage Corruption**: Replayed from local tile cache or streamed from upstream Input Log.
- **Runtime Trap / Invariant Divergence**: Deterministic `HALT` policy freezes state and preserves disk data for forensics.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode (Genesis Catch-Up Mode) Retirement
- **What Was Proposed & Investigated**:
  A dedicated bulk ingestion mode ("Backfill Mode" or "Genesis Catch-Up Mode") was designed and implemented across `vindex.Backfill`, `Coordinator.Backfill`, and `vindexd --backfill`. In this mode, leaf batches were streamed directly into Pebble and applied directly to in-memory MPT nodes via `mptMgr.SetBatch`, completely bypassing per-batch lock-free root prediction (`mpt.Predict`), Tessera Output Log publishing, and witness cosignatures. The mode used coarse periodic snapshotting and disk sync intervals (`backfillSnapInterval = 1,000,000`, `backfillSyncInterval`), followed by a post-catchup publishing step (`pub.PublishDirect`) upon reaching the target checkpoint.
- **Why It Was Investigated**:
  Theoretical concern that during initial synchronization from genesis (tens of millions of leaves), running `mpt.Predict` and publishing Output Log commitments per batch would cause severe memory accumulation, excessive heap cloning, and witness network roundtrip bottlenecks.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  An 8-run empirical benchmark matrix on multi-core NVMe hardware comparing Normal Serving Mode (`SyncOnce`) against Backfill Mode revealed:
  1. **Normal Mode is 85.1% Faster on Go SumDB**: Normal Mode achieved **90,797.2 leaves/sec** vs. Backfill Mode's **49,063.6 leaves/sec**. Normal Mode batches storage updates and streams leaf bundles efficiently without the per-batch in-memory MPT mutation overhead that throttles Backfill Mode.
  2. **100% Read Starvation in Backfill Mode**: Backfill Mode shut down the HTTP read server, causing 0% query availability for the entire ingestion window. In contrast, Normal Mode sustained sub-2ms P50 latency with 100% availability under concurrent queries while ingesting.
  3. **Identical Memory Footprint**: Backfill Mode yielded no meaningful RSS reduction (saving only 20–30 MB out of a 220 MB working set) because Pebble LSM write buffers and MPT node allocations dominate memory.
  4. **Production Personalities Never Adopted Backfill**: Real demonstrator CLIs (`sumdbindex`, `mtcindex`) never called Backfill Mode; both achieved headline rates (240,467 leaves/sec) using Normal Serving Mode (`SyncOnce`).
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode provided zero throughput advantage, introduced severe read starvation, duplicated batch streaming logic, and created dead code across 6 source files and 3 test files. It was permanently pruned from the codebase in Milestone M3.

### 4.2 Intermediate Write-Ahead Log in Storage ('w' Prefix & WalReaper)
- **Proposed**: Staging mapped records under a transient `'w'` prefix in Pebble DB before an asynchronous background worker (`WalReaper`) converted them into inverted chunks (`'c'`) and deleted `'w'` keys.
- **Findings**: Caused double-write disk amplification, massive LSM compaction churn, and severe P99 read latency spikes (up to 1,214 ms).
- **Resolution**: Retired in favor of the Zero-WAL direct inverted chunk commit architecture.

### 4.3 Per-Leaf WebAssembly Invocation (`map_leaf`)
- **Proposed**: Invoking WASM `map_leaf` individually for every leaf entry.
- **Findings**: Generated 768 FFI boundary crossings per 256-leaf tile, consuming ~23% of total host CPU time in FFI overhead.
- **Resolution**: Replaced with bundled tile mapping (`map_bundle`), reducing FFI transitions to 2–3 per tile (< 1% CPU).

### 4.4 In-Guest Software Cryptographic Hashing
- **Proposed**: Compiling SHA-256 cryptographic hashing into guest WebAssembly bytecode.
- **Findings**: Consumed ~55% of all CPU cycles during mapping due to lack of SIMD vector instructions inside WASM.
- **Resolution**: Delegated hashing to the Go host (`crypto/sha256`), leveraging hardware vector instructions (SHA-NI / ARMv8 Crypto).

### 4.5 Sparse Merkle Trees (SMT) & Verkle Trees
- **Sparse Merkle Trees (SMT)**: Rejected due to prohibitive memory and disk I/O across 256-level tree depths.
- **Verkle Trees**: Rejected due to high CPU polynomial commitment generation costs during high-throughput ingestion.
- **Resolution**: Standardized on binary Sparse Merkle Patricia Trie in `mmap` (`torchwood/mpt`).

### 4.6 Forward Paging (`start=X&limit=M`)
- **Proposed**: Returning indices in ascending chronological order from a start cursor.
- **Findings**: Requires either returning unverified future state, maintaining complex arbitrary suffix subtree proofs, or forcing clients to scan millions of historical entries to reach the latest state.
- **Resolution**: Standardized on backward paging (`before=X&limit=M`), leveraging the natural prefix property of Merkle compact ranges and inverted chunk layout.

### 4.7 Distributed Key-Value Engines (Cloud Bigtable, Spanner, Cassandra)
- **Proposed**: Backing the inverted chunk store with a distributed NoSQL database.
- **Findings**: The authenticated MPT already requires single-host physical RAM/mmap locality; remote RPC hops degrade bulk ingestion throughput by orders of magnitude without solving tree state replication.
- **Resolution**: Embedded Pebble LSM engine encapsulated behind the `IndexStore` interface.
