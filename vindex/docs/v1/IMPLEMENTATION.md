# Verifiable Index (v1) Implementation Proposal

This document outlines the first-draft technical implementation plan for a production-grade Verifiable Index (VIndex). It acts as the blueprint to transition the "Map Sandwich" architecture discussed in the README into a functional Go codebase.

## 1. Core Executables & Modules

The system is deployed as a single combined daemon (`vindexd`) alongside a WASM SDK. To enforce the separation of concerns, the daemon is internally split into three core sub-components that communicate with a legally shared key-value store:
- `Batch Builder / Mapper`: A background routine that polling-ingests the Input Log, verifies the leaf data is included in the log, runs the WASM mapping, and yields a stream of batches of mapped key-value pairs.
- `Index Updater`: A routine that takes the mapped pairs, updates the key-value store, updates the Verifiable Merkle Prefix Trie (MPT), and commits the new state to the Output Log.
- `Read Server`: A read-only API multiplexer that serves client queries from the MPT and KV store. Because it shares the `pebble.DB` reference, it exclusively uses the latest published Output Log state to natively ignore any inflight writes from the Index Updater.

**Daemon Flags Protocol**:
- `--input_log_url`: The URL of the Input Log to read from (must support [`tlog-tiles`](https://c2sp.org/tlog-tiles)).
- `--output_log_dir`: The directory where Output Log tiles will be written.
- `--db_path`: The directory where the Pebble database will be stored.
- `--wasm_path`: The path to the MapFn WASM module.
- `--poll_interval`: The interval between polling ticks (e.g. 10s).
- `--port`: The port to listen on for HTTP client queries.
- `wasm-tool` (or SDK): A component consisting of:
    - A Go library (`github.com/transparency-dev/vindex/wasm/guest`) that users import to register their `MapFn` and handle low-level marshalling (see [WASM Guest SDK Preview](#6-wasm-guest-sdk-preview)).
    - A CLI tool (or script) to facilitate compiling the user's Go code into a WASIP1 WASM binary.

## 2. Component Design

### 2.1 The Ingestion Engine (Batch Builder)
The `Batch Builder` will run a strict temporal polling loop (e.g. ticking every 10 seconds).
1. Read the latest `Output Log` leaf to determine exactly which `Input Log` checkpoint it successfully processed last.
2. Fetch the latest `Input Log` checkpoint (via `tlog-tiles`).
3. Fetch the delta of leaves between the two checkpoints.
4. **Cryptographic Verification**: The `Batch Builder` *must* verify that all fetched leaves are cryptographically committed to by the fetched `Input Log` checkpoint (e.g. by verifying inclusion proofs or recalculating the tree root). This ensures the index is immune to man-in-the-middle attacks serving fake or maliciously reordered leaves.
5. Push the verified leaves sequentially through the `MapFn` sandbox.

*Failure Mode*: If the system crashes mid-batch, it retains no state. On reboot, it re-queries the Output Log and re-processes the delta.

### 2.2 The Mapping Sandbox (WASM)
The primary reason for executing the `MapFn` inside a WebAssembly environment is to guarantee hermetic execution. This ensures the mapping logic remains completely deterministic and won't change behavior due to external factors like Go version updates. As a secondary benefit, because the `MapFn` operates on untrusted log byte slices, the WASM environment provides a heavily restricted security sandbox.
- **Runtime**: `wazero` (pure Go, zero CGO dependencies) allows hyper-fast instantiation.
- **Interface**: The WASM module exposes a single function `map_leaf(ptr, len) -> []Bytes`. The underlying Go function must implement the following signature:
  ```go
  type MapFn func([]byte) [][sha256.Size]byte
  ```
- **Validation**: The host Go process verifies that the returned byte stream is a multiple of 32 bytes (representing a list of SHA-256 hashes). These hashes are then used directly to update the index. No additional hashing is required.

### 2.3 The KV Data Store ("Map of Logs")
A persistent embedded key-value store optimized for fast writes and byte-range iteration. 
- **Database**: `Pebble` (CockroachDB's highly optimized LevelDB clone).
- **Schema**:
    - We evaluated three different storage layouts (Flat List, Log Construction, and Chunked Log) to balance write amplification, lookup latency, and tail-latency stalls under compaction.
    - **Default Layout**: **Chunked Log (PebbleChunk)**.
      - `Key`: `Hash(MapKey) + [BlockNum]` (40 bytes: 32B hash + 8B big-endian uint64 block number). `BlockNum = Input-Log-Index / 1024`.
      - `Value (Latest Block)`: `Header (1B)` + `PrevBlockNum (8B)` + `EndIndex (8B)` + `hashes (compact range)` + `RelativeIndices ([]uint16)`.
        - `EndIndex`: The absolute `Input-Log-Index` up to which this block's compact range is valid.
        - `hashes (compact range)`: Serialized hashes of the compact Merkle range. The number of hashes is determined by the number of set bits (1-bits) in `EndIndex`.
      - `Value (Older Blocks)`: `Header (1B)` + `PrevBlockNum (8B)` + `RelativeIndices ([]uint16)`. (Compact range is stripped).
      - **Relative Indices**: Each `uint16` in `RelativeIndices` represents an offset relative to the block's base index (`BlockNum * 1024`). For example, a relative index of `5` in block `2` represents absolute index `2053`.
      - **Linked Blockchain**: Blocks are backward-linked via `PrevBlockNum` (referencing the previous `BlockNum`), allowing history reconstruction via point lookups without expensive prefix scans.
    - For details on the alternative layouts and the performance benchmarks that led to this decision, see [Appendix: Storage Layout Evaluation](#8-appendix-storage-layout-evaluation).

### 2.4 The Verifiable Prefix Trie (MPT)
This maintains the global cryptographic map state.
- **Library**: `rsc/tmp/mpt`
- **Note**: We'll need to publish (or adopt) the `rsc` code before we can launch this. We are in open communication with Russ, so this won't be a problem.
- **Linkage**: For every `Hash(MapKey)` updated in the batch, the MPT is updated. The `<val>` field passed into the MPT is strictly the newly computed 32-byte *sub-root hash* of the key's "Map of Logs".

### 2.5 The Output Log
The cryptographic commit phase.
- **Library**: [Tessera](transparency-dev/tessera) POSIX implementation.
- **Structure**: It stores a tile-based Merkle tree directly into a filesystem/GCS bucket.
- **Leaf Format**:
  ```go
  type StateCommitment struct {
      MapRoot      [32]byte
      ILCheckpoint []byte // Raw bytes of the Input Log's signed tlog-tiles checkpoint
  }
  ```
- **Marshalling**: The `StateCommitment` leaf will be serialized simply as:
  `hex(MapRoot) + "\n" + ILCheckpoint`
  (i.e., 64 bytes of hex-encoded map root, a newline, followed by the raw checkpoint bytes).
- **Commit Phase**: After the MPT and Pebble DB safely flush to disk, `tessera` appends the `StateCommitment` leaf and updates the Output Log tile tree. See section 5.1 for atomicity details.

## 3. Serving API (`Read Server`)

A lightweight HTTP server (e.g., using `net/http` and standard JSON) exposing point lookups.
Since the Output Log guarantees that clients only care about the *latest* root, the `Read Server` routes always target the current state.

**Endpoint**: `GET /index/v1/lookup/{hashed_key}?start=N`
- `hashed_key`: The SHA-256 hash of the key the client is looking for.
- `start=N`: The incremental index size the client already knows (defaults to 0).

**Response Mechanics**:
1. Checks the MPT for the client's `hashed_key` to obtain the 32-byte sub-root.
2. Fetches the delta of matching Input Log `uint64` indices from `start=N` up to the current length inside the Pebble DB.
3. Returns the indices and the MPT inclusion proof. No consistency proof is computed or returned; clients are required to maintain a [compact range](https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md) to verify incremental updates.

## 4. Pipeline Concurrency & Batching

A major emergent property of this architecture is that the processing pipeline safely supports decoupling and **in-flight batch pipelining**. 

The system does *not* need to strictly block the ingestion and KV-store phases while waiting for the network-bound Output Log to witness and publish the previous batch.
- **Normal Operation**: The `Batch Builder` can safely map and write batches `M+1` and `M+2` to Pebble while the Output Log is still witnessing batch `M`. The `Read Server` seamlessly ignores the "future" pipelined writes in Pebble because its range queries are strictly capped by the actively published Output Log size `M`.
- **Crash Recovery**: If the system crashes with multiple pipelined batches in the KV store but unpublished in the Output Log, the replay recovery mechanism (`N_old` to `N_new`) automatically spans the entire gap. It will dynamically coalesce the dirtied keys from all in-flight batches into a single Output Log commit upon restart, gracefully squishing the pipeline back together.

## 5. Phase 1 Roadmap

1. **Step 1: Domain Interfaces**
   - Define Go interfaces for the `InputLogReader` and `OutputLogWriter`.
2. **Step 2: The KV & MPT Engine**
   - Wire `rsc/tmp/mpt`, alongside a `Pebble` KV store. Pebble is updated first, and then MPT and the OutputLog. See section 6.1 for details on atomicity.
3. **Step 3: The WASM Map Pipeline**
   - Build out the `wazero` host environment and simple test `.wasm` binaries.
4. **Step 4: The Ingestion Loop**
   - Write the main event loop bridging the components together.
5. **Step 5: API & Tooling**
   - Build the `Read Server` HTTP multiplexer and CLI tools for verification.

## 6. Open Questions / Issues

Here are design and architectural considerations that need refinement during the v1 implementation phase.

### 6.1 Atomicity of the Commit Phase

If the system crashes during the commit phase (e.g., after the KV store is updated but before the Output Log is successfully published), the persistent KV store will have run ahead of the published Output Log checkpoint. To recover safely without complex Write-Ahead Logs or background garbage collection tasks, the `Batch Builder` utilizes determinism and a special KV checkpoint.

**Recovery Strategy:**
1. **Atomic KV Metadata**: When the `Batch Builder` writes a batch of new indices and compact ranges to Pebble, it also atomically writes an internal target checkpoint metadata key (`_pebble_target_checkpoint = IL_Checkpoint_New`).
2. **Crash Detection**: On startup, the daemon reads the latest size from the published Output Log (`N_old`) and compares it against the size in `_pebble_target_checkpoint` (`N_new`). If `N_new > N_old`, the daemon knows Pebble successfully committed the batch, but the MPT/Output Log commit failed.
3. **Replaying the MapFn**: Rather than performing a full, expensive scan of the entire Pebble DB to discover which keys were updated (which would be required because the schema `Hash+Index` does not index by update-time), the `Batch Builder` simply fetches the Input Log leaves from `N_old` to `N_new` and re-runs the deterministic `MapFn`. 
4. **Resuming the Pipeline**: The `MapFn` acts as an exact diff generator, identically yielding the precise set of keys modified in the lost batch. The system looks up the *latest* already-written compact range for each of those dirtied keys in Pebble (which sit intact at sequence `N_new`), derives the sub-root hash, updates the MPT, and safely attempts to commit the `MapRoot` to the Output Log again. It is irrelevant whether the MPT had already been successfully updated prior to the crash; any tree rewrites during this recovery phase are inherently idempotent.

> [!NOTE]
> **Pending Discussion (MPT Concurrency & Snapshots)**
> While we have a robust strategy for recovering the KV store using deterministic replay, the MPT presents a severe concurrency bottleneck if it lacks snapshot capabilities. Because the `Read Server` strictly serves the last *published* Output Log state (`N_old`), an MPT that mutates in place cannot be safely queried while it is being updated to `N_new`. 
> 1. **Normal Operation**: To prevent serving uncommitted data, the `Index Updater` would need to hold a global exclusive mutex on the MPT. This lock would block all reads for the entire duration of the MPT update *and* the synchronous Output Log witnessing phase, causing massive latency spikes on every batch.
> 2. **Crash Recovery**: A crash *after* the MPT is mutated but *before* the Output Log publishes leaves the MPT stuck at `N_new`, completely breaking reads for `N_old` until the recovery process finishes.
>
> **Action**: We must evaluate `rsc/tmp/mpt` capabilities with Russ to determine if it can support A/B versions of the tree (or reliable snapshots). This is a critical path requirement ensuring the Read Server can seamlessly and concurrently serve the prior state during both normal ingestion and crash recovery.

## 7. WASM Guest SDK Preview

Here is a preview of what the user-facing API and the internal implementation of the WASM library are likely to look like.

### 7.1 User Code (`main.go`)

```go
package main

import (
	"crypto/sha256"
	"github.com/transparency-dev/vindex/wasm/guest"
)

func myMapFn(leaf []byte) [][sha256.Size]byte {
	// 1. Parse the leaf (e.g., JSON, Protobuf, etc.)
	// 2. Extract keys to index
	// 3. Return the hashes of those keys
	return [][sha256.Size]byte{
		sha256.Sum256([]byte("key1")),
		sha256.Sum256([]byte("key2")),
	}
}

func main() {
	// Register the function with the SDK
	guest.RegisterMapFn(myMapFn)
}
```

### 7.2 SDK Internals (` guest` package)

```go
package guest

import (
	"crypto/sha256"
	"unsafe"
)

type MapFn func([]byte) [][sha256.Size]byte

var registeredFn MapFn

// RegisterMapFn is called by the user's main() to wire up their logic.
func RegisterMapFn(fn MapFn) {
	registeredFn = fn
}

// map_leaf is the low-level function exported to the wazero host.
// We use //go:wasmexport to expose it.
//
//go:wasmexport map_leaf
func map_leaf(ptr uint32, len uint32) uint64 {
	// 1. Convert the raw WASM memory pointer/len into a Go slice
	input := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), len)

	// 2. Call the user's registered function
	if registeredFn == nil {
		return 0 // Or handle error
	}
	outputHashes := registeredFn(input)

	// 3. Serialize the results (flatten [][32]byte into a single []byte)
	serialized := flatten(outputHashes)

	// 4. Write the results back to WASM memory and return the new ptr/len
	// (This typically requires a helper to allocate memory for the return value)
	return packPtrLen(allocateAndWrite(serialized))
}

## 8. Appendix: Storage Layout Evaluation

During the implementation design phase, we evaluated three alternative layouts for storing index data in Pebble DB.

### 8.1 Evaluated Layouts
1.  **Flat List (PebbleFlat)**: Maps `Hash(Key)` to a serialized list of all its input log indices (`[]uint64`).
    *   *Pros*: Fast read lookups (single `Get`).
    *   *Cons*: High write amplification for hot keys (rewriting the entire history on every append).
2.  **Log Construction (PebbleLog)**: Maps `Hash(Key) + [Input-Log-Index]` to a serialized `compact.Range` (mini Merkle tree) state. Old values are cleared.
    *   *Pros*: Small write size, low write amplification.
    *   *Cons*: Read lookups require a prefix scan. Write path requires an iterator seek to find the latest index, which suffers from severe stalls during background compactions.
3.  **Chunked Log (PebbleChunk)**: Groups indices into blocks of 1024. Maps `Hash(Key) + [BlockNum]` to a chunk of relative `uint16` indices. Blocks are backward-linked.
    *   *Pros*: Caps write size (max 2KB blocks), eliminates prefix scans (uses point gets following links), and reduces key cardinality by 1000x, resolving write stalls.

### 8.2 Performance Comparison (Sustained Load)
We ran a 45-second write-heavy benchmark (10 hot keys, batch size 1000) to force background compactions and measure tail latencies and write stalls.

| Metric | PebbleFlat (Flat List) | PebbleLog (Log Construction) | PebbleChunk (Chunked Log) |
| :--- | :--- | :--- | :--- |
| **Write Throughput** | 2,012 batches | 3,508 batches | **14,311 batches** (7x vs Flat) |
| **Commit Latency (p50)** | 23.57 ms | 894.65 µs | **553.03 µs** |
| **Commit Latency (p99)** | 44.72 ms | 463.41 ms | **1.67 ms** (270x faster than Log) |
| **Commit Latency (Max)** | 117.17 ms | 1.15 s | **55.87 ms** (20x faster than Log) |
| **Write Stalls (>500ms)** | **0** | 32 | **0** |
| **WAL Bytes Written** | 16.22 GB | **1.34 GB** | 6.88 GB (2.4x less than Flat) |
| **Disk Space (Hot Keys)** | 8.24 MB | **5.52 MB** | 7.89 MB |

### 8.3 Conclusion
`PebbleChunk` was selected as the default layout because it resolves the write stalls of `PebbleLog` by reducing key cardinality (making seeks cache-friendly) while keeping write amplification low.
```

