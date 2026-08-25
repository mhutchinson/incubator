# Verifiable Index (VIndex) v1

A **Verifiable Index (VIndex)** provides efficient, trustless, and cryptographically verifiable querying over append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB).

---

## 1. Context & Problem Statement

Append-only transparency logs provide tamper-evident discoverability: anyone can mathematically verify that an entry exists at a specific sequence number in the log. However, discovering records by content (e.g., domain name, module path, or public key hash) historically forced an impossible trade-off:

1. **Massive Client Inefficiency**: Finding a subject required clients to download, deserialize, and scan gigabytes or terabytes of irrelevant log entries locally.
2. **Loss of Verifiability**: To avoid local downloads, users relied on centralized, third-party search APIs (such as `crt.sh`). However, these services lack cryptographic commitments; an untrusted or compromised operator can omit, reorder, or forge search results without detection.

A **Verifiable Index (VIndex)** eliminates this trade-off by acting as an authenticated "back-of-the-book index" that delivers O(1) point lookups with logarithmic Merkle inclusion proofs, mathematically guaranteeing completeness against witnessed checkpoints.

---

## 2. Background & Lineage

VIndex v1 represents the distillation of years of research, experimentation, and production experience with verifiable key-value mappings over transparency logs:

- [**Google Key Transparency**](https://github.com/google/key-transparency): Early pioneer in verifiable identity-to-key mapping, exploring sparse Merkle tree lookups and continuous auditability.
- [**Trillian Batch Map**](https://github.com/google/trillian/tree/master/experimental/batchmap): Experimental map engine investigating batch-oriented Sparse Merkle Tree mutations and log integration.
- [**VIndex Prototype (v0 MVP)**](../README.md): The working prototype in the parent directory (`vindex/`), which validated the core "Map Sandwich" concept, in-process Pebble storage, and demonstrated full-scale indexing on the Go Checksum Database (SumDB).

### The Key Evolution: Pure Indexing vs. State Summarization
Earlier systems attempted to act as verifiable state machines that copied, aggregated, or summarized application data directly inside the map nodes. VIndex v1 makes a fundamental architectural departure: it focuses **purely on indexing** an existing log rather than summarizing its state:
- **Pointers, Not Copies**: The index stores lightweight leaf pointers (indices) referencing the authoritative Input Log, rather than replicating or transforming leaf payloads.
- **High Throughput & Bounded Footprint**: Storing compact relative index offsets eliminates data amplification, enabling sustained indexing speeds exceeding 240,000 leaves per second on commodity hardware.
- **Clear Security Boundaries**: The Input Log remains the sole source of truth. VIndex acts as an untrusted search overlay; if the indexer halts, corrupts, or falls behind, the underlying log's consensus and integrity are completely unaffected, and clients independently verify retrieved leaf data against the Input Log's signed checkpoints.

---

## 3. The Map Sandwich Architecture

The VIndex topology bounds search indexing between two append-only logs—a structure known as the **"Map Sandwich"**:

| Component | Physical Role | Cryptographic Contract |
| :--- | :--- | :--- |
| **Input Log** | Authoritative source of truth (e.g. CT, MTC, Go SumDB, Sigstore). | Strictly append-only log of raw leaves and signed tree checkpoints. |
| **vindexd Daemon** | Single-host indexing and serving engine. | Ingests tiles, executes sandboxed WASM mapping, stores inverted chunks in Pebble DB, commits state in an in-memory MPT, and serves C2SP HTTP lookups. |
| **Output Log** | Cryptographic anchor committing to index state (`MapRoot` + Input Log checkpoint). | Append-only log of state commitments signed and monitored by an independent witness network. |

### Core System Guarantees
- **O(1) Point Lookups**: Constant-time key lookups returning targeted lists of leaf pointers.
- **Omission Resistance**: Every query response delivers cryptographic inclusion proofs (for matching keys) or non-inclusion proofs (for absent keys) against witnessed checkpoints.
- **Decoupled Security**: VIndex operates as a secondary search overlay. If an indexer halts, corrupts, or falls behind, the underlying Input Log's consensus and security remain completely unaffected.

---

## 4. Non-Negotiable System Scope

1. **Strictly Single-Machine Deployment**: VIndex operates strictly within a single process on a single host. It avoids internal clustering, distributed consensus (Raft/Paxos), or multi-node replication. High availability is achieved externally: independent monitors and mirrors run standalone VIndex instances against the shared Input Log.
2. **Point Lookups by 32-Byte Key Hashes**: The production serving plane provides point queries exclusively over exact 32-byte key hashes (`KeyHash = SHA256(CanonicalSubject)`). Cross-key scans, substring matches, full-text queries, and arbitrary regex searches are out of scope.
3. **Strictly Append-Only (Zero Tombstones)**: The index state progresses strictly forward. The system supports no deletions, key un-mappings, rollbacks, or tombstones.
4. **Hermetic, Deterministic Mapping**: The WebAssembly guest plugin operates in a restricted sandbox with zero host I/O, zero network access, and deterministic clocks. Any runtime trap, memory fault, or unhandled exception triggers an immediate `HALT` to prevent unverified state divergence across nodes.

---

## 5. Core Terminology Glossary

- **Input Log**: The authoritative, append-only source transparency log containing the raw entries to be indexed.
- **Claim Subject**: The specific entity or identifier a log entry is about (e.g. domain name in CT, module path in Go SumDB, or artifact digest in Sigstore).
- **Canonical Preimage**: The normalized byte or string representation of a Claim Subject (e.g. lowercase Punycode domain `example.com`) extracted from a raw leaf by the `MapFn` callback before host-side hashing.
- **MapFn**: A pure Go developer function (`type MapFn func([]byte) []string`) defining domain-specific key extraction logic without WebAssembly or runtime dependencies.
- **WASM Guest SDK (`mapfn/sdk`)**: The in-guest runtime harness compiled into the `.wasm` plugin that implements `map_bundle`, manages linear memory slabs, and invokes the user's `MapFn`.
- **WASM Mapper (`internal/ingest`)**: The host-side worker pool that executes `.wasm` plugins inside Wazero sandboxes, extracts canonical preimages, and hashes them via native CPU SIMD instructions.
- **Inverted Chunk (`^chunkNum`)**: An LSM-tree partition storing up to 65,536 occurrence indices under a bitwise-inverted key number, placing the active append chunk lexicographically first.
- **Sparse Merkle Patricia Trie (MPT)**: An authenticated binary trie mapping 32-byte key hashes to 32-byte mini-log roots, supporting logarithmic inclusion and non-inclusion proofs.
- **Witnessed Output Log**: A secondary append-only Merkle log (`tlog-tiles`) that commits to the cryptographic state (`MapRoot` + Input Log checkpoint) and is cosigned by an independent witness network.
- **Independent Auditor / Mirror**: A standalone daemon (`vindex-audit`) that re-indexes both logs from leaf 0, asserts root equality, halts forward sync and freezes database files on disk upon mismatches, raises critical alerts, and by default keeps serving lookups pinned to the last verified checkpoint (`Serving_CP`) with an opt-in fail-closed mode (`--fail_closed=true`).

---

## 6. Role-Based Reading Pathways

### System Architect
- Start with [Architecture & Subsystem Mechanics](./docs/ARCHITECTURE.md) for the 5-stage pipeline flow, system-wide invariants, crash recovery guarantees, and retired alternatives.
- Read [Coordinator & Lifecycle Engine](./internal/coordinator/README.md) for watermark governance, moving-goalpost prevention, and Zero-WAL recovery sequences.
- Read [Inverted Chunk Storage Engine](./internal/kvstore/README.md) for Pebble LSM key layout, bitwise chunk inversion (`^chunkNum`), and Bloom filter mechanics.

### WASM Plugin Author
- Read [WASM Guest SDK & Plugin Interface](./mapfn/README.md) for the pure Go developer contract (`type MapFn func([]byte) []string`), low-level `map_bundle` memory slabs, and the `vindex-map` CLI.
- Review [Applications & Ecosystem Specifications](./docs/APPLICATIONS.md) for real-world canonicalization profiles across Certificate Transparency, MTC, Go SumDB, Sigstore, and Sigsum.

### Client Application Engineer
- Read [Client SDK & Query Proof Verification](./client/README.md) for the public Go client API, multi-section response parsing, and the 5-step cryptographic verification sequence.
- Read [Read Serving & C2SP Query Protocol](./internal/server/README.md) for HTTP endpoints, multi-section response formats, and the inductive backward verification protocol.

### Auditor & Mirror Operator
- Read [Independent Log Auditor & Verified Mirror](./internal/auditor/README.md) for the continuous audit loop (`AuditOnce`), root mismatch alerting, state-preserving halts, pinned last-known-good serving, and verified mirror serving (`--serve_mirror`).
- Review operational commands in `cmd/vindex-audit/`.

### Test & Performance Engineer
- Read [Benchmarks & Empirical Evaluation](./docs/BENCHMARKS.md) for full-scale Go SumDB and Certificate Transparency benchmarks, FFI overhead profiles, and capacity sizing matrices.
- Read [Hammer Load Testing & Verification Framework](./hammer/README.md) for synthetic Zipfian load generation, drip-feed proxy scheduling, and continuous invariant verification.

---

## 7. Complete Documentation Index

### Core Architecture & Ecosystems
- [**System Architecture**](./docs/ARCHITECTURE.md): Primary pipeline flow, subsystem map, system-wide invariants, Zero-WAL crash consistency, operational sizing, and retired alternatives.
- [**Applications & Ecosystem Specifications**](./docs/APPLICATIONS.md): Universal Claim Subject Map model, canonicalization profiles, host hardware SIMD hashing, forward-compatible prefix tries, and ecosystem specifications (CT, MTC, Go SumDB, Sigstore, Sigsum).
- [**Benchmarks & Empirical Evaluation**](./docs/BENCHMARKS.md): Empirical telemetry on 24-core NVMe hardware, full Go SumDB ingestion (240k leaves/sec), read latency distributions, MapFn FFI profiling (< 1% CPU), and capacity planning guidelines.

### Client & Subsystem Specifications
- [**Client SDK & Query Proof Verification**](./client/README.md): Public, stateless Go client library, C2SP response parsing, 5-step cryptographic verification sequence, and backward pagination chains.
- [**Ingestion Pipeline & Tile Cache**](./internal/ingest/README.md): Upstream tile fetching, local tile cache durability, WASM worker pool, host SIMD hashing, monotonic resequencing, and `TileReaper` pruning.
- [**WASM Guest SDK & Plugin Interface**](./mapfn/README.md): Guest SDK runtime harness, pack-and-wipe linear memory slabs, high-level developer experience, bytecode immutability, and `vindex-map` verification tooling.
- [**Inverted Chunk Storage Engine**](./internal/kvstore/README.md): Embedded Pebble LSM engine, inverted chunk keys (`'c' + KeyHash + ^chunkNum`), 33-byte prefix Bloom filters, delimitless 16-bit offset serialization, and the `pebble-tests` empirical suite.
- [**Authenticated State Commitment (MPT & Publisher)**](./internal/tree/README.md): Binary Sparse Merkle Patricia Trie in `mmap`, lock-free root prediction (`mpt.Predict`), 3-step atomic commitment dance, and split-locking concurrency (< 5ms critical section).
- [**Read Serving & C2SP Query Protocol**](./internal/server/README.md): C2SP HTTP REST endpoints, multi-section plaintext wire format, inductive backward verification protocol, and reader snapshot isolation.
- [**Coordinator & Lifecycle Engine**](./internal/coordinator/README.md): Batch loop orchestration (`SyncOnce`), checkpoint progression chain, moving-goalpost prevention (freezing target sync checkpoints), and 3-phase Zero-WAL crash recovery.
- [**Independent Log Auditor & Verified Mirror**](./internal/auditor/README.md): Full-log audit verification from leaf 0, root mismatch alerting, state-preserving forensic halts, pinned last-known-good checkpoint serving (`Serving_CP`), opt-in fail-closed revocation (`--fail_closed=true`), and verified mirror serving.

### Tooling & Verification
- [**Hammer Load Testing Framework**](./hammer/README.md): Integration testbed, Zipfian synthetic generator, Tessera POSIX sequencer, drip-feed proxy schedules, and verifying concurrent readers.

---

## 8. Spec-Driven Development Workflow

The VIndex codebase is organized into a stacked development hierarchy:

```text
v1/docs (Specification Base) -> v1/impl (Engine Core) -> v1/personalities (Applications & Benchmarks)
```

1. **`v1/docs` (Base Specification)**: The bottom of the stack. Contains authoritative architectural designs, RFC-style subsystem specifications, load-bearing invariants, and empirical benchmark findings. Code changes are never committed here.
2. **`v1/impl` (Engine Implementation)**: Implements the core VIndex library (`vindex/v1`), internal worker packages (`internal/`), and the client verification SDK, conforming strictly to the `v1/docs` contracts.
3. **`v1/personalities` (Applications & Deployment)**: Builds ecosystem personality binaries (e.g. `cmd/sumdbindex`, `cmd/mtcindex`, `cmd/vindexd`), Docker deployment stacks, and end-to-end integration test harnesses.

### The Feedback Loop
Development follows iterative spec-driven cycles:
1. Specifications are updated at `v1/docs`.
2. The engine is developed or refactored in `v1/impl`.
3. Concrete personality applications and benchmarks are exercised in `v1/personalities`.
4. Empirical benchmark results and operational learnings from deployment are fed back into `v1/docs` at the base of the stack, beginning the next iteration.
