# Verifiable Index (VIndex) v1

A **Verifiable Index (VIndex)** provides efficient, trustless, and cryptographically verifiable querying over append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB).

> **New to VIndex?** Jump straight into the [**5-Minute Quickstart Guide**](./QUICKSTART.md) or run `just demo-local` to launch a fully self-contained local indexer and query client.

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
- **O(1) Point Lookups & Subtree Prefix Lookups**: Constant-time point lookups and bounded prefix scans (`?prefix=true`) over variable-length canonical keys (`1..1024` bytes), returning verified mini-log roots and targeted lists of leaf pointers.
- **Two-Endpoint Read Protocol**: Separates state commitment & MPT proof generation (`GET /vindex/v1/keys/{key...}`) from lock-free Pebble entry pagination (`GET /vindex/v1/entries/{key...}?before=X`).
- **Omission Resistance**: Every query response delivers cryptographic inclusion proofs, non-inclusion proofs, or two-sided prefix proofs against witnessed checkpoints.
- **Decoupled Security**: VIndex operates as a secondary search overlay. If an indexer halts, corrupts, or falls behind, the underlying Input Log's consensus and security remain completely unaffected.

### Input Log Checkpoint Verification Schemes

When configuring `vindexd` or `vindex` CLI, `--input_log_pubkey` (or `--in_log_pubkey`) accepts either an inlined key string or a file path, supporting two verification schemes:

1. **Standard RFC 6962 / SumDB Note format**:
   ```text
   <name>+<hash>+<base64Key>
   ```
2. **Merkle Tree Certificates (MTC) format**:
   ```text
   mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>
   ```

> [!NOTE]
> Multiplexing multiple verifier schemes under `--input_log_pubkey` via string prefixes is an interim mechanism and will be refactored before production.

---

## 4. Non-Negotiable System Scope

1. **Strictly Single-Machine Deployment**: VIndex operates strictly within a single process on a single host. It avoids internal clustering, distributed consensus (Raft/Paxos), or multi-node replication. High availability is achieved externally: independent monitors and mirrors run standalone VIndex instances against the shared Input Log.
2. **Canonical Key & Bounded Prefix Lookups**: The production serving plane provides point queries and policy-guarded prefix queries (`?prefix=true`) over canonical printable ASCII keys (`1..1024` bytes, `0x21..0x7E`), alongside legacy 32-byte key-hash point lookups. Unbounded full-tree scans, arbitrary substring matches, and regex searches are out of scope.
3. **Strictly Append-Only (Zero Tombstones)**: The index state progresses strictly forward. The system supports no deletions, key un-mappings, rollbacks, or tombstones.
4. **Hermetic, Deterministic Mapping**: The WebAssembly guest plugin operates in a restricted WASI-free sandbox (`mapfn/host`) with zero host I/O, zero network access, and deterministic execution. Any runtime trap, memory fault, or unhandled exception triggers an immediate `HALT` to prevent unverified state divergence across nodes.

---

## 5. Core Terminology Glossary

- **Input Log**: The authoritative, append-only source transparency log containing the raw entries to be indexed.
- **Claim Subject**: The specific entity or identifier a log entry is about (e.g. domain name in CT, module path in Go SumDB, or artifact digest in Sigstore).
- **Canonical Key (Preimage)**: The normalized printable ASCII representation (`1..1024` bytes in `0x21..0x7E`, e.g. reversed-label domain `com.google.mail.` or case-escaped Go module path) extracted from a raw leaf by `MapFn`. Canonical keys are stored directly in the Sparse Merkle Patricia Trie (`internal/mpt`) to support both point and prefix proofs, and hashed via `SHA-256(key)` into 32-byte keys for Pebble inverted chunk storage (`internal/kvstore`).
- **MapFn**: A pure Go developer function (`type EmitMapFunc func(leaf []byte, emit func(key []byte))`) defining domain-specific key extraction logic via streaming callback without WebAssembly or runtime dependencies.
- **WASM Guest SDK (`mapfn/sdk`)**: The in-guest runtime harness compiled into the `.wasm` plugin that implements `map_bundle`, manages linear memory slabs, and invokes the user's `MapFn`.
- **WASM Sandbox Host (`mapfn/host`)**: The standalone, WASI-free Wazero worker pool that executes `.wasm` plugins deterministically, shared by the ingestion pipeline (`internal/ingest`) and offline developer CLI (`cmd/vindex-wasm`).
- **Inverted Chunk (`^chunkNum`)**: An LSM-tree partition storing up to 65,536 occurrence indices under a bitwise-inverted key number, placing the active append chunk lexicographically first.
- **Sparse Merkle Patricia Trie (MPT, `internal/mpt`)**: An authenticated binary trie (`filippo.io/torchwood/mpt`) mapping variable-length canonical keys (`1..1024` bytes) to 32-byte mini-log roots, supporting point inclusion, point non-inclusion, and two-sided prefix subtree proofs.
- **Witnessed Output Log**: A secondary append-only Merkle log (`tlog-tiles`) that commits to the cryptographic state (`MapRoot` + Input Log checkpoint) and is cosigned by an independent witness network.
- **Independent Auditor / Mirror**: A standalone daemon (`vindex-auditor`) that re-indexes both logs from leaf 0, asserts root equality, halts forward sync and freezes database files on disk upon mismatches, raises critical alerts, and by default keeps serving lookups pinned to the last verified checkpoint (`Serving_CP`) with an opt-in fail-closed mode (`--fail_closed=true`).

---

## 6. Role-Based Reading Pathways

### System Architect
- Start with [Architecture & Subsystem Mechanics](./docs/ARCHITECTURE.md) for the 5-stage pipeline flow, system-wide invariants, crash recovery guarantees, and retired alternatives.
- Read [Coordinator & Lifecycle Engine](./internal/coordinator/README.md) for watermark governance, moving-goalpost prevention, and Zero-WAL recovery sequences.
- Read [Inverted Chunk Storage Engine](./internal/kvstore/README.md) for Pebble LSM key layout, bitwise chunk inversion (`^chunkNum`), and Bloom filter mechanics.

### WASM Plugin Author
- Read [WASM Guest SDK & Plugin Interface](./mapfn/README.md) for the pure Go developer contract (`type EmitMapFunc func(leaf []byte, emit func(key []byte))`), low-level `map_bundle` memory slabs, and the `vindex-wasm` CLI.
- Review [Applications & Ecosystem Specifications](./docs/APPLICATIONS.md) for real-world canonicalization profiles across Certificate Transparency, MTC, Go SumDB, Sigstore, and Sigsum.

### Client Application Engineer
- Read [Client SDK & Query Proof Verification](./client/README.md) for the public Go client API, multi-section response parsing, and the 5-step cryptographic verification sequence.
- Read [Read Serving & C2SP Query Protocol](./internal/server/README.md) for HTTP endpoints, multi-section response formats, and the inductive backward verification protocol.

### Auditor & Mirror Operator
- Read [Independent Log Auditor & Verified Mirror](./internal/auditor/README.md) for the continuous audit loop, root mismatch alerting, state-preserving halts, pinned last-known-good serving, and verified mirror serving (`--serve_mirror`).
- Review operational commands in `cmd/vindex-auditor/`.

### Test & Performance Engineer
- Read [Benchmarks & Empirical Evaluation](./docs/BENCHMARKS.md) for full-scale Go SumDB and Certificate Transparency benchmarks, FFI overhead profiles, and capacity sizing matrices.
- Read [Hammer Load Testing & Verification Framework](./hammer/README.md) for synthetic Zipfian load generation, drip-feed proxy scheduling, and continuous invariant verification.

---

## 7. Complete Documentation Index

### Core Architecture & Ecosystems
- [**System Architecture**](./docs/ARCHITECTURE.md): Primary pipeline flow, subsystem map, system-wide invariants, Zero-WAL crash consistency, operational sizing, and retired alternatives.
- [**True Prefix Lookups & Two-Endpoint Protocol**](./docs/PREFIX_LOOKUPS.md): Variable-length canonical MPT keys, two-sided prefix proofs, reversed-label domain canonicalization, eTLD+1 policy guardrails, and the two-endpoint C2SP read protocol (`/vindex/v1/keys/` and `/vindex/v1/entries/`).
- [**Applications & Ecosystem Specifications**](./docs/APPLICATIONS.md): Universal Claim Subject Map model, canonicalization profiles, host hardware SIMD hashing, and ecosystem specifications (CT, MTC, Go SumDB, Sigstore, Sigsum).
- [**Benchmarks & Empirical Evaluation**](./docs/BENCHMARKS.md): Empirical telemetry on 24-core NVMe hardware, full Go SumDB ingestion (up to 295k leaves/sec sustained / 258k leaves/sec overall), read latency distributions, MapFn FFI profiling (< 1% CPU), and capacity planning guidelines.

### Client & Subsystem Specifications
- [**Client SDK & Query Proof Verification**](./client/README.md): Public, stateless Go client library, two-endpoint C2SP verification, two-sided prefix proofs, witness policies, monotonic history ratcheting, and backward pagination chains.
- [**C2SP Wire Format & Merkle Codecs**](./wire/wire.go): Public, zero-I/O C2SP multi-section parser/formatter, Output Log leaf codecs, and RFC 6962 mini-log compact range root computation.
- [**Ingestion Pipeline & Tile Cache**](./internal/ingest/README.md): Upstream tile fetching, local tile cache durability, WASM worker pool, host SIMD hashing, monotonic resequencing, and safe cache pruning.
- [**WASM Guest SDK & Plugin Interface**](./mapfn/README.md): Guest SDK runtime harness (`mapfn/sdk`), WASI-free Wazero sandbox host (`mapfn/host`), pack-and-wipe linear memory slabs, and `vindex-wasm` verification tooling.
- [**Inverted Chunk Storage Engine**](./internal/kvstore/README.md): Embedded Pebble LSM engine, inverted chunk keys (`'c' + KeyHash + ^chunkNum`), 33-byte prefix Bloom filters, delimitless 16-bit offset serialization, and the `pebble-tests` empirical suite.
- [**Authenticated State Commitment (MPT & Publisher)**](./internal/tree/README.md): Variable-length binary Sparse Merkle Patricia Trie (`internal/mpt`), non-blocking root prediction, 3-step atomic commitment dance (`internal/tree`), and split-locking concurrency (< 5ms critical section).
- [**Read Serving & C2SP Query Protocol**](./internal/server/README.md): Two-endpoint C2SP HTTP REST protocol (`/vindex/v1/keys/` and lock-free `/vindex/v1/entries/`), prefix policy guardrails, inductive backward verification, and reader snapshot isolation.
- [**Coordinator & Lifecycle Engine**](./internal/coordinator/README.md): Batch loop orchestration, checkpoint progression chain, moving-goalpost prevention (freezing target sync checkpoints), and 3-phase Zero-WAL crash recovery.
- [**Independent Log Auditor & Verified Mirror**](./internal/auditor/README.md): Full-log audit verification from leaf 0, root mismatch alerting, state-preserving forensic halts, pinned last-known-good checkpoint serving (`Serving_CP`), opt-in fail-closed revocation (`--fail_closed=true`), and verified mirror serving.

### Tooling & Verification
- [**Hammer Load Testing Framework**](./hammer/README.md): Integration load generator, Zipfian workload synthesizer, and concurrent verifying reader harness.

---

## 8. Repository Structure & Development Workflow

### Repository Structure
The `vindex/v1/` repository layout reflects the decoupled modular architecture:

- [`client/`](./client/README.md): Public, lightweight client verification SDK and HTTP client (decoupled from `pebble` and `wazero`).
- [`wire/`](./wire/): Public C2SP `tlog-vindex` multi-section wire framing, Output Log leaf codecs, and RFC 6962 mini-log root calculation.
- [`cmd/`](./cmd/): Command-line developer utilities and operational binaries.
  - [`vindex-wasm/`](./cmd/vindex-wasm/): Offline CLI tooling for inspecting, testing, and benchmarking WASM mapping plugins (decoupled from `net/http` and `tessera`).
- [`docs/`](./docs/): Authoritative specifications, system architecture designs, prefix lookup specs, application profiles, and empirical benchmarks.
- [`hammer/`](./hammer/README.md): Synthetic Zipfian load generator and closed-loop verification harness.
- [`internal/`](./internal/): Private core engine subsystems:
  - [`auditor/`](./internal/auditor/README.md): Full-log independent auditor, root mismatch detection, and verified mirror engine.
  - [`budget/`](./internal/budget/): Host resource budget calculation across system RAM, CPU cores, and storage caches.
  - [`coordinator/`](./internal/coordinator/README.md): Batch loop orchestration, watermark synchronization, and Zero-WAL crash recovery.
  - [`ingest/`](./internal/ingest/README.md): Upstream tile fetching, local tile cache durability, and concurrent mapping pipeline.
  - [`kvstore/`](./internal/kvstore/README.md): Embedded Pebble LSM inverted chunk storage engine with bitwise chunk inversion.
  - [`metrics/`](./internal/metrics/): Prometheus metrics registration, latency histograms, and engine telemetry instrumentation.
  - [`mpt/`](./internal/mpt/): Variable-length `torchwood/mpt` manager, canonical key validation, and point/prefix proof verification.
  - [`mtc/`](./internal/mtc/): Merkle Tree Certificate (MTC) binary parser, X.509 SAN/CN extractor, and reversed-label domain canonicalizer.
  - [`server/`](./internal/server/README.md): C2SP HTTP read server (`/vindex/v1/keys/`, `/vindex/v1/entries/`, `/vindex/v1/lookup/`) and prefix policy enforcement.
  - [`tree/`](./internal/tree/README.md): Output Log publisher, Tessera POSIX log integration, and 3-step state commitment.
  - [`verifier/`](./internal/verifier/): Public key verifier parsers supporting RFC 6962/SumDB notes and MTC cosigned subtree signatures.
- [`mapfn/`](./mapfn/README.md): WebAssembly guest SDK, sandbox host runtime, and example mapping plugins:
  - [`sdk/`](./mapfn/sdk/): In-guest runtime harness, pack-and-wipe memory slabs, and low-level ABI bindings.
  - [`host/`](./mapfn/host/): Standalone WASI-free Wazero sandbox host and deterministic memory pool.
  - [`examples/`](./mapfn/examples/): Example mapping plugins for transparency ecosystems (SumDB, Certificate Transparency, MTC, starter).
- [`vindex.go`](./vindex.go): Top-level engine lifecycle orchestrator (`Engine`) and public Go API entrypoint.

### Spec-Driven Development Workflow

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
