# Verifiable Index (VIndex) v1

A Verifiable Index (VIndex) provides efficient, trustless, and cryptographically verifiable querying over append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB).

Operating as a "Map Sandwich" between an Input Log and a witnessed Output Log, VIndex delivers O(1) point lookups with O(log N) cryptographic inclusion proofs, preventing untrusted index operators from omitting or equivocating records.

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                         Input Log                           │
  │    (Immutable Source of Truth: CT, MTC, Go SumDB, Sigstore) │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ Authenticated Entry Bundles
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                       vindexd Daemon                        │
  │  ┌───────────────────────┐       ┌───────────────────────┐  │
  │  │  In-Memory Binary MPT │       │   Pebble DB KV Store  │  │
  │  │   (KeyHash -> SubRoot)│       │ (Inverted Chunks 'c') │  │
  │  └───────────────────────┘       └───────────────────────┘  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ State Commitments (hex(MapRoot) + ILCheckpoint)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                    Witnessed Output Log                     │
  │      (Tessera Merkle Tree Tiles + Witness Cosignatures)     │
  └─────────────────────────────────────────────────────────────┘
```

## Core Terminology

- **Input Log**: The authoritative, append-only source transparency log (e.g., Certificate Transparency, Go SumDB) containing the raw entries and cryptographic checkpoints to be indexed.
- **Claim Subject**: The specific entity or identifier a log entry is about (e.g., domain name in CT, module path in Go SumDB, or artifact URI in Sigstore).
- **Canonical Preimage**: The normalized string or byte representation of a Claim Subject (e.g., lowercase Punycode domain `example.com`) extracted from a raw log leaf by the WASM `MapFn` before host-side hashing.
- **WASM MapFn**: A deterministic WebAssembly mapping function executing in an isolated sandbox (`wazero`) that extracts domain-specific search keys (`KeyHash = SHA256(canonicalKey)`) from raw log leaves.
- **Witnessed Output Log**: A secondary append-only Merkle log (`tlog-tiles`) that commits to the cryptographic state (`MapRoot` + Input Log checkpoint) and is signed by an independent witness network to prevent equivocation.

## Documentation Reading Pathways

- **System Architect**:
  - Read [Architecture & Subsystem Map](./docs/ARCHITECTURE.md) for full end-to-end data flow, invariants, and threat models.
  - Review [Coordinator & Recovery Subsystem](./internal/coordinator/README.md) for serialized batch commit loops and Zero-WAL crash recovery.
  - Review [KV Storage Subsystem](./internal/kvstore/README.md) for inverted chunk layouts and the Pebble encapsulation barrier.
- **WASM Plugin Author**:
  - Read [WASM MapFn Plugin SDK & Runtime](./mapfn/README.md) for the guest ABI, memory management protocol, and Go/TinyGo/Rust SDKs.
  - Read [Applications & Ecosystems](./docs/APPLICATIONS.md) for ecosystem-specific key canonicalization rules (CT, MTC, SumDB, Sigstore, Sigsum).
- **Verifier Client Engineer**:
  - Read [Inductive Backward Verification Protocol in ARCHITECTURE.md](./docs/ARCHITECTURE.md#55-inductive-backward-verification-protocol) for client-side multi-page proof verification from Page 1 to genesis.
  - Read [Read Server & Protocol Subsystem](./internal/server/README.md) for HTTP endpoints, query parameters, and C2SP `text/plain` multi-section response framing.
- **Test & Ops Engineer**:
  - Read [Storage & Physical Hardware Topology in ARCHITECTURE.md](./docs/ARCHITECTURE.md#6-storage--physical-hardware-topology) for dual-disk NVMe isolation and RAM/disk sizing guidelines.
  - Read [Benchmarks & Performance Analysis](./docs/BENCHMARKS.md) for Zero-WAL throughput, latency profiles, and hardware scaling.
  - Read [Load & Verification Harness (Hammer)](./hammer/README.md) for synthetic load generation, fuzzing, and cryptographic invariant validation.

## Documentation Index

### Core Architecture & Ecosystems
- [**System Architecture**](./docs/ARCHITECTURE.md): Complete system architecture, subsystem map, pipeline invariants, dual-disk storage layout, security model, and architectural decisions.
- [**Applications & Ecosystems**](./docs/APPLICATIONS.md): Universal Claim Subject Map model, key canonicalization profiles, and mapping guides for Certificate Transparency (CT), Merkle Tree Certificates (MTCs), Go SumDB, Sigstore, and Sigsum.
- [**Benchmarks & Performance**](./docs/BENCHMARKS.md): Empirical performance benchmarks for the production Zero-WAL architecture, full Go SumDB ingestion, CT multi-domain fanout, and baseline WAL comparative analysis.

### Internal Subsystem Specifications
- [**Ingestion Pipeline**](./internal/ingest/README.md): Checkpoint validation, tile/leaf Merkle authentication, native entry bundle fetching, sandboxed WASM `MapFn` execution, priority resequencer, and `TileReaper` cache management.
- [**KV Storage Engine**](./internal/kvstore/README.md): Embedded Pebble key-value store encapsulation (`IndexStore`), inverted chunk numbering (`^chunkNum`), 33-byte prefix Bloom filters, delimitless value encoding, and sub-root read recovery.
- [**Authenticated State & MPT**](./internal/tree/README.md): In-memory Merkle Patricia Trie in `mmap`, lock-free root prediction (`mpt.Predict`), Tessera Output Log state commitments, and witness cosignature aggregation.
- [**Coordinator & Recovery**](./internal/coordinator/README.md): Checkpoint progression & Merkle consistency proofs, moving-goalpost prevention (`m_target_checkpoint`), watermark tracking, serialized batch coordination, and Zero-WAL startup recovery.
- [**Read Server & Serving Protocol**](./internal/server/README.md): HTTP lookup endpoints (`GET /vindex/lookup/{keyhash}?before=X&limit=M`), lock-free Pebble inverted scans, RFC 6962 prefix compact ranges, and C2SP multi-section response framing.

### Tooling & Runtime SDKs
- [**WASM MapFn Plugin SDK & Host Runtime**](./mapfn/README.md): Sandboxed deterministic mapping specification, guest ABI, Wazero host runtime, multi-language SDKs (Go, TinyGo, Rust), and offline `vindex-map` CLI.
- [**Load & Verification Harness (Hammer)](./hammer/README.md): Synthetic data generation, high-concurrency load testing, checkpoint drip proxy, and continuous cryptographic invariant verification framework.
