# Verifiable Index (VIndex) v1

A Verifiable Index (VIndex) provides efficient, trustless, and cryptographically verifiable querying over append-only transparency logs (such as Certificate Transparency, Merkle Tree Certificates, and Go SumDB).

Operating as a "Map Sandwich" between an Input Log and a witnessed Output Log, VIndex delivers $O(1)$ point lookups with $O(\log N)$ cryptographic inclusion proofs, preventing untrusted index operators from omitting or equivocating records.

## Documentation

- [**Architecture & Subsystem Map**](./docs/ARCHITECTURE.md): Complete system architecture, subsystem contracts, pipeline invariants, dual-disk storage layout, and threat model.
- [**Applications & Ecosystems**](./docs/APPLICATIONS.md): Ecosystem mapping guides for Certificate Transparency (CT), Merkle Tree Certificates (MTCs), Go SumDB, Sigstore, and Sigsum.
- [**Benchmarks & Performance**](./docs/BENCHMARKS.md): Empirical benchmarks comparing the Zero-WAL direct commit pipeline against the baseline WAL architecture.
- [**Load & Verification Harness (Hammer)**](./hammer/README.md): Synthetic data generation, high-concurrency load testing, and invariant verification framework.
