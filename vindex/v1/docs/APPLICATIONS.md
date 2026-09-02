# Verifiable Index Applications & Ecosystem Specifications

This document outlines the universal Claim Subject Map model, ecosystem specifications (Certificate Transparency, Merkle Tree Certificates, Go SumDB, Sigstore, Sigsum), verified performance optimizations, future extensions, and retired design branches.

---

## 1. Core Load-Bearing Invariants

### 1.1 The Claimant Model & Claim Subject Maps (CSM)
In terms of the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), VIndex operates as a **Claim Subject Map (CSM)** or **Map of Logs (Mog)** over an append-only log:
- **Claim Subjects**: The specific entities an index record or log entry concerns (e.g., domain name, module path, artifact digest, or public key hash).
- **Mini-Logs**: The value committed at each key is a chronologically ordered mini-log of leaf pointers in the Input Log.

### 1.2 Deterministic Agreement Invariant
The core security property of a Claim Subject Map is **Discoverability**: a verifier must be able to discover all claims regarding a Claim Subject without scanning the entire underlying log.
- **Invariant**: The canonicalization from a real-world entity to its preimage bytes MUST be **unambiguous and deterministically agreed upon** by both the indexer (`MapFn`) and the client verifier.
- If canonicalization rules diverge, claims become undiscoverable, causing false non-inclusion proofs.

### 1.3 Key Extraction, Deduplication & Mapping Rules
1. **Host-Side Key Hash Formula**:
   ```text
   KeyHash = SHA256(canonical_subject_bytes)
   ```
2. **Strict Lexicographical Sorting & Deduplication**:
   When a leaf maps to multiple keys (1-to-N fanout), the host sorts extracted key hashes with `bytes.Compare` and deduplicates using `slices.Compact`. A leaf index is recorded at most once per key hash, preventing duplicate relative offsets in storage chunks.

### 1.4 Ecosystem Canonicalization Profiles

| Application | Claim Subject Type | Canonical Preimage Extraction Profile (Guest WASM) | Host KeyHash Formula |
| :--- | :--- | :--- | :--- |
| **CT & MTC** | Domain Name | 1. Strip trailing dot (`.`): `example.com.` -> `example.com`<br>2. ASCII Case Folding: `strings.ToLower(domain)`<br>3. Internationalized Domain Names (IDN): Convert Unicode to ASCII Punycode via IDNA2008 / UTS #46 (`bücher.example` -> `xn--bcher-kva.example`) | `SHA256(canonical_domain_ascii_bytes)` |
| **Go SumDB** | Go Module Path | Canonical Go module path casing; apply standard Go toolchain module path escaping (`golang.org/x/mod/module.EscapePath` or UTF-8 lowercase path) | `SHA256(canonical_module_path_bytes)` |
| **Sigstore** | Artifact Digest | Format as lowercase hex string prefixed with algorithm name: `sha256:<64_hex_digits>` | `SHA256("sha256:" + lowercase_hex)` |
| **Sigstore** | Signer Identity | Lowercase, whitespace-trimmed OIDC email or URI string | `SHA256(canonical_identity_bytes)` |
| **Sigsum** | Ed25519 Key | Raw 32-byte public key | `SHA256(raw_pubkey_bytes)` |

### 1.5 Verification Invariants by Ecosystem

#### 1. Certificate Transparency (RFC 6962 / Static-CT)
- Parses ASN.1 DER `TBSCertificate` structures from `x509_entry` and `precert_entry` leaves.
- Extracts Subject Common Name (CN) and all Subject Alternative Name (SAN) `dNSName` extensions.
- Evaluates 1-to-N fanout across all associated domain names.
- Clients query `GET /vindex/lookup/{KeyHash}` where `KeyHash = SHA256("example.com")` and verify inclusion proofs against `MapRoot`.

#### 2. Merkle Tree Certificates (MTCs)
- Parses MTC leaf structures omitting individual signatures, extracting all SAN entries.
- Emits canonical domain preimages for instant verification of active certificates during their validity window.

#### 3. Go Software Supply Chain (SumDB)
- Parses two-line tile records:
  ```text
  <module> <version> <hash>
  <module> <version>/go.mod <hash>
  ```
- Extracts the module path, escaping characters per `golang.org/x/mod/module.EscapePath`.
- Indexes all releases under the canonical module path hash.

#### 4. Sigstore (Rekor)
- Extracts `hashedrekord` artifact digests (`sha256:<hex>`) and `intoto` signer identities (OIDC email/URI).
- Allows verification of all signatures associated with an artifact or developer identity.

#### 5. Sigsum
- Extracts 32-byte Ed25519 submitter public keys.
- Maps submitter identity hashes to signed log statements.

---

## 2. Verified Performance Optimizations

### 2.1 Bundled Preimage Extraction with Host Hardware Hashing
Guest WASM plugins extract raw canonical preimages rather than computing SHA-256 in bytecode. The Go host runtime computes hashes using SIMD hardware instructions (**x86 SHA-NI** or **ARMv8 Crypto**):
- slashes WASM FFI overhead from ~23% to < 1% CPU via `map_bundle` (up to 256 leaves per call).
- eliminates the ~55% software crypto bottleneck in guest bytecode.

### 2.2 Zero-Allocation Byte Scanner for Go SumDB
In the SumDB mapper, replacing the standard library regex engine with a zero-allocation byte scanner (`isPseudoVersion([]byte)`):
- Eliminated guest heap allocations during pseudo-version filtering.
- Shrank WASM binary size from 2.5 MB to 1.9 MB (-24%).
- Reduced guest CPU execution time by 40%.

### 2.3 High-Fanout Domain Compaction in CT Workloads
On CT workloads with 1 to 50 domains per certificate leaf (mean: ~25 SANs/leaf):
- The pipeline achieves an effective indexing rate of **~300,550 search keys/sec**.
- Two-generational active chunk caching retains hot parent domains in memory, eliminating redundant Pebble disk seeks.
- Zero-WAL direct commits keep the database footprint under 10 MB for 10M leaves (compared to 1.2 GB under WAL compaction).

### 2.4 High-Throughput MTC Post-Quantum Ingestion
On real MTC Shard3 logs (257.8M certificates):
- Normal Serving Mode sustains **32,705.9 certs/sec** with full ASN.1 DER parsing.
- Point lookups sustain sub-2ms P50 latency with 100% availability.

---

## 3. Miscellaneous / Optional Considerations

### 3.1 Forward-Compatibility: Prefix-Trie & Subtree Indexing
Preserving canonical preimages across the `map_bundle` boundary provides forward compatibility for future search extensions without modifying guest plugins:
- **Subdomain Discovery**: Querying all certificates under `*.example.com` via label prefix-tries.
- **Organization / Path Discovery**: Querying all packages under `github.com/org/*` via path prefix-tries.
- **Zero Guest ABI Changes**: Because plugins output raw preimages, the host runtime can index prefix tries or subtree roots in future versions with no guest recompilation.

### 3.2 Ecosystem Deployment Models
- **Integrated Issuer-Operated Index**: The Certificate Authority or Log Operator runs VIndex alongside the primary log.
- **Independent Mirror Index**: Third-party auditors, monitors, and security scanners operate standalone VIndex nodes against public mirrors.

### 3.3 Active Threat Monitoring vs. Historical Archiving
In pruned logs (such as MTC), expired certificates are retired from storage. VIndex coordinates retention via durable watermarks, prioritizing low-latency lookups for active, valid credentials.

---

## 4. Retired Ideas & Alternatives Considered

### 4.1 Backfill Mode Retirement across Ecosystem Workloads
- **What Was Proposed & Investigated**:
  A dedicated "Backfill Mode" was designed to perform fast-forward bulk catch-up of large ecosystem logs (54.3M leaves for Go SumDB, 257.8M certs for MTC). It bypassed intermediate Output Log state commitments and remote witness cosigning, applying leaf batches directly to in-memory MPT nodes via `mptMgr.SetBatch`.
- **Why It Was Investigated**:
  Hypothesized that bulk indexing historical logs from genesis would suffer from excessive heap cloning in `mpt.Predict` and witness network latency bottlenecks.
- **Empirical Findings (from BENCHMARK_RESULTS.md)**:
  Controlled benchmarks on real ecosystem datasets demonstrated:
  1. **Go SumDB (1M Bounded Leaves)**: Normal Mode was **85.1% faster** than Backfill Mode (**90,797.2 leaves/sec** vs. **49,063.6 leaves/sec**).
  2. **MTC Shard3 (256k Bounded Certs)**: Normal Mode was **5.6% faster** than Backfill Mode (**32,705.9 certs/sec** vs. **30,979.2 certs/sec**).
  3. **100% Read Starvation in Backfill**: Backfill Mode shut down the HTTP read server, denying domain owners and package consumers lookup access for the entire bulk ingest period. Normal Mode delivered sub-2ms P50 read latency with 100% availability while actively indexing.
  4. **Equal Memory Footprint**: Peak RSS was essentially identical (208.0 MB Normal vs. 185.6 MB Backfill on SumDB; 93.9 MB Normal vs. 101.5 MB Backfill on MTC).
  5. **Production Demonstrators (`sumdbindex`, `mtcindex`) Never Used Backfill**: The headline throughput of 240,467 leaves/sec was achieved using Normal Serving Mode (`SyncOnce`).
- **Why Permanently Set Aside & Pruned**:
  Backfill Mode provided no speed advantage on real workloads, starved readers, and introduced unwarranted code bifurcation. It was permanently pruned from the codebase in Milestone M3.

### 4.2 In-Guest Software Cryptographic Hashing
- In-guest software SHA-256 consumed ~55% of CPU cycles due to lack of SIMD instructions in WASM.
- Replaced by host-side hardware SIMD hashing (SHA-NI / ARMv8 Crypto), dropping crypto CPU load to < 5%.

### 4.3 In-Guest Regex Engines for Version Parsing
- Embedding standard library regex in guest WASM bloated binary size to 2.5 MB and increased CPU time by 40%.
- Replaced with zero-allocation byte scanner (`isPseudoVersion([]byte)`).
