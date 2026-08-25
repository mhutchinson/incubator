# Verifiable Index Applications & Ecosystem Specifications

This document defines the application architecture, canonicalization profiles, verified performance optimizations, real-world ecosystem specifications, operational considerations, and retired design branches for **VIndex v1**.

---

## 0. High Level Overview

### 0.0 The Claimant Model & Claim Subject Maps (CSM)
In terms of the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), VIndex operates as a **Claim Subject Map (CSM)** or **Map of Logs (MoL)** over an append-only log:
- **Claim Subjects**: The specific entities an index record or log entry concerns (e.g. domain name, Go module path, container image digest, or public key hash).
- **Mini-Logs**: The value committed at each key is a chronologically ordered mini-log of leaf pointers in the Input Log.

The core security property of a Claim Subject Map is **Discoverability**: a verifier must be able to discover all claims regarding a Claim Subject without scanning the entire underlying log.

### 0.1 Mental Models: The Phonebook and the Fanout Multiplier
- **The "Universal Phonebook"**: VIndex is agnostic to the internal structure of the underlying log payload. It does not parse or interpret payloads during serving; it only requires an unambiguous canonical preimage (the "name" in the phonebook) and index pointers to construct authenticated inclusion proofs.
- **The "Fanout Multiplier"**: Different ecosystems exhibit radically different mapping cardinality:
  - In **Go SumDB**, each entry maps to exactly one module path (strict 1-to-1 mapping).
  - In **Certificate Transparency (CT)**, a single certificate frequently contains dozens of Subject Alternative Names (1-to-N fanout). A single certificate can map to 50+ domain keys, multiplying Pebble write volume and requiring strict host-side deduplication.

---

## 1. Universal Mapping & Canonicalization Invariants

To guarantee that verifiers can independently discover records, the indexer (`MapFn`) and client verifiers must agree on the exact byte-level representation of every search key before hashing.

- **[Correctness Invariant] Deterministic Canonical Agreement**:
  - *Rule*: The normalization from a real-world identifier (e.g. domain name, module path) to its canonical preimage bytes MUST be unambiguous and deterministically agreed upon by both the indexer (`MapFn`) and client SDKs before computing `KeyHash = SHA256(canonical_preimage_bytes)`.
  - *Rationale*: Cryptographic hashing is sensitive to single-byte discrepancies. If the indexer strips trailing dots from domain names but a client verifier includes them, the resulting key hashes diverge completely.
  - *Consequence ("Or Else")*: The client will query an unpopulated key hash and receive a valid cryptographic non-inclusion proof, falsely concluding that no records exist for their identity.

- **[Correctness Invariant] Strict Lexicographical Sorting & Deduplication**:
  - *Rule*: When a single leaf maps to multiple search keys (1-to-N fanout), the host runtime must sort extracted key hashes with `bytes.Compare` and deduplicate them using `slices.Compact`. A leaf index is recorded at most once per key hash.
  - *Rationale*: Certificates frequently duplicate domains across the Common Name and Subject Alternative Name fields.
  - *Consequence ("Or Else")*: Duplicate relative offsets would be appended to storage chunks, producing corrupted compact ranges and wasting storage.

- **[Performance Optimization] Preimage Preservation & Host SIMD Hashing**:
  - *Mechanism*: The sandboxed WASM `MapFn` parses raw leaf bytes and outputs raw canonical preimages (e.g. lowercase Punycode domain strings) across the FFI boundary. The Go host hashes preimages using standard `crypto/sha256` backed by native hardware instructions (Single Instruction, Multiple Data / SIMD, such as **x86 SHA-NI** or **ARMv8 Crypto**).
  - *Impact*: Eliminates the ~55% software cryptographic hashing bottleneck inside WebAssembly bytecode while preserving raw preimages for forward-compatible subtree indexing.

### 1.1 Universal Canonicalization Reference Profiles

| Application | Claim Subject Type | Canonical Preimage Extraction Profile (Guest WASM) | Host KeyHash Formula | Cardinality Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Certificate Transparency** | Domain Name | Strip trailing dot (`.`); ASCII case-fold (`strings.ToLower`); IDNA2008 / UTS #46 Punycode (`xn--...`). | `SHA256(canonical_domain_ascii_bytes)` | 1-to-N (1 to 100+ keys/leaf) |
| **Merkle Tree Certificates** | Domain Name | Strict lower-case Punycode domain string (same as CT). | `SHA256(canonical_domain_ascii_bytes)` | 1-to-N (typically 1 to 5 keys/leaf) |
| **Go Software Supply Chain** | Module Path | Canonical module path casing; standard Go toolchain module path escaping (`golang.org/x/mod/module.EscapePath`). | `SHA256(canonical_module_path_bytes)` | 1-to-1 (exactly 1 key/leaf) |
| **Sigstore** | Artifact Digest | Lowercase hex string prefixed with algorithm: `sha256:<64_hex_digits>`. | `SHA256("sha256:" + lowercase_hex)` | 1-to-N (digest + identities) |
| **Sigstore** | Signer Identity | Lowercase, whitespace-trimmed OIDC email or URI string. | `SHA256(canonical_identity_bytes)` | 1-to-N (digest + identities) |
| **Sigsum** | Ed25519 Key | Raw 32-byte public key bytes. | `SHA256(raw_pubkey_bytes)` | 1-to-1 (exactly 1 key/leaf) |

---

## 2. Known Applications

### 2.1 Certificate Transparency (RFC 6962 / Static-CT)

- **Real-World Context & References**:
  - [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
  - [C2SP Static-CT Specification](https://c2sp.org/static-ct)
  - Primary production logs: Google Argon, Let's Encrypt Oak, Cloudflare Nimbus.

#### The Problem
In Certificate Transparency, domain owners must monitor all certificates issued for their domains to detect unauthorized issuance or compromised Certificate Authorities (CAs). Today, monitors face an untenable dilemma: either download and parse terabytes of massive CT logs, or trust centralized third-party search engines (like `crt.sh`), which can omit records inadvertently or maliciously without cryptographic detection.

#### Input Log Format & Payloads
CT logs store RFC 6962 / `static-ct` entries consisting of serialized X.509 certificates and precertificates (`x509_entry` / `precert_entry`). Leaf payloads contain ASN.1 DER-encoded `TBSCertificate` structures with Subject Common Names (CN) and Subject Alternative Name (SAN) extensions (`dNSName`).

#### MapFn Key Extraction & Normalization
The WASM `MapFn` parses the DER certificate or precertificate, extracts the Subject CN and all SAN `dNSName` entries, and outputs canonical domain preimages:
1. Strip trailing dot: `example.com.` -> `example.com`
2. ASCII case-folding: `strings.ToLower(domain)`
3. Convert Internationalized Domain Names (IDN) to Punycode via IDNA2008: `bücher.example` -> `xn--bcher-kva.example`

Each leaf produces a 1-to-N fanout mapping to index all associated domain names.

#### Verifier Query & Verification Flow
1. **Query**: A domain owner queries `GET /vindex/lookup/{KeyHash}?before=X&limit=M` where `KeyHash = SHA256("example.com")`.
2. **Response**: VIndex returns a compact, append-only list of leaf indices in the CT log, along with an MPT inclusion proof against `MapRoot` and a sub-log Merkle compact range proof.
3. **Verification**: The verifier validates the cryptographic proof against the witnessed Output Log checkpoint, ensuring the list of indices is complete.
4. **Certificate Retrieval**: The monitor fetches the raw certificates from the CT log using the returned indices to inspect validity dates, public keys, and revocation status via OCSP/CRL.

---

### 2.2 Merkle Tree Certificates (MTC & Post-Quantum)

- **Real-World Context & References**:
  - [C2SP Merkle Tree Certificates Specification](https://c2sp.org/sunlight)
  - [IETF Post-Quantum TLS / MTC Drafts](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/)

#### The Problem
Merkle Tree Certificates replace traditional WebPKI X.509 signatures with Merkle inclusion proofs in an append-only log. Because MTC certificates have very short lifespans (e.g. 14 days) and high issuance volumes (hundreds of millions of certs), log sizes expand exponentially. Full log auditing is completely impractical for standard domain owners.

#### Input Log Format & Payloads
MTC logs store compact binary assertions containing domain names, public keys, and validity windows. Leaf payloads are significantly smaller than X.509 certificates but are issued at 10x–50x the frequency of classic CT.

#### MapFn Key Extraction & Normalization
The WASM `MapFn` parses the binary assertion, extracts the domain labels, and applies the same canonical domain normalization rules as CT (strip trailing dot, lowercase, IDNA2008 Punycode).

#### Interaction with Log Pruning
MTC logs rely on aggressive log pruning to discard expired certificates. VIndex supports this operational model:
- Historical leaf pointers below the pruning threshold are dropped from bulk KV storage.
- The minimal set of internal Merkle node hashes (`CompactRange`) representing the deleted prefix is retained.
- Verifiers continue to receive valid inclusion proofs for active certificates against `MapRoot`.

---

### 2.3 Go Software Supply Chain (Go Checksum Database / SumDB)

- **Real-World Context & References**:
  - [Go Module Mirror and Checksum Database Specification](https://golang.org/cmd/go/#hdr-Module_authentication_failures)
  - [Go Checksum Database Architecture](https://go.dev/design/25530-sumdb)
  - Primary production log: `sum.golang.org` (>61.7 million leaves)

#### The Problem
The Go Checksum Database (`sum.golang.org`) ensures that module versions downloaded by `go get` match the versions downloaded by everyone else. However, SumDB provides point lookups only by exact version (`/lookup/{module}@{version}`). It provides no native mechanism to query all known versions of a module. Developers cannot discover whether new versions or unauthorized patch releases have been published without querying external package registries.

#### Input Log Format & Payloads
Each SumDB leaf contains plain-text, newline-delimited lines:
```text
github.com/google/uuid v1.3.0 h1:tIOElFI0...
github.com/google/uuid v1.3.0/go.mod h1:Usq...
```

#### MapFn Key Extraction & Normalization
The WASM `MapFn` parses the first line of the leaf, extracts the module path (the token preceding the version string), and outputs the canonical module path.
- Module paths are normalized using standard Go toolchain escaping (`golang.org/x/mod/module.EscapePath`), replacing uppercase characters with `!` followed by lowercase hex.
- Mapping is strictly 1-to-1 (exactly one module path per leaf).

- **[Performance Optimization] Zero-Allocation Byte Scanner**:
  - *Mechanism*: Guest WASM module replaces standard Go regex engines with a hand-tuned byte scanner (`isPseudoVersion([]byte)`) to filter pseudo-versions without heap allocations.
  - *Impact*: Eliminated `reflect`, `regexp`, and Unicode tables inside `sumdb.wasm`, reducing guest binary size by 24% (from 2.5 MB to 1.9 MB) and accelerating mapping throughput.

#### Verifier Query & Verification Flow
1. **Query**: A developer queries `GET /vindex/lookup/{KeyHash}?limit=100` where `KeyHash = SHA256("github.com/google/uuid")`.
2. **Response**: VIndex returns the list of all Input Log indices where `github.com/google/uuid` appeared.
3. **Audit**: The developer fetches the corresponding leaves from `sum.golang.org` to enumerate every release tag ever committed for that module.

---

### 2.4 Sigstore (Cosign & Rekor)

- **Real-World Context & References**:
  - [Sigstore Architecture Specification](https://docs.sigstore.dev/architecture/)
  - [Rekor Transparency Log](https://github.com/sigstore/rekor)
  - Primary production log: `rekor.sigstore.dev`

#### The Problem
Sigstore logs cryptographic software provenance, signatures, and attestations in an append-only transparency log (Rekor). Developers verifying a container image digest or searching for attestations signed by a specific OpenID Connect (OIDC) identity must scan Rekor or rely on Rekor's non-verifiable search index.

#### Input Log Format & Payloads
Rekor stores pluggable entry types (e.g. `hashedrekord`, `intoto`) containing JSON payloads with artifact digests, signatures, signing certificates, and transparency timestamps.

#### MapFn Key Extraction & Normalization
The WASM `MapFn` extracts two distinct classes of Claim Subjects from each entry, emitting multiple preimages:
1. **Artifact Digest**: Formatted as a lowercase string prefixed with the hash algorithm:
   ```text
   sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   ```
2. **Signer Identity**: Extracted from the X.509 certificate's Subject Alternative Name extension:
   - OIDC Email: Lowercase, whitespace-trimmed (e.g. `user@example.com`).
   - Workload Identity URI: Normalized URI string (e.g. `https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main`).

#### Verifier Query & Verification Flow
Security scanners query VIndex by artifact digest to retrieve all signatures and attestations associated with a build artifact, verifying completeness against witnessed Output Log checkpoints.

---

### 2.5 Sigsum (Public Key Logging)

- **Real-World Context & References**:
  - [Sigsum: Free and Open Source Public Key Logging](https://www.sigsum.org/)
  - [Sigsum System Design](https://git.sigsum.org/sigsum/tree/doc/design.md)

#### The Problem
Sigsum is a minimalist transparency log that stores cryptographic signatures tied to Ed25519 public keys. Verifiers need to discover all signatures issued by a specific public key to detect unauthorized key use or account compromise.

#### Input Log Format & Payloads
Sigsum leaves are strictly formatted, fixed-size binary records (80 bytes) consisting of a 32-byte Ed25519 public key hash, an 8-byte timestamp, a 32-byte artifact hash, and a 64-byte Ed25519 signature.

#### MapFn Key Extraction & Normalization
The WASM `MapFn` extracts the 32-byte public key hash directly from the fixed binary offset. Because the key is already a fixed 32-byte hash, the preimage is the raw 32-byte public key representation. Mapping is strictly 1-to-1.

---

## 3. Forward Compatibility: Prefix-Trie & Subtree Indexing

While VIndex v1 provides point lookups by exact 32-byte key hashes, preserving raw canonical Claim Subject preimages across the `map_bundle` guest-host boundary provides critical forward compatibility for future search extensions:

1. **Subdomain Discovery (`*.example.com`)**: In Certificate Transparency, domain owners frequently need to query all certificates issued across arbitrary subdomains (e.g. `app.example.com`, `api.staging.example.com`).
2. **Namespace / Organization Discovery (`github.com/org/*`)**: In Go SumDB and Sigstore, developers need to enumerate all modules or container images published under an organizational namespace.
3. **Zero Guest ABI Changes**: Because plugins output canonical string preimages rather than one-way hashes, a future VIndex version can construct auxiliary prefix-trie indices (radix trees or patricia tries) directly from the preserved preimages without requiring guest WASM plugin authors to recompile or update their mapping logic.

---

## 4. Operational Realities & Known Pain Points

- **High-Fanout Storage Amplification in CT**: Unlike 1-to-1 logs (SumDB, Sigsum), Certificate Transparency generates high key cardinality. A single certificate covering 100 SANs writes to 100 distinct inverted chunk keys in Pebble. This causes LSM-tree write amplification and requires provisioning larger SSD capacity.
- **Canonicalization Immutability**: If an ecosystem changes its canonicalization standard (e.g. transitioning from IDNA2003 to IDNA2008 domain Punycode normalization), the index cannot be patched in-place. The operator must redeploy a new VIndex instance and re-index from leaf 0.
- **Hot-Key Flooding in Open-Admission Logs**: Open-admission logs can be intentionally spammed with popular keys (e.g. thousands of certs issued for `example.com`), creating deeply stacked 64K chunks. Clients querying these hot keys must execute multiple backward pagination queries (`before=X`) to retrieve the complete history.

---

## 5. Retired Alternatives Considered

### 5.1 In-Guest Regex Engines for Version Parsing
- **Proposed**: Importing `golang.org/x/mod/module` inside the guest WASM binary to parse and filter pseudo-versions using standard Go regex expressions.
- **Empirical Rejection**: Embedded `reflect`, `regexp`, and Unicode tables into the WASM bytecode, bloating `sumdb.wasm` to 2.5 MB and consuming significant heap allocation cycles.
- **Resolution**: Replaced with a zero-allocation byte scanner (`isPseudoVersion([]byte)`), shrinking WASM binary size by 24% (down to 1.9 MB) and improving parsing throughput.

### 5.2 In-Guest Software Cryptographic Hashing
- **Proposed**: Compiling SHA-256 cryptographic hashing directly into guest WebAssembly bytecode.
- **Empirical Rejection**: Consumed ~55% of total CPU time inside the sandbox due to the lack of hardware vector instructions.
- **Resolution**: Delegated hashing to the Go host runtime using hardware vector instructions (SHA-NI / ARMv8 Crypto).
