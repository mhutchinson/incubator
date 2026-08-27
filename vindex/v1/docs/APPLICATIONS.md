# Verifiable Index Applications

This document outlines the universal Claim Subject Map model and specific ecosystem use cases where a [Verifiable Index](./ARCHITECTURE.md) is applied to provide efficient, trustless querying over append-only transparency logs.

## 1. Claim Subject Maps & Pre-Image Canonicalization

### 1.1 The Claimant Model & Map of Logs (Mog)

In terms of the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), VIndex operates as a **Claim Subject Map (CSM)** or **Map of Logs (Mog)** over an append-only log. The keys in VIndex are **Claim Subjects** (the specific entities a claim or log entry is about, such as a domain name, module path, or artifact hash), and the value at each key is a mini-log of leaf pointers.

### 1.2 The Role of Discoverability & 32-Byte Key Hash Abstraction

The core security property of a Claim Subject Map is **Discoverability**: a verifier must be able to discover all claims regarding a Claim Subject without having to scan the entire underlying log.

Discoverability requires that the mapping from a real-world entity to its map key is **unambiguous and deterministically agreed upon** by both the indexer (`MapFn`) and the verifier. Because VIndex endpoints and MPT commitments operate over 32-byte SHA-256 hashes:

```text
KeyHash = SHA256(canonicalSubjectBytes)
```

If canonicalization rules diverge between indexers and verifiers, claims become undiscoverable (resulting in false non-inclusion proofs).

### 1.3 Recommended Canonicalization Guidelines

While specific ecosystems define their own domain-specific identity representations, index operators and client SDKs should adhere to the following recommended canonicalization profiles:

| Application | Claim Subject Type | Recommended Canonicalization Profile | KeyHash Formula |
| :--- | :--- | :--- | :--- |
| **CT & MTC** | Domain Name | 1. Strip trailing dot (`.`): `example.com.` -> `example.com`<br>2. ASCII Case Folding: `strings.ToLower(domain)`<br>3. Internationalized Domain Names (IDN): Convert Unicode to ASCII Punycode via IDNA2008 / UTS #46 before hashing (`bücher.example` -> `xn--bcher-kva.example`) | `SHA256(canonical_domain_ascii_bytes)` |
| **Go SumDB** | Go Module Path | Canonical Go module path casing; apply standard Go toolchain module path escaping (`golang.org/x/mod/module.EscapePath` or UTF-8 lowercase path) | `SHA256(canonical_module_path_bytes)` |
| **Sigstore** | Artifact Digest | Format as lowercase hex string prefixed with algorithm name: `sha256:<64_hex_digits>` | `SHA256("sha256:" + lowercase_hex)` |
| **Sigstore** | Signer Identity | Lowercase, whitespace-trimmed OIDC email or URI string | `SHA256(canonical_identity_bytes)` |
| **Sigsum** | Ed25519 Key | Raw 32-byte public key or raw ASCII hex string | `SHA256(raw_pubkey_bytes)` |

---

## 2. Certificate Transparency (RFC 6962 / Static-CT)

### 2.1 Ecosystem Background & Problem

In Certificate Transparency, domain owners need to discover every certificate issued for their domain to detect unauthorized issuance or compromised Certificate Authorities (CAs). Today, monitors face an untenable trade-off: either download and parse terabytes of massive CT logs, or trust centralized third-party search engines (like `crt.sh`), which can omit records inadvertently or maliciously without cryptographic detection.

### 2.2 Input Log Format & Payloads

CT logs store RFC 6962 / `static-ct` entries consisting of serialized X.509 certificates and precertificates (`x509_entry` / `precert_entry`). Leaf payloads contain ASN.1 DER-encoded `TBSCertificate` structures with Subject Common Names (CN) and Subject Alternative Name (SAN) extensions (`dNSName`).

### 2.3 MapFn Key Extraction & Canonicalization Formula

The WASM `MapFn` parses the DER certificate or precertificate, extracts the Subject CN and all SAN `dNSName` entries, and canonicalizes each domain:

1. Strip trailing dot (`example.com.` -> `example.com`).
2. Convert ASCII characters to lowercase (`strings.ToLower`).
3. Convert Internationalized Domain Names (IDN) to Punycode via IDNA2008 (`xn--...`).

```text
KeyHash = SHA256(canonical_domain_ascii_bytes)
```

Each leaf produces a 1-to-N fanout mapping to index all associated domain names.

### 2.4 Verifier Query & Verification Flow

1. **Query**: A domain owner queries `GET /vindex/lookup/{KeyHash}?before=X&limit=M` where `KeyHash = SHA256("example.com")`.
2. **Result**: VIndex returns a compact, append-only list of leaf indices in the CT log, along with an MPT inclusion proof against `MapRoot` and a sub-log Merkle compact range proof.
3. **Verification**: The verifier cryptographically validates that the returned list is complete and correct against the publicly audited Output Log checkpoint.
4. **Revocation & Expiration**: The monitor fetches the raw certificates from the CT log using the returned indices to determine validity dates, public keys, and revocation status via OCSP/CRL.

---

## 3. Merkle Tree Certificates (MTCs)

### 3.1 Ecosystem Background & Problem

[Merkle Tree Certificates (MTCs)](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) minimize certificate sizes in Post-Quantum environments by omitting public keys and individual signatures from log entries, storing only public key hashes and anchoring trust via a single tree head signature. MTC logs are operated per-issuer and heavily utilize pruning to maintain sustainability. Independent domain monitors require an efficient query mechanism without downloading entire issuer logs.

### 3.2 Input Log Format & Payloads

Subject Alternative Names (SANs) remain fully present in the MTC leaf structure, alongside validity timestamps and public key hashes.

### 3.3 MapFn Key Extraction & Canonicalization Formula

The `MapFn` extracts all SAN entries from the MTC leaf and applies the standard domain canonicalization pipeline:

```text
KeyHash = SHA256(canonical_domain_ascii_bytes)
```

### 3.4 Verifier Query & Verification Flow

1. **Deployment Models**:
   - **Integrated CA-Operated Index**: The Certificate Authority (CA) runs both the primary MTC log and the VIndex as a unified offering.
   - **Mirror-Operated Index**: Independent mirrors operate the VIndex alongside a copy of the MTC log (pruned or unpruned).
2. **Active Real-Time Threat Monitoring**: The primary mission of a domain monitor is to detect unauthorized certificates *while they are active* so that revocation can occur. VIndex provides instant lookups for active certificates during their validity window.
3. **Pruning & Lifecycle Management**: In pruned MTC logs, historical entries are retired once expired. VIndex coordinates safe storage bounds via durable watermarks (see [Dual-Disk Physical Isolation in ARCHITECTURE.md](./ARCHITECTURE.md#61-dual-disk-physical-isolation)).

---

## 4. Go Software Supply Chain (SumDB)

### 4.1 Ecosystem Background & Problem

The Go Module Database (`sum.golang.org`) records cryptographic hashes for all released Go module versions. Package maintainers, auditors, and security scanners need to verify or audit all published versions of a specific module path (e.g. `github.com/gin-gonic/gin`) without scanning tens of millions of records or trusting unauthenticated mirrors.

### 4.2 Input Log Format & Payloads

SumDB uses tile-based storage (`tlog-tiles`). Each leaf entry contains a two-line record:
```text
<module> <version> <hash>
<module> <version>/go.mod <hash>
```

### 4.3 MapFn Key Extraction & Canonicalization Formula

The `MapFn` parses the module line, extracts the module path string, and applies standard Go module path escaping (`golang.org/x/mod/module.EscapePath`):

```text
KeyHash = SHA256(canonical_module_path_bytes)
```

### 4.4 Verifier Query & Verification Flow

1. **Query**: A client queries `GET /vindex/lookup/{KeyHash}` for a target module path.
2. **Result**: VIndex returns all historical leaf indices where releases for that module path were recorded.
3. **Verification**: Verifiers cryptographically validate the inclusion proof against the witnessed SumDB Output Log checkpoint and fetch individual record tiles from `sum.golang.org` to audit version publication history.

---

## 5. Sigstore (Rekor)

### 5.1 Ecosystem Background & Problem

Sigstore provides public transparency logging for software signatures, attestations, and provenance records via Rekor. Software consumers and policy engines need to verify all signatures associated with a developer's identity (OIDC email), an artifact digest, or a Git commit hash without scraping the full Rekor log.

### 5.2 Input Log Format & Payloads

Rekor stores structured JSON log entries including `hashedrekord` (SHA-256 artifact hash, signature, signing certificate) and `intoto` attestations containing OIDC identity claims and build provenance statements.

### 5.3 MapFn Key Extraction & Canonicalization Formula

The `MapFn` extracts artifact digests and signer identities, mapping each to the leaf index:
- **Artifact Digest**: Formatted as lowercase hex string prefixed with algorithm:
  ```text
  KeyHash = SHA256("sha256:" + lowercase_hex)
  ```
- **Signer Identity**: Formatted as lowercase, whitespace-trimmed OIDC email or URI string:
  ```text
  KeyHash = SHA256(canonical_identity_bytes)
  ```

### 5.4 Verifier Query & Verification Flow

1. **Query**: Software consumers query VIndex by artifact digest or signer identity.
2. **Result**: VIndex returns all leaf indices where signatures or attestations were published.
3. **Verification**: The client verifies the MPT inclusion proof against the Output Log checkpoint, retrieves the Rekor leaves by index, and validates the digital signatures and OIDC certificate validity.

---

## 6. Sigsum

### 6.1 Ecosystem Background & Problem

Sigsum is a minimal, non-general-purpose transparency log for SSH key signatures and small commitments. Clients need to verify that a specific key has signed specific submissions without traversing the full Sigsum log.

### 6.2 Input Log Format & Payloads

Sigsum leaf records contain fixed-format submitter public keys (32-byte Ed25519 public keys) and cryptographic statement hashes.

### 6.3 MapFn Key Extraction & Canonicalization Formula

The `MapFn` extracts the submitter public key:

```text
KeyHash = SHA256(raw_pubkey_bytes)
```

### 6.4 Verifier Query & Verification Flow

1. **Query**: Client queries `GET /vindex/lookup/{KeyHash}` with the Ed25519 public key hash.
2. **Result**: VIndex returns all Sigsum leaf indices submitted under that public key.
3. **Verification**: The verifier verifies the response against the Output Log checkpoint and retrieves the Sigsum leaves to inspect signed statements.

