# Verifiable Index Applications

This document outlines the various ecosystems and use cases where a [Verifiable Index](./ARCHITECTURE.md) can be applied to provide efficient, trustless querying over large append-only transparency logs.

## Certificate Transparency (CT)

In the context of Certificate Transparency, the Verifiable Index (VIndex) addresses the challenge of **efficient, trustless domain monitoring**.

### The Problem
A domain owner wants to know every certificate issued for their domain to detect unauthorized issuance. Today, they must either:
1. Download and process all massive CT logs themselves; OR
2. Trust a centralized third-party search tool (like `crt.sh`), which could theoretically omit results due to error or malice.

### The Solution
A VIndex can be deployed over a CT log to provide verifiable lookups:
* **Input Log**: A Certificate Transparency Log.
* **MapFn**: Designed to parse CT log leaves (X.509 certificates/precertificates) and output the Subject and Subject Alternative Name (SAN) entries as search keys (which are then cryptographically hashed for the index).

### Guarantees & Flow
1. **Query**: A domain owner queries the index for a specific key (e.g., `example.com`).
2. **Result**: The VIndex returns a compact, append-only list of pointers (leaf indices in the CT log) where certificates for `example.com` are located, along with a cryptographic inclusion proof. If the monitor has queried before, they only need to request the incremental delta of new entries.
3. **Verification**: The domain owner can cryptographically verify that the returned list is complete and correct against the publicly audited Output Log checkpoints.
4. **Revocation Monitoring**: Because the VIndex provides an append-only history of all certificates issued for the domain, monitors are responsible for parsing the returned certificates/precertificates to determine their expiration or revocation status.

### Post-Quantum & Merkle Tree Certificates (MTCs)

#### 1. MTC vs. Traditional CT Logs
[Merkle Tree Certificates (MTCs)](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) are designed to minimize certificate sizes by omitting public keys and signatures from log entries, storing only hashes of the public keys and using a single signature over the tree head. This makes MTC logs significantly smaller than traditional CT logs (like RFC6962 or `static-ct`), even when accounting for larger Post-Quantum keys.

Importantly, **Subject Alternative Names (SANs) remain fully present** in the MTC leaf structure. This is the essential ingredient that allows VIndex to parse the log and map domain names to their corresponding leaf indices. Combined with log pruning and the fact that MTCs are logged exclusively in their issuer's log, independent monitoring of MTC logs is inherently more efficient than traditional CT. However, downloading and processing all active certificates across multiple logs remains a high barrier for individual domain owners, making VIndex a crucial complementary layer.

#### 2. Deployment Models & Pruning Realities

A VIndex can be integrated into the MTC ecosystem across different operational models. However, unlike traditional CT where logs grow infinitely, MTC ecosystems heavily utilize pruning to maintain sustainability. This pruning can apply to the primary log, mirrors, and even the VIndex itself.

##### 2a. Integrated CA-Operated Index
* **Model**: The Certificate Authority (CA) runs both the primary MTC log and the VIndex as a unified offering.
* **Trade-offs**: Because MTC logs actively prune expired certificates, older VIndex pointers will eventually reference leaves that have been dropped from the primary log. If the VIndex itself is also managed via pruning or temporal epochs, these historical records may disappear entirely.

##### 2b. Mirror-Operated Index
* **Model**: Independent mirrors operate the VIndex alongside a copy of the MTC log. These mirrors may choose to maintain a full, unpruned history, or they may adopt the same pruning policy as the source log to reduce operational costs.
* **Trade-offs**: While an unpruned mirror is ideal for long-term historical forensics, funding and maintaining such storage is a significant barrier. If a mirror adopts standard pruning, older data becomes unavailable just as it does in the primary log.

##### The Value of Active Monitoring

Regardless of whether the underlying data is eventually pruned from all logs, mirrors, and the index, the VIndex retains its core value: **efficient real-time threat detection**. 

The primary mission of a domain monitor is to detect unauthorized certificates *while they are active* so that mitigation (revocation) can occur. The VIndex reduces the cost of discovering these active certificates to a simple targeted query, removing the need for domain owners to download massive datasets. While a full, unpruned mirror provides the best capability for retrospective auditing, the VIndex remains a crucial operational layer even in a fully pruned ecosystem.

#### 3. Open Questions
* **Deployment Path**: Which deployment model (CA-integrated vs. Mirror-operated) will be widely adopted by the ecosystem?
* **VIndex Lifecycle & Size Management**: If primary logs grow infinitely but prune older certificates, how should an unbounded VIndex be managed?
  * Should the VIndex be periodically rolled over (creating temporal epochs)?
  * Can individual sub-logs within the VIndex be safely pruned over time to reclaim storage? (See [VIndex Pruning & Storage Reclamation](./ARCHITECTURE.md#vindex-pruning--storage-reclamation))

---

## Go Software Supply Chain (SumDB)

The Go Module Database (`sum.golang.org`) records hashes for all released Go module versions.
* **The Problem**: A package maintainer or security scanner wanting to verify or audit all published versions of a specific module path (e.g. `github.com/gin-gonic/gin`) must scan tens of millions of records or trust third-party mirrors.
* **The VIndex Solution**:
  * **Input Log**: Go SumDB tile log.
  * **MapFn**: Parses SumDB leaf lines (`<module> <version> <hash>`) and maps the module path string to the leaf index.
  * **Guarantees**: Verifiers query a module path and receive all historical version publications with a tamper-proof cryptographic proof binding the list to the SumDB checkpoint.

---

## Sigstore

Sigstore provides public transparency logging for software signatures, attestations, and provenance records (via Rekor).
* **The Problem**: Software consumers want to verify all signatures associated with a developer's identity (OIDC email), a specific artifact digest, or a Git commit hash without scraping the full Rekor log.
* **The VIndex Solution**:
  * **Input Log**: Rekor transparency log.
  * **MapFn**: Parses entry payloads (hashedrekord, intoto attestations) to index artifact SHA-256 hashes and signer identities.
  * **Guarantees**: Provides instant, verifiable lookup of all signatures ever published for a specific artifact digest or identity.

---

## Sigsum

Sigsum is a minimal, non-general-purpose transparency log for SSH key signatures and small commitments.
* **The Problem**: Clients need to verify that a specific key has signed specific submissions without traversing the full Sigsum log.
* **The VIndex Solution**:
  * **Input Log**: Sigsum log tiles.
  * **MapFn**: Indexes submitter public key hashes to leaf indices.
  * **Guarantees**: O(1) verifiable discovery of all submissions signed by a specific public key.

---

## Claim Subject Maps & Pre-Image Canonicalization

In terms of the [Claimant Model](https://github.com/google/trillian/blob/master/docs/claimantmodel/Maps.md), VIndex operates as a **Claim Subject Map (CSM)** or **Map of Logs (Mog)** over an append-only log. The keys in VIndex are **Claim Subjects** (the specific entities a claim or log entry is about, such as a domain name, module path, or artifact hash), and the value at each key is a mini-log of leaf pointers.

### The Role of Discoverability
The core security property of a Claim Subject Map is **Discoverability**: a verifier must be able to discover all claims regarding a Claim Subject without having to scan the entire underlying log.

Discoverability requires that the mapping from a real-world entity to its map key is **unambiguous and deterministically agreed upon** by both the indexer (`MapFn`) and the verifier. Because VIndex endpoints and MPT commitments operate over 32-byte SHA-256 hashes (`KeyHash = SHA256(canonicalSubjectBytes)`), if canonicalization rules diverge, claims become undiscoverable to verifiers (resulting in false non-inclusion proofs).

### Recommended Canonicalization Guidelines

While specific ecosystems define their own domain-specific identity representations, index operators and client SDKs should adhere to the following recommended canonicalization profiles:

| Application | Claim Subject Type | Recommended Canonicalization Profile | KeyHash Formula |
| :--- | :--- | :--- | :--- |
| **CT & MTC** | Domain Name | 1. Strip trailing dot (`.`): `example.com.` -> `example.com`<br>2. ASCII Case Folding: `strings.ToLower(domain)`<br>3. Internationalized Domain Names (IDN): Convert Unicode to ASCII Punycode via IDNA2008 / UTS #46 before hashing (`bücher.example` -> `xn--bcher-kva.example`) | `SHA256(canonical_domain_ascii_bytes)` |
| **Go SumDB** | Go Module Path | Canonical Go module path casing; apply standard Go toolchain module path escaping (`golang.org/x/mod/module.EscapePath` or UTF-8 lowercase path) | `SHA256(canonical_module_path_bytes)` |
| **Sigstore** | Artifact Digest | Format as lowercase hex string prefixed with algorithm name: `sha256:<64_hex_digits>` | `SHA256("sha256:" + lowercase_hex)` |
| **Sigstore** | Signer Identity | Lowercase, whitespace-trimmed OIDC email or URI string | `SHA256(canonical_identity_bytes)` |
| **Sigsum** | Ed25519 Key | Raw 32-byte public key or raw ASCII hex string | `SHA256(raw_pubkey_bytes)` |
