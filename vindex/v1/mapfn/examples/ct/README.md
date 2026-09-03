# CT MapFn Example (`ct.wasm`)

This example implements a VIndex WASM MapFn for **Certificate Transparency (CT)** logs.

## Supported Leaf Formats

- **RFC 6962 CT Logs**: Parses TLS `MerkleTreeLeaf` structures containing both `x509_entry` (full X.509 certificate) and `precert_entry` (PreCertificate TBS DER).
- **Static CT Logs (C2SP / Sunlight / TesseraCT)**: Parses individual leaf entries unpacked from static data tiles (standard X.509 DER or RFC 6962 `MerkleTreeLeaf`).

> [!NOTE]
> **Merkle Tree Certificates (MTC) are not supported** by this MapFn. MTC issuance logs use a distinct ASN.1 `TBSCertificateLogEntry` schema with `SubjectPublicKeyInfoHash` rather than standard X.509 `SubjectPublicKeyInfo`.

## Indexing & Domain Expansion

For each certificate or precertificate leaf, the mapper:
1. Extracts all DNS names from the **Common Name (CN)** and **Subject Alternative Name (SAN)** extension.
2. Normalizes domains (lowercasing, stripping wildcards and trailing dots).
3. Computes hierarchical domain sub-roots down to **eTLD+1** (using the Public Suffix List). For example, `auth.service.example.com` emits search keys for:
   - `auth.service.example.com`
   - `service.example.com`
   - `example.com`
4. Emits deterministic SHA-256 key hashes for each domain label.

## Building & Testing

Compile the WASM binary:
```bash
go generate ./...
```

Inspect and test against sample inputs:
```bash
# Verify ABI compliance
vindex-wasm inspect --wasm=ct.wasm

# Test against a leaf payload
vindex-wasm test --wasm=ct.wasm --input_file=leaf.bin
```
