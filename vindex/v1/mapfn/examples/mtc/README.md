# MTC MapFn Example (`mtc.wasm`)

This example implements a VIndex WASM MapFn for **Merkle Tree Certificates (MTC)** logs.

## Supported Leaf Formats

- **MTC Entry Type 1 (`TBSCertificateLogEntry`)**: Parses 2-byte big-endian entry type (`0x0001`) prefix followed by ASN.1 DER `TBSCertificateLogEntry`. Other entry types are ignored.

## Indexing & Domain Expansion

For each certificate leaf, the mapper:
1. Extracts all DNS names from the **Subject Alternative Name (SAN)** extension.
2. Normalizes domains (lowercasing, stripping wildcards like `*.`).
3. Computes hierarchical domain sub-roots down to **eTLD+1** (using the Public Suffix List). For example, `deep.maps.google.co.uk` emits search keys for:
   - `deep.maps.google.co.uk`
   - `maps.google.co.uk`
   - `google.co.uk`
4. Emits canonical preimages to the host runtime via `sdk.RegisterEmit`.

## Building & Testing

Compile the WASM binary:
```bash
go generate ./...
```

Inspect and test against sample inputs:
```bash
# Verify ABI compliance
vindex-wasm inspect --wasm=mtc.wasm

# Test against a leaf payload
vindex-wasm test --wasm=mtc.wasm --input_file=leaf.bin
```
