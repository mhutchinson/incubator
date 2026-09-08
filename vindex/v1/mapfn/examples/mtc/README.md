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

## Running with `vindexd`

`vindexd` supports indexing MTC logs using the compiled `mtc.wasm` plugin.

### Input Log Public Key Schemes

The `--input_log_pubkey` flag accepts either a raw key string or a path to a file containing the key. It supports two schemes:

1. **Standard RFC 6962 / SumDB Note format**:
   ```text
   <name>+<hash>+<base64Key>
   ```
2. **MTC Cosigned Subtree format**:
   ```text
   mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>
   ```
   - `<name>`: Log name / key name matching the checkpoint signature line (e.g., `oid/1.3.6.1.4.1.44363.47.1.44363.48.8`).
   - `<cosignerID>`: Dotted relative OID for the cosigner (e.g., `44363.48.9`).
   - `<logID>`: Dotted relative OID for the log (e.g., `44363.48.8`).
   - `<ed25519_base64_pubkey>`: Base64-encoded 32-byte Ed25519 public key.

> [!NOTE]
> Combining two distinct public key schemes under `--input_log_pubkey` is an interim configuration mechanism and will be refactored before production.

### Example Invocation

To run `vindexd` indexing the live Cloudflare MTC Shard 3 log:

```bash
vindexd \
  --mode=publisher \
  --input_log_url="https://bootstrap-mtca-shard3.cloudflareresearch.com/" \
  --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --input_log_pubkey="mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=" \
  --wasm_path="vindex/v1/mapfn/examples/mtc/mtc.wasm" \
  --output_log_dir="/data/vindex/outputlog" \
  --output_log_signer_key="/path/to/output_log_signer.sec" \
  --db_path="/data/vindex/pebble" \
  --mpt_dir="/data/vindex/mpt" \
  --listen_addr=":8080"
```

Or indexing from a local clone:

```bash
vindexd \
  --mode=publisher \
  --input_log_url="file:///usr/local/google/home/mhutchinson/log-clones/mtc" \
  --input_log_origin="bootstrap-mtca.cloudflareresearch.com/logs/shard3" \
  --input_log_pubkey="mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=" \
  --wasm_path="vindex/v1/mapfn/examples/mtc/mtc.wasm" \
  --output_log_dir="/tmp/vindex-mtc/outputlog" \
  --output_log_signer_key="/path/to/signer.sec" \
  --db_path="/tmp/vindex-mtc/pebble" \
  --mpt_dir="/tmp/vindex-mtc/mpt" \
  --listen_addr=":8080"
```

