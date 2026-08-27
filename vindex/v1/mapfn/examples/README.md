# VIndex WASM MapFn Examples

This directory contains standalone example implementations of VIndex WASM MapFn binaries.

These examples demonstrate how external developers can implement and compile custom indexing logic using the [VIndex Guest SDK](../sdk) without needing to upstream code into the core VIndex repository.

---

## Examples Overview

1. **`sumdb`** (`mapfn/examples/sumdb`):
   - Parses Go Checksum Database (`go.sum`) leaves.
   - Validates module path and semver formats.
   - Filters out ephemeral pseudo-versions.
   - Emits canonical 32-byte SHA-256 hashes of module paths.

2. **`ct`** (`mapfn/examples/ct`):
   - Parses Certificate Transparency (RFC 6962) `MerkleTreeLeaf`, raw X.509 DER certificates, and PreCertificates.
   - Extracts Subject Common Name (CN) and Subject Alternative Names (SANs).
   - Generates hierarchical domain sub-roots down to eTLD+1 using `publicsuffix`.
   - Emits sorted, deterministic 32-byte SHA-256 hashes.

---

## Building the Examples

### 1. Using `go generate`
Build all example WASM binaries from anywhere in the repository:

```bash
go generate ./vindex/v1/mapfn/examples/...
```

### 2. Manual Invocation
Or compile individually using standard Go flags:

```bash
# Build SumDB example
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-buildid=" \
  -buildmode=c-shared \
  -o vindex/v1/mapfn/examples/sumdb/sumdb.wasm \
  github.com/transparency-dev/incubator/vindex/v1/mapfn/examples/sumdb

# Build CT example
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-buildid=" \
  -buildmode=c-shared \
  -o vindex/v1/mapfn/examples/ct/ct.wasm \
  github.com/transparency-dev/incubator/vindex/v1/mapfn/examples/ct
```

---

## Testing with `vindex-map`

You can test and benchmark the precompiled binaries using `vindex-map`:

```bash
# 1. Test single leaf
go run ./vindex/v1/cmd/vindex-map test \
  --wasm=./vindex/v1/mapfn/examples/sumdb/sumdb.wasm \
  --input="golang.org/x/mod v0.14.0 h1:abc=" \
  --format=json

# 2. Verify determinism across parallel worker goroutines
go run ./vindex/v1/cmd/vindex-map verify-determinism \
  --wasm=./vindex/v1/mapfn/examples/ct/ct.wasm \
  --input="sub.domain.example.com" \
  --iterations=50 \
  --concurrency=4

# 3. Benchmark throughput and latency percentiles
go run ./vindex/v1/cmd/vindex-map bench \
  --wasm=./vindex/v1/mapfn/examples/sumdb/sumdb.wasm \
  --iterations=1000 \
  --workers=4
```
