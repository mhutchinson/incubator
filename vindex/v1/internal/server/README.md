# Sub-Design: HTTP Read Server API & C2SP Wire Protocol

## 1. Context & Objectives

The **Read Server Subsystem** (`vindex/v1/internal/server`) serves verifiable index lookup requests over HTTP adhering to standard Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions. It executes lock-free Pebble backwards scans, applies active watermark filtering, computes on-the-fly Merkle prefix compact ranges, and packages cryptographic proofs into human-readable plain-text responses.

### 1.1 Core Guarantees
1. **Concurrent Serving Unblocked by Pebble I/O**: The MPT critical section is strictly minimized (< 1ms under `mpt_lock.RLock()`), after which Pebble disk reads and text formatting execute completely lock-free.
2. **Watermark Isolation**: Readers are strictly isolated from in-flight writes ahead of `serving_state.InputLogSize` via index filtering.
3. **Bounded Memory & Latency (Hot-Key Pagination)**: Supports `start` and `limit` query parameters with continuation headers (`indices-v1 next_start`) and RFC 6962 prefix compact ranges (`prefix-compact-range-v1`).
4. **End-to-End Cryptographic Verifiability**: Every response contains full cryptographic proof from the witnessed Output Log checkpoint down to individual Input Log indices.

### 1.2 Non-Requirements & Out of Scope
- **No Write Endpoints**: The Read Server is strictly read-only (GET methods only). No POST, PUT, or administrative write endpoints.
- **No Identity Auth / ACLs**: Serves public cryptographic proofs openly over HTTP. Client authentication, authorization, and per-tenant rate-limiting are out of scope (delegated to edge reverse proxies if required).
- **No Plaintext String Lookups**: Serves lookups exclusively by exact 32-byte hex key hashes (`/vindex/lookup/{hash}`). Pre-image hashing (e.g. domain names or certificate fingerprints) is performed client-side.

### 1.3 Alternatives Considered
- **Wire Protocol & Framing**:
  - **Selected - C2SP Multi-Section text/plain Framing**: Standardized in transparency ecosystem (signed-note, tlog-checkpoint), human-readable, curl-friendly, zero Base64 JSON overhead, simple line-scanner parsing.
  - **Rejected - REST / JSON**: Unnecessary serialization overhead, Base64 bloat on binary hashes and cryptographic proofs, lacks native C2SP log format alignment.
  - **Rejected - gRPC / Protobuf**: Requires compiled client SDKs, incompatible with lightweight curl-based inspection and transparent web auditing.
- **Sub-Log Merkle Proof Construction**:
  - **Selected - On-the-Fly Compact Range Accumulation**: Reconstructs `prefix-compact-range-v1` dynamically from 64K chunk boundaries during reverse scan. Keeps Pebble storage compact without writing internal Merkle node records.
  - **Rejected - Storing Full Merkle Trees per Key in Pebble**: Incurs > 4x storage amplification to persist all intermediate Merkle tree branch hashes.

---

## 2. Package API & Responsibilities

### Responsibilities
- **HTTP Routing & Request Validation**: Parses and validates `GET /vindex/lookup/{keyhash}?start=N&limit=M` and `GET /checkpoint`.
- **MPT Proof Generation**: Queries inclusion or non-inclusion proofs from `tree.MPTManager` under a short read lock.
- **Pebble Chunk Traversal**: Positions on the starting inverted chunk via `SeekGE` and reverse-scans (`iter.Prev()`) in forward chronological order.
- **On-the-Fly Compact Range Accumulation**: Generates `prefix-compact-range-v1` hashes for historical occurrences prior to `start`.
- **C2SP Response Framing**: Formats multi-section `text/plain; charset=utf-8` responses.

### Go Interfaces & Types

```go
package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

// LookupRequest encapsulates parsed HTTP query parameters.
type LookupRequest struct {
	KeyHash [sha256.Size]byte
	Start   uint64
	Limit   uint64
}

// ReadServer manages the HTTP serving plane.
type ReadServer struct {
	db        *kvstore.DB
	mptMgr    *tree.MPTManager
	publisher *tree.OutputPublisher
	chunkSize uint64
}

func NewReadServer(db *kvstore.DB, mptMgr *tree.MPTManager, pub *tree.OutputPublisher, chunkSize uint64) *ReadServer
func (s *ReadServer) RegisterRoutes(mux *http.ServeMux)
func (s *ReadServer) HandleLookup(w http.ResponseWriter, r *http.Request)
func (s *ReadServer) HandleCheckpoint(w http.ResponseWriter, r *http.Request)

// ClientVerifier encapsulates client-side response parsing and cryptographic verification.
type ClientVerifier struct {
	OutputLogOrigin   string
	OutputLogVerifier func(checkpoint []byte) error
	InputLogOrigin    string
	InputLogVerifier  func(checkpoint []byte) error
}

type VerifiedLookupResult struct {
	KeyHash       [sha256.Size]byte
	Exists        bool
	Indices       []uint64
	NextStart     *uint64
	OutputLogSize uint64
	InputLogSize  uint64
	MapRoot       [sha256.Size]byte
	MiniLogRoot   [sha256.Size]byte
}

func (v *ClientVerifier) VerifyResponse(ctx context.Context, keyHash [sha256.Size]byte, start uint64, rawBody []byte) (*VerifiedLookupResult, error)
```

---

## 3. Read Path & Lock Sequencing

```text
[Incoming Lookup Request: GET /vindex/lookup/{keyhash}?start=N&limit=M]
          │
          ▼ (1. Acquire mptMgr.mu.RLock)
[Snapshot serving_state & Generate MPT Proof: mpt.Prove(keyhash)]
          │
          ▼ (2. Release mptMgr.mu.RUnlock -- Critical Section ENDS, < 1ms)
[Position Pebble Iterator: 'c' + keyhash + BigEndian(^startChunkNum)]
          │
          ▼ (3. Lock-Free Reverse Scan: iter.Prev() across inverted chunks)
[Decompress RelativeIndices & Reconstruct Absolute Indices]
[Filter: start <= idx < serving_state.InputLogSize]
[Fold CompactRange for prefix entries < start -> prefix-compact-range-v1]
          │
          ▼ (4. Assemble Multi-Section text/plain Response)
[Return HTTP 200 OK]
```

1. **Snapshot under `RLock` (< 1ms)**: `serving_state` pointer and binary MPT proof for `keyhash` are retrieved under read lock, ensuring perfect consistency between `serving_state.MapRoot` and the MPT proof.
2. **Lock-Free Pebble Seek & Reverse Scan**:
   - `startChunkNum = start / chunkSize`.
   - Seek `iter.SeekGE('c' + keyhash + BigEndian(^startChunkNum))`.
   - Call `iter.Prev()` to traverse chunks in forward chronological order towards newer chunks.
   - Filter indices: `start <= idx < serving_state.InputLogSize`.
3. **Pebble Snapshots Unnecessary**: Writes only append to active chunks at or above `serving_state.InputLogSize`. In-flight writes are cleanly dropped by the index filter.

---

## 4. `tlog-vindex` C2SP Wire Protocol Specification

### 1. Protocol Conventions
- **Content-Type**: `text/plain; charset=utf-8`.
- **Framing**: Sections delimited by `— <section-name>[ <arguments>] —` (Unicode U+2014 or ASCII `---`).
- **Section Order**:
  1. `— vindex/v1 —` (Mandatory)
  2. `— output-log-leaf-v1 <leaf_index> —` (Mandatory)
  3. `— output-log-proof-v1 —` (Mandatory)
  4. `— mpt-proof-v1 <inclusion|non-inclusion> —` (Mandatory)
  5. `— prefix-compact-range-v1 —` (Optional, present when `start > 0` and prefix occurrences exist)
  6. `— indices-v1 [next_start] —` (Mandatory)

---

## 5. Protocol Examples

### Example 1: Paginated Query (Page 1 with `next_start`)
`GET /vindex/lookup/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?start=0&limit=3`

```text
— vindex/v1 —
example.com/vindex/output
100
qU/V52nPq2YV1e9L+ZgP0x7bB+fB7r8O/2y0lY8d7hM=

— example.com/witness/alpha AwGgYkYwRAIgR3X5F0b3kK9s8M1P3R5T7V9X1Z3b5d7f9h1j3l5n7p8CIAy7z9A1C3E5G7I9K1M3O5Q7S9U1W3Y5a7c9e1g3i5

— output-log-leaf-v1 99 —
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
example.com/inputlog
500000
fN7y3K1J1T7S4r8E9Q0W2Y5U8O1I4K7M0P3R6T9V2X5=

— example.com/inputlog/witness BxHjZkYwRAIgR1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8CIAy1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A1C3E5G7I9K

— output-log-proof-v1 —
K1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8=
m9N1P3R5T7V9X1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A=

— mpt-proof-v1 inclusion —
BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=

— indices-v1 50000 —
104
2095
48190
```

### Example 2: Continuation Query (Page 2 with `prefix-compact-range-v1`)
`GET /vindex/lookup/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?start=50000&limit=3`

```text
— vindex/v1 —
example.com/vindex/output
100
qU/V52nPq2YV1e9L+ZgP0x7bB+fB7r8O/2y0lY8d7hM=

— example.com/witness/alpha AwGgYkYwRAIgR3X5F0b3kK9s8M1P3R5T7V9X1Z3b5d7f9h1j3l5n7p8CIAy7z9A1C3E5G7I9K1M3O5Q7S9U1W3Y5a7c9e1g3i5

— output-log-leaf-v1 99 —
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
example.com/inputlog
500000
fN7y3K1J1T7S4r8E9Q0W2Y5U8O1I4K7M0P3R6T9V2X5=

— example.com/inputlog/witness BxHjZkYwRAIgR1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8CIAy1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A1C3E5G7I9K

— output-log-proof-v1 —
K1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8=
m9N1P3R5T7V9X1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A=

— mpt-proof-v1 inclusion —
BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=

— prefix-compact-range-v1 —
H8k2L4n6P8r0T2v4X6z8B0d2F4h6J8l0N2p4R6t8V0w=
y1A3C5E7G9I1K3M5O7Q9S1U3W5Y7a9c1e3g5i7k9m1o=

— indices-v1 —
51200
98412
```

### Example 3: Non-Inclusion Query (Key never appeared in log)
`GET /vindex/lookup/0000000000000000000000000000000000000000000000000000000000000000`

```text
— vindex/v1 —
example.com/vindex/output
100
qU/V52nPq2YV1e9L+ZgP0x7bB+fB7r8O/2y0lY8d7hM=

— example.com/witness/alpha AwGgYkYwRAIgR3X5F0b3kK9s8M1P3R5T7V9X1Z3b5d7f9h1j3l5n7p8CIAy7z9A1C3E5G7I9K1M3O5Q7S9U1W3Y5a7c9e1g3i5

— output-log-leaf-v1 99 —
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
example.com/inputlog
500000
fN7y3K1J1T7S4r8E9Q0W2Y5U8O1I4K7M0P3R6T9V2X5=

— example.com/inputlog/witness BxHjZkYwRAIgR1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8CIAy1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A1C3E5G7I9K

— output-log-proof-v1 —
K1j8+u7L0a9D2f4G6h8J1k3M5o7Q9s1U3w5Y7a9C1e8=
m9N1P3R5T7V9X1Z3b5d7f9h1j3l5n7p9r1t3v5x7z9A=

— mpt-proof-v1 non-inclusion —
CAkK

— indices-v1 —
```

---

## 6. Client Verification Specification

```text
[1. Parse Sections & Verify Output Log Checkpoint (vindex/v1)]
                      │
                      ▼
[2. Verify Output Log Inclusion (output-log-leaf-v1 + output-log-proof-v1)]
                      │
                      ├──────────────────────────┐
                      ▼                          ▼
               Extract MapRoot           Extract InputLogSize
                      │                          │
                      ▼                          ▼
       [3. Inspect mpt-proof-v1 Type]   [Filter returned indices]
       ├── non-inclusion:                         │
       │   Verify MPT Non-Inclusion               │
       │   Assert indices-v1 is empty (Stop)      │
       └── inclusion:                             │
           Verify MPT Inclusion Proof             ▼
           Extract MiniLogRoot        [4. Accumulate CompactRange]
                      │              (prefix-compact-range-v1 + LeafHash(idx))
                      │                          │
                      └──────────┬───────────────┘
                                 ▼
                     [5. Assert Equality]
                     MiniLogRoot == CompactRange.Root
```

1. **Parse Response Sections**: Parse sections delimited by `— <section-name> [args] —`.
2. **Output Log Checkpoint Verification (`vindex/v1`)**: Validate witness signatures on signed note.
3. **Output Log Leaf & Inclusion Proof (`output-log-leaf-v1`, `output-log-proof-v1`)**:
   - Extract `MapRoot` (Line 1) and Input Log Checkpoint note.
   - Verify RFC 6962 inclusion proof for `leaf_index` against Output Log root.
4. **MPT Proof Verification (`mpt-proof-v1`)**:
   - If `non-inclusion`: Verify against `MapRoot`. Assert `indices-v1` is empty. Verification completes.
   - If `inclusion`: Verify against `MapRoot` to extract `MiniLogRoot`.
5. **Mini-Log Accumulation & Verification**:
   - Assert `start <= idx < InputLogSize` and strictly monotonic order.
   - Initialize `CompactRange` with `prefix-compact-range-v1` hashes (if present).
   - Append `LeafHash(idx) = SHA256(0x00 || BigEndian(idx))` for each index.
   - Assert `CompactRange.Root == MiniLogRoot`.

---

## 7. Security & DoS Protection

- **Parameter Clamping**: `limit` is strictly clamped (`max_limit = 1000`, default `100`) to prevent unbounded disk scans and RAM exhaustion.
- **Path Sanitization**: Enforces strict validation on `{keyhash}` (`^[0-9a-f]{64}$`), returning HTTP 400 immediately before touching the trie or disk.
- **Direct Stream Serialization**: Formats and streams multi-section lines directly to `http.ResponseWriter` without large intermediate memory buffering.

---

## 8. Operational Health Probes & Subsystem Metrics

### Operational Probes
- `GET /healthz`: Process liveness (HTTP 200).
- `GET /readyz`: Readiness probe (HTTP 200 if `publisher.GetServingState() != nil`; HTTP 503 during startup recovery or error state).

### Metrics
- `server_http_requests_total` (Counter, partitioned by endpoint and status code).
- `server_lookup_latency_seconds` (Histogram): End-to-end lookup latency.
- `server_mpt_prove_duration_seconds` (Histogram): Time spent generating MPT proofs under read lock (< 1ms).
- `server_pebble_scan_duration_seconds` (Histogram): Time spent traversing inverted chunks.
- `server_response_bytes_total` (Counter): Total bytes served.

---

## 9. Conformance Testing & Wire Verification

- **Golden File Test Fixtures**: Validating responses against golden file test cases for all 3 scenarios (Page 1 with `next_start`, Continuation with prefix compact range, Non-Inclusion).
- **ClientVerifier Tamper Suite**: Testing `ClientVerifier` against corrupted MPT proofs, altered indices, forged witness signatures, and mismatched mini-log roots to assert 100% rejection.
- **HTTP Endpoint Fuzzing**: Fuzzing query parameters (`start`, `limit`) and hex hash formats.

