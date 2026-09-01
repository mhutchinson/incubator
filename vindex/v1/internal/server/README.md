# Sub-Design: HTTP Read Server API & C2SP Wire Protocol

## 1. Context & Objectives

The **Read Server Subsystem** (`vindex/v1/internal/server`) serves verifiable index lookup requests over HTTP adhering to standard Community Cryptography Specification Project ([C2SP](https://c2sp.org/)) conventions. It queries the abstract `kvstore.IndexStore`, applies active watermark filtering, packages on-the-fly Merkle prefix compact ranges, and formats cryptographic proofs into human-readable plain-text responses.

### 1.1 Core Guarantees
1. **Concurrent Serving Unblocked by Storage I/O**: The MPT critical section is strictly minimized (< 1ms under `mpt_lock.RLock()`), after which storage queries (`store.Lookup`) and response streaming execute completely lock-free.
2. **Watermark Isolation**: Readers are strictly isolated from in-flight writes ahead of `serving_state.InputLogSize` via index filtering.
3. **Bounded Memory & Latency (Hot-Key Pagination)**: Supports backward paging via `before` and `limit` query parameters with continuation headers (`indices-v1 [next_before]`) and RFC 6962 prefix compact ranges (`prefix-compact-range-v1`).
4. **End-to-End Cryptographic Verifiability**: Every response contains full cryptographic proof from the witnessed Output Log checkpoint down to individual Input Log indices.

### 1.2 Non-Requirements & Out of Scope
- **No Write Endpoints**: The Read Server is strictly read-only (GET methods only). No POST, PUT, or administrative write endpoints.
- **No Identity Auth / ACLs**: Serves public cryptographic proofs openly over HTTP. Client authentication, authorization, and per-tenant rate-limiting are out of scope (delegated to edge reverse proxies if required).
- **No Plaintext String Lookups**: Serves lookups exclusively by exact 32-byte hex key hashes (`/vindex/lookup/{hash}`). Pre-image hashing (e.g. domain names or certificate fingerprints) is performed client-side.

---

## 2. Package API & Responsibilities

### Responsibilities
- **HTTP Routing & Request Validation**: Parses and validates `GET /vindex/lookup/{keyhash}?limit=M` and `GET /vindex/lookup/{keyhash}?before=X&limit=M` and `GET /checkpoint`.
- **MPT Proof Generation**: Queries inclusion or non-inclusion proofs from `tree.MPTManager` under a short read lock.
- **Encapsulated Index Query**: Invokes `kvstore.IndexStore.Lookup` to retrieve matching newest indices and prefix compact ranges without awareness of underlying storage mechanics.
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
	Before  *uint64
	Limit   uint64
}

// ReadServer manages the HTTP serving plane.
type ReadServer struct {
	store     kvstore.IndexStore
	mptMgr    *tree.MPTManager
	publisher *tree.OutputPublisher
}

func NewReadServer(store kvstore.IndexStore, mptMgr *tree.MPTManager, pub *tree.OutputPublisher) *ReadServer
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
	NextBefore    *uint64
	OutputLogSize uint64
	InputLogSize  uint64
	MapRoot       [sha256.Size]byte
	MiniLogRoot   [sha256.Size]byte
}

func (v *ClientVerifier) VerifyResponse(ctx context.Context, keyHash [sha256.Size]byte, before *uint64, rawBody []byte) (*VerifiedLookupResult, error)
```

---

## 3. Read Path & Subsystem Interaction

```text
[Incoming Lookup Request: GET /vindex/lookup/{keyhash}?before=X&limit=M]
          │
          ▼ (1. Acquire mptMgr.mu.RLock)
[Snapshot serving_state & Generate MPT Proof: mpt.Prove(keyhash)]
          │
          ▼ (2. Release mptMgr.mu.RUnlock -- Critical Section ENDS, < 1ms)
[Query Storage: store.Lookup(keyhash, before, limit, serving_state.InputLogSize)]
          │
          ▼ (3. Receive LookupResult: MatchedIndices & Prefix Compact Range)
[Assemble Multi-Section text/plain Response]
          │
          ▼ (4. Stream Response to Client)
[Return HTTP 200 OK]
```

1. **Snapshot under `RLock` (< 1ms)**: `serving_state` pointer and binary MPT proof for `keyhash` are retrieved under read lock, ensuring perfect consistency between `serving_state.MapRoot` and the MPT proof.
2. **Encapsulated Store Lookup (`store.Lookup`)**:
   - The server delegates storage retrieval entirely to `kvstore.IndexStore.Lookup(keyHash, before, limit, serving_state.InputLogSize)`.
   - The server has zero knowledge of the underlying storage engine (Pebble, SSTables, bitwise key inversion, or iterators).
3. **Response Assembly**: The server formats the multi-section C2SP response from the MPT proof, Output Log leaf, prefix compact range (covering older occurrences before the oldest returned index), and matched indices.

---

## 4. `tlog-vindex` C2SP Wire Protocol Specification

### 4.1 Protocol Conventions
- **Content-Type**: `text/plain; charset=utf-8`.
- **Framing**: Sections delimited by `— <section-name>[ <arguments>] —` (Unicode U+2014 em dash or ASCII `---`).
- **Section Order**:
  1. `— vindex/v1 —` (Mandatory)
  2. `— output-log-leaf-v1 <leaf_index> —` (Mandatory)
  3. `— output-log-proof-v1 —` (Mandatory)
  4. `— mpt-proof-v1 <inclusion|non-inclusion> —` (Mandatory)
  5. `— prefix-compact-range-v1 <covered_size> —` (Optional, present when earlier occurrences exist prior to this page)
  6. `— indices-v1 [next_before] —` (Mandatory)

### 4.2 Section Grammar Table

The following table formally defines the grammar, argument parameters, optionality, line positions, and data types for all 6 wire sections:

| Section Header | Header Arguments | Optionality | Line / Field | Field Name | Type / Encoding | Description & Validation Rules |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `— vindex/v1 —` | *None* | **Mandatory** | Line 1 | `OutputLogOrigin` | `string` (UTF-8) | Output Log checkpoint origin ID (e.g. `example.com/vindex/output`). |
| | | | Line 2 | `OutputLogTreeSize` | `uint64` (decimal ASCII) | Output Log tree size committed at time of query serving snapshot. |
| | | | Line 3 | `OutputLogRootHash` | `[32]byte` (RFC 4648 Base64) | Merkle tree root hash of the Output Log at `OutputLogTreeSize`. |
| | | | Line 4 | `Separator` | `\n` (blank line) | Signed-note header separator dividing body from witness signatures. |
| | | | Line 5+ | `WitnessSignatures` | `string` (`— <origin> <sig>`) | One or more signed-note witness cosignatures verifying Lines 1–3. |
| `— output-log-leaf-v1 <leaf_index> —` | `<leaf_index>` (`uint64` decimal) | **Mandatory** | Line 1 | `MapRoot` | `[32]byte` (64-char lowercase hex) | Binary Merkle Patricia Trie root hash committed at this Output Log leaf. |
| | | | Line 2 | `InputLogOrigin` | `string` (UTF-8) | Input Log origin ID embedded in the state commitment. |
| | | | Line 3 | `InputLogSize` | `uint64` (decimal ASCII) | Watermark Input Log tree size indexed by `MapRoot`. |
| | | | Line 4 | `InputLogRootHash` | `[32]byte` (RFC 4648 Base64) | Merkle tree root hash of the Input Log at `InputLogSize`. |
| | | | Line 5 | `Separator` | `\n` (blank line) | Signed-note separator dividing Input Log checkpoint from signatures. |
| | | | Line 6+ | `InputLogSignatures` | `string` (`— <origin> <sig>`) | One or more Input Log witness cosignatures. |
| `— output-log-proof-v1 —` | *None* | **Mandatory** | Lines 1..K | `AuditPathHashes` | `[32]byte` (RFC 4648 Base64, 1/line) | RFC 6962 Merkle audit path proving `leaf_index` in Output Log. Empty (0 lines) if `OutputLogTreeSize == 1`. |
| `— mpt-proof-v1 <proof_type> —` | `<proof_type>` (`inclusion` \| `non-inclusion`) | **Mandatory** | Line 1 | `SerializedMPTProof` | `bytes` (RFC 4648 Base64) | Serialized MPT proof. If `inclusion`, proves `KeyHash -> MiniLogRoot` against `MapRoot`. If `non-inclusion`, proves key absence. |
| `— prefix-compact-range-v1 <covered_size> —` | `<covered_size>` (`uint64` decimal) | **Optional** (present when `covered_size > 0`) | Lines 1..M | `CompactRangeHashes` | `[32]byte` (RFC 4648 Base64, 1/line) | RFC 6962 compact range hashes committing to the cumulative sub-log prefix `0 .. covered_size-1`. |
| `— indices-v1 [next_before] —` | `[next_before]` (`uint64` decimal, optional) | **Mandatory** | Lines 1..N | `MatchedIndices` | `uint64` (decimal ASCII, 1/line) | Monotonically ascending Input Log leaf indices (`idx_0 < idx_1 < ...`). Empty if non-inclusion or no entries in window. |

---

## 5. Wire Protocol Examples & Cryptographic Annotations

### Example 1: Tip Query (Page 1 with `next_before`)
`GET /vindex/lookup/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?limit=3`

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

— prefix-compact-range-v1 48190 —
H8k2L4n6P8r0T2v4X6z8B0d2F4h6J8l0N2p4R6t8V0w=
y1A3C5E7G9I1K3M5O7Q9S1U3W5Y7a9c1e3g5i7k9m1o=

— indices-v1 48190 —
48190
51200
98412
```

#### Cryptographic Guarantee Breakdown (Example 1):
- **`— vindex/v1 —` (Section '— vindex/v1 —')**: Standard C2SP signed note checkpoint. Proves that Output Log root `qU/V...` at tree size 100 has been publicly witnessed and signed by `example.com/witness/alpha`.
- **`— output-log-leaf-v1 99 —` (Section '— output-log-leaf-v1 —')**: Output Log leaf payload at index 99. Authenticates the `MapRoot` (`7f83b165...`) and binds it cryptographically to the Input Log checkpoint (`example.com/inputlog` at watermark size 500,000, root `fN7y3K...`, witnessed by `example.com/inputlog/witness`).
- **`— output-log-proof-v1 —` (Section '— output-log-proof-v1 —')**: RFC 6962 audit path hashes. Proves mathematically that leaf 99 is included within the witnessed Output Log root at size 100.
- **`— mpt-proof-v1 inclusion —` (Section '— mpt-proof-v1 —')**: Sparse binary Merkle Patricia Trie proof. Proves that `keyhash` exists in `MapRoot` and commits to `MiniLogRoot`.
- **`— prefix-compact-range-v1 48190 —` (Section '— prefix-compact-range-v1 —')**: RFC 6962 compact range hashes committing to the cumulative sub-log prefix of the earlier 48,190 occurrences (`0 .. 48189`).
- **`— indices-v1 48190 —` (Section '— indices-v1 —')**: Returns the newest 3 matched Input Log leaf indices [48190, 51200, 98412]. When client initializes a compact range with the prefix hashes and appends `LeafHash(48190)`, `LeafHash(51200)`, and `LeafHash(98412)`, the computed root matches `MiniLogRoot`. The header argument `48190` signals that more historical records exist and provides the cursor for the next query (`before=48190`).

---

### Example 2: Backward Continuation Query (Page 2 reaching beginning)
`GET /vindex/lookup/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?before=48190&limit=3`

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

— indices-v1 —
104
2095
```

#### Cryptographic Guarantee Breakdown (Example 2):
- **Omission of `prefix-compact-range-v1`**: Because this continuation page encompasses the earliest occurrences of `keyhash` in the log (indices 104 and 2095), `covered_size == 0` and no earlier prefix exists.
- **`— indices-v1 —` (Section '— indices-v1 —')**: Header lacks a `next_before` argument, signaling that the beginning of the index history (genesis) has been reached.
- **Inductive Verification**: The client appends `LeafHash(104)` and `LeafHash(2095)` to an empty compact range. The resulting range state matches the target `prefix-compact-range-v1 48190` cached from Page 1, proving complete historical continuity without gap or omission.

---

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

#### Cryptographic Guarantee Breakdown (Example 3):
- **`— mpt-proof-v1 non-inclusion —` (Section '— mpt-proof-v1 —')**: Contains an MPT proof demonstrating that the queried 32-byte hash `0000...00` falls on an empty trie branch or intermediate prefix boundary in `MapRoot`.
- **`— indices-v1 —` (Section '— indices-v1 —')**: Empty index list. The client confirms non-inclusion by asserting that the non-inclusion proof verifies against `MapRoot` and `indices-v1` contains 0 entries.

---

### Example 4: Paginated Query Prior to Oldest Occurrence (`before <= min_index`)
`GET /vindex/lookup/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?before=100&limit=100`

When a key exists in the log (e.g. with historical occurrences starting at index 104), but the client queries with `before` less than or equal to the oldest known occurrence, the server returns an **inclusion** proof for the key, no prefix compact range (0 covered size), and an empty `indices-v1`:

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

— indices-v1 —
```

---

## 6. Client Verification Specification

The client verification protocol executes across two distinct tiers: **Tier 1 (Page 1 / Tip Verification)** anchoring the query directly against the signed Output Log checkpoint, and **Tier 2 (Continuation Page Verification)** chaining backward inductively against previous prefix compact ranges.

### 6.1 Two-Tier Verification Flowchart

```text
================================================================================
TIER 1: PAGE 1 (TIP) VERIFICATION (before == nil)
================================================================================

[Wire Response: Page 1]
         │
         ▼
[1. Verify Output Log Checkpoint (vindex/v1)] ──► Validates Output Log Root
         │
         ▼
[2. Verify Output Log Leaf (output-log-leaf-v1 + output-log-proof-v1)]
         │
         ├────────────────────────────────────────┬────────────────────────┐
         ▼                                        ▼                        ▼
  Extract MapRoot                       Extract InputLogSize       Extract InputLog Root
         │                                        │                        │
         ▼                                        ▼                        ▼
[3. Verify mpt-proof-v1 against MapRoot]   [Assert indices < InputLogSize]  [Verify Input Log CP]
         │
         ├────────────────────────────────────────┐
         │ (if non-inclusion)                     │ (if inclusion)
         ▼                                        ▼
   [Assert indices-v1 is empty]             Extract MiniLogRoot
   [Verification Complete: KEY ABSENT]            │
                                                  ▼
                                           [4. Init CompactRange from prefix-compact-range-v1 (size: covered_size)]
                                                  │
                                                  ▼
                                           [5. Append LeafHash(idx) for idx in indices-v1]
                                                  │
                                                  ▼
                                           [6. Assert CompactRange.Root() == MiniLogRoot]
                                                  │
                                                  ▼
                                           [7. Cache prefix-compact-range-v1 as Target for Continuation]
                                                  │
                                                  ▼
                                           [Verification Complete: PAGE 1 VALID]


================================================================================
TIER 2: CONTINUATION PAGE VERIFICATION (before == X, inductive step)
================================================================================

[Wire Response: Continuation Page (before=X)]
         │
         ▼
[1. Parse Continuation Page Sections]
         │
         ├─────────────────────────────────────────────────────────────────┐
         ▼                                                                 ▼
[Validate indices-v1 < before & strictly ascending]               [Extract covered_size from header]
         │                                                                 │
         └────────────────────────────────┬────────────────────────────────┘
                                          ▼
                   [2. Init fresh CompactRange from continuation prefix-compact-range-v1]
                                          │
                                          ▼
                   [3. Append LeafHash(idx) for idx in continuation indices-v1]
                                          │
                                          ▼
                   [4. Assert resulting CompactRange == Cached previous_prefix_compact_range]
                                          │
                                          ▼
                   [5. Update Cached Target = continuation prefix-compact-range-v1]
                                          │
                                          ▼
                   [Repeat until covered_size == 0 (Genesis reached)]
```

### 6.2 Step-by-Step Verification Protocol

1. **Parse Response Sections**: Parse sections delimited by `— <section-name> [args] —`.
2. **Output Log Checkpoint Verification (`vindex/v1`)**: Validate witness signatures on signed note.
3. **Output Log Leaf & Inclusion Proof (`output-log-leaf-v1`, `output-log-proof-v1`)**:
   - Extract `MapRoot` (Line 1) and Input Log Checkpoint note.
   - Verify RFC 6962 inclusion proof for `leaf_index` against Output Log root.
4. **MPT Proof Verification (`mpt-proof-v1`)**:
   - If `non-inclusion`: Verify against `MapRoot`. Assert `indices-v1` is empty. Verification completes.
   - If `inclusion`: Verify against `MapRoot` to extract `MiniLogRoot`.
5. **Mini-Log Accumulation & Verification (Inductive Backward Verification Protocol)**:
   Continuation pages are verified inductively from Page 1 downward. Standalone continuation queries (`before != nil`) cannot be verified against `MapRoot` in isolation.
   - **Index Validation**: If `indices-v1` is non-empty, assert `idx < before` (when specified), `idx < InputLogSize`, and strictly monotonic ascending order.
   - **Base Step (Page 1 / Tip Verification, `before == nil`)**:
     - Extract `covered_size` from the `— prefix-compact-range-v1 <covered_size> —` header (if present) to initialize the RFC 6962 `compact.Range` with `covered_size` and the provided prefix hashes (commits to prefix `0 .. covered_size-1`). If absent/empty, the range starts empty (size 0).
     - Append `LeafHash(idx) = SHA256(0x00 || BigEndian(idx))` for each index in `indices-v1`.
     - Assert `CompactRange.Root() == MiniLogRoot` (extracted from the verified MPT inclusion proof against `MapRoot`).
     - Retain `prefix-compact-range-v1` (including its `covered_size` and hashes) as the expected accumulator target for the subsequent continuation page.
   - **Inductive Step (Continuation Verification, `before != nil`)**:
     - Extract `covered_size` from the continuation page's `— prefix-compact-range-v1 <covered_size> —` header to initialize a fresh RFC 6962 `compact.Range` with the prefix hashes.
     - Append `LeafHash(idx)` for each index in the continuation page's `indices-v1`.
     - Assert that the resulting compact range matches the prefix compact range retained from the preceding page.
     - Update the retained expected compact range to this page's `prefix-compact-range-v1` for the next backward query.
     - Repeat until genesis (`prefix-compact-range-v1` empty) is reached.

---

## 7. Security & DoS Protection

- **Parameter Clamping**: `limit` is strictly clamped (`max_limit = 1000`, default `100`) to prevent unbounded disk scans and RAM exhaustion.
- **Path Sanitization**: Enforces strict validation on `{keyhash}` (`^[0-9a-f]{64}$`), returning HTTP 400 immediately before touching the trie or disk.
- **Direct Stream Serialization**: Formats and streams multi-section lines directly to `http.ResponseWriter` without large intermediate memory buffering.

---

## 8. Alternatives Considered

For comprehensive discussion of architectural trade-offs across storage engines, commit pipelines, and trie structures, see [ARCHITECTURE.md](../../docs/ARCHITECTURE.md#9-architectural-decisions--alternatives-considered).

- **Paging Model & Traversal Direction**:
  - **Selected - Backward Paging (`before=X&limit=M`)**: Merkle tree compact ranges natively commit to a contiguous prefix of history (`0 .. K-1`). Returning the latest tail entries alongside a single `prefix-compact-range-v1` allows O(log N) cryptographic verification of all prior history in a single response. Traversal naturally aligns with inverted chunk storage (`'c' + KeyHash + ^chunkNum`). For detailed rationale, see [ARCHITECTURE.md](../../docs/ARCHITECTURE.md#9-architectural-decisions--alternatives-considered).
  - **Rejected - Forward Paging (`start=X&limit=M`)**: Requires either returning unverified future state, maintaining complex arbitrary suffix sub-tree proofs, or forcing clients to traverse millions of historical entries to reach the latest state.
- **Wire Protocol & Framing**:
  - **Selected - C2SP Multi-Section text/plain Framing**: Standardized in transparency ecosystem (signed-note, tlog-checkpoint), human-readable, curl-friendly, zero Base64 JSON overhead, simple line-scanner parsing.
  - **Rejected - REST / JSON**: Unnecessary serialization overhead, Base64 bloat on binary hashes and cryptographic proofs, lacks native C2SP log format alignment.
  - **Rejected - gRPC / Protobuf**: Requires compiled client SDKs, incompatible with lightweight curl-based inspection and transparent web auditing.
- **Sub-Log Merkle Proof Construction**:
  - **Selected - On-the-Fly Compact Range Accumulation**: Reconstructs `prefix-compact-range-v1` dynamically from 64K chunk boundaries during storage lookup. Keeps storage compact without writing internal Merkle node records.
  - **Rejected - Storing Full Merkle Trees per Key in Storage**: Incurs > 4x storage amplification to persist all intermediate Merkle tree branch hashes.

---

## 9. Operational Health Probes & Subsystem Metrics

### Operational Probes
- `GET /healthz`: Process liveness (HTTP 200).
- `GET /readyz`: Readiness probe (HTTP 200 if `publisher.GetServingState() != nil`; HTTP 503 during startup recovery or error state).

### Metrics
- `vindex_server_http_requests_total` (Counter, partitioned by endpoint and status code).
- `vindex_server_lookup_latency_seconds` (Histogram): End-to-end lookup latency.
- `vindex_server_mpt_prove_duration_seconds` (Histogram): Time spent generating MPT proofs under read lock (< 1ms).
- `vindex_server_pebble_scan_duration_seconds` (Histogram): Time spent traversing inverted chunks.
- `vindex_server_response_bytes_total` (Counter): Total bytes served.

---

## 10. Conformance Testing & Wire Verification

- **Golden File Test Fixtures**: Validating responses against golden file test cases for all 3 scenarios (Page 1 with `next_before`, Continuation with prefix compact range, Non-Inclusion).
- **ClientVerifier Tamper Suite**: Testing `ClientVerifier` against corrupted MPT proofs, altered indices, forged witness signatures, and mismatched mini-log roots to assert 100% rejection.
- **HTTP Endpoint Fuzzing**: Fuzzing query parameters (`before`, `limit`) and hex hash formats.
