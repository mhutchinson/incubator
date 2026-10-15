# Sub-Design: True Prefix Lookups & Subtree Discovery

This document specifies the architectural overhaul of **VIndex** from fixed 32-byte hashed Merkle Patricia Trie (MPT) keys to variable-length canonical keys with verifiable prefix subtree discovery, alongside the two-endpoint `/keys/` and `/entries/` read protocol.

---

## 1. Context & Objectives

### 1.1 Problem Statement & Real-World Friction
In VIndex v1, the state commitment trie ([`internal/tree/`](../internal/tree/README.md)) indexed every search key by its 32-byte `SHA256(canonical_preimage)` digest. Because cryptographic hashing destroys lexicographical locality, the trie could only prove the inclusion or non-inclusion of an exact pre-known key.

To support subdomain discovery in Certificate Transparency (CT) and Merkle Tree Certificates (MTC) under a hashed-key trie, the mapping stage ([`APPLICATIONS.md`](APPLICATIONS.md)) had to expand every certificate domain up its parent hierarchy to the registrable eTLD+1 boundary at ingest time. This design introduced three compounding operational bottlenecks:

1. **Write Amplification at the MPT Bottleneck**: A single certificate covering `a.b.c.d.example.com` emitted 5 distinct keys (`a.b.c.d.example.com`, `b.c.d.example.com`, `c.d.example.com`, `d.example.com`, and `example.com`). Across multi-SAN certificates, map-time suffix expansion multiplied unique MPT key insertions and Pebble inverted chunk writes by 3x–5x, directly amplifying I/O and rehashing work in the MPT—the primary indexing bottleneck.
2. **Public Suffix List (PSL) Coupling in the Cryptographic TCB**: Determining the eTLD+1 stop boundary required embedding the Public Suffix List inside the deterministic WebAssembly guest module. Because the PSL changes frequently as new TLDs and registrar boundaries are added, any PSL update altered the emitted key set and invalidated historical `MapRoot` commitments, forcing a full re-index from leaf 0.
3. **Loss of Subdomain Granularity & Wildcard Distinction**: Rolling all subdomains and wildcards (`*.example.com`) into the parent `example.com` mini-log forced clients querying the apex domain to download leaf indices for every subdomain, with no way to enumerate which distinct subdomains existed or isolate certificates affecting only the root domain.

Upgrading the underlying Merkle Patricia Trie (`filippo.io/torchwood/mpt` v0.10.1+) to store variable-length un-hashed keys (`[]byte` up to 1024 bytes) unlocks true radix prefix mode: each domain or identifier is emitted once under its natural hierarchical key, point lookups operate directly on un-hashed keys, and prefix queries cryptographically discover and verify the complete subtree of matching keys.

### 1.2 Goals & Non-Goals
- **Goals**:
  - Eliminate map-time parent suffix expansion in CT and MTC guest plugins, emitting at most one reversed-label key per SAN/CN (`"com.google.mail."`, `"com.google.*."`, `"com.google."`).
  - Remove the Public Suffix List from the deterministic WebAssembly mapping boundary and relocate prefix breadth policy enforcement to the HTTP read server.
  - Support both direct exact-key lookups and verifiable prefix subtree discovery (`prefix=true`) via `filippo.io/torchwood/mpt` path and prefix proofs.
  - Separate MPT state commitment queries (`/vindex/v1/keys/`) from Pebble mini-log index pagination (`/vindex/v1/entries/`) so index retrieval never acquires MPT locks.
  - Preserve fixed-size 32-byte hashed keys inside Pebble inverted chunk storage (`'c' + SHA256(key) + ^chunkNum`) and in-memory active chunk caches to retain pointer-free Go map keys and 33-byte prefix Bloom filters.
- **Non-Goals**:
  - Arbitrary regular expression or suffix/substring matching (queries must be exact keys or leading byte prefixes).
  - Range scanning across keys inside Pebble (all prefix key discovery is served and authenticated exclusively from the MPT).
  - Single-RTT combined prefix discovery + multi-key index inlining (deferred as a future optional composite endpoint if needed).

### 1.3 Requirements, Constraints & Explicit Trade-Offs
- **Key Size Bounds**: Canonical keys stored in the MPT must be between 1 and 1024 bytes (`MaxKeyLen = 1024`) and must not contain `NUL` (`0x00`) bytes or ASCII whitespace (`' '`, `'\t'`, `'\n'`, `'\r'`).
- **Explicit Trade-Offs & Limitations**:
  - *Two-RTT Point Lookups*: Separating `/vindex/v1/keys/` (MPT) from `/vindex/v1/entries/` (Pebble) requires 2 HTTP requests for a cold point lookup (`1 + K` requests for a prefix matching `K` keys) in exchange for strict storage-layer decoupling and zero MPT lock contention during index retrieval.
  - *Full Subtree Reconstruction on Prefix Queries*: Verifying a prefix proof requires reconstructing the Merkle hash of the entire matching MPT subtree on the client. Consequently, prefix queries covering millions of keys (such as bare TLDs like `"com."`) cannot be paginated at the MPT proof layer and must be rejected by server-side prefix policy and cardinality limits.
  - *MPT Disk Format Incompatibility*: Upgrading `filippo.io/torchwood/mpt` transitions the on-disk trie magic header from `"mpt tree\n"` to `"mpt tree v2\n"` (52-byte in-memory nodes with variable-length leaf records in `mpt.disk`), requiring existing persisted MPT directories to be rebuilt.
- **Invariants & Verification Gates**:
  - `go test -race ./vindex/...`

---

## 2. Detailed Design & Contracts

### 2.1 Canonical Key Formatting & Hierarchical Prefix Ordering

To enable prefix subtree discovery in a binary radix trie, hierarchical identifiers must order from most general (root/TLD/organization) to most specific (subdomain/leaf package), with an explicit label terminator so a parent prefix never collides with a sibling label that shares a character prefix.

| Ecosystem | Input Identifier | Canonical MPT Key | Example Prefix Query | Matched Keys | Excluded Sibling Keys |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CT / MTC (Apex)** | `google.com` | `com.google.` | `com.google.` | `com.google.`, `com.google.mail.`, `com.google.*.` | `com.googleapis.`, `com.googleusercontent.` |
| **CT / MTC (Subdomain)** | `mail.google.com` | `com.google.mail.` | `com.google.mail.` | `com.google.mail.`, `com.google.mail.*.` | `com.google.`, `com.google.Mail2.` |
| **CT / MTC (Wildcard)** | `*.google.com` | `com.google.*.` | `com.google.*.` | `com.google.*.` | `com.google.`, `com.google.mail.` |
| **Go SumDB** | `github.com/google/uuid` | `github.com/google/uuid` | `github.com/google/` | `github.com/google/uuid`, `github.com/google/go-cmp` | `github.com/googleapis/gax-go` |
| **Sigstore (Digest)** | `sha256:e3b0c442...` | `sha256:e3b0c442...` | *(Exact lookup only)* | `sha256:e3b0c442...` | All other digests |
| **Sigsum (PubKey)** | 32-byte Ed25519 key | 64-char lowercase hex | *(Exact lookup only)* | `<64-char hex>` | All other keys |

#### Domain Canonicalization Rules (CT & MTC)
1. Trim surrounding ASCII whitespace, strip a single trailing dot (`.`) if present, and convert ASCII characters to lowercase.
2. Convert non-ASCII internationalized domain labels to ASCII Punycode (`xn--...`) via IDNA2008 lookup rules; reject malformed labels.
3. Preserve a leading wildcard label (`*.`) as a distinct label `*` rather than stripping it.
4. Split the domain on `.`, reverse the label order, join with `.`, and append a mandatory trailing `.` (e.g., `*.mail.google.com` -> `com.google.mail.*.`).

- **[Correctness Invariant] Mandatory Trailing Delimiter on Reversed Domain Keys**:
  - *Rule*: Every reversed-label domain key emitted by a CT or MTC mapper and every domain prefix query must terminate with a trailing dot (`.`).
  - *Rationale*: In a byte-prefix trie, the trailing dot acts as an explicit label boundary separator. Prefix `"com.google."` matches the apex key `"com.google."` and all child keys `"com.google.<sublabel>."`.
  - *Consequence ("Or Else")*: Without a trailing dot, querying prefix `"com.google"` would match unrelated sibling domains sharing the same character prefix (such as `"com.googleapis"`), forcing the subtree proof and scan to include unrelated third-party domains.

- **[Correctness Invariant] Wildcard Label Preservation**:
  - *Rule*: Wildcard certificates (`*.example.com`) must be indexed under their literal wildcard label (`"com.example.*."`) rather than stripped to the parent domain (`"com.example."`).
  - *Rationale*: Preserves exact-match separation between certificates scoped solely to the apex domain and wildcard certificates covering arbitrary subdomains, while keeping `"com.example.*."` inside the `"com.example."` prefix subtree.
  - *Consequence ("Or Else")*: Stripping `*.` conflates wildcard and apex certificates under a single key, preventing monitors from querying root-only certificates without downloading subdomain wildcard history.

- **[Correctness Invariant] NUL-Free Printable ASCII Canonical Keys**:
  - *Rule*: Canonical keys emitted by guest plugins must consist solely of printable ASCII bytes (`0x21..0x7E`, excluding whitespace and `0x00`) and must not exceed 1024 bytes.
  - *Rationale*: `filippo.io/torchwood/mpt` pads variable-length keys of length `L` with a `0x00` byte at index `L` followed by infinite `0xFF` bytes so that no key is a bit-prefix of another. When keys contain no `0x00` bytes, the trie's key ordering and prefix matching are strictly equivalent to standard byte slice comparison and byte prefix matching, and keys can be serialized in newline/space-delimited wire sections without escaping.
  - *Consequence ("Or Else")*: Keys containing `0x00` bytes would sort after shorter prefix keys in non-lexicographical order under MPT `00 FF FF...` padding, and keys containing whitespace or newlines would corrupt line-oriented C2SP wire responses.

- **[Performance Optimization] Elimination of Map-Time Suffix Expansion**:
  - *Mechanism*: Guest WASM plugins emit only the single reversed-label domain for each extracted CN/SAN rather than looping up the label hierarchy to eTLD+1.
  - *Impact*: Reduces per-certificate key emissions and MPT `Set` operations by 3x–5x on typical multi-level domains and removes the Public Suffix List lookup table from the guest WASM binary.

---

### 2.2 Storage Architecture: Hybrid Raw-Key MPT & Hashed-Key Pebble LSM

Data flows through the write pipeline using raw canonical keys at the mapping and MPT layers while retaining fixed 32-byte SHA-256 digests inside the Pebble inverted chunk store:

1. **Sandboxed Mapping (`mapfn/` & `internal/ingest/`)**: The guest WASM plugin emits raw canonical key bytes via the bundle slab ABI. The host unpacks and validates the key bytes (enforcing `1 <= len(key) <= 1024`), deduplicates occurrences per leaf, and aggregates ordered batches keyed by the canonical key string.
2. **Inverted Chunk Storage (`internal/kvstore/`)**: When indexing a batch of canonical keys and leaf indices, the storage engine computes `KeyHash = SHA256(key)` internally at the storage boundary. Active chunk caches and Pebble LSM records remain keyed by the fixed 41-byte layout (`'c' + 32-byte KeyHash + 8-byte ^chunkNum`). The indexer returns the map of modified sub-roots keyed by the raw canonical key (`key -> SubRoot`).
3. **State Commitment (`internal/tree/` & `internal/coordinator/`)**: The coordinator and publisher sort the modified `(key, SubRoot)` pairs using MPT key order and apply them directly to the `torchwood/mpt` v2 tree (`Key = []byte(key)`, `Val = SubRoot[:]`). During crash recovery replay, re-mapped batches yield raw keys which are hashed internally by the KV store to look up persisted sub-roots and re-applied as raw keys to the MPT.

- **[Correctness Invariant] Deterministic MPT Key Sorting on Batch Prediction and Commit**:
  - *Rule*: All batch mutations passed to MPT root prediction must be strictly sorted and deduplicated according to the MPT padded key comparison order.
  - *Rationale*: The `torchwood/mpt` stack-reduction prediction algorithm requires changes to be presented in strictly increasing trie key order.
  - *Consequence ("Or Else")*: Unsorted or duplicate keys cause root prediction to fail and halt the publication pipeline.

- **[Performance Optimization] Internal SHA-256 Keying in Pebble & Active Chunk Caches**:
  - *Mechanism*: Hashes variable-length keys to `[32]byte` at the KV storage boundary while keeping raw keys in the MPT.
  - *Impact*: Preserves fixed 41-byte Pebble keys, 33-byte prefix Bloom filters (`O(1)` point non-inclusion pruning), and pointer-free `[32]byte` keys in the 131,072-entry generational chunk cache (zero Go garbage collector mark-phase pointer scanning), at the cost of a single hardware-accelerated SHA-256 instruction (~40ns) per unique key per batch.

---

### 2.3 Two-Endpoint Read Protocol (`/vindex/v1/keys/` & `/vindex/v1/entries/`)

The read serving plane ([`internal/server/`](../internal/server/README.md)) splits queries into two orthogonal HTTP endpoints corresponding to the two underlying data structures:

| Endpoint | Backing Store | MPT Lock Acquired? | Purpose |
| :--- | :--- | :--- | :--- |
| `GET /vindex/v1/keys/{key...}[?prefix=true]` | In-memory MPT + Output Log | Yes (`RLock` during `Path`/`Scan`) | Authenticates `MapRoot` against the witnessed Output Log and proves exact key inclusion/non-inclusion (`prefix=false`) or discovers all `(key, subRoot)` pairs under a prefix (`prefix=true`). |
| `GET /vindex/v1/entries/{key...}?before=X[&limit=Y]` | Pebble LSM (`kvstore`) | **Never** | Returns a page of matching Input Log leaf indices `< before` and the RFC 6962 prefix compact range needed to reconstruct the key's mini-log `subRoot`. |

#### 2.3.1 Endpoint 1: `GET /vindex/v1/keys/{key...}[?prefix=true]`

##### Query Parameters & Guardrails
- `{key...}`: The URL-decoded path suffix after `/vindex/v1/keys/`. Must be 1..1024 printable ASCII bytes.
- `prefix` (optional boolean, default `false`):
  - When `false` or omitted (**Point Mode**): Executes `Tree.Path(key)` and `ProveLookup(key, path)` to prove presence or absence of the exact key.
  - When `true` (**Prefix Discovery Mode**):
    1. **Pre-Scan Policy Check**: Validates `{key...}` against the server's configured prefix policy (for CT/MTC: requires a trailing `.` and verifies via the Public Suffix List that the reversed prefix contains at least a registrable `eTLD+1` boundary, rejecting bare TLDs or public suffixes such as `"com."` or `"uk.co."` with `HTTP 400 Bad Request`).
    2. **Subtree Proof & Bounded Scan**: Under a shared read lock on the serving state and MPT, executes `Tree.Path(prefix)` + `ProvePrefix(prefix, path)` and iterates `Tree.Scan(prefix)`. If the number of yielded keys exceeds the server's configured cardinality limit (on the order of thousands to tens of thousands of keys), iteration aborts immediately and returns `HTTP 413 Content Too Large`.

##### Wire Format (`text/plain; charset=utf-8`)
```text
— vindex/v1 —
<raw_output_log_checkpoint_note>

— output-log-leaf-v1 <output_log_leaf_index> —
<64_char_hex_map_root>
<raw_input_log_checkpoint_note>

— output-log-proof-v1 —
<base64_inclusion_proof_hash_1>
<base64_inclusion_proof_hash_2>

— mpt-proof-v1 <mode> —
<base64_mpt_proof_bytes>

— keys-v1 —
<canonical_key_1> <64_char_hex_sub_root_1>
<canonical_key_2> <64_char_hex_sub_root_2>
```
Where `<mode>` in `— mpt-proof-v1 <mode> —` is one of:
- `inclusion`: Exact key lookup (`prefix=false`) where the key exists (`keys-v1` contains exactly 1 line: `<key> <subRootHex>`).
- `non-inclusion`: Exact key lookup (`prefix=false`) where the key does not exist (`keys-v1` is empty).
- `prefix`: Prefix subtree lookup (`prefix=true`). `keys-v1` contains 0 or more `<key> <subRootHex>` lines in strictly ascending MPT key order. When 0 keys match the prefix, `keys-v1` is empty and the `mpt-proof-v1 prefix` section contains the non-existence path proof for `EmptyTreeHash()`.

#### 2.3.2 Endpoint 2: `GET /vindex/v1/entries/{key...}?before=X[&limit=Y]`

##### Query Parameters
- `{key...}`: The exact canonical key whose mini-log indices are being requested.
- `before` (**required** `uint64`): Exclusive upper bound on Input Log leaf indices. On the first page after calling `/vindex/v1/keys/`, the client passes `before={InputLogSize}` extracted from the `output-log-leaf-v1` section of the `/keys/` response. On subsequent continuation pages, the client passes `before={next_before}` from the preceding `/entries/` response.
- `limit` (optional `uint64`): Maximum number of indices to return in this page.

##### Wire Format (`text/plain; charset=utf-8`)
```text
— prefix-compact-range-v1 <covered_size> —
<base64_compact_range_hash_1>
<base64_compact_range_hash_2>

— indices-v1 [<next_before>] —
<leaf_index_1>
<leaf_index_2>
```
*(Note: The `— prefix-compact-range-v1 —` section is omitted when `covered_size == 0`, i.e., when the returned page reaches the beginning of the key's mini-log history).*

- **[Correctness Invariant] Snapshot Pinning via Mandatory `before` Parameter on `/entries/`**:
  - *Rule*: Every request to `/vindex/v1/entries/{key...}` must specify `before` (initialized to `InputLogSize` from the authenticated `/keys/` response), and the server must filter out any mini-log occurrences with `leafIdx >= before`.
  - *Rationale*: Because `/keys/` and `/entries/` are separate stateless HTTP requests, the server may commit a new batch of Input Log leaves between the client's `/keys/` request and its `/entries/` request.
  - *Consequence ("Or Else")*: If `/entries/` returned indices from a newer `InputLogSize` than the `subRoot` obtained from `/keys/`, the client's reconstructed mini-log Merkle root would not match `subRoot`, causing false cryptographic verification failures under concurrent ingestion.

- **[Performance Optimization] Zero-MPT-Lock Index Serving**:
  - *Mechanism*: `/vindex/v1/entries/` hashes `{key...}` with SHA-256 and queries Pebble directly without acquiring any MPT read lock or traversing the trie.
  - *Impact*: Eliminates MPT lock contention and redundant proof generation across multi-page hot-key pagination and multi-subdomain index retrieval.

---

### 2.4 Client Verification Protocol (`client/`)

#### 2.4.1 Point Lookup Verification (`prefix=false`)
1. Fetch `GET /vindex/v1/keys/{key}`.
2. Verify the Output Log checkpoint signatures (origin + witness policy), verify the Output Log inclusion proof for `output-log-leaf-v1`, and verify the Input Log checkpoint signatures. Extract `MapRoot` and `InputLogSize`.
3. If `mpt-proof-v1` mode is `non-inclusion`:
   - Assert `keys-v1` is empty.
   - Call `mpt.VerifyLookup(Snapshot{Hash: MapRoot}, key, nil, false, mptProof)`. Done (0 entries exist).
4. If `mpt-proof-v1` mode is `inclusion`:
   - Assert `keys-v1` contains exactly one entry matching `key`, and extract its 32-byte `subRoot`.
   - Call `mpt.VerifyLookup(Snapshot{Hash: MapRoot}, key, subRoot[:], true, mptProof)`.
5. Paginate `GET /vindex/v1/entries/{key}?before={InputLogSize}&limit=Y` (following `next_before` backward) and verify each page's compact range and indices against `subRoot` (Page 1) and the prior page's prefix compact range root (Pages 2+).

#### 2.4.2 Prefix Discovery Verification (`prefix=true`)
1. Fetch `GET /vindex/v1/keys/{prefix}?prefix=true`.
2. Verify Output Log checkpoint, Output Log inclusion proof, and Input Log checkpoint as in Step 2 above to authenticate `MapRoot` and `InputLogSize`.
3. Validate the `keys-v1` list:
   - For every `(k, subRoot)` entry in `keys-v1`, verify that `mpt.Key(k).HasPrefix(prefix)` is `true` and that keys are in strictly increasing `mpt.Key.Compare` order.
   - Compute the reconstructed subtree hash: `subtreeHash := mpt.TreeHash(slices.Values(kvs))` (which yields `mpt.EmptyTreeHash()` when `keys-v1` is empty).
4. Verify the prefix proof against `MapRoot`:
   - Call `mpt.VerifyPrefix(Snapshot{Hash: MapRoot}, prefix, subtreeHash, mptProof)`.
5. Iterate over the verified `(k, subRoot)` pairs and fetch each key's indices via `GET /vindex/v1/entries/{k}?before={InputLogSize}`, verifying each key's mini-log against its authenticated `subRoot`.

- **[Correctness Invariant] Two-Sided Client Prefix Verification (`HasPrefix` + `VerifyPrefix`)**:
  - *Rule*: Before calling `mpt.TreeHash` and `mpt.VerifyPrefix`, the client verifier must explicitly assert that every returned key `k` in `keys-v1` satisfies `mpt.Key(k).HasPrefix(prefix)`.
  - *Rationale*: `mpt.VerifyPrefix` is a one-sided proof: it enforces that all proof split bits `B_k < 8*len(prefix)`, which proves that the claimed subtree contains *at least* every key in the snapshot starting with `prefix`, but does not prevent a server from claiming a larger ancestor subtree (up to the entire tree root with an empty proof) that also contains keys outside `prefix`.
  - *Consequence ("Or Else")*: Without checking `HasPrefix(prefix)` on every leaf fed into `TreeHash`, a malicious or buggy server could return a parent subtree containing unrelated keys and pass `VerifyPrefix`.Because a binary radix trie only branches when keys diverge, if every leaf in a valid subtree starts with `prefix`, no key outside `prefix` can exist in that subtree, making `HasPrefix` + `TreeHash` + `VerifyPrefix` both sound and complete.

---

## 3. Alternatives Considered (or Tried)

### 3.1 Map-Time eTLD+1 Parent Suffix Expansion with Hashed MPT Keys (Empirical Rejection)
- **Tried**: In VIndex v1, guest WASM plugins parsed the Public Suffix List (`golang.org/x/net/publicsuffix`) and emitted `SHA256(domain)` for the full domain and every parent suffix up to eTLD+1.
- **Why Rejected**: Multiplied per-certificate key cardinality by 3x–5x, inflating MPT node count and disk writes at the primary indexing bottleneck; coupled the immutable cryptographic `MapRoot` to a mutable third-party Public Suffix List; and prevented clients from distinguishing apex certificates from subdomain or wildcard certificates without downloading all subdomain indices.

### 3.2 Variable-Length Raw Keys in Pebble (`kvstore`) (Theoretical Rejection)
- **Evaluated**: Replacing `'c' + 32B KeyHash + 8B ^chunkNum` in Pebble and `map[[32]byte]activeChunkEntry` in `KVIndexer` with variable-length `'c' + rawKey + 0x00 + ^chunkNum` and `map[string]activeChunkEntry`.
- **Why Rejected**: Pebble is never used for prefix discovery across keys—the in-memory MPT handles all `Scan(prefix)` operations and returns the exact keys to look up. Switching Pebble and the 131,072-entry active chunk cache from value-type `[32]byte` keys to variable-length strings would introduce heap pointer scanning overhead for the Go garbage collector and complicate the fixed 33-byte prefix Bloom filter splitter for zero functional gain.

### 3.3 Three Separate Endpoints (`/lookup`, `/prefix`, `/entries`) or Inline Prefix Indices (Theoretical Rejection)
- **Evaluated**: Keeping a 1-RTT combined `/lookup/{key}` alongside `/prefix/{prefix}` and `/entries/{key}` (3 endpoints), or inlining all matched mini-log indices directly inside the `/prefix/{prefix}` response.
- **Why Rejected**: Three endpoints overlap in responsibility (`/lookup` duplicates `/keys` + `/entries`), while inlining indices into `/prefix` creates unbounded response payloads and complex multi-cursor pagination when a prefix matches thousands of subdomains. The two-endpoint split (`/keys` for MPT, `/entries` for Pebble) maps 1-to-1 to the two storage engines and can be augmented with a composite convenience endpoint later if latency profiling warrants it.

---

## 4. Design Log

- **Round 0 Initial Draft (`Architect`):**
  - `feat(mpt)`: Specify upgrade to `filippo.io/torchwood/mpt` v0.10.1+ with variable-length un-hashed keys (`<= 1024` bytes), `ProveLookup`, `ProvePrefix`, `Tree.Scan`, and `TreeHash`.
  - `feat(mapfn)`: Replace map-time eTLD+1 suffix expansion in CT/MTC with single reversed-label emission (`com.google.mail.`, `com.google.*.`) and move eTLD+1 policy enforcement to the lookup server.
  - `feat(protocol)`: Define the two-endpoint `/vindex/v1/keys/{key}[?prefix=true]` (MPT) and `/vindex/v1/entries/{key}?before=X` (Pebble) wire protocol and client verification flow.
  - **Verification Gate:** Design specification complete; ready for milestone implementation and `go test -race ./vindex/...`.
