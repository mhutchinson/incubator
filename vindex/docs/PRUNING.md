# Mini-Design: Pruning in `tlog-vindex`

> **Status**: Draft Design Proposal

In ecosystems such as [Merkle Tree Certificates (MTC)](./APPLICATIONS.md#32-merkle-tree-certificates-mtc) and Certificate Transparency, logs grow rapidly as short-lived certificates are issued and renewed. [`c2sp.org/tlog-tiles`](https://c2sp.org/tlog-tiles) supports pruning historical prefixes below a `minimum_index` (`M_in`) without changing entry indices, Merkle hashes, or log identity.

In [`c2sp.org/tlog-vindex`](./tlog-vindex.md), `mpt-root` commits deterministically to all key occurrences across `[from, input_size)`. Once an Input Log prunes past `from` (`M_in > from`), two problems arise:

1. **Unbounded Index Storage**: Value logs in Pebble accumulate historical chunks pointing to unreachable Input Log entries (`< M_in`), and the Output Log accumulates historical state entries indefinitely.
2. **Audit & Recovery Bootstrap**: Late-joining auditors and operators recovering from cold disk loss cannot replay `[from, M_in)` from the Input Log to reconstruct or verify `mpt-root`.

This document proposes routine value-log and Output Log pruning for `tlog-vindex` with zero wire-format changes to lookup endpoints and zero signing-key or witness churn.

### Goals

- Bound Pebble KV disk usage and Output Log size as the Input Log's `minimum_index` advances.
- Preserve cryptographic completeness and soundness of `/keys` and `/values` across `[P, input_size)` with **zero wire-format changes** to `tlog-vindex-state@v1`, `tlog-vindex-keys@v1`, or `tlog-vindex-values@v1`.
- Keep `<output-log-origin>`, Output Log signing keys, witness configs, and `<index-url>` permanent across routine pruning cycles.
- Enable late-joining auditors and cold operator disaster recovery to initialize at prune point `P` without fetching Input Log entries `< P` or introducing new signing keys.

### Non-Goals

- **Removing dead keys from the MPT in-place**: Keys that appeared only in `[from, P)` remain in the MPT (`from` and `mpt-root` semantics stay unchanged). Multi-year keyspace garbage collection is handled orthogonally by standing up a fresh VIndex instance (`from = P_epoch`) on rare (e.g. annual) intervals once cumulative dead-key RAM warrants it.

---

## 1. Prune Horizon & Retention Invariant

A pruned VIndex maintains a monotonic prune horizon `P` (`from <= P <= Serving_CP.InputSize`) anchored to a specific witnessed Output Log entry `E_P` (at Output Log index `M_out`) whose committed `input-size` equals `P`.

Let `M_in` be the Input Log's `tlog-tiles` `minimum_index`, and let `H_retention` be the oldest Input Log index still relevant to the ecosystem (for example, the oldest unexpired MTC certificate minus monitor polling grace). Operators advance `P` subject to:

```text
M_in  <=  P  <=  H_retention  <=  input_size
```

- **`P <= H_retention`**: Every entry relevant to relying parties and polling monitors lies in `[P, input_size)`.
- **`M_in <= P`**: Every entry in `[P, input_size)` (along with the Input Log consistency proof from `P` to `latest_input_size`) remains available on the pruned Input Log for lookup clients, late-joining auditors, and recovering operators.

In practice, the indexer periodically publishes a Base State (§3) at a witnessed checkpoint behind `H_retention`, ensuring a valid `P` in `[M_in, H_retention]` is always ready before `M_in` advances.

---

## 2. Value-Log Compaction & The Per-Key Anchor Leaf

### 2.1 Why One Anchor Leaf `< P` per Key Is Required

Just as MTC and `tlog-tiles` retention keeps boundary context, VIndex value-log pruning retains each key's single highest `entry_idx < P` (`last_idx`) rather than deleting everything `< P` and relying solely on the next `>= P` chunk's `CompactRange`:

1. **Keys with zero occurrences `>= P` (dead keys)**: Dead keys remain in the MPT, so `/keys` still returns their `value_root` even though they have no chunks `>= P`. Retaining `last_idx < P` lets `/values` prove in one page that all occurrences of that key predate `P`.
2. **Gapless boundary proofs on `/values`**: A chunk's `CompactRange` is an opaque SHA-256 summary of all prior leaves; it does not reveal *which* Input Log indices were folded into it. Suppose key `k` occurred at `100` (`< P`), `P + 500` (an unauthorized certificate), and `P + 90_000` (a legitimate renewal). Without `last_idx < P`, a malicious HTTP server could return `[P + 90_000]` (whose `CompactRange` folds `100` and `P + 500` together and verifies against `value_root`) and then claim `410 Gone` on `before = P + 90_000` to hide `P + 500`. Retaining `last_idx < P` forces the server to prove the step across `P`: seeing verified adjacent leaves `last_idx < P` and `P + 90_000` proves by strict leaf monotonicity that zero occurrences exist in `[P, P + 90_000)`.

### 2.2 Pebble Chunk Compaction

As detailed in [`internal/kvstore`](../internal/kvstore/README.md), Pebble stores value-log chunks in 65,536-entry windows ordered newest-first per `KeyHash = SHA-256(key)`:

```text
Key: 'c' || KeyHash (32B) || ^BigEndian(chunkNum) (8B)
Val: Preceding (8B) || CompactRange (32B * popcount(Preceding)) || RelativeIndices ([]uint16)
```

For prune horizon `P`, let `C = P / 65536` (`C * 65536 <= P`). Because `^BigEndian(chunkNum)` sorts chunks descending by `chunkNum`, compacting Pebble for horizon `P` is a single sequential scan over `'c'` records that runs concurrently with live indexing:

1. **Chunks `chunkNum >= C`**: Keep untouched. (When `P` is not an exact multiple of 65,536, leaving entries in `[C * 65536, P)` inside chunk `C` avoids splitting 64k windows.)
2. **Anchor selection & folding**:
   - If chunk `C` exists for `KeyHash` and already contains at least one offset `< P` (`C * 65536 + RelativeIndices[0] < P`), chunk `C` itself holds `last_idx < P` and summarizes all chunks `< C`. Delete **all** chunks `< C` for `KeyHash`.
   - Otherwise, the first chunk with `chunkNum < C` (`anchorChunk`) holds `last_idx < P`. If `len(RelativeIndices) > 1`, fold `RelativeIndices[:len-1]` into `Preceding` and `CompactRange`, rewrite `anchorChunk` with its single final offset `RelativeIndices[len-1:]` (`last_idx`), and delete all older chunks `< anchorChunk` (down through chunk `0` inclusive, using the same-prefix 42-byte exclusive upper bound `'c' || KeyHash || 0xFF..FF || 0x00` to preserve Pebble's 33-byte prefix Bloom filters) in the same atomic Pebble batch.

Every compacted anchor stub uses the standard `'c'` record layout (~50 to 150 bytes per key), and active chunk writes avoid rewriting unmodified historical chunks on window rollover so compacted stubs stay compact.

### 2.3 HTTP `/values` Contract & Client Pagination

Before deleting any Pebble chunks for horizon `P`, the server durably persists `P` as its minimum served index watermark (also clamping local crash-recovery and cache-pruning watermarks to `max(from, P)`):

- **`before >= P`**: Server behavior is unchanged (`200 OK` with a valid `c2sp.org/tlog-vindex-values@v1` page, or `404 Not Found` if the key has zero occurrences in `[from, before)`). Note that even `before == P` is served normally because `last_idx < P` is strictly `< P`.
- **`from < before < P`**: The server responds with **`410 Gone`**. Returning `410 Gone` (mapped to a typed `ErrPruned` in [`vindex/client`](../client/README.md), never `404 Not Found`) distinguishes pruned historical pages from a missing promised page on an active key, which clients treat as a verification failure.
- **`before <= from`**: `404 Not Found` (unchanged).

**Lookup client rule**: Clients check `from <= required_horizon` (where `required_horizon >= P`) on `state_entry`, paginate `/values` backward from `before = input_size`, and stop as soon as `preceding == 0` or a verified entry index satisfies `entry_idx < required_horizon`. Existing [`vindex/client`](../client/README.md) loops (`if entryIdx < requiredHorizon { break }`) work unmodified without ever issuing a request with `before < P`.

---

## 3. Base State & Late-Joining Verification

### 3.1 Base State Format (`c2sp.org/tlog-vindex-base@v1`)

To allow verifiers and recovering operators to initialize at `E_P` (Output Log index `M_out`, `input-size = P`) without fetching `[from, P)` from the Input Log, the operator publishes an immutable, compressible snapshot at `<output-log-url>/base/<M_out>` (offloaded to object storage or a CDN):

```text
c2sp.org/tlog-vindex-base@v1
output-index <decimal-M_out>

<binary-key-records...>
```

Following the blank line (`\n\n`), `<binary-key-records>` encodes one record per canonical key present in the MPT at `E_P`, in strictly increasing lexicographical key order, using the canonical `uvarint` (minimal LEB128) conventions of [`tlog-vindex`](./tlog-vindex.md):

```text
uvarint(len(key))
  || key
  || uvarint(last_idx)
  || uvarint(preceding_before_last)
  || compact_range_hashes   // 32 bytes * popcount(preceding_before_last)
```

Alongside immutable `<output-log-url>/base/<M_out>`, the operator publishes a small [C2SP signed note](https://c2sp.org/signed-note) signed by `<output-log-origin>`'s existing key (requiring zero new keys and zero witness changes) at two paths:

- `<output-log-url>/base/<M_out>.note` (immutable, long-cached)
- `<output-log-url>/base/latest.note` (`Cache-Control: no-store`, updated atomically so cold auditors can discover `M_out` without probing `tlog-tiles` bundles)

```text
c2sp.org/tlog-vindex-base-note@v1
output-index <decimal-M_out>
size <decimal-byte-length>
sha256 <base64-sha256-of-base-snapshot>

— <output-log-origin> <signature>
```

- **Why both `E_P.mpt_root` and `<output-log-origin>`'s note signature are used**: `E_P.mpt_root` in the **witnessed** Output Log authenticates the exact set of canonical keys, `last_idx`, and `value_root` against the witness quorum (even a compromised operator key cannot forge them). However, because RFC 6962 root hashes do not commit to leaf counts when folding a single trailing leaf `last_idx`, `E_P.mpt_root` alone does not bind `preceding_before_last` against an untrusted CDN or storage bucket altering the count bits. Signing the snapshot digest with `<output-log-origin>` prevents third-party CDN tampering and non-repudiably binds the operator to a single compact-range state.
- **Size**: A 1-occurrence key (`preceding_before_last == 0`) takes ~26 to 35 bytes raw (~15 to 20 bytes compressed), or ~1.5 to 3 GB compressed per 100M distinct keys.
- **Online generation & sequential pruning pipeline**: Because Pebble keys are hashed (`SHA-256(key)`), the indexer exports `/base/<M_out>` by scanning the MPT in bounded lexicographical slices, releasing the trie read lock between slices so `/keys` latency stays unaffected. Because the MPT key set grows monotonically (`Keys(P)` is a subset of `Keys(S)` for all `S >= P`), concurrent `> P` commits never hide a `< P` key, and looking up each key's `< P` state in Pebble deterministically skips keys first seen `>= P`. Pruning runs as a single sequential loop (`export & verify /base/<M_out> against E_P.mpt_root -> publish .note & latest.note -> advance min_served_index to P -> compact Pebble below P`), guaranteeing Pebble is never compacted past an in-flight export.
- **Output Log pruning**: Once `/base/<M_out>` and `/base/<M_out>.note` are published, the Output Log itself MAY advance its `tlog-tiles` `minimum_index` to `M_out` (retaining upper-level hash tiles needed for inclusion and consistency proofs `>= M_out`).

### 3.2 Auditor Bootstrap, Continuous Base Checks & Cold Recovery

A cold auditor discovers whether the VIndex has pruned by fetching `GET <output-log-url>/base/latest.note` (unless an explicit `M_out` override is configured). On `404 Not Found`, the VIndex is unpruned and the auditor starts at `0`; on `200 OK`, it initializes at `M_out`:

1. **Authenticate Note & `E_P`**: Verify the `.note` signature against `<output-log-origin>` to extract `M_out`, `size`, and `sha256`. Verify the Output Log checkpoint (`output_size > M_out`) against `<output-log-origin>` and the Output Log policy; fetch and authenticate entry `M_out` (`E_P`) via `tlog-tiles` to obtain `(input_origin, from, P, input_root_P, mpt_root_P)`. Verify a signed Input Log checkpoint (`latest_input_size >= P`) and check Merkle consistency between `(P, input_root_P)` and `(latest_input_size, latest_input_root)`.
2. **Stream & Validate Base State**: Stream `<output-log-url>/base/<M_out>` in O(1) memory while verifying its byte length and SHA-256 digest against the signed `.note`. For each record:
   - Assert `key` is a valid canonical key (`1..1024` bytes in `0x21..0x7E`) and `key > prev_key`.
   - Assert `from <= last_idx < P` and `preceding_before_last <= last_idx - from`, and read `popcount(preceding_before_last)` 32-byte hashes.
   - Fold `compact_range_hashes` with `value_log_leaf_hash(last_idx)` to obtain `value_root`, and feed `(key, value_root)` into the streaming MPT Whole Tree Hash computation ([`tlog-vindex`](./tlog-vindex.md#tree-topology)).
3. **Assert Digest & Root Equality**: At EOF, assert both the `.note` SHA-256 digest and `computed_mpt_root == mpt_root_P` before activating the imported Pebble anchor stubs (`chunkNum = last_idx / 65536`) and MPT leaves at `P`.
4. **Audit Forward**: Set `prev_size = P` and run the standard [`tlog-vindex` audit loop](./tlog-vindex.md#auditing-the-index) for Output Log entries `M_out + 1, M_out + 2, ...` using unpruned Input Log bundles in `[P, input_size)`.

*(Note: Even when the live indexer left boundary chunk `C` uncompacted across `[C * 65536, P)` while the Base State folded offsets `< last_idx` into `compact_range_hashes`, associativity of RFC 6962 left-prefix compact ranges guarantees both nodes compute bit-for-bit identical `value_root` and `mpt_root` digests for all future `input_size > P`.)*

**Continuous-Auditor Base Verification**: Continuous auditors already running across `M_out` (at `S >= P`) also poll `/base/latest.note` and validate each newly published `/base/<M_out>` against their own local Pebble `< P` counts and compact ranges before compacting their own local Pebble below `P`, catching a malformed `preceding_before_last` immediately upon publication even for dead keys.

**Cold Operator Disaster Recovery**: If an indexer loses local disk while its witnessed Output Log survives at tip `S_tip >= P` (`N_out - 1 >= M_out`), it executes Steps 1 to 3 against its latest `/base/<M_out>`, keeps HTTP lookup endpoints gated (`503 Service Unavailable`), replays unpruned Input Log entries across `[P, S_tip)` locally *without* appending duplicate entries to the Output Log, asserts its reconstructed `mpt_root` matches the Output Log tip at `S_tip`, and resumes normal serving.

---

## 4. Security Properties

- **Gapless Completeness & Soundness Across `[P, input_size)`**: Every key in `[from, input_size)` retains either its full value log (if first seen `>= P`) or at least `last_idx < P`. Because value-log leaves are strictly increasing integers verified against `value_root` in the witnessed MPT, a verified `/values` page containing an index `< required_horizon` (for `required_horizon >= P`) proves that all `preceding` leaves are strictly smaller and therefore `< required_horizon`, guaranteeing zero omissions in `[required_horizon, input_size)`. Any attempt by a server to hide an occurrence `>= P` inside `preceding` leaves `first_entry_idx >= P`, allowing the client to request `before = first_entry_idx >= P` where `410 Gone` is forbidden.
- **Dead-Key Soundness in One Round-Trip**: Keys that occurred only in `[from, P)` remain in the MPT with their original `value_root`. A `/values` query at `before = input_size` returns the single `[last_idx]` anchor stub (`last_idx < P`), verifying against `value_root` and proving in one page that no occurrences exist in `[P, input_size)`.
- **Witness-Backed Snapshot Integrity & Non-Equivocation**: `E_P.mpt_root` binds all `(key, last_idx, value_root)` state to the witnessed Output Log, while `<output-log-origin>`'s signature on `/base/<M_out>.note` protects `preceding_before_last` against CDN tampering. If a malicious operator signs a malformed `preceding_before_last` (which still cannot hide or forge `[P, input_size)` `/values` proofs because `preceding_before_last <= last_idx - from`), continuous auditors polling `/base/latest.note` detect the mismatch immediately at `M_out` with a signed misbehavior proof, and recurring keys independently force an `mpt_root` divergence once post-`P` appends cross the lowest differing bit of the leaf count.

---

## 5. Operational Footprint & Lifecycle

- **Per-Key Steady-State Cost (Dead Keys `< P`)**:
  - `torchwood/mpt` RAM: `52 B / key` (~26 GB RAM at 500M cumulative FQDNs).
  - `mpt.disk` + Pebble anchor stub: `~130 B / key` on NVMe (~65 GB at 500M FQDNs).
- **Prefix Query Behavior**: `GET /keys?prefix=...` continues returning historical keys `< P`. Stateful monitors avoid extra `/values` calls by caching `(key -> value_root)` across polls and skipping unchanged roots; prefixes with extreme ephemeral subdomain churn (such as tens of thousands of one-off CI preview hosts) eventually approach the server's `413 Content Too Large` guardrail.
- **Two-Tier Lifecycle for High-Velocity Logs (MTC / CT)**:
  1. **Frequent (days / weeks, tracking `minimum_index`)**: Export `/base/<M_out>`, publish `.note` and `latest.note`, advance `min_served_index` to `P`, compact Pebble below `P`, and prune the Output Log below `M_out`. Zero re-indexing, zero witness churn, and zero URL rotation.
  2. **Rare (e.g. annually, if cumulative dead keys warrant RAM / prefix cleanup)**: Stand up a fresh VIndex instance starting at `from = P_epoch` and retire the old instance after one retention window of overlap.
