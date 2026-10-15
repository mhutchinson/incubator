---
description: Verifiable key and prefix index for transparency logs
---

> [!WARNING]
> **Status: Non-Canonical Draft Proposal (Editor's Copy)**
>
> This document is a draft proposal for a [c2sp.org/tlog-vindex](https://c2sp.org/tlog-vindex) specification and is **not yet canonical**. Relative to the current `vindex` code, this draft proposes:
> 1. Tagged `c2sp.org/tlog-vindex-leaf@v1` Output Log leaves committing to `map-root`, `map-fn`, `from`, and `<input-log-checkpoint>`.
> 2. Line-oriented `c2sp.org/tlog-vindex-keys@v1` + `c2sp.org/tlog-proof@v1` and `c2sp.org/tlog-vindex-entries@v1` response formats (replacing `— <section> —` headers).
> 3. Query-parameter key routing (`GET <prefix>/keys?key=<key>[&prefix=true]` and `GET <prefix>/entries?key=<key>&before=<B>[&limit=<L>]`).
> 4. Standard Base64 encoding for all 32-byte SHA-256 digests (`map-root`, `map-fn`, and `<subroot>`).
>
> These changes are awaiting review before being folded back into the `vindex` implementation.

# Transparency Log Verifiable Index

This document specifies a verifiable key and prefix lookup index over a
transparency log, exposing an HTTP query API alongside a tiled transparency log
of index state commitments.

## Conventions used in this document

The hashing algorithm used throughout is SHA-256, as defined in [FIPS 180-4][],
producing a 32-byte digest. The base64 encoding used throughout is the standard
Base 64 encoding specified in [RFC 4648][], Section 4. All 32-byte SHA-256
digests in text formats are encoded as 44-character base64 strings ending in `=`.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

`uint64_be(x)` denotes the 8-byte big-endian unsigned integer encoding of `x`.
`uvarint(x)` denotes the unsigned 64-bit Little-Endian Base 128 (LEB128)
variable-length integer encoding of `x`. A value in `0..127` encodes as a single
byte; multi-byte encodings MUST use the minimal number of bytes (with no
trailing zero continuation bytes) and MUST NOT exceed 10 bytes (`<= 2^64 - 1`).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[FIPS 180-4]: https://csrc.nist.gov/pubs/fips/180-4/final
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Introduction

A verifiable index allows clients to look up which entries in an existing
append-only transparency log (the *input log*) match a given search key or key
prefix, without downloading the entire input log or trusting the index operator.

The index operator applies a deterministic *mapping function* to each entry in
the input log to extract zero or more canonical search keys. For each key, the
index maintains an [RFC 6962][] Merkle tree (the key's *value log*) over the
ascending sequence of input log entry indices at which that key appeared. The
32-byte roots of all non-empty value logs (`SubRoot`) are stored in a
path-compressed binary Merkle Patricia Trie (the *index map*).

Rather than signing standalone map checkpoints, the index operator publishes
each index state commitment—binding the index map root hash (`MapRoot`), mapping
function identifier (`map-fn`), starting input log index (`from`), and signed
input log [checkpoint][]—as an entry in a tiled transparency log (the *output
log*) witnessed according to [tlog-witness][]. Lookup clients verify query
responses against witnessed output log checkpoints, while monitors and auditors
can deterministically replay the input log to verify every state commitment in
the output log.

## Parameters

A verifiable index is defined by:

- an *input log*, parameterized by its [checkpoint][] origin and [tlog-policy][],
  along with any entry retrieval mechanism that defines how clients and auditors
  fetch and authenticate `entry[i]` (the entry at zero-based index `i` in the
  input log) against the input log checkpoint root hash (such as [tlog-tiles][]
  or [static-ct-api][]);

- an *output log*, which is a [tlog-tiles][] log parameterized by its URL prefix
  (`<output_log_prefix>`) and its [tlog-policy][];

- a *query prefix* (`<prefix>`), the base URL serving the HTTP lookup endpoints
  defined in this document; and

- a deterministic *mapping function* (`MapFn`) that maps a raw input log entry to
  a set of canonical keys, identified by a 32-byte SHA-256 commitment digest
  (`map-fn`) distributed out-of-band alongside the input and output log
  policies.

An operator MAY use the same URL prefix for both `<output_log_prefix>` and
`<prefix>`.

[checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-tiles]: https://c2sp.org/tlog-tiles
[tlog-witness]: https://c2sp.org/tlog-witness
[tlog-policy]: https://c2sp.org/tlog-policy
[tlog-proof]: https://c2sp.org/tlog-proof
[static-ct-api]: https://c2sp.org/static-ct-api
[signed-note]: https://c2sp.org/signed-note
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

## Index Structure

This section specifies the deterministic transformation from an input log range
`[from, N)` to the 32-byte `MapRoot` committed in an output log entry. Any
independent verifier given the input log entries in `[from, N)` and `MapFn` MUST
arrive at the identical `MapRoot`.

### Canonical keys

A *canonical key* is a byte string representing a normalized search subject (for
example, a reversed-label domain name `com.example.mail.` or an escaped Go
module path `golang.org/x/crypto`).

A canonical key MUST be between `1` and `1024` bytes in length, inclusive
(`1 <= len(key) <= 1024`). Every byte in a canonical key MUST be a printable
ASCII character in the range `0x21` to `0x7E` (`!` through `~`), inclusive.
Canonical keys MUST NOT contain `NUL` (`0x00`), space (`0x20`), or ASCII
control or whitespace characters.

If `MapFn(entry[i])` emits the same canonical key `K` multiple times for a
single input log entry at index `i`, duplicates MUST be discarded so that index
`i` is recorded at most once for key `K`.

### Value logs

For an input log covering entry indices `[from, N)` (where `0 <= from <= N`),
each canonical key `K` is associated with the strictly increasing sequence of
input log entry indices at which `MapFn(entry[i])` emitted `K`:

```text
Indices(K, from, N) = [ i_0, i_1, ..., i_{m-1} ]   where from <= i_0 < i_1 < ... < i_{m-1} < N
```

If a key `K` has zero occurrences in `[from, N)` (`m == 0`), it MUST NOT be
inserted into the index map.

If `m >= 1`, the occurrences of `K` form an append-only [RFC 6962, Section 2.1][]
Merkle tree (the key's *value log*) of size `m`. The `j`-th leaf (`0 <= j < m`)
is the 8-byte big-endian encoding of the input log index `i_j`:

```text
ValueLogLeafHash(i_j) = SHA-256(0x00 || uint64_be(i_j))
ValueLogNodeHash(left, right) = SHA-256(0x01 || left || right)
```

The 32-byte RFC 6962 Merkle root of this tree of size `m` is denoted
`SubRoot(K)` and serves as the 32-byte value stored at key `K` in the index map.

[RFC 6962, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1

### Index map

The *index map* is a path-compressed binary Merkle Patricia Trie (MPT) mapping
every canonical key `K` with `m >= 1` occurrences to its 32-byte value
`SubRoot(K)`. The tree structure and proof encodings are compatible with
[filippo.io/torchwood/mpt][].

[filippo.io/torchwood/mpt]: https://pkg.go.dev/filippo.io/torchwood/mpt

#### Key padding and bit ordering

To ensure that no distinct key is a bit-prefix of another key, a key `K` of
length `L` bytes (`1 <= L <= 1024`) is treated for bit extraction and comparison
as an infinite byte stream:

```text
Padded(K) = K[0] || K[1] || ... || K[L-1] || 0x00 || 0xFF || 0xFF || ...
```

The `b`-th bit of `K` (`b >= 0`, numbered from `0` at the most significant bit
of `K[0]`) is defined as:

```text
bit(K, b):
  byte_idx = b >> 3
  bit_idx  = 7 - (b & 7)
  if byte_idx < len(K):
    return (K[byte_idx] >> bit_idx) & 1
  if byte_idx == len(K):
    return 0   // from the 0x00 terminator byte
  return 1     // from the infinite 0xFF padding bytes
```

Because canonical keys contain no `0x00` bytes (`0x21..0x7E`, see [Canonical
keys](#canonical-keys)), the padded bitstream order `Padded(X) < Padded(Y)` is
identical to unsigned lexicographical byte order, and a canonical key `K` falls
in the MPT subtree of a canonical prefix `P` if and only if `P` is a byte prefix
of `K`.

> [!NOTE]
> General [filippo.io/torchwood/mpt][] trees allow arbitrary binary keys
> (including `0x00` bytes). When keys may contain `0x00`, `Padded(X) < Padded(Y)`
> and prefix membership must be evaluated on the full `0x00 || 0xFF*`-padded
> bitstreams rather than via plain byte-slice comparison (for example,
> `"a\x00\xff"` precedes `"a"` in `Padded` order). The byte-slice equivalence
> used in this specification relies strictly on the NUL-free (`0x21..0x7E`)
> canonical key invariant.

Let `maxKeyBits = 1024 * 8 + 1 = 8193` (corresponding to bit indices `0..8192`,
since a 1024-byte key has its `0x00` terminator at byte index `1024`, whose
first bit is at bit index `8192`). For any two keys `X` and `Y`
(`1 <= len(X), len(Y) <= 1024`), define `key_overlap(X, Y)` as the smallest bit
index `b >= 0` at which `bit(X, b) != bit(Y, b)`, or `maxKeyBits` (`8193`) if
`X == Y`.

#### Tree topology

The MPT over a set of `(K, SubRoot(K))` pairs is the unique path-compressed
binary radix tree such that:

- If the set of keys is empty, the tree is the empty tree.
- If the set contains a single pair `(K, V)`, the tree is a single leaf node.
- If the set contains two or more keys, let `B` be the minimum
  `key_overlap(X, Y)` across all pairs in the set. The root of the subtree is an
  inner node with split bit `B`, whose left child is the MPT over all keys in
  the set with `bit(K, B) == 0` and whose right child is the MPT over all keys
  in the set with `bit(K, B) == 1`.

Because the topology is uniquely determined by the set of present keys and their
values, `MapRoot` is independent of the order in which keys are inserted or
updated.

#### Node hashing

Every node in the MPT has a 32-byte hash.

The hash of the empty tree is the SHA-256 hash of the empty byte string:

```text
EmptyTreeHash = SHA-256("")
              = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

The hash of a leaf node for canonical key `K` and 32-byte value `V = SubRoot(K)`
is:

```text
LeafNodeHash(K, V) = SHA-256(0x00 || uvarint(len(K)) || K || uvarint(len(V)) || V)
```

Since `V` is always a 32-byte `SubRoot`, `uvarint(len(V))` is the single byte
`0x20`.

The hash of an inner node with split bit `B >= 0`, 32-byte left child hash `L`,
and 32-byte right child hash `R` is:

```text
InnerNodeHash(B, L, R) = SHA-256(0x01 || uvarint(B) || L || R)
```

#### Computing `TreeHash` from sorted key-value pairs

Given a list of `(K_i, V_i)` pairs sorted in strictly increasing lexicographical
key order (`K_0 < K_1 < ... < K_{n-1}`), the root hash of the tree (or of any
prefix subtree) is computed in `O(n)` operations using a stack `s` of
`(key, bits, hash)` entries, where `s[-1]` is the top of the stack:

```text
func TreeHash(list):
  if len(list) == 0:
    return EmptyTreeHash
  s = []
  for (K, V) in list:
    push s, { key: K, bits: maxKeyBits, hash: LeafNodeHash(K, V) }
    while len(s) >= 3 and node_overlap(s[-3], s[-2]) > node_overlap(s[-2], s[-1]):
      s[-3], s[-2] = merge(s[-3], s[-2]), s[-1]
      pop s
  while len(s) >= 2:
    s[-2] = merge(s[-2], s[-1])
    pop s
  return s[0].hash

func node_overlap(nodeA, nodeB):
  return min(nodeA.bits, nodeB.bits, key_overlap(nodeA.key, nodeB.key))

func merge(left, right):
  B = node_overlap(left, right)
  return { key: left.key, bits: B, hash: InnerNodeHash(B, left.hash, right.hash) }
```

### Output log leaves

Each entry in the output log commits to the state of the index over an input log
range `[from, size)`. An entry is a sequence of lines separated by newlines
(U+000A). Carriage returns (U+000D) MUST NOT be used.

```text
c2sp.org/tlog-vindex-leaf@v1
map-root <base64-map-root>
map-fn <base64-map-fn-sha256>
from <decimal-start-index>

<input-log-checkpoint>
```

The first line MUST be the string `c2sp.org/tlog-vindex-leaf@v1`.

The second line MUST start with the string `map-root` followed by a space
(U+0020) and the base64 encoding of the 32-byte index map root hash (`MapRoot`).

The third line MUST start with the string `map-fn` followed by a space (U+0020)
and the base64 encoding of the 32-byte SHA-256 commitment to the mapping
function (`MapFn`) that produced `MapRoot`. Lookup clients that do not pin a
specific `map-fn` digest MUST validate the syntactic format of this line and MAY
ignore its value.

> [!NOTE]
> **TODO (pre-1.0)**: Decide whether the `map-fn` preimage is the raw compiled
> `.wasm` module bytecode directly, or a canonical provenance/build manifest
> (`{source repo @ tag, build toolchain, output wasm hash}`) committing to both
> the source definition and compiled artifact.

The fourth line MUST start with the string `from` followed by a space (U+0020)
and the starting input log entry index (inclusive), represented as an ASCII
decimal with no leading zeroes (unless the index is `0`). `from` MUST satisfy
`0 <= from <= input_log_checkpoint.size` and MUST remain constant across all
entries in a given output log (typically `0` when indexing from the start of the
input log).

After the `from` line and an empty line, the signed input log [checkpoint][] is
included verbatim, according to [tlog-checkpoint][], ending with a single
trailing newline (U+000A).

The canonical output log leaf bytes hashed into the output log's RFC 6962 Merkle
tree (`SHA-256(0x00 || leaf_bytes)`) are the exact bytes of the record above.

Example output log leaf:

```text
c2sp.org/tlog-vindex-leaf@v1
map-root AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
map-fn 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
from 0

example.com/inputlog
98765
k2g+47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3h=

— example.com/inputlog Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
```

## HTTP Interface

A verifiable index exposes two HTTP GET lookup endpoints under `<prefix>`,
alongside the output log's [tlog-tiles][] endpoints. All successful (`200 OK`)
lookup responses use `Content-Type: text/plain; charset=utf-8` and are formatted
as sequences of newline-terminated (U+000A) lines.

The endpoints defined in this section MUST NOT serve HTTP redirect (`3xx`)
responses. If a server has not yet published its first output log checkpoint, or
receives an `entries` request with `before` greater than its currently indexed
input log size, it MUST respond with a "503 Service Unavailable" HTTP status
code.

`<prefix>/keys` is mutable (returning the latest output log state commitment),
so its HTTP headers SHOULD prevent caching beyond a few seconds. Once a server
has indexed input log entries at least up to `before`,
`<prefix>/entries?key=<key>&before=<B>[&limit=<L>]` is deterministic for a fixed
server page-boundary policy, so its caching headers MAY be long-lived.

### keys

Key and prefix lookups are served at

    GET <prefix>/keys?key=<key>[&prefix=true]

`<key>` is a required query parameter containing the lookup key or prefix,
percent-encoded per [RFC 3986][]. The unescaped value MUST be a valid canonical
key (`1` to `1024` bytes in the range `0x21` to `0x7E`, see [Canonical
keys](#canonical-keys)). Otherwise, the server MUST respond with a "400 Bad
Request" HTTP status code.

`prefix` is an optional boolean query parameter. If omitted or `false`, the
server proves whether `<key>` exists in the index map. If `true`, the server
proves and returns all `(K, SubRoot)` pairs in the index map whose key `K` has
`<key>` as a byte prefix.

Because verifying a prefix proof requires reconstructing the Merkle hash of the
matched MPT subtree, a server cannot paginate matched keys across multiple
responses. When `prefix=true`, a server MAY enforce an application-specific
prefix policy (for example, rejecting bare TLD queries such as `com.` or
`co.uk.` that do not contain a registrable `eTLD+1` domain). If `<key>` violates
the server's prefix policy, the server MUST respond with a "400 Bad Request"
HTTP status code. A server SHOULD enforce a maximum key count on prefix queries;
if the number of keys in the MPT starting with `<key>` exceeds the server's
limit, the server MUST abort the scan and respond with a "413 Content Too Large"
HTTP status code.

[RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986.html

```text
c2sp.org/tlog-vindex-keys@v1
proof <base64-mpt-proof>
mode <inclusion|non-inclusion|prefix>
<canonical-key-1> <base64-subroot-1>
<canonical-key-2> <base64-subroot-2>

c2sp.org/tlog-proof@v1
extra <base64-encoded-tlog-vindex-leaf>
index <output-log-leaf-index>
<base64-audit-path-hash-1>
<base64-audit-path-hash-2>

<output-log-checkpoint>
```

The first line MUST be the string `c2sp.org/tlog-vindex-keys@v1`.

The second line MAY start with the string `proof` followed by a space (U+0020)
and the base64 encoding of the binary MPT proof (see [Binary MPT
proofs](#binary-mpt-proofs)). If the binary MPT proof is `0` bytes (for example,
when `MapRoot == EmptyTreeHash` or when proving inclusion in a 1-leaf MPT), this
line is omitted.

The next line MUST start with the string `mode` followed by a space (U+0020) and
the lookup proof mode, which MUST be `inclusion` or `non-inclusion` when
`prefix=false`, and MUST be `prefix` when `prefix=true`.

The next zero or more non-empty lines are the matched keys and their value log
roots, each formatted as `<canonical-key>`, a space (U+0020), and the base64
encoding of the 32-byte `SubRoot`. When `mode` is `non-inclusion`, there MUST be
zero matched key lines. When `mode` is `inclusion`, there MUST be exactly one
matched key line whose `<canonical-key>` equals `<key>`. When `mode` is
`prefix`, there are zero or more matched key lines sorted in strictly increasing
lexicographical key order.

After the matched key lines and an empty line, an output log proof is included
verbatim according to [tlog-proof][] (`c2sp.org/tlog-proof@v1`). Because none of
the lines in the `c2sp.org/tlog-vindex-keys@v1` block can be empty, the first
empty line (`\n\n`) in the response body unambiguously separates the
`c2sp.org/tlog-vindex-keys@v1` block from the trailing `c2sp.org/tlog-proof@v1`
block. Within the `c2sp.org/tlog-proof@v1` block, the `extra` line MUST be
present and MUST contain the base64 encoding of the canonical
`c2sp.org/tlog-vindex-leaf@v1` entry (`leaf_bytes`, see [Output log
leaves](#output-log-leaves)), and the `index` line MUST equal `OutSize - 1` (the
latest entry in the embedded `<output-log-checkpoint>`).

#### Binary MPT proofs

Let `maxKeyBits = 1024 * 8 + 1 = 8193`. A *path step* in a binary MPT proof is
encoded as:

```text
Step = uvarint(B) || H
```

where `B` (`0 <= B < maxKeyBits`) is the inner node's split bit index and `H` is
the 32-byte sibling node hash at that split. Across any sequence of path steps
`Step_1, Step_2, ..., Step_k` walking from a leaf or subtree up to the root, the
bit indices MUST be strictly decreasing (`B_1 > B_2 > ... > B_k >= 0`).

- For `mode inclusion`, the proof proves that `(K, V)` is present in `MapRoot`
  and is encoded as `Step_1 || Step_2 || ... || Step_k` (omitting `K` and `V`,
  as both are already present in the matched key line).

- For `mode non-inclusion`, the proof proves that `K` is not present in
  `MapRoot`. If `MapRoot == EmptyTreeHash`, the proof is `0` bytes (and the
  `proof` line is omitted). Otherwise, the proof encodes the existing leaf
  `(altKey, altVal)` where lookup for `K` terminated followed by its path steps:

  ```text
  NonInclusionProof = uvarint(len(altKey)) || altKey || uvarint(len(altVal)) || altVal || Step_1 || ... || Step_k
  ```

- For `mode prefix`, the proof proves that the matched key lines are the
  complete set of keys in `MapRoot` starting with `prefix`
  (`P = 8 * len(prefix)` bits). If the matched key lines are non-empty, the
  proof encodes the path steps strictly above the prefix subtree root:

  ```text
  PrefixProof (non-empty) = Step_1 || Step_2 || ... || Step_k   (where B_1 < 8 * len(prefix))
  ```

  If the matched key lines are empty (`subtreeHash == EmptyTreeHash`), the proof
  is `0` bytes when `MapRoot == EmptyTreeHash`, or otherwise encodes the
  existing leaf `(altKey, altVal)` reached when looking up `prefix` (padded as a
  key) followed by its path steps:

  ```text
  PrefixProof (empty) = uvarint(len(altKey)) || altKey || uvarint(len(altVal)) || altVal || Step_1 || ... || Step_k
  ```

### entries

Value log entry indices for a key are served at

    GET <prefix>/entries?key=<key>&before=<B>[&limit=<L>]

Because a single key may appear thousands or millions of times in the input log,
occurrence indices are paginated backward in time using the `before` cursor.
Because [RFC 6962][] compact ranges represent tree prefixes (`0..covered`),
backward pagination allows clients to verify every page inductively against
`SubRoot(K)` without Merkle consistency proofs.

`<key>` is a required query parameter containing the canonical key (`1` to
`1024` bytes in the range `0x21` to `0x7E`, see [Canonical
keys](#canonical-keys)), percent-encoded per [RFC 3986][]. If `<key>` is not a
valid canonical key, the server MUST respond with a "400 Bad Request" HTTP
status code. Once the server has indexed at least up to `before`, if `<key>` has
zero occurrences strictly less than `before`, the server MUST respond with a
"404 Not Found" HTTP status code.

`before` is a required query parameter giving the exclusive upper bound on input
log entry indices as a positive ASCII decimal integer (`> 0`) with no leading
zeroes. On the initial page for a key discovered via `keys`, the client MUST set
`before` to the input log checkpoint tree size (`N`) from the
`c2sp.org/tlog-vindex-leaf@v1` payload of the `keys` response, pinning the
query to the exact snapshot committed by `SubRoot(K)`. On continuation pages,
the client MUST set `before` to the first (smallest) entry index (`idx_0`)
returned on the preceding page.

`limit` is an optional query parameter giving an advisory maximum number of
indices to return as a positive ASCII decimal integer (`> 0`). The server MAY
return fewer or more indices (for example, to align page boundaries with
precomputed storage chunks) provided at least one index is returned whenever
matching entries strictly less than `before` exist.

```text
c2sp.org/tlog-vindex-entries@v1
covered <covered-size>
<base64-compact-range-hash-1>
<base64-compact-range-hash-2>

<decimal-entry-index-1>
<decimal-entry-index-2>
```

The first line MUST be the string `c2sp.org/tlog-vindex-entries@v1`.

The second line MUST start with the string `covered` followed by a space
(U+0020) and the number of earlier occurrences of `<key>` in the value log that
precede `<decimal-entry-index-1>`, represented as an ASCII decimal integer
(`covered >= 0`) with no leading zeroes (unless the count is `0`).

The next `popcount(covered)` non-empty lines (where `popcount` is the number of
`1` bits in the binary representation of `covered`, or zero lines when
`covered == 0`) are the base64-encoded 32-byte SHA-256 subtree hashes of the
value log prefix `[0, covered)`, ordered from largest subtree (most significant
`1` bit of `covered`) to smallest subtree (least significant `1` bit of
`covered`).

After the compact range lines and an empty line, one or more non-empty lines
give the matching input log entry indices in strictly increasing numerical
order (`from <= idx_0 < idx_1 < ... < idx_{k-1} < before`), each represented as
an ASCII decimal integer with no leading zeroes (unless the index is `0`). When
`covered > 0`, `idx_0` serves as the `before` cursor for the next backward page.

## Verifying a Lookup

A client MUST NOT trust any lookup response until all verification steps below
succeed.

### Verifying the state commitment

To authenticate the state commitment in a `GET <prefix>/keys?key=<key>[&prefix=true]`
response:

1. Split the response body on the first empty line (`"\n\n"`) into the
   `c2sp.org/tlog-vindex-keys@v1` block and the trailing
   `c2sp.org/tlog-proof@v1` block.

2. Extract the base64-encoded `extra` field from the `c2sp.org/tlog-proof@v1`
   block, decode `leaf_bytes`, and compute the output log leaf hash
   `leaf_hash = SHA-256(0x00 || leaf_bytes)`.

3. Verify the `c2sp.org/tlog-proof@v1` block against `leaf_hash` and the
   client's configured output log [tlog-policy][] according to [tlog-proof][].
   Let `OutSize` and `OutRoot` be the verified output log checkpoint tree size
   and root hash. Check that the proven entry `index` equals `OutSize - 1`.

4. Parse `leaf_bytes` as a `c2sp.org/tlog-vindex-leaf@v1` record (see [Output
   log leaves](#output-log-leaves)) to obtain `MapRoot` (`map-root`), `map-fn`,
   `from`, and `<input-log-checkpoint>`. If the client is configured with an
   expected `map-fn` commitment, check that the leaf's `map-fn` matches;
   otherwise, validate its syntactic encoding and ignore its value.

5. Verify the embedded `<input-log-checkpoint>` against the client's configured
   input log [tlog-policy][]. Let `InSize` be the verified input log tree size,
   and check that `0 <= from <= InSize`.

6. A stateful client that caches previously observed checkpoints MUST reject the
   response if `OutSize` or `InSize` is smaller than previously verified sizes,
   if a checkpoint at an equal size has a different root hash, or if `from`
   differs from previously verified output log leaves.

### Verifying a key lookup

To verify a point lookup (`prefix=false`):

1. Check that the queried `key` is a valid canonical key (see [Canonical
   keys](#canonical-keys)), and verify the state commitment (see [Verifying the
   state commitment](#verifying-the-state-commitment)) to obtain the
   authenticated `(MapRoot, from, InSize)`.

2. Parse the `c2sp.org/tlog-vindex-keys@v1` block header, optional `proof`
   (defaulting to `0` bytes if omitted), `mode`, and matched key lines.

3. If `mode` is `non-inclusion`:
   - Check that there are zero matched key lines.
   - If `MapRoot == EmptyTreeHash`, check that `len(proof) == 0`.
   - Otherwise, read `altKey` and `altVal` from `proof` via `uvarint` length
     prefixes. Check that `altKey` is a valid canonical key,
     `len(altVal) == 32`, and `altKey != key`. Set
     `h = LeafNodeHash(altKey, altVal)` and `prevB = maxKeyBits`. For each
     `(B, H)` step in the remainder of `proof`, check that `0 <= B < prevB` and
     `bit(key, B) == bit(altKey, B)`, set `prevB = B`, and update
     `h = InnerNodeHash(B, h, H)` if `bit(key, B) == 0` or
     `InnerNodeHash(B, H, h)` if `bit(key, B) == 1`. Check that the final hash
     `h` equals `MapRoot`.
   - Verification is complete: `key` has zero occurrences in `[from, InSize)`.

4. If `mode` is `inclusion`:
   - Check that there is exactly one matched key line `<k> <subRootBase64>` with
     `<k> == key`, and decode the 32-byte `SubRoot`.
   - Set `h = LeafNodeHash(key, SubRoot)` and `prevB = maxKeyBits`. For each
     `(B, H)` step in `proof`, check that `0 <= B < prevB`, set `prevB = B`, and
     update `h = InnerNodeHash(B, h, H)` if `bit(key, B) == 0` or
     `InnerNodeHash(B, H, h)` if `bit(key, B) == 1`. Check that the final hash
     `h` equals `MapRoot`.
   - Proceed to [Verifying entry indices](#verifying-entry-indices) to fetch and
     verify the entry indices for `key` against `SubRoot` with initial cursor
     `before = InSize`.

### Verifying a prefix lookup

To verify a prefix lookup (`prefix=true`):

1. Check that the queried `prefix` (`key`) is a valid canonical key prefix (`1`
   to `1024` bytes in `0x21..0x7E`, see [Canonical keys](#canonical-keys)), and
   verify the state commitment (see [Verifying the state
   commitment](#verifying-the-state-commitment)) to obtain the authenticated
   `(MapRoot, from, InSize)`.

2. Parse the `c2sp.org/tlog-vindex-keys@v1` block, decode optional `proof`
   (defaulting to `0` bytes if omitted), and check that `mode` is `prefix`.

3. If there are zero matched key lines:
   - If `MapRoot == EmptyTreeHash`, check that `len(proof) == 0`.
   - Otherwise, read `altKey` and `altVal` from `proof` via `uvarint` length
     prefixes. Check that `altKey` is a valid canonical key,
     `len(altVal) == 32`, and `prefix` is not a byte prefix of `altKey`. Set
     `h = LeafNodeHash(altKey, altVal)` and `prevB = maxKeyBits`. For each
     `(B, H)` step in the remainder of `proof`, check that `0 <= B < prevB` and
     `bit(prefix, B) == bit(altKey, B)`, set `prevB = B`, and update
     `h = InnerNodeHash(B, h, H)` if `bit(prefix, B) == 0` or
     `InnerNodeHash(B, H, h)` if `bit(prefix, B) == 1`. Check that the final
     hash `h` equals `MapRoot`.

4. If there are one or more matched key lines
   `(K_0, SubRoot_0), ..., (K_{n-1}, SubRoot_{n-1})`:
   - For every `i` in `0..n-1`, check that `K_i` is a valid canonical key, that
     `prefix` is a byte prefix of `K_i`, and (for `i > 0`) that `K_{i-1} < K_i`
     in unsigned lexicographical byte order. Checking that `prefix` is a byte
     prefix of every `K_i` is required for soundness because the path check
     below only constrains split bits strictly above `8 * len(prefix)`, which on
     its own would not prevent a server from returning a larger ancestor subtree
     containing keys outside `prefix`.
   - Compute `subtreeHash = TreeHash([(K_0, SubRoot_0), ..., (K_{n-1}, SubRoot_{n-1})])`
     using the algorithm in [Computing `TreeHash` from sorted key-value
     pairs](#computing-treehash-from-sorted-key-value-pairs).
   - Set `h = subtreeHash` and `prevB = 8 * len(prefix)`. For each `(B, H)` step
     in `proof`, check that `0 <= B < prevB`, set `prevB = B`, and update
     `h = InnerNodeHash(B, h, H)` if `bit(prefix, B) == 0` or
     `InnerNodeHash(B, H, h)` if `bit(prefix, B) == 1`. Check that the final
     hash `h` equals `MapRoot`.

5. For each verified `(K_i, SubRoot_i)` of interest, proceed to [Verifying entry
   indices](#verifying-entry-indices) with initial cursor `before = InSize`.

### Verifying entry indices

Given a canonical key `K`, an expected 32-byte value log root `expectedSubRoot`
(initialized to `SubRoot(K)` from `keys`), and cursor `before` (initialized to
`InSize`):

1. Fetch `GET <prefix>/entries?key=<K>&before=<before>[&limit=<L>]`.

2. Check that the first line is `c2sp.org/tlog-vindex-entries@v1`, parse
   `covered` from the second line (`covered <covered-size>`), and decode the
   next `p = popcount(covered)` lines before the empty line as 32-byte hashes
   `C_0, C_1, ..., C_{p-1}`.

3. Parse the decimal indices `idx_0, idx_1, ..., idx_{k-1}` after the empty
   line. Check that `k >= 1`, that `from <= idx_0 < idx_1 < ... < idx_{k-1} < before`,
   and that `covered <= idx_0 - from`.

4. Initialize a compact range `cr` at size `covered` with subtree hashes
   `[C_0, ..., C_{p-1}]` (or an empty compact range if `covered == 0`). For each
   `idx_j` in `idx_0 .. idx_{k-1}`:
   - Compute `lh = SHA-256(0x00 || uint64_be(idx_j))`.
   - While the binary representation of `cr.size` has a trailing `1` bit at the
     current level, pop the rightmost hash `left` from `cr.hashes` and set
     `lh = SHA-256(0x01 || left || lh)`; then push `lh` onto `cr.hashes` and
     increment `cr.size` by `1`.

   Fold the remaining hashes in `cr.hashes` from right to left
   (`acc = SHA-256(0x01 || cr.hashes[i] || acc)`) to obtain `computedSubRoot`,
   and check that `computedSubRoot == expectedSubRoot`.

5. If `covered == 0`, the client has retrieved and verified the complete set of
   occurrences of `K` in `[from, InSize)`. If `covered > 0` and the client
   wishes to fetch older pages, compute the expected root of the remaining
   prefix `[0, covered)` by folding `[C_0, ..., C_{p-1}]` from right to left:

   ```text
   nextExpectedSubRoot = C_{p-1}
   for i = p - 2 down to 0:
     nextExpectedSubRoot = SHA-256(0x01 || C_i || nextExpectedSubRoot)
   ```

   Set `expectedSubRoot = nextExpectedSubRoot`, set `before = idx_0`, and repeat
   from step 1.

## Auditing the Index

Because every state transition of a verifiable index is committed to the output
log ([tlog-tiles][]), any third party can audit the index operator without
trusting the `keys` or `entries` HTTP endpoints:

1. Fetch and verify the output log checkpoint at `<output_log_prefix>/checkpoint`
   against the output log [tlog-policy][], verifying Merkle consistency with
   previously audited output log checkpoints. Fetch new output log entry bundles
   from `<output_log_prefix>/tile/entries/...` and authenticate them against the
   output log's level-0 hash tiles (`<output_log_prefix>/tile/0/...`) and
   checkpoint root hash.

2. For each output log entry `L_m` (`m = 0, 1, ...`), parse the
   `c2sp.org/tlog-vindex-leaf@v1` payload (`MapRoot_m`, `map_fn_m`, `from_m`,
   `InputLogCheckpoint_m`). Verify `InputLogCheckpoint_m` against the input log
   [tlog-policy][], let `N_m = InputLogCheckpoint_m.Size`, check that
   `0 <= from_m <= N_m`, and check that `map_fn_m` matches the auditor's
   out-of-band configured `MapFn` commitment. If `m > 0`, check that
   `from_m == from_0`, check that `N_m >= N_{m-1}`, and verify that
   `InputLogCheckpoint_m` is Merkle-consistent with `InputLogCheckpoint_{m-1}`
   (including `InputLogCheckpoint_m.Hash == InputLogCheckpoint_{m-1}.Hash` when
   `N_m == N_{m-1}`).

3. Fetch the input log entries `entry[i]` covering `[N_{m-1}, N_m)` (or
   `[from_0, N_0)` for `m == 0`) and authenticate them against
   `InputLogCheckpoint_m.Hash` according to the input log's specification. For
   each input log entry `entry[i]` at index `i` in sequential order
   `N_{m-1} .. N_m - 1`:
   - Execute the deterministic `MapFn` on `entry[i]` to obtain the deduplicated
     set of canonical keys `{K}`.
   - Check that every emitted key `K` satisfies [Canonical
     keys](#canonical-keys) (`1` to `1024` bytes in `0x21..0x7E`).
   - For each emitted key `K`, append `SHA-256(0x00 || uint64_be(i))` to `K`'s
     value log and compute its updated 32-byte `SubRoot(K)`.

4. Update the local MPT with `(K, SubRoot(K))` for all keys modified in
   `[N_{m-1}, N_m)` and compute the local MPT root hash `LocalMapRoot_m`. Check
   that `LocalMapRoot_m == MapRoot_m`. Any mismatch proves that the index
   operator published an invalid state commitment to the output log.
