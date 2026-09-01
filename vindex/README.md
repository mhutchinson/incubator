## Verifiable Index

> [!IMPORTANT]
> **Plan of Record (PoR)**: For the production-ready VIndex v1 specification, architecture, benchmarks, and WASM SDK, see [**`vindex/v1`**](./v1/README.md) and [**System Architecture (`vindex/v1/docs/ARCHITECTURE.md`)**](./v1/docs/ARCHITECTURE.md).

Status: Working Prototype and v1 Production Design of an end-to-end verifiable index for transparency logs.

There is a complete solution provided for the [Go Module Proxy (SumDB) log](./cmd/sumdbindex/).

This idea has been distilled from years of experiments with maps, and a pressing need to have an efficient and verifiable way for an end-user to find _their_ data in logs without needing to download the whole log.

Discussions are welcome, please join us on [Transparency-Dev Slack](https://transparency.dev/slack/).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

## Overview

### The Problem: Verifiability vs. Efficiency

Logs, such as those used in Certificate Transparency or Software Supply Chains, provide a strong foundation for discoverability. You can prove that an entry exists in a log. However, they lack a critical feature: the ability to _verifiably_ query for entries based on their content.

This forces users who need to find specific data, like a domain owner finding their certificates, or a developer finding their software packages, into a painful choice:

1.  **Massive Inefficiency**: Download and process the _entire_ log, which can be terabytes of mostly irrelevant data, just to find the few entries that matter to you.
2.  **Losing Verifiability**: Rely on a third-party service to index the data. This breaks the chain of verifiability, as the index operator could, by accident or design, fail to show you all the results. You are forced to trust them.

Neither option is acceptable. Users should not have to sacrifice efficiency for security, or security for efficiency.

### The Solution: A Verifiable "Back-of-the-Book" Index

A Verifiable Index resolves this conflict by providing a third option: an efficient, cryptographically verifiable way to query log data.

At its core it works like a familiar index, much like one would find in the back of a book. It maps search terms (like a domain or package name) to the exact locations (pointers) in the main log where that data can be found.

This provides two key guarantees:

-   **Efficiency**: Users can look up data by a meaningful key and receive a small, targeted list of pointers back, avoiding the need to download the entire log.
-   **Verifiability**: Every lookup response comes with a cryptographic proof. This proof guarantees that the list of results is complete and that the index operator has not omitted any entries for your query.

The result is a system that extends the verifiability of the underlying log to its queries, preserving the end-to-end chain of trust while providing the efficiency modern systems require.

## Applications

This verifiable map can be applied to any log where users have a need to enumerate all values matching a specific query. For example:

* CT: domain owners wish to query for all certs matching a domain they own
* [SumDB](./cmd/sumdbindex/): package owners want to find all releases for a package they maintain

Indices exist for both ecosystems at the moment, but they aren’t verifiable. See [**`vindex/v1/docs/APPLICATIONS.md`**](./v1/docs/APPLICATIONS.md) for full ecosystem profiles.

## Core Idea; TL;DR

The Verifiable Index has 3 data structures involved (and is informally called a Map Sandwich, as the Map sits between two Logs):

1. The _Input Log_ that is to be indexed
2. The _Verifiable Index_ containing pointers back into the _Input Log_
3. The _Output Log_ that contains a list of all revisions of the map

The Input Log likely already exists before the Verifiable Index is added, but the Output Log is new, and required in order to make the Verifiable Index historically verifiable.
For example, in Certificate Transparency, the Input Log could be any one of the CT Logs.
In order to make certificates in a log be efficiently looked up by domain, an operator can spin up a Verifiable Index and a corresponding Output Log.
The Index would map domain names to indices in the Input Log where the cert is for this domain.

> [!TIP]
> Note that the map doesn't have a "signed map root", i.e. it has no direct analog for a Log Checkpoint.
> Instead, the state of a Verifiable Index is committed to by including its state as a leaf in the Output Log.

> [!NOTE]
> A Verifiable Index is constructed for a single Input Log.
> For ecosystems of multiple logs (e.g. CT), there will be as many Verifiable Indices as there are Input Logs.

### Constructing

1. Log data is consumed tile by tile (256 leaves per entry bundle)
2. Each tile is parsed using a [`map_bundle`](./v1/mapfn/README.md) WebAssembly function that extracts canonical Claim Subject preimages (e.g., domain names, package paths)
3. The host computes hardware-accelerated SHA-256 key hashes (`KeyHash = SHA256(preimage)`) using SIMD extensions (x86 SHA-NI / ARM Crypto)
4. Mapped key entries are streamed directly into Pebble inverted chunk storage records (`'c'`) without intermediate WAL overhead
5. An in-memory Binary Merkle Patricia Trie (MPT) is updated and the new root hash is written as a leaf into the Tessera Output Log
6. The Output Log is witnessed, and an Output Log Checkpoint is made available with witness cosignatures

### Reading & Verifying

Given a key to read, a read operation queries `GET /vindex/lookup/{keyhash}`:
- Returns the latest matching leaf indices and a Merkle prefix compact range
- Returns an MPT inclusion/non-inclusion proof to `MapRoot`
- Returns a witnessed Output Log Checkpoint and Output Log inclusion proof

Verifying this involves verifying:
- The Output Log Checkpoint is signed by the Map Operator and sufficient witnesses
- The inclusion proof in the Output Log ties `MapRoot` to the Output Log Checkpoint
- The inclusion proof in the MPT ties the index mini-log to `MapRoot`
- The RFC 6962 Compact Range recalculation matches the mini-log root

---

## Sub-Problems & Architecture Evolutions

### Bundled WASM MapFn & Host Hardware Cryptography

The VIndex v1 Plan of Record (PoR) standardizes on a bundled WebAssembly mapping ABI ([`map_bundle`](./v1/mapfn/README.md)):
- **Bundled Execution**: Ingests 256-leaf tiles in a single FFI crossing, reducing boundary transitions from 768 to 2–3 per tile (< 1% CPU).
- **Host Hardware Hashing**: Sandboxed guest modules emit canonical Claim Subject preimages; the Go host computes SHA-256 using native SIMD acceleration (**Intel SHA-NI** or **ARMv8 Crypto**), eliminating the ~55% software crypto bottleneck.
- **Prefix Extensibility**: Preserving preimages on the host enables future prefix-trie search capabilities without guest ABI changes.

### Zero-WAL Direct Commit Architecture

Early prototypes staged records in an intermediate Write-Ahead Log (WAL). Production profiling revealed that double-writing to a WAL caused severe tail latency spikes (up to 1,214 ms) and disk compaction churn. 

VIndex v1 replaces the WAL with a **Zero-WAL direct commit pipeline**:
- Inverted chunks (`'c'`) are written directly to Pebble DB with synchronous fsync (`pebble.Sync`).
- Startup recovery replays un-synced MPT state directly from local verified tile caches (`torchwood.PermanentCache`) with O(1) point seeks (`GetSubRoot`), achieving **2.4 ms warm recovery** and **240,467 leaves/sec** sustained throughput.
- Cached tiles are pruned behind `SafeWatermark = mptDurableSize` via a background `TileReaper`.

---

## Status & Milestones

For the latest v1 production roadmap and milestones, refer to the [**VIndex v1 Documentation Index**](./v1/README.md).


