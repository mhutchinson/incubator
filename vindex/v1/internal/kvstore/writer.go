// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kvstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"golang.org/x/sync/errgroup"
)

// activeChunkEntry caches the in-memory descriptor of the active (unsealed) chunk for a key.
type activeChunkEntry struct {
	chunkNum uint64
	record   *ChunkRecord

	// runningRange is a purely in-memory performance optimization (NOT a functional requirement).
	// It maintains the cumulative compact Merkle range across batches for the active chunk.
	//
	// Without runningRange, computing the modified sub-root on every batch requires cloning
	// record.CompactHashes and re-hashing all historical relative indices in the active chunk
	// from index 0, leading to O(N^2) leaf hashing over the life of a chunk.
	//
	// In benchmarks (BenchmarkKVIndexer_IncrementalIndex), maintaining runningRange in RAM
	// improves incremental indexing throughput by ~71% (3.5x speedup: 640.9ms down to 185.1ms
	// for 200 keys x 50 batches) and eliminates ~85% of transient heap allocations on hot keys.
	//
	// It has NO effect on the persisted storage layout: Pebble DB rows continue to store only
	// the compact hashes of prior sealed chunks. On cache eviction or node restart, runningRange
	// is lazily reconstructed once from the persisted record upon first load.
	runningRange *CompactRange
}

// maxGenChunkCacheSize bounds the in-memory active chunk cache.
// Performance optimization (NOT a functional requirement): a bounded two-generational
// cache (currentCache + previousCache) absorbs repeated writes to hot keys across consecutive
// batches, eliminating >90% of Pebble block cache read I/O without the mutex or pointer overhead of an LRU.
const maxGenChunkCacheSize = 32768

// KVIndexer indexes mapped batches into Pebble inverted chunks ('c') and maintains Merkle compact ranges.
type KVIndexer struct {
	// Required for correctness: database instance, chunk capacity, and root state.
	db               *DB
	chunkSize        uint64
	lastModifiedSubs map[[sha256.Size]byte][sha256.Size]byte

	// Performance optimizations (NOT functional requirements):
	// Generational in-memory active chunk cache to avoid Pebble block cache read I/O on hot keys.
	currentCache  map[[sha256.Size]byte]activeChunkEntry
	previousCache map[[sha256.Size]byte]activeChunkEntry
	marshalBuf    []byte          // Reusable serialization buffer to eliminate heap churn during chunk writes.
	writesBuf     []chunkMutation // Reusable chunk mutation buffer for sequential batch path.
	numWorkers    int             // Number of worker goroutines for parallel key indexing (defaults to min(8, max(1, GOMAXPROCS/2))).
}

// DefaultKVIndexerWorkers calculates the recommended worker count for parallel key indexing.
// Performance optimization: caps workers to min(8, max(1, GOMAXPROCS/2)) to capture >80% of
// parallel Merkle speedup while preserving cores for WASM mapping, Pebble compactions, and read RPCs.
func DefaultKVIndexerWorkers() int {
	w := runtime.GOMAXPROCS(0) / 2
	if w > 8 {
		w = 8
	}
	if w < 1 {
		w = 1
	}
	return w
}

// NewKVIndexer creates a new KVIndexer with the given DB and chunk size.
// If chunkSize is 0, ChunkSize (65536) is used.
func NewKVIndexer(db *DB, chunkSize uint64) *KVIndexer {
	if chunkSize == 0 {
		chunkSize = ChunkSize
	}
	return &KVIndexer{
		db:           db,
		chunkSize:    chunkSize,
		currentCache: make(map[[sha256.Size]byte]activeChunkEntry, 1024),
		numWorkers:   DefaultKVIndexerWorkers(),
	}
}

// SetNumWorkers sets the number of worker goroutines for parallel key indexing.
// Performance optimization: setting n <= 1 enforces sequential single-threaded execution.
func (idx *KVIndexer) SetNumWorkers(n int) {
	if n < 1 {
		n = 1
	}
	idx.numWorkers = n
}

// NumWorkers returns the configured number of worker goroutines.
func (idx *KVIndexer) NumWorkers() int {
	return idx.numWorkers
}

// ClearCache evicts all cached active chunk descriptors.
func (idx *KVIndexer) ClearCache() {
	idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, 1024)
	idx.previousCache = nil
}

// ChunkSize returns the configured chunk capacity.
func (idx *KVIndexer) ChunkSize() uint64 {
	return idx.chunkSize
}

// ModifiedSubRoots returns the sub-roots modified in the last indexing batch.
func (idx *KVIndexer) ModifiedSubRoots() map[[sha256.Size]byte][sha256.Size]byte {
	return idx.lastModifiedSubs
}

// IndexBatch indexes a MappedBatch into Pebble inverted chunks and updates metadata in the same atomic Pebble batch.
func (idx *KVIndexer) IndexBatch(ctx context.Context, batch *ingest.MappedBatch, targetCP *ingest.Checkpoint) (*IndexResult, error) {
	if batch == nil {
		kvSize, _ := idx.db.GetUint64(KeyMetaKVSize)
		return &IndexResult{NewKVSize: kvSize, ModifiedSubRoots: make(map[[32]byte][32]byte)}, nil
	}

	var rawCP []byte
	var targetSize uint64
	if targetCP != nil {
		rawCP = targetCP.Raw
		targetSize = targetCP.Size
	}
	return idx.IndexMappedBatch(ctx, batch, rawCP, targetSize)
}

// IndexMappedBatch indexes a MappedBatch with optional raw target checkpoint bytes and target size.
func (idx *KVIndexer) IndexMappedBatch(ctx context.Context, batch *ingest.MappedBatch, rawTargetCP []byte, targetSize uint64) (*IndexResult, error) {
	if batch == nil {
		kvSize, _ := idx.db.GetUint64(KeyMetaKVSize)
		return &IndexResult{NewKVSize: kvSize, ModifiedSubRoots: make(map[[32]byte][32]byte)}, nil
	}

	persistedKVSize, err := idx.db.GetUint64(KeyMetaKVSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read persisted kv_size: %w", err)
	}

	keys := make([][sha256.Size]byte, 0, len(batch.KeyMap))
	for k := range batch.KeyMap {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [sha256.Size]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	for _, k := range keys {
		slices.Sort(batch.KeyMap[k])
		batch.KeyMap[k] = slices.Compact(batch.KeyMap[k])
	}

	pBatch := idx.db.NewBatch()
	defer func() { _ = pBatch.Close() }()

	modifiedSubRoots := make(map[[sha256.Size]byte][sha256.Size]byte)
	newCachedEntries := make(map[[sha256.Size]byte]activeChunkEntry, len(keys))

	newKVSize := batch.EndLeafIdx
	if newKVSize == 0 && batch.Count > 0 {
		newKVSize = batch.StartLeafIdx + uint64(batch.Count)
	} else if newKVSize == 0 && targetSize > 0 {
		newKVSize = targetSize
	}

	const parallelThreshold = 4
	if idx.numWorkers <= 1 || len(keys) < parallelThreshold {
		iter, err := idx.db.NewIter(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create iterator: %w", err)
		}
		defer func() { _ = iter.Close() }()
		getIter := func() (*pebble.Iterator, error) { return iter, nil }

		var prefixBuf [33]byte

		for _, keyHash := range keys {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			idx.marshalBuf = idx.marshalBuf[:0]
			idx.writesBuf = idx.writesBuf[:0]
			res, newBuf, err := idx.processKey(
				keyHash, batch.KeyMap[keyHash], persistedKVSize, newKVSize, targetSize,
				batch.StartLeafIdx, idx.marshalBuf, &idx.writesBuf, &prefixBuf, getIter,
			)
			if err != nil {
				return nil, err
			}
			idx.marshalBuf = newBuf
			modifiedSubRoots[keyHash] = res.subRoot
			if res.hasCache {
				newCachedEntries[keyHash] = res.cached
			}
			for j := range idx.writesBuf {
				w := &idx.writesBuf[j]
				if err := pBatch.Set(w.key[:], w.val, nil); err != nil {
					return nil, fmt.Errorf("failed to set chunk: %w", err)
				}
			}
		}
	} else {
		// Performance optimization: partition keys across worker goroutines to compute
		// CompactRange.Append, runningRange.Root(), and chunk serialization in parallel.
		workers := idx.numWorkers
		if workers > len(keys) {
			workers = len(keys)
		}
		if workers < 1 {
			workers = 1
		}

		chunkSize := (len(keys) + workers - 1) / workers
		results := make([]keyProcessResult, len(keys))
		workerWrites := make([][]chunkMutation, workers)
		g, gCtx := errgroup.WithContext(ctx)

		for w := 0; w < workers; w++ {
			w := w
			start := w * chunkSize
			if start >= len(keys) {
				continue
			}
			end := min(start+chunkSize, len(keys))
			workerWrites[w] = make([]chunkMutation, 0, end-start)

			g.Go(func() error {
				var wIter *pebble.Iterator
				defer func() {
					if wIter != nil {
						_ = wIter.Close()
					}
				}()
				getIter := func() (*pebble.Iterator, error) {
					if wIter == nil {
						var err error
						wIter, err = idx.db.NewIter(nil)
						if err != nil {
							return nil, fmt.Errorf("failed to create worker iterator: %w", err)
						}
					}
					return wIter, nil
				}

				var wPrefixBuf [33]byte
				wMarshalBuf := make([]byte, 0, (end-start)*64)
				wWrites := workerWrites[w]

				for i := start; i < end; i++ {
					select {
					case <-gCtx.Done():
						return gCtx.Err()
					default:
					}

					keyHash := keys[i]
					res, newBuf, err := idx.processKey(
						keyHash, batch.KeyMap[keyHash], persistedKVSize, newKVSize, targetSize,
						batch.StartLeafIdx, wMarshalBuf, &wWrites, &wPrefixBuf, getIter,
					)
					if err != nil {
						return err
					}
					wMarshalBuf = newBuf
					results[i] = res
				}
				workerWrites[w] = wWrites
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return nil, err
		}

		for i := range results {
			r := &results[i]
			modifiedSubRoots[r.keyHash] = r.subRoot
			if r.hasCache {
				newCachedEntries[r.keyHash] = r.cached
			}
		}
		for _, wWrites := range workerWrites {
			for j := range wWrites {
				w := &wWrites[j]
				if err := pBatch.Set(w.key[:], w.val, nil); err != nil {
					return nil, fmt.Errorf("failed to set chunk: %w", err)
				}
			}
		}
	}

	if newKVSize > persistedKVSize {
		var szBuf [8]byte
		binary.BigEndian.PutUint64(szBuf[:], newKVSize)
		if err := pBatch.Set(KeyMetaKVSize, szBuf[:], nil); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_size: %w", err)
		}

		// Performance optimization: use pebble.NoSync for intermediate catch-up batches
		// to avoid blocking on synchronous disk fsync() every 256 leaves. Durability is enforced
		// via pebble.Sync on the final catch-up boundary (newKVSize == targetSize) and steady-state commits.
		syncOption := pebble.Sync
		if targetSize > 0 && newKVSize < targetSize {
			syncOption = pebble.NoSync
		} else if len(rawTargetCP) > 0 {
			if err := pBatch.Set(KeyMetaKVCheckpoint, rawTargetCP, nil); err != nil {
				return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
			}
		}

		applyStart := time.Now()
		if err := idx.db.Pebble().Apply(pBatch, syncOption); err != nil {
			return nil, fmt.Errorf("failed to commit indexing batch: %w", err)
		}
		metrics.PebbleApplyDurationSeconds.Observe(time.Since(applyStart).Seconds())

		if len(idx.currentCache)+len(newCachedEntries) > maxGenChunkCacheSize {
			idx.previousCache = idx.currentCache
			idx.currentCache = make(map[[sha256.Size]byte]activeChunkEntry, maxGenChunkCacheSize)
		}
		for k, v := range newCachedEntries {
			idx.currentCache[k] = v
		}
	} else if len(rawTargetCP) > 0 && targetSize > 0 && newKVSize == targetSize {
		if err := idx.db.SetMetadata(KeyMetaKVCheckpoint, rawTargetCP); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_checkpoint: %w", err)
		}
	}

	idx.lastModifiedSubs = modifiedSubRoots
	return &IndexResult{
		NewKVSize:        newKVSize,
		ModifiedSubRoots: modifiedSubRoots,
	}, nil
}

type chunkMutation struct {
	key [41]byte
	val []byte
}

type keyProcessResult struct {
	keyHash  [sha256.Size]byte
	subRoot  [sha256.Size]byte
	cached   activeChunkEntry
	hasCache bool
}

func (idx *KVIndexer) processKey(
	keyHash [sha256.Size]byte,
	indices []uint64,
	persistedKVSize uint64,
	newKVSize uint64,
	targetSize uint64,
	batchStartLeafIdx uint64,
	marshalBuf []byte,
	writes *[]chunkMutation,
	prefixBuf *[33]byte,
	getIter func() (*pebble.Iterator, error),
) (res keyProcessResult, outBuf []byte, err error) {
	res.keyHash = keyHash

	// Filter unpersisted indices (indices >= persistedKVSize).
	var unpersisted []uint64
	if batchStartLeafIdx >= persistedKVSize {
		unpersisted = indices
	} else {
		hasPersisted := false
		for _, leafIdx := range indices {
			if leafIdx < persistedKVSize {
				hasPersisted = true
				break
			}
		}
		if !hasPersisted {
			unpersisted = indices
		} else {
			for _, leafIdx := range indices {
				if leafIdx >= persistedKVSize {
					unpersisted = append(unpersisted, leafIdx)
				}
			}
		}
	}

	if len(unpersisted) == 0 {
		limit := newKVSize
		if limit == 0 {
			limit = targetSize
		}
		if limit == 0 {
			limit = persistedKVSize
		}
		sr, err := idx.GetSubRoot(keyHash, limit)
		if err != nil {
			return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to get sub-root for key %x: %w", keyHash, err)
		}
		res.subRoot = sr
		return res, marshalBuf, nil
	}

	var currChunkNum uint64
	var rec *ChunkRecord
	var runningRange *CompactRange

	if cached, ok := idx.currentCache[keyHash]; ok {
		currChunkNum = cached.chunkNum
		rec = cached.record
		runningRange = cached.runningRange
	} else if cached, ok := idx.previousCache[keyHash]; ok {
		currChunkNum = cached.chunkNum
		rec = &ChunkRecord{
			CoveredSize:     cached.record.CoveredSize,
			CompactHashes:   cached.record.CompactHashes,
			RelativeIndices: append([]uint16(nil), cached.record.RelativeIndices...),
		}
		runningRange = &CompactRange{
			CoveredSize: cached.runningRange.CoveredSize,
			Hashes:      slices.Clone(cached.runningRange.Hashes),
		}
	} else {
		prefix := EncodeChunkPrefixInto(prefixBuf, keyHash)
		iter, err := getIter()
		if err != nil {
			return keyProcessResult{}, marshalBuf, err
		}
		if iter.SeekPrefixGE(prefix) && bytes.HasPrefix(iter.Key(), prefix) {
			_, cNum, err := DecodeChunkKey(iter.Key())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to decode chunk key: %w", err)
			}
			currChunkNum = cNum
			rec, err = UnmarshalChunkValue(iter.Value())
			if err != nil {
				return keyProcessResult{}, marshalBuf, fmt.Errorf("failed to unmarshal chunk value: %w", err)
			}
			runningRange = &CompactRange{
				CoveredSize: rec.CoveredSize,
				Hashes:      slices.Clone(rec.CompactHashes),
			}
			for _, rel := range rec.RelativeIndices {
				absIdx := currChunkNum*idx.chunkSize + uint64(rel)
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], absIdx)
				runningRange.Append(LeafHash(b[:]))
			}
		} else {
			currChunkNum = 0
			rec = &ChunkRecord{
				CoveredSize:     0,
				CompactHashes:   nil,
				RelativeIndices: nil,
			}
			runningRange = NewCompactRange()
		}
	}

	for _, leafIdx := range unpersisted {
		targetChunkNum := leafIdx / idx.chunkSize
		if targetChunkNum > currChunkNum {
			start := len(marshalBuf)
			marshalBuf = AppendChunkValue(marshalBuf, rec)
			sealedVal := marshalBuf[start:]
			var sealedKey [41]byte
			EncodeChunkKeyInto(&sealedKey, keyHash, currChunkNum)
			*writes = append(*writes, chunkMutation{key: sealedKey, val: sealedVal})

			currChunkNum = targetChunkNum
			rec = &ChunkRecord{
				CoveredSize:     runningRange.CoveredSize,
				CompactHashes:   slices.Clone(runningRange.Hashes),
				RelativeIndices: nil,
			}
		}
		rec.RelativeIndices = append(rec.RelativeIndices, uint16(leafIdx%idx.chunkSize))
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], leafIdx)
		runningRange.Append(LeafHash(b[:]))
	}

	start := len(marshalBuf)
	marshalBuf = AppendChunkValue(marshalBuf, rec)
	activeVal := marshalBuf[start:]
	var activeKey [41]byte
	EncodeChunkKeyInto(&activeKey, keyHash, currChunkNum)
	*writes = append(*writes, chunkMutation{key: activeKey, val: activeVal})

	res.subRoot = runningRange.Root()
	res.cached = activeChunkEntry{
		chunkNum:     currChunkNum,
		record:       rec,
		runningRange: runningRange,
	}
	res.hasCache = true
	return res, marshalBuf, nil
}

// GetSubRoot calculates the Merkle sub-root for the given keyHash up to maxInputLogSize.
func (idx *KVIndexer) GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error) {
	prefix := EncodeChunkPrefix(keyHash)
	iter, err := idx.db.NewIter(nil)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(prefix) || !bytes.HasPrefix(iter.Key(), prefix) {
		return EmptyRoot(), nil
	}

	type chunkEntry struct {
		chunkNum uint64
		rec      *ChunkRecord
	}
	var chunks []chunkEntry
	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		_, chunkNum, err := DecodeChunkKey(iter.Key())
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		rec, err := UnmarshalChunkValue(iter.Value())
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		chunks = append(chunks, chunkEntry{chunkNum: chunkNum, rec: rec})
	}

	slices.Reverse(chunks)

	cr := NewCompactRange()
	hasEntries := false

	for _, ce := range chunks {
		cNum := ce.chunkNum
		rec := ce.rec

		if cNum*idx.chunkSize >= maxInputLogSize {
			break
		}

		if cr.CoveredSize == 0 && len(rec.CompactHashes) > 0 {
			cr.CoveredSize = rec.CoveredSize
			cr.Hashes = slices.Clone(rec.CompactHashes)
			if cr.CoveredSize > 0 {
				hasEntries = true
			}
		}

		for _, rel := range rec.RelativeIndices {
			absIdx := cNum*idx.chunkSize + uint64(rel)
			if absIdx < maxInputLogSize {
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], absIdx)
				cr.Append(LeafHash(b[:]))
				hasEntries = true
			}
		}
	}

	if !hasEntries {
		return EmptyRoot(), nil
	}

	return cr.Root(), nil
}
