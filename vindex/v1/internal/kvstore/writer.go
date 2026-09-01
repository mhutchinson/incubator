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
	"slices"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
)

type activeChunkEntry struct {
	chunkNum uint64
	record   *ChunkRecord
}

const maxGenChunkCacheSize = 32768

// KVIndexer indexes mapped batches into Pebble inverted chunks ('c') and maintains Merkle compact ranges.
type KVIndexer struct {
	db               *DB
	chunkSize        uint64
	lastModifiedSubs map[[sha256.Size]byte][sha256.Size]byte
	currentCache     map[[sha256.Size]byte]activeChunkEntry
	previousCache    map[[sha256.Size]byte]activeChunkEntry
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
	}
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

	iter, err := idx.db.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

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

	for _, keyHash := range keys {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Filter unpersisted indices (indices >= persistedKVSize)
		var unpersisted []uint64
		for _, leafIdx := range batch.KeyMap[keyHash] {
			if leafIdx >= persistedKVSize {
				unpersisted = append(unpersisted, leafIdx)
			}
		}

		if len(unpersisted) == 0 {
			// All occurrences for this key in this batch were already persisted.
			// Reconstruct sub-root from existing chunks without mutating storage.
			limit := newKVSize
			if limit == 0 {
				limit = targetSize
			}
			subRoot, err := idx.GetSubRoot(keyHash, limit)
			if err != nil {
				return nil, fmt.Errorf("failed to get sub-root for key %x: %w", keyHash, err)
			}
			modifiedSubRoots[keyHash] = subRoot
			continue
		}

		prefix := EncodeChunkPrefix(keyHash)
		var currChunkNum uint64
		var rec *ChunkRecord
		var currentRange *CompactRange

		if cached, ok := idx.currentCache[keyHash]; ok {
			currChunkNum = cached.chunkNum
			rec = &ChunkRecord{
				CoveredSize:     cached.record.CoveredSize,
				CompactHashes:   cached.record.CompactHashes,
				RelativeIndices: append([]uint16(nil), cached.record.RelativeIndices...),
			}
			currentRange = &CompactRange{
				CoveredSize: rec.CoveredSize,
				Hashes:      rec.CompactHashes,
			}
		} else if cached, ok := idx.previousCache[keyHash]; ok {
			currChunkNum = cached.chunkNum
			rec = &ChunkRecord{
				CoveredSize:     cached.record.CoveredSize,
				CompactHashes:   cached.record.CompactHashes,
				RelativeIndices: append([]uint16(nil), cached.record.RelativeIndices...),
			}
			currentRange = &CompactRange{
				CoveredSize: rec.CoveredSize,
				Hashes:      rec.CompactHashes,
			}
		} else if iter.SeekPrefixGE(prefix) && bytes.HasPrefix(iter.Key(), prefix) {
			_, cNum, err := DecodeChunkKey(iter.Key())
			if err != nil {
				return nil, fmt.Errorf("failed to decode chunk key: %w", err)
			}
			currChunkNum = cNum
			rec, err = UnmarshalChunkValue(iter.Value())
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal chunk value: %w", err)
			}
			currentRange = &CompactRange{
				CoveredSize: rec.CoveredSize,
				Hashes:      rec.CompactHashes,
			}
		} else {
			currChunkNum = 0
			rec = &ChunkRecord{
				CoveredSize:     0,
				CompactHashes:   nil,
				RelativeIndices: nil,
			}
			currentRange = NewCompactRange()
		}

		for _, leafIdx := range unpersisted {
			targetChunkNum := leafIdx / idx.chunkSize
			if targetChunkNum > currChunkNum {
				// Rollover: finalize current chunk into compact range
				cr := &CompactRange{
					CoveredSize: currentRange.CoveredSize,
					Hashes:      slices.Clone(currentRange.Hashes),
				}
				for _, rel := range rec.RelativeIndices {
					absIdx := currChunkNum*idx.chunkSize + uint64(rel)
					var b [8]byte
					binary.BigEndian.PutUint64(b[:], absIdx)
					cr.Append(LeafHash(b[:]))
				}
				// Write sealed historical chunk
				sealedVal := MarshalChunkValue(rec)
				if err := pBatch.Set(EncodeChunkKey(keyHash, currChunkNum), sealedVal, nil); err != nil {
					return nil, fmt.Errorf("failed to write sealed chunk: %w", err)
				}
				// Allocate new active chunk
				currChunkNum = targetChunkNum
				rec = &ChunkRecord{
					CoveredSize:     cr.CoveredSize,
					CompactHashes:   cr.Hashes,
					RelativeIndices: nil,
				}
				currentRange = cr
			}
			rec.RelativeIndices = append(rec.RelativeIndices, uint16(leafIdx%idx.chunkSize))
		}

		// Write active chunk
		activeVal := MarshalChunkValue(rec)
		if err := pBatch.Set(EncodeChunkKey(keyHash, currChunkNum), activeVal, nil); err != nil {
			return nil, fmt.Errorf("failed to write active chunk: %w", err)
		}

		// Compute modified sub-root
		crClone := &CompactRange{
			CoveredSize: rec.CoveredSize,
			Hashes:      slices.Clone(rec.CompactHashes),
		}
		for _, rel := range rec.RelativeIndices {
			absIdx := currChunkNum*idx.chunkSize + uint64(rel)
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], absIdx)
			crClone.Append(LeafHash(b[:]))
		}
		modifiedSubRoots[keyHash] = crClone.Root()

		newCachedEntries[keyHash] = activeChunkEntry{
			chunkNum: currChunkNum,
			record:   rec,
		}
	}

	if newKVSize > persistedKVSize {
		var szBuf [8]byte
		binary.BigEndian.PutUint64(szBuf[:], newKVSize)
		if err := pBatch.Set(KeyMetaKVSize, szBuf[:], nil); err != nil {
			return nil, fmt.Errorf("failed to set metadata kv_size: %w", err)
		}

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
