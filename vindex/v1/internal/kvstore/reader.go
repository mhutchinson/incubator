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
	"crypto/sha256"
	"fmt"
	"slices"
)

// ReadChunk retrieves and deserializes the ChunkRecord for a given keyHash and chunkNum.
// Returns nil, nil if the chunk does not exist.
func (d *DB) ReadChunk(keyHash [sha256.Size]byte, chunkNum uint64) (*ChunkRecord, error) {
	key := EncodeChunkKey(keyHash, chunkNum)
	val, closer, err := d.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer.Close() }()
	return UnmarshalChunkValue(val)
}

// ActiveChunk retrieves the newest (active) ChunkRecord for a given keyHash.
// Returns chunkNum, record, exists, error.
func (d *DB) ActiveChunk(keyHash [sha256.Size]byte) (uint64, *ChunkRecord, bool, error) {
	var prefixBuf [33]byte
	prefix := EncodeChunkPrefixInto(&prefixBuf, keyHash)
	iter, err := d.NewIter(nil)
	if err != nil {
		return 0, nil, false, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(prefix) || !bytes.HasPrefix(iter.Key(), prefix) {
		return 0, nil, false, nil
	}

	_, chunkNum, err := DecodeChunkKey(iter.Key())
	if err != nil {
		return 0, nil, false, err
	}

	rec, err := UnmarshalChunkValue(iter.Value())
	if err != nil {
		return 0, nil, false, err
	}

	return chunkNum, rec, true, nil
}

// Lookup retrieves matching leaf indices and prefix compact ranges for keyHash up to before.
//
// Optimization rationale:
// 1. Prefix Bloom Filters (SeekPrefixGE): Exploits Pebble's 33-byte prefix split ('c' + KeyHash)
//    and inverted chunk key ordering (^chunkNum) via SeekPrefixGE to prune absent keys in O(1)
//    and seek directly to the newest chunk <= upperBound.
// 2. Chunk-Aligned Paging: Treats 'limit' as an advisory hint and aligns page boundaries to whole
//    inverted chunks. Every stored chunk already contains precomputed rec.CompactHashes and
//    rec.CoveredSize committing to all prior chunks, so prefix compact ranges are copied in O(1)
//    with zero dynamic SHA-256 hashing on the read path.
// 3. Bounded Chunk Visitation: Halts once totalMatched >= limit OR chunksVisited >= maxChunksPerRequest
//    (DefaultMaxChunksPerRequest = 16) to bound worst-case SSTable seeks on sparse keys.
func (d *DB) Lookup(keyHash [sha256.Size]byte, before *uint64, limit uint64, maxInputLogSize uint64) (*LookupResult, error) {
	if limit == 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}

	upperBound := maxInputLogSize
	if before != nil && *before < upperBound {
		upperBound = *before
	}
	if upperBound == 0 {
		return &LookupResult{}, nil
	}

	chunkSize := d.ChunkSize()
	maxChunkNum := (upperBound - 1) / chunkSize
	var seekKey [41]byte
	EncodeChunkKeyInto(&seekKey, keyHash, maxChunkNum)
	prefix := seekKey[:33]

	iter, err := d.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(seekKey[:]) || !bytes.HasPrefix(iter.Key(), prefix) {
		return &LookupResult{}, nil
	}

	maxChunks := d.MaxChunksPerRequest()
	var matchedSlices [][]uint64
	var totalMatched int
	var chunksVisited int
	var prefixCoveredSz uint64
	var prefixHashes [][sha256.Size]byte
	var nextBefore *uint64

	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		_, cNum, err := DecodeChunkKey(iter.Key())
		if err != nil {
			return nil, fmt.Errorf("decode chunk key: %w", err)
		}
		if cNum*chunkSize >= upperBound {
			continue
		}

		rec, err := UnmarshalChunkValue(iter.Value())
		if err != nil {
			return nil, fmt.Errorf("unmarshal chunk value: %w", err)
		}

		chunkBase := cNum * chunkSize
		validCount := 0
		if (cNum+1)*chunkSize <= upperBound {
			validCount = len(rec.RelativeIndices)
		} else {
			for _, rel := range rec.RelativeIndices {
				if chunkBase+uint64(rel) < upperBound {
					validCount++
				} else {
					break
				}
			}
		}

		if validCount == 0 {
			continue
		}

		chunkMatches := make([]uint64, validCount)
		for i, rel := range rec.RelativeIndices[:validCount] {
			chunkMatches[i] = chunkBase + uint64(rel)
		}
		matchedSlices = append(matchedSlices, chunkMatches)
		totalMatched += validCount
		chunksVisited++

		if totalMatched >= int(limit) || chunksVisited >= maxChunks {
			if rec.CoveredSize > 0 {
				prefixCoveredSz = rec.CoveredSize
				prefixHashes = slices.Clone(rec.CompactHashes)
				firstMatch := chunkMatches[0]
				nextBefore = &firstMatch
			}
			break
		}
	}

	if totalMatched == 0 {
		return &LookupResult{}, nil
	}

	var allMatched []uint64
	if len(matchedSlices) == 1 {
		allMatched = matchedSlices[0]
	} else {
		// matchedSlices was collected newest-first, so assemble in reverse order.
		allMatched = make([]uint64, 0, totalMatched)
		for i := len(matchedSlices) - 1; i >= 0; i-- {
			allMatched = append(allMatched, matchedSlices[i]...)
		}
	}

	if nextBefore != nil {
		first := allMatched[0]
		nextBefore = &first
	}

	return &LookupResult{
		MatchedIndices:  allMatched,
		NextBefore:      nextBefore,
		PrefixCoveredSz: prefixCoveredSz,
		PrefixHashes:    prefixHashes,
	}, nil
}
