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
	"encoding/binary"
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
	prefix := EncodeChunkPrefix(keyHash)
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
// Previously: Scanned all historical chunks in Pebble for keyHash, reversed them into memory,
// allocated allIndices for every historical occurrence, and re-hashed all prefix indices
// from scratch via cr.Append(LeafHash(idx)) on every query. For high-frequency keys with
// thousands of matches, this caused severe latency spikes and multi-megabyte allocations.
//
// Now: Exploits inverted chunk key ordering (^chunkNum) to seek directly to the newest
// chunk <= upperBound and iterate backwards. Stops reading as soon as 'limit' entries are
// satisfied. Leverages rec.CompactHashes and rec.CoveredSize stored on the oldest contributing
// chunk to commit to all prior chunks in O(1), hashing only the leftover entries in that single chunk.
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

	prefix := EncodeChunkPrefix(keyHash)
	chunkSize := d.ChunkSize()
	maxChunkNum := (upperBound - 1) / chunkSize
	seekKey := EncodeChunkKey(keyHash, maxChunkNum)

	iter, err := d.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekGE(seekKey) || !bytes.HasPrefix(iter.Key(), prefix) {
		return &LookupResult{}, nil
	}

	var matchedSlices [][]uint64
	var totalMatched int
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

		needed := int(limit) - totalMatched
		if validCount > needed {
			// This chunk satisfies all remaining needed matches with leftover prefix entries.
			splitIdx := validCount - needed
			chunkMatches := make([]uint64, needed)
			for i, rel := range rec.RelativeIndices[splitIdx:validCount] {
				chunkMatches[i] = chunkBase + uint64(rel)
			}
			matchedSlices = append(matchedSlices, chunkMatches)
			totalMatched += needed

			// Build prefix compact range from rec.CompactHashes + leftover entries in this chunk.
			cr := &CompactRange{
				CoveredSize: rec.CoveredSize,
				Hashes:      slices.Clone(rec.CompactHashes),
			}
			for _, rel := range rec.RelativeIndices[:splitIdx] {
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], chunkBase+uint64(rel))
				cr.Append(LeafHash(b[:]))
			}
			prefixCoveredSz = cr.CoveredSize
			prefixHashes = cr.Hashes
			firstMatch := chunkMatches[0]
			nextBefore = &firstMatch
			break
		}

		// validCount <= needed: take all valid entries from this chunk.
		chunkMatches := make([]uint64, validCount)
		for i, rel := range rec.RelativeIndices[:validCount] {
			chunkMatches[i] = chunkBase + uint64(rel)
		}
		matchedSlices = append(matchedSlices, chunkMatches)
		totalMatched += validCount

		if totalMatched == int(limit) {
			// Exactly reached the limit on a chunk boundary.
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

	// Reconstruct matchedIndices in ascending order.
	// matchedSlices was collected newest-first, so assemble in reverse order.
	allMatched := make([]uint64, 0, totalMatched)
	for i := len(matchedSlices) - 1; i >= 0; i-- {
		allMatched = append(allMatched, matchedSlices[i]...)
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
