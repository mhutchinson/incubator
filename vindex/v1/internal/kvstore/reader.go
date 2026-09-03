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

	prefix := EncodeChunkPrefix(keyHash)
	iter, err := d.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(prefix) || !bytes.HasPrefix(iter.Key(), prefix) {
		return &LookupResult{
			MatchedIndices:  nil,
			NextBefore:      nil,
			PrefixCoveredSz: 0,
			PrefixHashes:    nil,
		}, nil
	}

	type chunkEntry struct {
		chunkNum uint64
		rec      *ChunkRecord
	}
	var chunks []chunkEntry
	for ; iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		_, cNum, err := DecodeChunkKey(iter.Key())
		if err != nil {
			return nil, fmt.Errorf("decode chunk key: %w", err)
		}
		rec, err := UnmarshalChunkValue(iter.Value())
		if err != nil {
			return nil, fmt.Errorf("unmarshal chunk value: %w", err)
		}
		chunks = append(chunks, chunkEntry{chunkNum: cNum, rec: rec})
	}

	slices.Reverse(chunks)

	chunkSize := d.ChunkSize()
	var allIndices []uint64
	for _, ce := range chunks {
		cNum := ce.chunkNum
		rec := ce.rec

		if cNum*chunkSize >= upperBound {
			break
		}

		for _, rel := range rec.RelativeIndices {
			absIdx := cNum*chunkSize + uint64(rel)
			if absIdx < upperBound {
				allIndices = append(allIndices, absIdx)
			}
		}
	}

	if len(allIndices) == 0 {
		return &LookupResult{
			MatchedIndices:  nil,
			NextBefore:      nil,
			PrefixCoveredSz: 0,
			PrefixHashes:    nil,
		}, nil
	}

	if len(allIndices) <= int(limit) {
		return &LookupResult{
			MatchedIndices:  allIndices,
			NextBefore:      nil,
			PrefixCoveredSz: 0,
			PrefixHashes:    nil,
		}, nil
	}

	splitIdx := len(allIndices) - int(limit)
	prefixIndices := allIndices[:splitIdx]
	matchedIndices := allIndices[splitIdx:]

	cr := NewCompactRange()
	for _, idx := range prefixIndices {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		cr.Append(LeafHash(b[:]))
	}

	nextBeforeVal := matchedIndices[0]
	return &LookupResult{
		MatchedIndices:  matchedIndices,
		NextBefore:      &nextBeforeVal,
		PrefixCoveredSz: cr.CoveredSize,
		PrefixHashes:    cr.Hashes,
	}, nil
}
