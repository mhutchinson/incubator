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

// Package kvstore implements the persistent key-value and chunk storage layer for VIndex using Pebble DB.
package kvstore

import (
	"crypto/sha256"
	"errors"
)

const (
	// ChunkSize is the logical capacity of a single chunk (65536 entries).
	ChunkSize uint64 = 65536

	// PrefixChunkByte identifies KV Chunk records.
	PrefixChunkByte byte = 'c'

	// PrefixMetaByte identifies metadata keys.
	PrefixMetaByte byte = 'm'
)

var (
	// Standard metadata keys.
	KeyMetaTargetCheckpoint = []byte("m_target_checkpoint")
	KeyMetaKVCheckpoint     = []byte("m_kv_checkpoint")
	KeyMetaKVSize           = []byte("m_kv_size")
)

var (
	ErrInvalidValue    = errors.New("invalid storage value")
	ErrInvalidChunkKey = errors.New("invalid chunk key")
	ErrInvalidMetadata = errors.New("invalid metadata value")
)

// ChunkRecord represents the deserialized content of a KV chunk value.
type ChunkRecord struct {
	CoveredSize     uint64
	CompactHashes   [][sha256.Size]byte
	RelativeIndices []uint16
}

// LookupResult encapsulates range lookup matches and the prefix compact range.
type LookupResult struct {
	MatchedIndices  []uint64
	NextBefore      *uint64
	PrefixCoveredSz uint64
	PrefixHashes    [][sha256.Size]byte
}

// IndexStore defines the abstract, black-box storage contract for VIndex.
type IndexStore interface {
	WriteBatch(entries map[[sha256.Size]byte][]uint64, targetSize uint64) error
	Lookup(keyHash [sha256.Size]byte, before *uint64, limit uint64, maxInputLogSize uint64) (*LookupResult, error)
	GetSubRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error)
	GetMetadata(key []byte) ([]byte, error)
	SetMetadata(key, val []byte) error
	GetUint64(key []byte) (uint64, error)
	SetUint64(key []byte, val uint64) error
	SetChunkSize(chunkSize uint64)
	ChunkSize() uint64
	Close() error
}

// IndexResult contains the result of an indexing batch.
type IndexResult struct {
	NewKVSize        uint64
	ModifiedSubRoots map[[sha256.Size]byte][sha256.Size]byte
}
