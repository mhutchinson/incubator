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
	"crypto/sha256"
	"math/bits"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// LeafHash computes the RFC 6962 standard leaf hash: SHA256(0x00 || data).
func LeafHash(data []byte) [sha256.Size]byte {
	h := rfc6962.DefaultHasher.HashLeaf(data)
	var out [sha256.Size]byte
	copy(out[:], h)
	return out
}

// InteriorHash computes the RFC 6962 standard interior node hash: SHA256(0x01 || left || right).
func InteriorHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	h := rfc6962.DefaultHasher.HashChildren(left[:], right[:])
	var out [sha256.Size]byte
	copy(out[:], h)
	return out
}

// EmptyRoot returns the RFC 6962 root hash of an empty tree (SHA256("")).
func EmptyRoot() [sha256.Size]byte {
	h := rfc6962.DefaultHasher.EmptyRoot()
	var out [sha256.Size]byte
	copy(out[:], h)
	return out
}

// BatchRoot computes the RFC 6962 root hash from a slice of raw leaf data.
func BatchRoot(leaves [][]byte) [sha256.Size]byte {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	leafHashes := make([][sha256.Size]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = LeafHash(l)
	}
	return BatchRootHashes(leafHashes)
}

// BatchRootHashes computes the RFC 6962 root hash from a slice of leaf hashes.
func BatchRootHashes(hashes [][sha256.Size]byte) [sha256.Size]byte {
	n := len(hashes)
	if n == 0 {
		return EmptyRoot()
	}
	if n == 1 {
		return hashes[0]
	}

	k := uint64(1) << (bits.Len(uint(n-1)) - 1)
	left := BatchRootHashes(hashes[:k])
	right := BatchRootHashes(hashes[k:])
	return InteriorHash(left, right)
}

// CompactRange represents an incremental RFC 6962 compact Merkle tree range.
type CompactRange struct {
	CoveredSize uint64
	Hashes      [][sha256.Size]byte
}

// NewCompactRange creates a new empty CompactRange.
func NewCompactRange() *CompactRange {
	return &CompactRange{}
}

// Append incrementally appends a single leaf hash, collapsing subtrees according to binary representation.
func (cr *CompactRange) Append(leafHash [sha256.Size]byte) {
	h := leafHash
	trailingOnes := bits.TrailingZeros64(^cr.CoveredSize)
	for i := 0; i < trailingOnes; i++ {
		idx := len(cr.Hashes) - 1
		left := cr.Hashes[idx]
		cr.Hashes = cr.Hashes[:idx]
		h = InteriorHash(left, h)
	}
	cr.Hashes = append(cr.Hashes, h)
	cr.CoveredSize++
}

// AppendRange combines this compact range with another compact range.
func (cr *CompactRange) AppendRange(other CompactRange) {
	if other.CoveredSize == 0 {
		return
	}
	if cr.CoveredSize == 0 {
		cr.CoveredSize = other.CoveredSize
		cr.Hashes = make([][sha256.Size]byte, len(other.Hashes))
		copy(cr.Hashes, other.Hashes)
		return
	}

	rf := &compact.RangeFactory{
		Hash: rfc6962.DefaultHasher.HashChildren,
	}

	lhsHashes := make([][]byte, len(cr.Hashes))
	for i := range cr.Hashes {
		lhsHashes[i] = cr.Hashes[i][:]
	}
	lhsRange, err := rf.NewRange(0, cr.CoveredSize, lhsHashes)
	if err != nil {
		return
	}

	rhsHashes := make([][]byte, len(other.Hashes))
	for i := range other.Hashes {
		rhsHashes[i] = other.Hashes[i][:]
	}
	rhsRange, err := rf.NewRange(cr.CoveredSize, cr.CoveredSize+other.CoveredSize, rhsHashes)
	if err != nil {
		return
	}

	if err := lhsRange.AppendRange(rhsRange, nil); err != nil {
		return
	}

	resHashes := lhsRange.Hashes()
	cr.CoveredSize = lhsRange.End()
	cr.Hashes = make([][sha256.Size]byte, len(resHashes))
	for i, h := range resHashes {
		copy(cr.Hashes[i][:], h)
	}
}

// Root computes the RFC 6962 root hash of the compact range tree.
func (cr *CompactRange) Root() [sha256.Size]byte {
	if cr.CoveredSize == 0 || len(cr.Hashes) == 0 {
		return EmptyRoot()
	}
	ln := len(cr.Hashes)
	root := cr.Hashes[ln-1]
	for i := ln - 2; i >= 0; i-- {
		root = InteriorHash(cr.Hashes[i], root)
	}
	return root
}
