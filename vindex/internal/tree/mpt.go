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

package tree

import (
	"crypto/sha256"

	torchmpt "filippo.io/torchwood/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
)

const (
	// MaxKeyLen is the maximum length in bytes of a canonical key stored in the MPT.
	MaxKeyLen = mpt.MaxKeyLen
	// MaxValLen is the maximum length in bytes of a value stored in the MPT.
	MaxValLen = mpt.MaxValLen
)

var (
	// ErrKeySize is returned when an MPT key is empty or exceeds MaxKeyLen (1024 bytes).
	ErrKeySize = mpt.ErrKeySize
	// ErrValSize is returned when an MPT value exceeds MaxValLen (1024 bytes).
	ErrValSize = mpt.ErrValSize
	// ErrInvalidCanonicalKey is returned when a canonical key is outside 1..1024 printable ASCII bytes (0x21..0x7E).
	ErrInvalidCanonicalKey = mpt.ErrInvalidCanonicalKey
	// ErrPrefixTooManyKeys is returned when a prefix scan exceeds the configured maximum key cardinality.
	ErrPrefixTooManyKeys = mpt.ErrPrefixTooManyKeys
)

// PrefixKeyVal represents a canonical key and its 32-byte mini-log sub-root yielded by a prefix scan.
type PrefixKeyVal = mpt.PrefixKeyVal

// Manager manages a Merkle Patricia Trie with thread-safe read access and lock-free root prediction.
type Manager = mpt.Manager

// ValidateCanonicalKey checks that key is between 1 and 1024 printable ASCII bytes (0x21..0x7E),
// containing no NUL (0x00) bytes or ASCII whitespace.
func ValidateCanonicalKey(key []byte) error {
	return mpt.ValidateCanonicalKey(key)
}

// Open opens an existing MPT in the specified directory or creates a new one.
// If mmapDir is empty or ":memory:", an in-memory tree is used.
func Open(mmapDir string) (*Manager, error) {
	return mpt.Open(mmapDir)
}

// NewMem creates a new in-memory MPT manager.
func NewMem() *Manager {
	return mpt.NewMem()
}

// NewManager opens an existing MPT in the specified directory or creates a new one (alias for Open).
func NewManager(mmapDir string) (*Manager, error) {
	return mpt.NewManager(mmapDir)
}

// SortKeyVals sorts changes by Key using parallel bucket sort across CPU cores when size is large.
func SortKeyVals(changes []torchmpt.KeyVal) {
	mpt.SortKeyVals(changes)
}

// VerifyKey verifies an inclusion or non-inclusion proof for a variable-length key against an MPT root hash.
func VerifyKey(root [sha256.Size]byte, key []byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	return mpt.VerifyKey(root, key, valHash, exists, proof)
}

// Verify verifies an inclusion or non-inclusion proof for a 32-byte keyHash (encoded as 64-byte lowercase hex) against an MPT root hash.
func Verify(root [sha256.Size]byte, keyHash [sha256.Size]byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	return mpt.Verify(root, keyHash, valHash, exists, proof)
}

// VerifyPrefix verifies a prefix subtree proof and the completeness/soundness of matches against an MPT root hash.
func VerifyPrefix(root [sha256.Size]byte, prefix []byte, matches []PrefixKeyVal, proof []byte) error {
	return mpt.VerifyPrefix(root, prefix, matches, proof)
}
