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
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

// EncodeChunkPrefix formats the 33-byte prefix for a key hash ('c' + KeyHash).
func EncodeChunkPrefix(keyHash [sha256.Size]byte) []byte {
	buf := make([]byte, 33)
	buf[0] = PrefixChunkByte
	copy(buf[1:33], keyHash[:])
	return buf
}

// EncodeChunkKey formats the 41-byte inverted chunk key ('c' + KeyHash + ^BigEndian(chunkNum)).
func EncodeChunkKey(keyHash [sha256.Size]byte, chunkNum uint64) []byte {
	buf := make([]byte, 41)
	buf[0] = PrefixChunkByte
	copy(buf[1:33], keyHash[:])
	invChunkNum := math.MaxUint64 - chunkNum // ^chunkNum
	binary.BigEndian.PutUint64(buf[33:41], invChunkNum)
	return buf
}

// DecodeChunkKey parses a 41-byte chunk key into key hash and original chunkNum.
func DecodeChunkKey(key []byte) (keyHash [sha256.Size]byte, chunkNum uint64, err error) {
	if len(key) != 41 || key[0] != PrefixChunkByte {
		return [sha256.Size]byte{}, 0, fmt.Errorf("%w: expected 41 bytes starting with 'c', got %d bytes", ErrInvalidChunkKey, len(key))
	}
	copy(keyHash[:], key[1:33])
	invChunkNum := binary.BigEndian.Uint64(key[33:41])
	chunkNum = math.MaxUint64 - invChunkNum // ^invChunkNum
	return keyHash, chunkNum, nil
}

// MarshalChunkValue serializes a ChunkRecord into uniform delimitless binary format.
func MarshalChunkValue(rec *ChunkRecord) []byte {
	if rec == nil {
		return nil
	}
	numHashes := len(rec.CompactHashes)
	numIndices := len(rec.RelativeIndices)
	buf := make([]byte, 8+32*numHashes+2*numIndices)
	binary.BigEndian.PutUint64(buf[0:8], rec.CoveredSize)
	offset := 8
	for _, h := range rec.CompactHashes {
		copy(buf[offset:offset+32], h[:])
		offset += 32
	}
	for _, idx := range rec.RelativeIndices {
		binary.BigEndian.PutUint16(buf[offset:offset+2], idx)
		offset += 2
	}
	return buf
}

// UnmarshalChunkValue deserializes a ChunkRecord from uniform delimitless binary format.
func UnmarshalChunkValue(data []byte) (*ChunkRecord, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: chunk value too short (%d bytes)", ErrInvalidValue, len(data))
	}
	coveredSize := binary.BigEndian.Uint64(data[0:8])
	numHashes := bits.OnesCount64(coveredSize)
	hashesEnd := 8 + 32*numHashes
	if len(data) < hashesEnd {
		return nil, fmt.Errorf("%w: chunk value truncated for compact hashes (expected at least %d bytes, got %d)", ErrInvalidValue, hashesEnd, len(data))
	}
	rem := len(data) - hashesEnd
	if rem%2 != 0 {
		return nil, fmt.Errorf("%w: chunk value invalid relative indices length (%d bytes)", ErrInvalidValue, rem)
	}
	numIndices := rem / 2

	var hashes [][sha256.Size]byte
	if numHashes > 0 {
		hashes = make([][sha256.Size]byte, numHashes)
		offset := 8
		for i := 0; i < numHashes; i++ {
			copy(hashes[i][:], data[offset:offset+32])
			offset += 32
		}
	}

	var indices []uint16
	if numIndices > 0 {
		indices = make([]uint16, numIndices)
		offset := 8 + 32*numHashes
		for i := 0; i < numIndices; i++ {
			indices[i] = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
		}
	}

	return &ChunkRecord{
		CoveredSize:     coveredSize,
		CompactHashes:   hashes,
		RelativeIndices: indices,
	}, nil
}
