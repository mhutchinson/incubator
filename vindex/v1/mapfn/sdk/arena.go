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

package sdk

import (
	"crypto/sha256"
	"encoding/binary"
	"unsafe"
)

const (
	// MaxBufferSize is the 1MB static arena buffer size.
	MaxBufferSize = 1024 * 1024
)

var (
	inputBuf    [MaxBufferSize]byte
	outputBuf   [MaxBufferSize]byte
	allocOffset uint32
)

// Allocate allocates a slice of size bytes from the static input arena.
// Returns a 32-bit WASM memory address, or 0 if allocation exceeds capacity.
func Allocate(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	if allocOffset+size > MaxBufferSize {
		return 0
	}
	ptr := uint32(uintptr(unsafe.Pointer(&inputBuf[allocOffset])))
	allocOffset += size
	return ptr
}

// GetInputSlice returns a byte slice corresponding to the allocated memory region.
func GetInputSlice(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	base := uint32(uintptr(unsafe.Pointer(&inputBuf[0])))
	if ptr >= base && ptr+length <= base+MaxBufferSize {
		offset := ptr - base
		return inputBuf[offset : offset+length]
	}
	// Fallback when accessed outside static arena
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
}

// Reset clears the bump allocator offset for the next execution.
func Reset() {
	allocOffset = 0
}

// EncodeRaw encodes raw 32-byte hashes into the output arena and returns (ptr, len).
func EncodeRaw(hashes [][sha256.Size]byte) (uint32, uint32) {
	totalLen := uint32(len(hashes) * sha256.Size)
	if totalLen == 0 {
		return 0, 0
	}
	if totalLen > MaxBufferSize {
		return 0, 0
	}
	for i, h := range hashes {
		copy(outputBuf[i*sha256.Size:(i+1)*sha256.Size], h[:])
	}
	ptr := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	return ptr, totalLen
}

// EncodeStructured encodes structured entries into the output arena and returns (ptr, len).
// Format: [Count(4B)][Entry: KeyHash(32B) + ValLen(2B) + Val]...
func EncodeStructured(entries []Entry) (uint32, uint32) {
	if len(entries) == 0 {
		return 0, 0
	}
	totalLen := 4
	for _, e := range entries {
		if len(e.Value) > 0xFFFF {
			return 0, 0
		}
		totalLen += sha256.Size + 2 + len(e.Value)
	}
	if totalLen > MaxBufferSize {
		return 0, 0
	}
	binary.BigEndian.PutUint32(outputBuf[0:4], uint32(len(entries)))
	offset := 4
	for _, e := range entries {
		copy(outputBuf[offset:offset+sha256.Size], e.KeyHash[:])
		offset += sha256.Size
		binary.BigEndian.PutUint16(outputBuf[offset:offset+2], uint16(len(e.Value)))
		offset += 2
		if len(e.Value) > 0 {
			copy(outputBuf[offset:offset+len(e.Value)], e.Value)
			offset += len(e.Value)
		}
	}
	ptr := uint32(uintptr(unsafe.Pointer(&outputBuf[0])))
	return ptr, uint32(totalLen)
}
