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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestArena_AllocateAndReset(t *testing.T) {
	Reset()

	ptr1 := Allocate(100)
	if ptr1 == 0 {
		t.Fatal("expected non-zero pointer for 100 bytes allocation")
	}

	ptr2 := Allocate(200)
	if ptr2 == 0 {
		t.Fatal("expected non-zero pointer for 200 bytes allocation")
	}
	if ptr2 != ptr1+100 {
		t.Fatalf("expected bump allocation: ptr2=%d, want %d", ptr2, ptr1+100)
	}

	// Test writing and reading via GetInputSlice
	slice := GetInputSlice(ptr1, 100)
	for i := range slice {
		slice[i] = byte(i)
	}
	readSlice := GetInputSlice(ptr1, 100)
	for i := range readSlice {
		if readSlice[i] != byte(i) {
			t.Fatalf("mismatch at byte %d: got %d, want %d", i, readSlice[i], byte(i))
		}
	}

	Reset()
	ptrAfterReset := Allocate(50)
	if ptrAfterReset != ptr1 {
		t.Fatalf("expected reset to return to base ptr %d, got %d", ptr1, ptrAfterReset)
	}
}

func TestArena_AllocateOverflow(t *testing.T) {
	Reset()

	ptr := Allocate(MaxBufferSize + 1)
	if ptr != 0 {
		t.Fatalf("expected 0 for oversized allocation, got %d", ptr)
	}

	// Allocate entire buffer
	ptr = Allocate(MaxBufferSize)
	if ptr == 0 {
		t.Fatal("expected successful full buffer allocation")
	}

	// Subsequent allocation must fail
	ptrExtra := Allocate(1)
	if ptrExtra != 0 {
		t.Fatalf("expected 0 after full buffer allocated, got %d", ptrExtra)
	}
	Reset()
}

func TestEncodeRaw(t *testing.T) {
	Reset()

	h1 := sha256.Sum256([]byte("key1"))
	h2 := sha256.Sum256([]byte("key2"))

	ptr, length := EncodeRaw([][sha256.Size]byte{h1, h2})
	if ptr == 0 || length != 64 {
		t.Fatalf("unexpected EncodeRaw result: ptr=%d, length=%d", ptr, length)
	}

	expected := append(h1[:], h2[:]...)
	actual := outputBuf[:length]
	if !bytes.Equal(actual, expected) {
		t.Fatalf("raw bytes mismatch:\ngot  %x\nwant %x", actual, expected)
	}
}

func TestEncodeStructured(t *testing.T) {
	Reset()

	h1 := sha256.Sum256([]byte("key1"))
	val1 := []byte("val1")
	h2 := sha256.Sum256([]byte("key2"))
	val2 := []byte("val2_longer_string")

	entries := []Entry{
		{KeyHash: h1, Value: val1},
		{KeyHash: h2, Value: val2},
	}

	ptr, length := EncodeStructured(entries)
	if ptr == 0 {
		t.Fatal("expected valid ptr from EncodeStructured")
	}

	data := outputBuf[:length]
	if len(data) < 4 {
		t.Fatalf("data too short: %d", len(data))
	}
	count := binary.BigEndian.Uint32(data[0:4])
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}

	offset := 4
	// Entry 1
	var gotH1 [32]byte
	copy(gotH1[:], data[offset:offset+32])
	if gotH1 != h1 {
		t.Fatalf("entry 1 hash mismatch")
	}
	offset += 32
	vlen1 := binary.BigEndian.Uint16(data[offset : offset+2])
	if int(vlen1) != len(val1) {
		t.Fatalf("entry 1 value len mismatch")
	}
	offset += 2
	if !bytes.Equal(data[offset:offset+int(vlen1)], val1) {
		t.Fatalf("entry 1 value mismatch")
	}
	offset += int(vlen1)

	// Entry 2
	var gotH2 [32]byte
	copy(gotH2[:], data[offset:offset+32])
	if gotH2 != h2 {
		t.Fatalf("entry 2 hash mismatch")
	}
	offset += 32
	vlen2 := binary.BigEndian.Uint16(data[offset : offset+2])
	if int(vlen2) != len(val2) {
		t.Fatalf("entry 2 value len mismatch")
	}
	offset += 2
	if !bytes.Equal(data[offset:offset+int(vlen2)], val2) {
		t.Fatalf("entry 2 value mismatch")
	}
	offset += int(vlen2)

	if offset != int(length) {
		t.Fatalf("offset %d != length %d", offset, length)
	}
}

func TestRegisterAndExecuteMap(t *testing.T) {
	Reset()

	h := sha256.Sum256([]byte("sdk_test"))
	Register(func(leaf []byte) []Entry {
		return []Entry{{KeyHash: h, Value: leaf}}
	})

	ptr, length := ExecuteMap([]byte("hello"))
	if ptr == 0 || length == 0 {
		t.Fatalf("ExecuteMap failed: ptr=%d len=%d", ptr, length)
	}

	packed := mapLeaf(0, 0)
	if packed == 0 {
		t.Fatalf("mapLeaf failed, got packed 0")
	}

	reset()
	if allocOffset != 0 {
		t.Fatalf("reset failed, allocOffset is %d", allocOffset)
	}
}
