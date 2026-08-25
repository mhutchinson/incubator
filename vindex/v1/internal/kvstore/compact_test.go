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
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRFC6962TestVectors(t *testing.T) {
	emptyRoot := EmptyRoot()
	wantEmptyHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(emptyRoot[:]) != wantEmptyHex {
		t.Fatalf("empty root got %x, want %s", emptyRoot, wantEmptyHex)
	}

	leaf0 := []byte("")
	h0 := LeafHash(leaf0)
	wantH0Hex := "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
	if hex.EncodeToString(h0[:]) != wantH0Hex {
		t.Fatalf("leaf0 hash got %x, want %s", h0, wantH0Hex)
	}
}

func TestCompactRange_IncrementalMatchesBatch(t *testing.T) {
	for size := 0; size <= 257; size++ {
		var leaves [][]byte
		cr := NewCompactRange()
		for i := 0; i < size; i++ {
			leaf := []byte(fmt.Sprintf("entry_%d", i))
			leaves = append(leaves, leaf)
			cr.Append(LeafHash(leaf))
		}

		expectedRoot := BatchRoot(leaves)
		crRoot := cr.Root()

		if crRoot != expectedRoot {
			t.Fatalf("size %d root mismatch: compact=%x, batch=%x", size, crRoot, expectedRoot)
		}
		if cr.CoveredSize != uint64(size) {
			t.Fatalf("size %d covered size mismatch: got %d", size, cr.CoveredSize)
		}
	}
}

func TestCompactRange_AppendRange(t *testing.T) {
	testSplits := [][2]int{
		{0, 0},
		{0, 5},
		{5, 0},
		{1, 1},
		{2, 2},
		{4, 4},
		{8, 8},
		{16, 16},
		{64, 64},
		{128, 64},
		{256, 128},
	}

	for _, split := range testSplits {
		n1, n2 := split[0], split[1]
		t.Run(fmt.Sprintf("split_%d_%d", n1, n2), func(t *testing.T) {
			var allLeaves [][]byte
			cr1 := NewCompactRange()
			for i := 0; i < n1; i++ {
				l := []byte(fmt.Sprintf("leaf_%d", i))
				allLeaves = append(allLeaves, l)
				cr1.Append(LeafHash(l))
			}

			cr2 := NewCompactRange()
			for i := 0; i < n2; i++ {
				l := []byte(fmt.Sprintf("leaf_%d", n1+i))
				allLeaves = append(allLeaves, l)
				cr2.Append(LeafHash(l))
			}

			cr1.AppendRange(*cr2)

			expectedRoot := BatchRoot(allLeaves)
			gotRoot := cr1.Root()

			if gotRoot != expectedRoot {
				t.Fatalf("AppendRange (%d+%d) root mismatch: got %x, want %x", n1, n2, gotRoot, expectedRoot)
			}
			if cr1.CoveredSize != uint64(n1+n2) {
				t.Fatalf("AppendRange (%d+%d) covered size mismatch: got %d, want %d", n1, n2, cr1.CoveredSize, n1+n2)
			}
		})
	}
}
