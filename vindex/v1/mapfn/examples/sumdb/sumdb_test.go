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

package main

import (
	"crypto/sha256"
	"testing"
)

func TestMapSumDBLeaf_StandardRelease(t *testing.T) {
	leaf := []byte("golang.org/x/mod v0.40.0 h1:testHash123=\ngolang.org/x/mod v0.40.0/go.mod h1:testHash456=\n")
	hashes := MapSumDBLeaf(leaf)

	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}

	expected := sha256.Sum256([]byte("golang.org/x/mod"))
	if hashes[0] != expected {
		t.Fatalf("hash mismatch: got %x, want %x", hashes[0], expected)
	}
}

func TestMapSumDBLeaf_PseudoVersionFiltered(t *testing.T) {
	leaf := []byte("github.com/example/repo v0.0.0-20230101000000-0123456789ab h1:testHash=\n")
	hashes := MapSumDBLeaf(leaf)

	if len(hashes) != 0 {
		t.Fatalf("expected 0 hashes for pseudo-version, got %d", len(hashes))
	}
}

func TestMapSumDBLeaf_MultipleModulesInSingleLeaf(t *testing.T) {
	leaf := []byte("github.com/mod1 v1.0.0 h1:h1=\ngithub.com/mod2 v2.1.0 h1:h2=\n")
	hashes := MapSumDBLeaf(leaf)

	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}

	h1 := sha256.Sum256([]byte("github.com/mod1"))
	h2 := sha256.Sum256([]byte("github.com/mod2"))

	if hashes[0] != h1 || hashes[1] != h2 {
		t.Fatalf("hashes mismatch")
	}
}

func TestMapSumDBLeaf_EmptyOrMalformed(t *testing.T) {
	testCases := [][]byte{
		nil,
		[]byte(""),
		[]byte("   \n\n  "),
		[]byte("invalidline_without_spaces"),
	}

	for _, tc := range testCases {
		res := MapSumDBLeaf(tc)
		if len(res) != 0 {
			t.Fatalf("expected 0 results for input %q, got %d", string(tc), len(res))
		}
	}
}

func BenchmarkMapSumDBLeaf(b *testing.B) {
	leaf := []byte("golang.org/x/mod v0.40.0 h1:testHash123=\ngolang.org/x/mod v0.40.0/go.mod h1:testHash456=\n")
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = MapSumDBLeaf(leaf)
	}
}
