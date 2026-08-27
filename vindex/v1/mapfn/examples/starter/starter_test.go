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

func TestMapLeaf(t *testing.T) {
	input := []byte("sample leaf entry")
	hashes := MapLeaf(input)
	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}
	expected := sha256.Sum256(input)
	if hashes[0] != expected {
		t.Fatalf("expected hash %x, got %x", expected, hashes[0])
	}
}

func TestMapLeaf_Empty(t *testing.T) {
	if res := MapLeaf(nil); len(res) != 0 {
		t.Fatalf("expected empty result for nil input, got %d", len(res))
	}
	if res := MapLeaf([]byte("   \n\t  ")); len(res) != 0 {
		t.Fatalf("expected empty result for whitespace input, got %d", len(res))
	}
}
