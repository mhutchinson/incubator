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
	"testing"
)

func TestMapSumDBLeaf_StandardRelease(t *testing.T) {
	leaf := []byte("golang.org/x/mod v0.40.0 h1:testHash123=\ngolang.org/x/mod v0.40.0/go.mod h1:testHash456=\n")
	keys := MapSumDBLeaf(leaf)

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if string(keys[0]) != "golang.org/x/mod" {
		t.Fatalf("key mismatch: got %q, want %q", string(keys[0]), "golang.org/x/mod")
	}
}

func TestMapSumDBLeaf_PseudoVersionFiltered(t *testing.T) {
	leaf := []byte("github.com/example/repo v0.0.0-20230101000000-0123456789ab h1:testHash=\n")
	keys := MapSumDBLeaf(leaf)

	if len(keys) != 0 {
		t.Fatalf("expected 0 keys for pseudo-version, got %d", len(keys))
	}
}

func TestMapSumDBLeaf_MultipleModulesInSingleLeaf(t *testing.T) {
	leaf := []byte("github.com/mod1 v1.0.0 h1:h1=\ngithub.com/mod2 v2.1.0 h1:h2=\n")
	keys := MapSumDBLeaf(leaf)

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if string(keys[0]) != "github.com/mod1" || string(keys[1]) != "github.com/mod2" {
		t.Fatalf("keys mismatch: got %q, %q", string(keys[0]), string(keys[1]))
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

func TestIsPseudoVersion_Parity(t *testing.T) {
	testVersions := []struct {
		v    string
		want bool
	}{
		// Valid pseudo-versions
		{"v0.0.0-20190528180746-1234567890ab", true},
		{"v1.2.4-0.20190528180746-1234567890ab", true},
		{"v1.2.4-0.20190528180746-1234567890ab+incompatible", true},
		{"v1.2.3-pre.0.20190528180746-1234567890ab", true},
		{"v1.2.3-alpha.beta.0.20190528180746-1234567890ab", true},
		{"v1.2.3-alpha.beta.0.20190528180746-1234567890ab+build.1", true},
		{"v2.0.0-0.20200101120000-abcdef123456", true},

		// Standard releases / Non-pseudo
		{"v1.0.0", false},
		{"v0.40.0", false},
		{"v1.2.3-alpha", false},
		{"v1.2.3-alpha.1", false},
		{"v1.2.3-rc1", false},
		{"v1.2.3+build", false},
		{"", false},
		{"invalid", false},
		{"v0.0.0-2019052818074-1234567890ab", false},  // 13 digits
		{"v0.0.0-201905281807460-1234567890ab", false}, // 15 digits
		{"v1.2.3-20190528180746-1234567890ab", false},  // Missing .0 for non-v0.0.0
	}

	for _, tc := range testVersions {
		got := isPseudoVersion([]byte(tc.v))
		if got != tc.want {
			t.Errorf("isPseudoVersion(%q) = %v, want %v", tc.v, got, tc.want)
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

