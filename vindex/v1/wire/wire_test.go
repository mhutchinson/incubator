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

package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os/exec"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
)

func TestOutputLogLeafRoundTrip(t *testing.T) {
	mapRoot := sha256.Sum256([]byte("map-root"))
	inRoot := sha256.Sum256([]byte("in-root"))
	rawInCP := []byte("example.com/inputlog\n42\n" + base64.StdEncoding.EncodeToString(inRoot[:]) + "\n\n— example.com/inputlog sig==\n")

	leaf := FormatOutputLogLeaf(mapRoot, rawInCP)
	gotRoot, gotCP, gotRaw, err := ParseOutputLogLeaf(leaf)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}
	if gotRoot != mapRoot {
		t.Errorf("mapRoot = %x, want %x", gotRoot, mapRoot)
	}
	if gotCP.Origin != "example.com/inputlog" || gotCP.Size != 42 || !bytes.Equal(gotCP.Hash, inRoot[:]) {
		t.Errorf("gotCP = %+v", gotCP)
	}
	if !bytes.Equal(gotRaw, rawInCP) {
		t.Errorf("gotRaw = %q, want %q", gotRaw, rawInCP)
	}
}

func TestFormatAndParseSections(t *testing.T) {
	mapRoot := sha256.Sum256([]byte("map-root"))
	subRoot := sha256.Sum256([]byte("sub-root"))
	rawOutCP := []byte("example.com/vindex\n1\n" + base64.StdEncoding.EncodeToString(mapRoot[:]) + "\n")
	rawInCP := []byte("example.com/inputlog\n10\n" + base64.StdEncoding.EncodeToString(mapRoot[:]) + "\n")

	keysBody := FormatKeysResponse(
		rawOutCP,
		0,
		mapRoot,
		rawInCP,
		nil,
		"inclusion",
		[]byte("proof-bytes"),
		[]KeySubRoot{{Key: "com.google.mail.", SubRoot: subRoot}},
	)

	secs, err := ParseSections(keysBody)
	if err != nil {
		t.Fatalf("ParseSections failed: %v", err)
	}
	if secs["mpt-proof-v1"].Arg != "inclusion" {
		t.Errorf("mpt-proof-v1 arg = %q, want inclusion", secs["mpt-proof-v1"].Arg)
	}
	if _, ok := secs["keys-v1"]; !ok {
		t.Error("missing keys-v1 section")
	}

	next := uint64(5)
	entriesBody := FormatEntriesResponse([]uint64{5, 8}, 1, [][32]byte{subRoot}, &next)
	entSecs, err := ParseSections(entriesBody)
	if err != nil {
		t.Fatalf("ParseSections(entries) failed: %v", err)
	}
	if entSecs["prefix-compact-range-v1"].Arg != "1" {
		t.Errorf("prefix-compact-range-v1 arg = %q, want 1", entSecs["prefix-compact-range-v1"].Arg)
	}
	if entSecs["indices-v1"].Arg != "5" {
		t.Errorf("indices-v1 arg = %q, want 5", entSecs["indices-v1"].Arg)
	}
}

func TestLeafAndInteriorHashMatchRFC6962(t *testing.T) {
	for _, sz := range []int{0, 8, 64, 511, 512, 1024} {
		data := bytes.Repeat([]byte{0xAB}, sz)
		got := LeafHash(data)
		want := rfc6962.DefaultHasher.HashLeaf(data)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("LeafHash(len=%d) = %x, want %x", sz, got, want)
		}
	}

	l := sha256.Sum256([]byte("left"))
	r := sha256.Sum256([]byte("right"))
	gotInt := InteriorHash(l, r)
	wantInt := rfc6962.DefaultHasher.HashChildren(l[:], r[:])
	if !bytes.Equal(gotInt[:], wantInt) {
		t.Fatalf("InteriorHash = %x, want %x", gotInt, wantInt)
	}

	var b0, b1 [8]byte
	binary.BigEndian.PutUint64(b0[:], 10)
	binary.BigEndian.PutUint64(b1[:], 20)
	h0 := LeafHash(b0[:])
	root2, err := ComputeMiniLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		t.Fatalf("ComputeMiniLogRoot(2) failed: %v", err)
	}
	rootFromPrefix, err := ComputeMiniLogRoot([][32]byte{h0}, 1, []uint64{20})
	if err != nil {
		t.Fatalf("ComputeMiniLogRoot(prefix+1) failed: %v", err)
	}
	if root2 != rootFromPrefix {
		t.Fatalf("root2 %x != rootFromPrefix %x", root2, rootFromPrefix)
	}
}

func TestPackageDependencyBoundaries(t *testing.T) {
	cases := []struct {
		pkg       string
		forbidden []string
	}{
		{
			pkg: "github.com/transparency-dev/incubator/vindex/v1/client",
			forbidden: []string{
				"github.com/cockroachdb/pebble",
				"github.com/tetratelabs/wazero",
				"github.com/transparency-dev/incubator/vindex/v1/internal/tree",
				"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/v1/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/v1/internal/mtc",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/v1/cmd/vindex-wasm",
			forbidden: []string{
				"net/http",
				"github.com/transparency-dev/tessera",
				"github.com/transparency-dev/incubator/vindex/v1/internal/ingest",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/v1/internal/mtc",
			forbidden: []string{
				"github.com/transparency-dev/incubator/vindex/v1/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/v1/internal/tree",
			},
		},
	}

	for _, tc := range cases {
		out, err := exec.Command("go", "list", "-deps", tc.pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s failed: %v\n%s", tc.pkg, err, string(out))
		}
		deps := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, dep := range deps {
			for _, bad := range tc.forbidden {
				if dep == bad || strings.HasPrefix(dep, bad+"/") {
					t.Errorf("package %s transitively depends on forbidden package %s (via %s)", tc.pkg, bad, dep)
				}
			}
		}
	}
}
