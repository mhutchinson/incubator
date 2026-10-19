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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseOutputLogLeaf_Valid(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("test_mpt_root_123"))
	mapFn := sha256.Sum256([]byte("test_map_fn_123"))
	cpHash := sha256.Sum256([]byte("checkpoint_hash_123"))
	cpHashB64 := base64.StdEncoding.EncodeToString(cpHash[:])

	rawCP := fmt.Sprintf("example.com/log\n42\n%s\n\n— sig1\n— sig2\n", cpHashB64)
	leafData := FormatOutputLogLeafFull(mptRoot, mapFn, 5, []byte(rawCP))

	parsedRoot, inCP, parsedRawCP, err := ParseOutputLogLeaf(leafData)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}

	if parsedRoot != mptRoot {
		t.Fatalf("parsedRoot = %x, want %x", parsedRoot, mptRoot)
	}
	if inCP == nil {
		t.Fatal("inCP is nil")
	}
	if inCP.Origin != "example.com/log" {
		t.Fatalf("inCP.Origin = %q, want %q", inCP.Origin, "example.com/log")
	}
	if inCP.Size != 42 {
		t.Fatalf("inCP.Size = %d, want 42", inCP.Size)
	}
	if !bytes.Equal(inCP.Hash, cpHash[:]) {
		t.Fatalf("inCP.Hash = %x, want %x", inCP.Hash, cpHash[:])
	}
	if !strings.HasSuffix(string(parsedRawCP), "\n") {
		t.Fatalf("parsedRawCP missing trailing newline: %q", string(parsedRawCP))
	}

	full, err := ParseOutputLogLeafFull(leafData)
	if err != nil {
		t.Fatalf("ParseOutputLogLeafFull failed: %v", err)
	}
	if full.MPTRoot != mptRoot || full.MapFn != mapFn || full.From != 5 {
		t.Fatalf("full = %+v", full)
	}
}

func TestParseOutputLogLeaf_Errors(t *testing.T) {
	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validCP := fmt.Sprintf("example.com/log\n100\n%s\n\n— sig\n", validHashB64)
	validHeader := fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root %s\nmap-fn %s\nfrom 0", validHashB64, validHashB64)

	tests := []struct {
		name     string
		leafData []byte
	}{
		{
			name:     "empty_leaf",
			leafData: []byte(""),
		},
		{
			name:     "whitespace_only",
			leafData: []byte("   \n\t  \n"),
		},
		{
			name:     "single_line_no_newline",
			leafData: []byte("c2sp.org/tlog-vindex-state@v1"),
		},
		{
			name:     "missing_blank_line_separator",
			leafData: []byte(validHeader + "\n" + validCP),
		},
		{
			name:     "mpt_root_too_short",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root abcd\nmap-fn %s\nfrom 0\n\n%s", validHashB64, validCP)),
		},
		{
			name:     "map_fn_invalid_base64",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root %s\nmap-fn %s\nfrom 0\n\n%s", validHashB64, strings.Repeat("!", 44), validCP)),
		},
		{
			name:     "from_leading_zero",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root %s\nmap-fn %s\nfrom 01\n\n%s", validHashB64, validHashB64, validCP)),
		},
		{
			name:     "from_exceeds_in_cp_size",
			leafData: []byte(fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root %s\nmap-fn %s\nfrom 101\n\n%s", validHashB64, validHashB64, validCP)),
		},
		{
			name:     "empty_checkpoint",
			leafData: []byte(validHeader + "\n\n"),
		},
		{
			name:     "checkpoint_insufficient_lines",
			leafData: []byte(validHeader + "\n\nexample.com/log\n"),
		},
		{
			name:     "checkpoint_invalid_size",
			leafData: []byte(validHeader + "\n\nexample.com/log\nnot_a_number\n" + validHashB64 + "\n"),
		},
		{
			name:     "checkpoint_invalid_hash",
			leafData: []byte(validHeader + "\n\nexample.com/log\n100\nnot_valid_base64_or_hex!\n"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseOutputLogLeaf(tc.leafData)
			if err == nil {
				t.Fatalf("ParseOutputLogLeaf(%q) succeeded, want error", string(tc.leafData))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("ParseOutputLogLeaf error = %v, want errors.Is(err, ErrOutputLogCorrupted)", err)
			}
		})
	}
}

func TestFormatOutputLogLeaf_Roundtrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		mptRoot := sha256.Sum256([]byte(fmt.Sprintf("mpt_root_iteration_%d", i)))
		cpHash := sha256.Sum256([]byte(fmt.Sprintf("cp_hash_iteration_%d", i)))
		rawCP := fmt.Sprintf("origin.example.com\n%d\n%s\n— signature_%d\n", i*10, base64.StdEncoding.EncodeToString(cpHash[:]), i)

		leaf := FormatOutputLogLeaf(mptRoot, []byte(rawCP))

		parsedRoot, inCP, parsedRawCP, err := ParseOutputLogLeaf(leaf)
		if err != nil {
			t.Fatalf("iteration %d: ParseOutputLogLeaf failed: %v", i, err)
		}
		if parsedRoot != mptRoot {
			t.Fatalf("iteration %d: parsedRoot = %x, want %x", i, parsedRoot, mptRoot)
		}
		if inCP.Size != uint64(i*10) {
			t.Fatalf("iteration %d: inCP.Size = %d, want %d", i, inCP.Size, i*10)
		}
		if inCP.Origin != "origin.example.com" {
			t.Fatalf("iteration %d: inCP.Origin = %q, want %q", i, inCP.Origin, "origin.example.com")
		}

		reformatted := FormatOutputLogLeaf(parsedRoot, parsedRawCP)
		if !bytes.Equal(reformatted, leaf) {
			t.Fatalf("iteration %d: roundtrip leaf mismatch:\ngot:\n%s\nwant:\n%s", i, string(reformatted), string(leaf))
		}
	}
}

func TestFormatOutputLogLeaf_FormattingEdgeCases(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("dummy"))
	var zeroFn [32]byte
	rawCPNoNewline := "origin\n5\n" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	rawCPWithNewlines := rawCPNoNewline + "\n\n\n"

	leaf1 := FormatOutputLogLeaf(mptRoot, []byte(rawCPNoNewline))
	leaf2 := FormatOutputLogLeaf(mptRoot, []byte(rawCPWithNewlines))

	if !bytes.Equal(leaf1, leaf2) {
		t.Fatalf("FormatOutputLogLeaf with/without trailing newline differed:\nleaf1: %q\nleaf2: %q", string(leaf1), string(leaf2))
	}

	expectedPrefix := fmt.Sprintf("c2sp.org/tlog-vindex-state@v1\nmpt-root %s\nmap-fn %s\nfrom 0\n\n%s\n",
		base64.StdEncoding.EncodeToString(mptRoot[:]),
		base64.StdEncoding.EncodeToString(zeroFn[:]),
		rawCPNoNewline)
	if string(leaf1) != expectedPrefix {
		t.Fatalf("unexpected formatted leaf: got %q, want %q", string(leaf1), expectedPrefix)
	}
}
