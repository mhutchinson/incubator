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
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseOutputLogLeaf_Valid(t *testing.T) {
	mapRoot := sha256.Sum256([]byte("test_map_root_123"))
	rootHex := hex.EncodeToString(mapRoot[:])
	cpHash := sha256.Sum256([]byte("checkpoint_hash_123"))
	cpHashB64 := base64.StdEncoding.EncodeToString(cpHash[:])

	rawCP := fmt.Sprintf("example.com/log\n42\n%s\n— sig1\n— sig2\n", cpHashB64)
	leafData := []byte(rootHex + "\n" + rawCP)

	parsedRoot, inCP, parsedRawCP, err := ParseOutputLogLeaf(leafData)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}

	if parsedRoot != mapRoot {
		t.Fatalf("parsedRoot = %x, want %x", parsedRoot, mapRoot)
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
}

func TestParseOutputLogLeaf_Errors(t *testing.T) {
	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validCP := fmt.Sprintf("example.com/log\n100\n%s\n", validHashB64)
	validHexRoot := hex.EncodeToString(make([]byte, 32))

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
			leafData: []byte(validHexRoot),
		},
		{
			name:     "single_line_with_newline",
			leafData: []byte(validHexRoot + "\n"),
		},
		{
			name:     "hex_too_short",
			leafData: []byte("abcd1234\n" + validCP),
		},
		{
			name:     "hex_too_long",
			leafData: []byte(validHexRoot + "00\n" + validCP),
		},
		{
			name:     "hex_invalid_characters",
			leafData: []byte(strings.Repeat("z", 64) + "\n" + validCP),
		},
		{
			name:     "empty_checkpoint",
			leafData: []byte(validHexRoot + "\n\n"),
		},
		{
			name:     "checkpoint_insufficient_lines",
			leafData: []byte(validHexRoot + "\nexample.com/log\n"),
		},
		{
			name:     "checkpoint_invalid_size",
			leafData: []byte(validHexRoot + "\nexample.com/log\nnot_a_number\n" + validHashB64 + "\n"),
		},
		{
			name:     "checkpoint_invalid_hash",
			leafData: []byte(validHexRoot + "\nexample.com/log\n100\nnot_valid_base64_or_hex!\n"),
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
		mapRoot := sha256.Sum256([]byte(fmt.Sprintf("map_root_iteration_%d", i)))
		cpHash := sha256.Sum256([]byte(fmt.Sprintf("cp_hash_iteration_%d", i)))
		rawCP := fmt.Sprintf("origin.example.com\n%d\n%s\n— signature_%d\n", i*10, base64.StdEncoding.EncodeToString(cpHash[:]), i)

		leaf := FormatOutputLogLeaf(mapRoot, []byte(rawCP))

		parsedRoot, inCP, parsedRawCP, err := ParseOutputLogLeaf(leaf)
		if err != nil {
			t.Fatalf("iteration %d: ParseOutputLogLeaf failed: %v", i, err)
		}
		if parsedRoot != mapRoot {
			t.Fatalf("iteration %d: parsedRoot = %x, want %x", i, parsedRoot, mapRoot)
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
	mapRoot := sha256.Sum256([]byte("dummy"))
	rawCPNoNewline := "origin\n5\n" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	rawCPWithNewlines := rawCPNoNewline + "\n\n\n"

	leaf1 := FormatOutputLogLeaf(mapRoot, []byte(rawCPNoNewline))
	leaf2 := FormatOutputLogLeaf(mapRoot, []byte(rawCPWithNewlines))

	if !bytes.Equal(leaf1, leaf2) {
		t.Fatalf("FormatOutputLogLeaf with/without trailing newline differed:\nleaf1: %q\nleaf2: %q", string(leaf1), string(leaf2))
	}

	expectedPrefix := hex.EncodeToString(mapRoot[:]) + "\n" + rawCPNoNewline + "\n"
	if string(leaf1) != expectedPrefix {
		t.Fatalf("unexpected formatted leaf: got %q, want %q", string(leaf1), expectedPrefix)
	}
}
