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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"
)

// TestParseOutputLogLeaf_StressEdgeCases exercises boundary conditions, malformed inputs,
// whitespace variations, invalid hex lengths, embedded nulls, and uppercase vs lowercase hex.
func TestParseOutputLogLeaf_StressEdgeCases(t *testing.T) {
	validMapRoot := sha256.Sum256([]byte("stress_test_root"))
	lowerHexRoot := hex.EncodeToString(validMapRoot[:])
	upperHexRoot := strings.ToUpper(lowerHexRoot)
	mixedHexRoot := ""
	for i, c := range lowerHexRoot {
		if i%2 == 0 {
			mixedHexRoot += strings.ToUpper(string(c))
		} else {
			mixedHexRoot += string(c)
		}
	}

	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validHashHex := hex.EncodeToString(make([]byte, 32))
	validCP := fmt.Sprintf("example.com/log\n12345\n%s\n— sig1\n", validHashB64)

	t.Run("nil_and_empty", func(t *testing.T) {
		inputs := [][]byte{
			nil,
			{},
			[]byte(""),
		}
		for i, in := range inputs {
			_, _, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for nil/empty input, got nil", i)
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("whitespace_variations", func(t *testing.T) {
		corruptedWhitespace := [][]byte{
			[]byte(" "),
			[]byte("   "),
			[]byte("\t\t"),
			[]byte("\n"),
			[]byte("\r\n"),
			[]byte("\n\n\n"),
			[]byte("  \t \r\n \n \t  "),
			// Hex followed by only spaces/tabs/newlines
			[]byte(lowerHexRoot + "   "),
			[]byte(lowerHexRoot + "\t"),
			[]byte(lowerHexRoot + "\n\n\n"),
			[]byte(lowerHexRoot + "\r\n"),
			[]byte(lowerHexRoot + "\n   \t  \n"),
		}
		for i, in := range corruptedWhitespace {
			_, _, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for whitespace-only checkpoint %q, got nil", i, string(in))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("single_line_malformed", func(t *testing.T) {
		singleLines := [][]byte{
			[]byte("not_even_hex"),
			[]byte("deadbeef"),
			[]byte(lowerHexRoot),
			[]byte(upperHexRoot),
			[]byte("a" + lowerHexRoot),
		}
		for i, in := range singleLines {
			_, _, _, err := ParseOutputLogLeaf(in)
			if err == nil {
				t.Fatalf("[%d] expected error for single line input %q, got nil", i, string(in))
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("[%d] expected ErrOutputLogCorrupted, got %v", i, err)
			}
		}
	})

	t.Run("hex_length_and_format_variations", func(t *testing.T) {
		invalidHexRoots := []string{
			"",                                   // length 0
			"a",                                  // length 1 (odd)
			"ab",                                 // length 2
			"deadbeef",                           // length 8
			strings.Repeat("a", 63),              // length 63 (odd)
			strings.Repeat("a", 65),              // length 65 (odd)
			strings.Repeat("b", 128),             // length 128
			strings.Repeat("g", 64),              // length 64 invalid chars
			strings.Repeat("z", 64),              // length 64 invalid chars
			lowerHexRoot[:32] + " " + lowerHexRoot[33:], // internal space
			lowerHexRoot[:32] + "\t" + lowerHexRoot[33:], // internal tab
			lowerHexRoot[:32] + "\x00" + lowerHexRoot[33:], // embedded null
		}
		for _, badHex := range invalidHexRoots {
			leaf := []byte(badHex + "\n" + validCP)
			_, _, _, err := ParseOutputLogLeaf(leaf)
			if err == nil {
				t.Fatalf("expected error for bad hex %q, got nil", badHex)
			}
			if !errors.Is(err, ErrOutputLogCorrupted) {
				t.Fatalf("expected ErrOutputLogCorrupted for bad hex %q, got %v", badHex, err)
			}
		}
	})

	t.Run("uppercase_and_mixed_case_hex", func(t *testing.T) {
		// Uppercase hex should parse successfully to the exact same 32-byte root
		parsedRoot, inCP, rawCP, err := ParseOutputLogLeaf([]byte(upperHexRoot + "\n" + validCP))
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for uppercase hex: %v", err)
		}
		if parsedRoot != validMapRoot {
			t.Fatalf("parsedRoot mismatch for upperHex: got %x, want %x", parsedRoot, validMapRoot)
		}
		if inCP.Size != 12345 {
			t.Fatalf("inCP.Size mismatch: got %d, want 12345", inCP.Size)
		}

		// Mixed-case hex
		parsedRootMixed, _, _, err := ParseOutputLogLeaf([]byte(mixedHexRoot + "\n" + validCP))
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for mixed-case hex: %v", err)
		}
		if parsedRootMixed != validMapRoot {
			t.Fatalf("parsedRoot mismatch for mixedHex: got %x, want %x", parsedRootMixed, validMapRoot)
		}

		// Verify re-formatting outputs lowercase canonical hex
		reformatted := FormatOutputLogLeaf(parsedRoot, rawCP)
		expectedPrefix := lowerHexRoot + "\n"
		if !strings.HasPrefix(string(reformatted), expectedPrefix) {
			t.Fatalf("reformatted leaf does not have canonical lowercase prefix: got %q, want prefix %q", string(reformatted)[:65], expectedPrefix)
		}
	})

	t.Run("embedded_nulls", func(t *testing.T) {
		// Null in hex line
		nullInHex := []byte(lowerHexRoot[:10] + "\x00" + lowerHexRoot[11:] + "\n" + validCP)
		if _, _, _, err := ParseOutputLogLeaf(nullInHex); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in hex line, got %v", err)
		}

		// Null in size line of checkpoint
		nullInSize := []byte(lowerHexRoot + "\nexample.com/log\n12\x0034\n" + validHashB64 + "\n")
		if _, _, _, err := ParseOutputLogLeaf(nullInSize); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in checkpoint size, got %v", err)
		}

		// Null in hash line of checkpoint
		nullInHash := []byte(lowerHexRoot + "\nexample.com/log\n1234\n" + validHashB64[:10] + "\x00" + validHashB64[11:] + "\n")
		if _, _, _, err := ParseOutputLogLeaf(nullInHash); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for null in checkpoint hash, got %v", err)
		}

		// Null in signature line of checkpoint: note headers (lines 0-2) are valid,
		// signatures are preserved raw in rawInCP.
		nullInSig := []byte(lowerHexRoot + "\nexample.com/log\n1234\n" + validHashB64 + "\n— sig\x00extra\n")
		_, inCP, rawInCP, err := ParseOutputLogLeaf(nullInSig)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed on raw signature containing null byte: %v", err)
		}
		if inCP.Size != 1234 {
			t.Fatalf("inCP.Size = %d, want 1234", inCP.Size)
		}
		if !bytes.Contains(rawInCP, []byte("\x00extra")) {
			t.Fatalf("rawInCP did not preserve raw signature bytes with null byte: %q", string(rawInCP))
		}
	})

	t.Run("checkpoint_size_boundaries", func(t *testing.T) {
		// Size = 0 (valid for empty tree)
		leafZero := []byte(fmt.Sprintf("%s\nexample.com/log\n0\n%s\n", lowerHexRoot, validHashB64))
		_, cpZero, _, err := ParseOutputLogLeaf(leafZero)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for size 0: %v", err)
		}
		if cpZero.Size != 0 {
			t.Fatalf("cpZero.Size = %d, want 0", cpZero.Size)
		}

		// Size = MaxUint64 (18446744073709551615)
		leafMax := []byte(fmt.Sprintf("%s\nexample.com/log\n%d\n%s\n", lowerHexRoot, uint64(math.MaxUint64), validHashB64))
		_, cpMax, _, err := ParseOutputLogLeaf(leafMax)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for size MaxUint64: %v", err)
		}
		if cpMax.Size != math.MaxUint64 {
			t.Fatalf("cpMax.Size = %d, want %d", cpMax.Size, uint64(math.MaxUint64))
		}

		// Size = MaxUint64 + 1 (overflow)
		leafOverflow := []byte(fmt.Sprintf("%s\nexample.com/log\n18446744073709551616\n%s\n", lowerHexRoot, validHashB64))
		if _, _, _, err := ParseOutputLogLeaf(leafOverflow); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for uint64 overflow, got %v", err)
		}

		// Size = negative (-1)
		leafNeg := []byte(fmt.Sprintf("%s\nexample.com/log\n-1\n%s\n", lowerHexRoot, validHashB64))
		if _, _, _, err := ParseOutputLogLeaf(leafNeg); err == nil || !errors.Is(err, ErrOutputLogCorrupted) {
			t.Fatalf("expected ErrOutputLogCorrupted for negative size, got %v", err)
		}
	})

	t.Run("checkpoint_hash_encodings", func(t *testing.T) {
		// Standard 32-byte base64 hash
		leafB64 := []byte(fmt.Sprintf("%s\nexample.com/log\n100\n%s\n", lowerHexRoot, validHashB64))
		_, cpB64, _, err := ParseOutputLogLeaf(leafB64)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for base64 hash: %v", err)
		}
		if len(cpB64.Hash) != 32 {
			t.Fatalf("cpB64.Hash len = %d, want 32", len(cpB64.Hash))
		}

		// Anomaly/Edge Case Finding: 64-char hex string as checkpoint hash.
		// Because 64 hex characters [0-9a-f] are also valid base64 symbols,
		// ParseCheckpointHeader's base64.DecodeString decodes them into 48 bytes
		// instead of falling through to hex.DecodeString (32 bytes).
		// Furthermore, ParseCheckpointHeader does not validate len(hashBytes) == 32.
		leafHex := []byte(fmt.Sprintf("%s\nexample.com/log\n100\n%s\n", lowerHexRoot, validHashHex))
		_, cpHex, _, err := ParseOutputLogLeaf(leafHex)
		if err != nil {
			t.Fatalf("ParseOutputLogLeaf failed for hex hash: %v", err)
		}
		if len(cpHex.Hash) != 48 {
			t.Fatalf("cpHex.Hash len = %d, expected 48 due to base64 interpretation of 64 hex chars", len(cpHex.Hash))
		}

		// Short base64 hash (e.g. "aGFzaA==" = 4 bytes "hash") is accepted without error
		// because ParseCheckpointHeader does not enforce 32-byte SHA-256 hash length.
		leafShortHash := []byte(fmt.Sprintf("%s\nexample.com/log\n100\naGFzaA==\n", lowerHexRoot))
		_, cpShort, _, err := ParseOutputLogLeaf(leafShortHash)
		if err != nil {
			t.Fatalf("unexpected error for short base64 hash: %v", err)
		}
		if len(cpShort.Hash) != 4 {
			t.Fatalf("cpShort.Hash len = %d, want 4", len(cpShort.Hash))
		}
	})
}

// TestParseOutputLogLeaf_MassivePayload tests resilience against massive checkpoint notes (e.g. 5MB with 50,000 cosignatures).
func TestParseOutputLogLeaf_MassivePayload(t *testing.T) {
	mapRoot := sha256.Sum256([]byte("massive_test_root"))
	validHashB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	var cpBuilder bytes.Buffer
	cpBuilder.WriteString("example.com/log\n1000000\n")
	cpBuilder.WriteString(validHashB64 + "\n\n")

	// Append 50,000 witness cosignature lines (~5MB total)
	for i := 0; i < 50000; i++ {
		fmt.Fprintf(&cpBuilder, "— witness.corp.example.com/%05d wId%04d %s\n", i, i%1000, validHashB64)
	}
	rawCP := cpBuilder.Bytes()

	leafPayload := FormatOutputLogLeaf(mapRoot, rawCP)

	start := time.Now()
	parsedRoot, inCP, parsedRawCP, err := ParseOutputLogLeaf(leafPayload)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed on massive payload (%d bytes): %v", len(leafPayload), err)
	}
	if parsedRoot != mapRoot {
		t.Fatalf("parsedRoot mismatch on massive payload")
	}
	if inCP.Size != 1000000 {
		t.Fatalf("inCP.Size = %d, want 1000000", inCP.Size)
	}
	if inCP.Origin != "example.com/log" {
		t.Fatalf("inCP.Origin = %q, want %q", inCP.Origin, "example.com/log")
	}
	if len(parsedRawCP) == 0 || parsedRawCP[len(parsedRawCP)-1] != '\n' {
		t.Fatalf("parsedRawCP missing trailing newline")
	}

	t.Logf("Parsed %d byte leaf with 50,000 signatures in %v", len(leafPayload), elapsed)
	if elapsed > 2*time.Second {
		t.Fatalf("Parsing massive payload took too long: %v (expected < 2s)", elapsed)
	}
}

// TestDifferentialFuzzing_Roundtrip exercises differential testing (random generator vs roundtrip oracle)
// over 2,000 randomized iterations.
func TestDifferentialFuzzing_Roundtrip(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(133742))

	for i := 0; i < 2000; i++ {
		var mapRoot [sha256.Size]byte
		_, _ = rand.Read(mapRoot[:])

		origin := fmt.Sprintf("origin-%d.example.com", rng.Intn(10000))
		size := rng.Uint64()
		var hash [sha256.Size]byte
		_, _ = rand.Read(hash[:])
		hashB64 := base64.StdEncoding.EncodeToString(hash[:])

		numSigs := rng.Intn(10)
		var rawCP bytes.Buffer
		fmt.Fprintf(&rawCP, "%s\n%d\n%s\n", origin, size, hashB64)
		if numSigs > 0 {
			rawCP.WriteString("\n")
			for s := 0; s < numSigs; s++ {
				fmt.Fprintf(&rawCP, "— sig-%d %s\n", s, hashB64[:16])
			}
		}

		formatted := FormatOutputLogLeaf(mapRoot, rawCP.Bytes())

		parsedRoot, parsedCP, parsedRawCP, err := ParseOutputLogLeaf(formatted)
		if err != nil {
			t.Fatalf("iteration %d: ParseOutputLogLeaf failed on valid generated leaf: %v", i, err)
		}
		if parsedRoot != mapRoot {
			t.Fatalf("iteration %d: mapRoot mismatch: got %x, want %x", i, parsedRoot, mapRoot)
		}
		if parsedCP.Origin != origin {
			t.Fatalf("iteration %d: origin mismatch: got %q, want %q", i, parsedCP.Origin, origin)
		}
		if parsedCP.Size != size {
			t.Fatalf("iteration %d: size mismatch: got %d, want %d", i, parsedCP.Size, size)
		}
		if !bytes.Equal(parsedCP.Hash, hash[:]) {
			t.Fatalf("iteration %d: hash mismatch: got %x, want %x", i, parsedCP.Hash, hash[:])
		}

		// Verify re-formatting produces identical bytes
		reformatted := FormatOutputLogLeaf(parsedRoot, parsedRawCP)
		if !bytes.Equal(reformatted, formatted) {
			t.Fatalf("iteration %d: roundtrip non-idempotent:\ngot:\n%s\nwant:\n%s", i, string(reformatted), string(formatted))
		}
	}
}

// TestDifferentialFuzzing_Mutations mutates valid leaf bytes with random bit flips, deletions,
// and insertions, asserting that ParseOutputLogLeaf NEVER panics and ALWAYS wraps ErrOutputLogCorrupted on error.
func TestDifferentialFuzzing_Mutations(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(987654))

	baseMapRoot := sha256.Sum256([]byte("fuzz_base_root"))
	baseHash := sha256.Sum256([]byte("fuzz_base_hash"))
	baseCP := fmt.Sprintf("example.com/log\n500\n%s\n— sig1\n", base64.StdEncoding.EncodeToString(baseHash[:]))
	baseLeaf := FormatOutputLogLeaf(baseMapRoot, []byte(baseCP))

	for i := 0; i < 3000; i++ {
		mutated := make([]byte, len(baseLeaf))
		copy(mutated, baseLeaf)

		mutationType := rng.Intn(4)
		switch mutationType {
		case 0: // bit flip
			pos := rng.Intn(len(mutated))
			mutated[pos] ^= 1 << rng.Intn(8)
		case 1: // random byte insertion
			pos := rng.Intn(len(mutated))
			mutated = append(mutated[:pos], append([]byte{byte(rng.Intn(256))}, mutated[pos:]...)...)
		case 2: // random byte deletion
			if len(mutated) > 1 {
				pos := rng.Intn(len(mutated))
				mutated = append(mutated[:pos], mutated[pos+1:]...)
			}
		case 3: // random truncation
			truncLen := rng.Intn(len(mutated))
			mutated = mutated[:truncLen]
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iteration %d: ParseOutputLogLeaf panicked on mutated input %q: %v", i, string(mutated), r)
				}
			}()

			_, _, _, err := ParseOutputLogLeaf(mutated)
			if err != nil {
				if !errors.Is(err, ErrOutputLogCorrupted) {
					t.Fatalf("iteration %d: error does not wrap ErrOutputLogCorrupted: %v", i, err)
				}
			}
		}()
	}
}
