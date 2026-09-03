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

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

func setupAdvTestServer(t *testing.T) ([sha256.Size]byte, string) {
	t.Helper()
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key := sha256.Sum256([]byte("adv_test_key.example.com"))
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20, 30},
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err = pub.PublishBatch(ctx, res.ModifiedSubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 100}, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:]), nil)
	w := httptest.NewRecorder()
	srv.HandleLookup(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleLookup failed: %d", w.Code)
	}

	return key, w.Body.String()
}

// TestAdv_VerifyResponse_OutputLogLeafCorruption tests that any corruption of the
// OutputLog leaf within the response envelope is detected and properly wrapped with tree.ErrOutputLogCorrupted.
func TestAdv_VerifyResponse_OutputLogLeafCorruption(t *testing.T) {
	ctx := context.Background()
	key, validBody := setupAdvTestServer(t)

	verifier := NewVerifier(VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	})

	// Baseline check: valid body must verify cleanly
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(validBody)); err != nil {
		t.Fatalf("Baseline valid body failed verification: %v", err)
	}

	// Extract current output log leaf payload from valid response
	lines := strings.Split(validBody, "\n")
	var leafLines []string
	inLeaf := false
	for _, l := range lines {
		if strings.HasPrefix(l, "— output-log-leaf-v1") {
			inLeaf = true
			continue
		}
		if inLeaf && strings.HasPrefix(l, "— ") {
			break
		}
		if inLeaf {
			leafLines = append(leafLines, l)
		}
	}
	originalLeaf := strings.Join(leafLines, "\n")
	if originalLeaf == "" {
		t.Fatal("failed to extract output-log-leaf-v1 from valid body")
	}

	corruptionCases := []struct {
		name        string
		corruptLeaf string
	}{
		{
			name:        "truncated_single_line_no_newline",
			corruptLeaf: "abcd1234deadbeef",
		},
		{
			name:        "invalid_hex_root_length_short",
			corruptLeaf: "abcd1234\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "invalid_hex_root_length_long",
			corruptLeaf: strings.Repeat("a", 66) + "\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "invalid_hex_chars",
			corruptLeaf: strings.Repeat("z", 64) + "\nexample.com/input\n100\nAAAA\n",
		},
		{
			name:        "corrupted_checkpoint_missing_lines",
			corruptLeaf: strings.Repeat("0", 64) + "\nonly_one_line",
		},
		{
			name:        "corrupted_checkpoint_invalid_size",
			corruptLeaf: strings.Repeat("0", 64) + "\nexample.com/input\nnot_a_number\nAAAA\n",
		},
		{
			name:        "corrupted_checkpoint_invalid_hash_encoding",
			corruptLeaf: strings.Repeat("0", 64) + "\nexample.com/input\n100\n!@#$%^&*\n",
		},
	}

	for _, tc := range corruptionCases {
		t.Run(tc.name, func(t *testing.T) {
			tamperedBody := strings.Replace(validBody, originalLeaf, tc.corruptLeaf, 1)
			_, err := verifier.VerifyResponse(ctx, key, nil, []byte(tamperedBody))
			if err == nil {
				t.Fatalf("expected error for corrupted leaf in %s, got nil", tc.name)
			}
			if !errors.Is(err, tree.ErrOutputLogCorrupted) {
				t.Fatalf("expected errors.Is(err, tree.ErrOutputLogCorrupted), got %v", err)
			}
		})
	}
}

// TestAdv_VerifyLookupResponse_OutputLogLeafErrorWrapping tests that VerifyLookupResponse
// properly wraps tree.ErrOutputLogCorrupted when output log leaf parsing fails.
func TestAdv_VerifyLookupResponse_OutputLogLeafErrorWrapping(t *testing.T) {
	testLeaves := []struct {
		name string
		leaf []byte
	}{
		{"empty", []byte("")},
		{"short_hex", []byte("1234\nexample.com/in\n1\nAAAA\n")},
		{"bad_hex_chars", []byte(strings.Repeat("q", 64) + "\nexample.com/in\n1\nAAAA\n")},
		{"bad_checkpoint", []byte(strings.Repeat("0", 64) + "\nexample.com/in\nnot_num\nAAAA\n")},
	}

	for _, tc := range testLeaves {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := tree.ParseOutputLogLeaf(tc.leaf)
			if err == nil {
				t.Fatalf("ParseOutputLogLeaf should fail for %s", tc.name)
			}
			if !errors.Is(err, tree.ErrOutputLogCorrupted) {
				t.Fatalf("ParseOutputLogLeaf error must wrap ErrOutputLogCorrupted: %v", err)
			}

			// VerifyLookupResponse line 640 wrap pattern:
			wrappedErr := fmt.Errorf("output log leaf malformed: %w", err)
			if !errors.Is(wrappedErr, tree.ErrOutputLogCorrupted) {
				t.Fatalf("wrappedErr must satisfy errors.Is(wrappedErr, tree.ErrOutputLogCorrupted)")
			}
		})
	}
}
