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

package auditor_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
)

// TestAdv_M3_ClientProofVerification_InclusionAndNonInclusion tests Task 1:
// Audit client.NewClient proof verification against mirror server for both
// inclusion and non-inclusion paths, including multi-occurrence keys and pagination (LookupAll).
func TestAdv_M3_ClientProofVerification_InclusionAndNonInclusion(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// Seed 20 input leaves with known key distributions:
	// - keyAlice: present at 0, 4, 8, 12, 16 (5 occurrences)
	// - keyBob: present at 1, 5, 9 (3 occurrences)
	// - keyCharlie: present at 2 (1 occurrence)
	// - keyAbsent: absent (0 occurrences)
	keyAlice := sha256.Sum256([]byte("alice@example.com"))
	keyBob := sha256.Sum256([]byte("bob@example.com"))
	keyCharlie := sha256.Sum256([]byte("charlie@example.com"))
	keyAbsent := sha256.Sum256([]byte("absent@example.com"))

	for i := 0; i < 20; i++ {
		var entry []byte
		switch {
		case i%4 == 0:
			entry = []byte("alice@example.com")
		case i%4 == 1 && i < 12:
			entry = []byte("bob@example.com")
		case i == 2:
			entry = []byte("charlie@example.com")
		default:
			entry = []byte(fmt.Sprintf("other-%d@example.com", i))
		}
		h.inLog.AppendLeaf(entry)
	}

	leaves20 := h.inLog.leaves[:20]
	expectedRoot20 := computeExpectedMapRoot(t, leaves20, h.mapper)
	signedInCP20, err := h.inLog.SignCheckpoint(20)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	rawLeaf0 := tree.FormatOutputLogLeaf(expectedRoot20, signedInCP20)
	if _, _, err := h.outLog.Append(ctx, rawLeaf0); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
		ServeMirror:       true,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	readServer := v.ReadServer()
	if readServer == nil {
		t.Fatal("expected non-nil ReadServer when ServeMirror=true")
	}
	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.NewClient(ts.URL, client.VerifierConfig{
		OutputLogOrigin:   h.outLog.origin,
		OutputLogVerifier: h.outVerifier,
		InputLogOrigin:    h.inLog.origin,
		InputLogVerifier:  h.inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.NewClient failed: %v", err)
	}

	// Verify mirror before sync fails
	if _, err := cli.Lookup(ctx, keyAlice, nil, 10); err == nil {
		t.Fatal("expected pre-verification client lookup to fail, got success")
	}

	// Perform verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	t.Run("PositiveInclusion_SingleOccurrence", func(t *testing.T) {
		resp, err := cli.Lookup(ctx, keyCharlie, nil, 10)
		if err != nil {
			t.Fatalf("Lookup(keyCharlie) failed: %v", err)
		}
		if !resp.Exists {
			t.Fatal("expected Exists=true for keyCharlie")
		}
		if !slices.Equal(resp.Indices, []uint64{2}) {
			t.Fatalf("keyCharlie indices = %v, want [2]", resp.Indices)
		}
		if resp.MapRoot != expectedRoot20 {
			t.Fatalf("MapRoot = %x, want %x", resp.MapRoot, expectedRoot20)
		}
		if resp.InputLogSize != 20 {
			t.Fatalf("InputLogSize = %d, want 20", resp.InputLogSize)
		}
		if resp.OutputLogSize != 1 {
			t.Fatalf("OutputLogSize = %d, want 1", resp.OutputLogSize)
		}
	})

	t.Run("PositiveInclusion_MultipleOccurrences", func(t *testing.T) {
		resp, err := cli.Lookup(ctx, keyAlice, nil, 10)
		if err != nil {
			t.Fatalf("Lookup(keyAlice) failed: %v", err)
		}
		if !resp.Exists {
			t.Fatal("expected Exists=true for keyAlice")
		}
		expectedIndices := []uint64{0, 4, 8, 12, 16}
		if !slices.Equal(resp.Indices, expectedIndices) {
			t.Fatalf("keyAlice indices = %v, want %v", resp.Indices, expectedIndices)
		}
		if resp.MapRoot != expectedRoot20 {
			t.Fatalf("MapRoot = %x, want %x", resp.MapRoot, expectedRoot20)
		}
	})

	t.Run("CryptographicNonInclusion_AbsentKey", func(t *testing.T) {
		resp, err := cli.Lookup(ctx, keyAbsent, nil, 10)
		if err != nil {
			t.Fatalf("Lookup(keyAbsent) failed: %v", err)
		}
		if resp.Exists {
			t.Fatal("expected Exists=false for keyAbsent")
		}
		if len(resp.Indices) != 0 {
			t.Fatalf("expected empty indices for non-inclusion, got %v", resp.Indices)
		}
		if resp.MapRoot != expectedRoot20 {
			t.Fatalf("MapRoot = %x, want %x", resp.MapRoot, expectedRoot20)
		}
	})

	t.Run("Pagination_LookupAll_KeyAlice", func(t *testing.T) {
		// LookupAll with pageSize = 2 forces multiple pages and compact range verification
		resp, err := cli.LookupAll(ctx, keyAlice, 2)
		if err != nil {
			t.Fatalf("LookupAll(keyAlice, 2) failed: %v", err)
		}
		if !resp.Exists {
			t.Fatal("expected Exists=true for keyAlice in LookupAll")
		}
		expectedIndices := []uint64{0, 4, 8, 12, 16}
		if !slices.Equal(resp.Indices, expectedIndices) {
			t.Fatalf("LookupAll indices = %v, want %v", resp.Indices, expectedIndices)
		}
	})

	t.Run("Pagination_LookupAll_KeyBob", func(t *testing.T) {
		resp, err := cli.LookupAll(ctx, keyBob, 1)
		if err != nil {
			t.Fatalf("LookupAll(keyBob, 1) failed: %v", err)
		}
		if !resp.Exists {
			t.Fatal("expected Exists=true for keyBob in LookupAll")
		}
		expectedIndices := []uint64{1, 5, 9}
		if !slices.Equal(resp.Indices, expectedIndices) {
			t.Fatalf("LookupAll indices = %v, want %v", resp.Indices, expectedIndices)
		}
	})

	t.Run("Pagination_LookupAll_AbsentKey", func(t *testing.T) {
		resp, err := cli.LookupAll(ctx, keyAbsent, 2)
		if err != nil {
			t.Fatalf("LookupAll(keyAbsent, 2) failed: %v", err)
		}
		if resp.Exists {
			t.Fatal("expected Exists=false for absent key in LookupAll")
		}
	})
}

// TestAdv_M3_ClientProofVerification_AdversarialTampering tests that client.NewClient
// strictly rejects any tampered response from a mirror server:
// - Corrupted checkpoint signatures
// - Corrupted inclusion proofs
// - Corrupted MPT proofs
// - Tampered indices
func TestAdv_M3_ClientProofVerification_AdversarialTampering(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	key := sha256.Sum256([]byte("target@example.com"))
	h.inLog.AppendLeaf([]byte("target@example.com"))
	leaves1 := h.inLog.leaves[:1]
	expectedRoot := computeExpectedMapRoot(t, leaves1, h.mapper)
	signedInCP, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	rawLeaf0 := tree.FormatOutputLogLeaf(expectedRoot, signedInCP)
	if _, _, err := h.outLog.Append(ctx, rawLeaf0); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
		ServeMirror:       true,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	readServer := v.ReadServer()
	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	realTS := httptest.NewServer(mux)
	defer realTS.Close()

	// Capture authentic response
	hexKey := hex.EncodeToString(key[:])
	resp, err := realTS.Client().Get(realTS.URL + "/vindex/lookup/" + hexKey)
	if err != nil {
		t.Fatalf("GET lookup failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	authenticBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	authenticBody := string(authenticBodyBytes)

	// Proxy test server that allows tampering with response body
	var tamperedBody string
	proxyTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(tamperedBody))
	}))
	defer proxyTS.Close()

	cli, err := client.NewClient(proxyTS.URL, client.VerifierConfig{
		OutputLogOrigin:   h.outLog.origin,
		OutputLogVerifier: h.outVerifier,
		InputLogOrigin:    h.inLog.origin,
		InputLogVerifier:  h.inVerifier,
	}, proxyTS.Client())
	if err != nil {
		t.Fatalf("client.NewClient failed: %v", err)
	}

	// 1. Baseline verification with authentic body
	tamperedBody = authenticBody
	if _, err := cli.Lookup(ctx, key, nil, 10); err != nil {
		t.Fatalf("baseline authentic lookup failed: %v", err)
	}

	// 2. Tampered output log checkpoint signature
	t.Run("TamperedOutputLogCheckpoint", func(t *testing.T) {
		tamperedBody = strings.Replace(authenticBody, h.outVerifier.Name(), "fake.signer.name", 1)
		_, err := cli.Lookup(ctx, key, nil, 10)
		if err == nil {
			t.Fatal("expected error for tampered output log checkpoint, got nil")
		}
		if !errors.Is(err, client.ErrCheckpointFailed) {
			t.Fatalf("expected ErrCheckpointFailed, got: %v", err)
		}
	})

	// 3. Tampered output log leaf map root
	t.Run("TamperedMapRootInLeaf", func(t *testing.T) {
		// Replace map root with bogus hex in output log leaf section
		bogusRoot := hex.EncodeToString(make([]byte, 32))
		hexExpectedRoot := hex.EncodeToString(expectedRoot[:])
		tamperedBody = strings.Replace(authenticBody, hexExpectedRoot, bogusRoot, 1)
		_, err := cli.Lookup(ctx, key, nil, 10)
		if err == nil {
			t.Fatal("expected error for tampered map root in leaf, got nil")
		}
		// Fails inclusion proof verification against output log tree
		if !errors.Is(err, client.ErrInclusionFailed) {
			t.Fatalf("expected ErrInclusionFailed, got: %v", err)
		}
	})

	// 4. Tampered indices (value changed from 0 to 999)
	t.Run("TamperedIndices", func(t *testing.T) {
		// Replace index 0 with 999
		tamperedBody = strings.Replace(authenticBody, "\n0\n", "\n999\n", 1)
		_, err := cli.Lookup(ctx, key, nil, 10)
		if err == nil {
			t.Fatal("expected error for tampered index value, got nil")
		}
		// 999 is outside bound [0, 1) -> ErrIndexRange
		if !errors.Is(err, client.ErrIndexRange) {
			t.Fatalf("expected ErrIndexRange, got: %v", err)
		}
	})

	// 5. Tampered MPT proof
	t.Run("TamperedMPTProof", func(t *testing.T) {
		lines := strings.Split(authenticBody, "\n")
		found := false
		for i, l := range lines {
			if strings.Contains(l, "mpt-proof-v1") && i+1 < len(lines) {
				lines[i+1] = base64.StdEncoding.EncodeToString([]byte("invalid_mpt_proof_bytes_1234567890"))
				found = true
				break
			}
		}
		if !found {
			t.Fatal("failed to find mpt-proof-v1 section in authentic body")
		}
		tamperedBody = strings.Join(lines, "\n")
		_, err := cli.Lookup(ctx, key, nil, 10)
		if err == nil {
			t.Fatal("expected error for tampered MPT proof, got nil")
		}
		if !errors.Is(err, client.ErrMPTFailed) {
			t.Fatalf("expected ErrMPTFailed, got: %v", err)
		}
	})
}

// TestAdv_M3_ColdRestart_RehydrationAndImmediateServing tests Task 2:
// Start verifier with persistent storage, verify one leaf, close verifier,
// restart verifier without new leaves, assert /vindex/lookup/{keyhash} immediately
// returns 200 with verified proofs, and health endpoints report 200.
func TestAdv_M3_ColdRestart_RehydrationAndImmediateServing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	mptDir := filepath.Join(tmpDir, "mpt")

	keyPresent := sha256.Sum256([]byte("item-present-0"))
	hexKeyPresent := hex.EncodeToString(keyPresent[:])
	keyAbsent := sha256.Sum256([]byte("item-absent-999"))
	hexKeyAbsent := hex.EncodeToString(keyAbsent[:])

	// 1. Seed 1 input leaf and 1 output leaf
	h.inLog.AppendLeaf([]byte("item-present-0"))
	leaves1 := h.inLog.leaves[:1]
	expectedRoot := computeExpectedMapRoot(t, leaves1, h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	rawLeaf0 := tree.FormatOutputLogLeaf(expectedRoot, signedInCP0)
	if _, _, err := h.outLog.Append(ctx, rawLeaf0); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	// 2. Initial Run: Verify 1 leaf with persistent storage
	cfg1 := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
		ServeMirror:       true,
	}
	v1, err := auditor.New(cfg1)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// 3. Restart Run: Cold restart with same persistent storage without new leaves
	cfg2 := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
		ServeMirror:       true,
	}
	v2, err := auditor.New(cfg2)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	readServer := v2.ReadServer()
	if readServer == nil {
		t.Fatal("v2 ReadServer is nil")
	}

	// Re-hydration happens during VerifyOnce when outCP.Size == v.verifiedOutputSize
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	// Mount HTTP routes
	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.NewClient(ts.URL, client.VerifierConfig{
		OutputLogOrigin:   h.outLog.origin,
		OutputLogVerifier: h.outVerifier,
		InputLogOrigin:    h.inLog.origin,
		InputLogVerifier:  h.inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.NewClient failed: %v", err)
	}

	// Assert /vindex/lookup/{keyhash} immediately returns 200 with verified proofs
	t.Run("ImmediateLookup200_InclusionProof", func(t *testing.T) {
		// Check direct HTTP GET status
		httpResp, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexKeyPresent)
		if err != nil {
			t.Fatalf("GET /vindex/lookup failed: %v", err)
		}
		defer func() { _ = httpResp.Body.Close() }()
		if httpResp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(httpResp.Body)
			t.Fatalf("GET /vindex/lookup status = %d, want 200; body: %s", httpResp.StatusCode, string(b))
		}

		// Check cryptographic proof verification via client
		resp, err := cli.Lookup(ctx, keyPresent, nil, 10)
		if err != nil {
			t.Fatalf("cli.Lookup failed: %v", err)
		}
		if !resp.Exists {
			t.Fatal("expected Exists=true for keyPresent")
		}
		if !slices.Equal(resp.Indices, []uint64{0}) {
			t.Fatalf("keyPresent indices = %v, want [0]", resp.Indices)
		}
		if resp.MapRoot != expectedRoot {
			t.Fatalf("MapRoot = %x, want %x", resp.MapRoot, expectedRoot)
		}
	})

	t.Run("ImmediateLookup200_NonInclusionProof", func(t *testing.T) {
		httpResp, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexKeyAbsent)
		if err != nil {
			t.Fatalf("GET /vindex/lookup failed: %v", err)
		}
		defer func() { _ = httpResp.Body.Close() }()
		if httpResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /vindex/lookup status = %d, want 200", httpResp.StatusCode)
		}

		resp, err := cli.Lookup(ctx, keyAbsent, nil, 10)
		if err != nil {
			t.Fatalf("cli.Lookup failed: %v", err)
		}
		if resp.Exists {
			t.Fatal("expected Exists=false for keyAbsent")
		}
		if len(resp.Indices) != 0 {
			t.Fatalf("indices = %v, want empty", resp.Indices)
		}
	})

	t.Run("HealthAndCheckpointsReturn200", func(t *testing.T) {
		// /healthz
		respHealth, err := ts.Client().Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		defer func() { _ = respHealth.Body.Close() }()
		if respHealth.StatusCode != http.StatusOK {
			t.Fatalf("/healthz status = %d, want 200", respHealth.StatusCode)
		}

		// /readyz
		respReady, err := ts.Client().Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz failed: %v", err)
		}
		defer func() { _ = respReady.Body.Close() }()
		if respReady.StatusCode != http.StatusOK {
			t.Fatalf("/readyz status = %d, want 200", respReady.StatusCode)
		}

		// /vindex/v1/checkpoint
		respCP, err := ts.Client().Get(ts.URL + "/vindex/v1/checkpoint")
		if err != nil {
			t.Fatalf("GET /vindex/v1/checkpoint failed: %v", err)
		}
		defer func() { _ = respCP.Body.Close() }()
		if respCP.StatusCode != http.StatusOK {
			t.Fatalf("/vindex/v1/checkpoint status = %d, want 200", respCP.StatusCode)
		}

		// /inputlog_checkpoint
		respInCP, err := ts.Client().Get(ts.URL + "/inputlog_checkpoint")
		if err != nil {
			t.Fatalf("GET /inputlog_checkpoint failed: %v", err)
		}
		defer func() { _ = respInCP.Body.Close() }()
		if respInCP.StatusCode != http.StatusOK {
			t.Fatalf("/inputlog_checkpoint status = %d, want 200", respInCP.StatusCode)
		}
	})
}

// TestAdv_M3_ColdRestart_MultiLeaf_PicksLatestVerified tests that cold restart
// after multiple published leaves re-hydrates state from the latest leaf index (N-1),
// correctly setting InputLogSize, MapRoot, and OutputLogIndex.
func TestAdv_M3_ColdRestart_MultiLeaf_PicksLatestVerified(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	mptDir := filepath.Join(tmpDir, "mpt")

	key0 := sha256.Sum256([]byte("batch-0-item"))
	key1 := sha256.Sum256([]byte("batch-1-item"))
	key2 := sha256.Sum256([]byte("batch-2-item"))

	// Batch 0: leaves 0..3 (size 4)
	for i := 0; i < 4; i++ {
		h.inLog.AppendLeaf([]byte("batch-0-item"))
	}
	root0 := computeExpectedMapRoot(t, h.inLog.leaves[:4], h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(4)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0))

	// Batch 1: leaves 4..7 (size 8)
	for i := 4; i < 8; i++ {
		h.inLog.AppendLeaf([]byte("batch-1-item"))
	}
	root1 := computeExpectedMapRoot(t, h.inLog.leaves[:8], h.mapper)
	cp1, _ := h.inLog.SignCheckpoint(8)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, cp1))

	// Batch 2: leaves 8..11 (size 12)
	for i := 8; i < 12; i++ {
		h.inLog.AppendLeaf([]byte("batch-2-item"))
	}
	root2 := computeExpectedMapRoot(t, h.inLog.leaves[:12], h.mapper)
	cp2, _ := h.inLog.SignCheckpoint(12)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root2, cp2))

	// Run 1: Verify all 3 leaves
	cfg1 := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
		ServeMirror:       true,
	}
	v1, err := auditor.New(cfg1)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	if v1.Status().VerifiedOutputSize != 3 {
		t.Fatalf("verifiedOutputSize = %d, want 3", v1.Status().VerifiedOutputSize)
	}
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// Run 2: Restart without new leaves (outCP.Size == 3 == verifiedOutputSize)
	cfg2 := cfg1
	v2, err := auditor.New(cfg2)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	readServer := v2.ReadServer()
	st := readServer.Publisher().GetServingState()
	if st == nil {
		t.Fatal("expected non-nil ServingState after cold restart")
	}
	if st.OutputLogIndex != 2 {
		t.Errorf("rehydrated OutputLogIndex = %d, want 2", st.OutputLogIndex)
	}
	if st.InputLogSize != 12 {
		t.Errorf("rehydrated InputLogSize = %d, want 12", st.InputLogSize)
	}
	if st.MapRoot != root2 {
		t.Errorf("rehydrated MapRoot = %x, want %x", st.MapRoot, root2)
	}

	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.NewClient(ts.URL, client.VerifierConfig{
		OutputLogOrigin:   h.outLog.origin,
		OutputLogVerifier: h.outVerifier,
		InputLogOrigin:    h.inLog.origin,
		InputLogVerifier:  h.inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.NewClient failed: %v", err)
	}

	// Verify lookups for keys across all three batches
	for _, tc := range []struct {
		name    string
		key     [sha256.Size]byte
		indices []uint64
	}{
		{"batch0", key0, []uint64{0, 1, 2, 3}},
		{"batch1", key1, []uint64{4, 5, 6, 7}},
		{"batch2", key2, []uint64{8, 9, 10, 11}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := cli.Lookup(ctx, tc.key, nil, 10)
			if err != nil {
				t.Fatalf("Lookup(%s) failed: %v", tc.name, err)
			}
			if !resp.Exists {
				t.Fatalf("expected Exists=true for %s", tc.name)
			}
			if !slices.Equal(resp.Indices, tc.indices) {
				t.Fatalf("indices for %s = %v, want %v", tc.name, resp.Indices, tc.indices)
			}
			if resp.MapRoot != root2 {
				t.Fatalf("MapRoot = %x, want %x", resp.MapRoot, root2)
			}
		})
	}
}

// TestAdv_M3_ColdRestart_OutputLogTreeSizeRegressed verifies that if the OutputLog
// tree size regressed across a cold restart (outCP.Size < verifiedOutputSize),
// VerifyOnce returns ErrOutputLogRegressed and halts.
func TestAdv_M3_ColdRestart_OutputLogTreeSizeRegressed(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	mptDir := filepath.Join(tmpDir, "mpt")

	// Verify 2 leaves in run 1
	h.inLog.AppendLeaf([]byte("leaf-0"))
	root0 := computeExpectedMapRoot(t, h.inLog.leaves[:1], h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(1)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0))

	h.inLog.AppendLeaf([]byte("leaf-1"))
	root1 := computeExpectedMapRoot(t, h.inLog.leaves[:2], h.mapper)
	cp1, _ := h.inLog.SignCheckpoint(2)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, cp1))

	cfg1 := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   h.outLog.origin,
		InputLogOrigin:    h.inLog.origin,
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
		ServeMirror:       true,
	}
	v1, err := auditor.New(cfg1)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	_ = v1.Close()

	// Truncate outLog leaves to 1 (regressing tree size from 2 to 1)
	h.outLog.mu.Lock()
	h.outLog.leaves = h.outLog.leaves[:1]
	h.outLog.mu.Unlock()

	// Run 2: Restart with regressed log
	cfg2 := cfg1
	v2, err := auditor.New(cfg2)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	err = v2.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrOutputLogRegressed) {
		t.Fatalf("expected ErrOutputLogRegressed, got: %v", err)
	}
	if !v2.Status().IsHalted {
		t.Fatal("expected verifier to be halted after regression")
	}
}
