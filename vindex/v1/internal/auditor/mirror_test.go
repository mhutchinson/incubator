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

func TestVerifier_MirrorServing_PreAndPostVerification(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed input leaves
	aliceKey := sha256.Sum256([]byte("alice@example.com"))
	absentKey := sha256.Sum256([]byte("absent@example.com"))

	for i := 0; i < 10; i++ {
		var entry []byte
		if i%2 == 0 {
			entry = []byte("alice@example.com")
		} else {
			entry = []byte(fmt.Sprintf("other-%d@example.com", i))
		}
		h.inLog.AppendLeaf(entry)
	}

	leaves10 := h.inLog.leaves[:10]
	expectedRoot := computeExpectedMapRoot(t, leaves10, h.mapper)
	signedInCP, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	rawLeaf0 := tree.FormatOutputLogLeaf(expectedRoot, signedInCP)
	if _, _, err := h.outLog.Append(ctx, rawLeaf0); err != nil {
		t.Fatalf("outLog.Append failed: %v", err)
	}

	// 2. Instantiate Verifier in mirror mode
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

	hexAlice := hex.EncodeToString(aliceKey[:])

	// =========================================================================
	// Phase 1: Pre-Verification: /vindex/lookup/{keyhash} and /readyz return 503
	// =========================================================================
	t.Run("PreVerification_Returns503", func(t *testing.T) {
		// Client lookup must fail because serving state is uninitialized
		_, err := cli.Lookup(ctx, aliceKey, nil, 10)
		if err == nil {
			t.Fatal("expected pre-verification client lookup to fail, got success")
		}

		// Direct HTTP lookup endpoint check
		resp, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexAlice)
		if err != nil {
			t.Fatalf("HTTP GET /vindex/lookup failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusServiceUnavailable {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Pre-verification /vindex/lookup status = %d, want 503; body: %s", resp.StatusCode, string(body))
		}

		// Direct /readyz check
		respReady, err := ts.Client().Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("HTTP GET /readyz failed: %v", err)
		}
		defer func() { _ = respReady.Body.Close() }()
		if respReady.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("Pre-verification /readyz status = %d, want 503", respReady.StatusCode)
		}

		// Direct /healthz check (liveness should be 200)
		respHealth, err := ts.Client().Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("HTTP GET /healthz failed: %v", err)
		}
		defer func() { _ = respHealth.Body.Close() }()
		if respHealth.StatusCode != http.StatusOK {
			t.Fatalf("Pre-verification /healthz status = %d, want 200", respHealth.StatusCode)
		}
	})

	// =========================================================================
	// Phase 2: Post-Verification: /vindex/lookup/{keyhash} returns 200
	// with valid inclusion and non-inclusion proofs verified via client.NewClient
	// =========================================================================
	t.Run("PostVerification_ValidProofsVerifiedViaClient", func(t *testing.T) {
		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("VerifyOnce failed: %v", err)
		}

		// 1. Positive inclusion proof verification via client.NewClient
		respInclusion, err := cli.Lookup(ctx, aliceKey, nil, 10)
		if err != nil {
			t.Fatalf("client.Lookup(aliceKey) failed: %v", err)
		}
		if !respInclusion.Exists {
			t.Fatal("expected Exists=true for aliceKey")
		}
		expectedIndices := []uint64{0, 2, 4, 6, 8}
		if !slices.Equal(respInclusion.Indices, expectedIndices) {
			t.Fatalf("got indices %v, want %v", respInclusion.Indices, expectedIndices)
		}
		if respInclusion.MapRoot != expectedRoot {
			t.Fatalf("resp.MapRoot = %x, want %x", respInclusion.MapRoot, expectedRoot)
		}

		// 2. Cryptographic non-inclusion proof verification via client.NewClient
		respNonInclusion, err := cli.Lookup(ctx, absentKey, nil, 10)
		if err != nil {
			t.Fatalf("client.Lookup(absentKey) failed: %v", err)
		}
		if respNonInclusion.Exists {
			t.Fatal("expected Exists=false for absentKey")
		}
		if len(respNonInclusion.Indices) != 0 {
			t.Fatalf("expected empty indices for non-inclusion, got %v", respNonInclusion.Indices)
		}

		// 3. /readyz and /healthz both 200
		respReady, err := ts.Client().Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("HTTP GET /readyz failed: %v", err)
		}
		defer func() { _ = respReady.Body.Close() }()
		if respReady.StatusCode != http.StatusOK {
			t.Fatalf("Post-verification /readyz status = %d, want 200", respReady.StatusCode)
		}

		// 4. Checkpoint endpoints
		respCP, err := ts.Client().Get(ts.URL + "/vindex/v1/checkpoint")
		if err != nil {
			t.Fatalf("HTTP GET /vindex/v1/checkpoint failed: %v", err)
		}
		defer func() { _ = respCP.Body.Close() }()
		if respCP.StatusCode != http.StatusOK {
			t.Fatalf("/vindex/v1/checkpoint status = %d, want 200", respCP.StatusCode)
		}

		respInCP, err := ts.Client().Get(ts.URL + "/inputlog_checkpoint")
		if err != nil {
			t.Fatalf("HTTP GET /inputlog_checkpoint failed: %v", err)
		}
		defer func() { _ = respInCP.Body.Close() }()
		if respInCP.StatusCode != http.StatusOK {
			t.Fatalf("/inputlog_checkpoint status = %d, want 200", respInCP.StatusCode)
		}
	})
}

func TestVerifier_MirrorServing_RootMismatchWithdrawsServing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed leaf 0
	targetKey := sha256.Sum256([]byte("record-0"))
	hexTargetKey := hex.EncodeToString(targetKey[:])
	h.inLog.AppendLeaf([]byte("record-0"))

	leaves1 := h.inLog.leaves[:1]
	expectedRoot := computeExpectedMapRoot(t, leaves1, h.mapper)
	signedInCP0, _ := h.inLog.SignCheckpoint(1)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(expectedRoot, signedInCP0))

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
		FailClosed:        true,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	readServer := v.ReadServer()
	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Initial sync succeeds
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}

	// Verify serving is initially healthy
	respReady, _ := ts.Client().Get(ts.URL + "/readyz")
	if respReady.StatusCode != http.StatusOK {
		t.Fatalf("initial /readyz = %d, want 200", respReady.StatusCode)
	}
	_ = respReady.Body.Close()

	// 2. Append tampered leaf 1 with mismatched root
	h.inLog.AppendLeaf([]byte("record-1"))
	signedInCP1, _ := h.inLog.SignCheckpoint(2)
	tamperedRoot := sha256.Sum256([]byte("bogus_tampered_map_root"))
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, signedInCP1))

	// 3. Verification must fail with ErrRootMismatch
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	// 4. In fail-closed mode, assert all endpoints return 503:
	// - /healthz returns 503
	respHealth, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer func() { _ = respHealth.Body.Close() }()
	if respHealth.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-mismatch /healthz status = %d, want 503", respHealth.StatusCode)
	}
	healthBody, _ := io.ReadAll(respHealth.Body)
	if !strings.Contains(string(healthBody), "verifier root hash mismatch") {
		t.Fatalf("/healthz body missing mismatch message: %s", string(healthBody))
	}

	// - /readyz returns 503
	respReadyPost, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer func() { _ = respReadyPost.Body.Close() }()
	if respReadyPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-mismatch /readyz status = %d, want 503", respReadyPost.StatusCode)
	}

	// - /vindex/lookup/{keyhash} returns 503
	respLookup, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexTargetKey)
	if err != nil {
		t.Fatalf("GET /vindex/lookup failed: %v", err)
	}
	defer func() { _ = respLookup.Body.Close() }()
	if respLookup.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-mismatch /vindex/lookup status = %d, want 503", respLookup.StatusCode)
	}

	// 5. ServingState withdrawn
	if st := readServer.Publisher().GetServingState(); st != nil {
		t.Fatalf("expected ServingState to be withdrawn (nil), got: %v", st)
	}
}

// TestVerifier_MirrorServing_RootMismatchPinnedServing verifies the default pinned serving behavior:
// on root mismatch, forward sync halts and /readyz degrades to 503, but /healthz remains 200 OK
// and lookups continue serving valid authentic proofs against the last verified checkpoint (Serving_CP).
func TestVerifier_MirrorServing_RootMismatchPinnedServing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed leaf 0
	targetKey := sha256.Sum256([]byte("record-0"))
	hexTargetKey := hex.EncodeToString(targetKey[:])
	h.inLog.AppendLeaf([]byte("record-0"))

	leaves1 := h.inLog.leaves[:1]
	expectedRoot := computeExpectedMapRoot(t, leaves1, h.mapper)
	signedInCP0, _ := h.inLog.SignCheckpoint(1)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(expectedRoot, signedInCP0))

	// Default config: FailClosed is false (pinned serving)
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
		FailClosed:        false,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	readServer := v.ReadServer()
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

	// Initial sync succeeds
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}

	// 2. Append tampered leaf 1 with mismatched root
	h.inLog.AppendLeaf([]byte("record-1"))
	signedInCP1, _ := h.inLog.SignCheckpoint(2)
	tamperedRoot := sha256.Sum256([]byte("bogus_tampered_map_root"))
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, signedInCP1))

	// 3. Verification must fail with ErrRootMismatch
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	// 4. Assert Pinned Serving Invariants:
	// - /healthz remains HTTP 200 OK (liveness stays up so orchestrator does not kill replica)
	respHealth, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer func() { _ = respHealth.Body.Close() }()
	if respHealth.StatusCode != http.StatusOK {
		t.Fatalf("post-mismatch /healthz status = %d, want 200 (pinned serving)", respHealth.StatusCode)
	}

	// - /readyz returns HTTP 503 with structured JSON diagnostics
	respReadyPost, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer func() { _ = respReadyPost.Body.Close() }()
	if respReadyPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-mismatch /readyz status = %d, want 503", respReadyPost.StatusCode)
	}
	readyBody, _ := io.ReadAll(respReadyPost.Body)
	if !strings.Contains(string(readyBody), "degraded") || !strings.Contains(string(readyBody), "verifier root hash mismatch") {
		t.Fatalf("/readyz body missing structured diagnostics: %s", string(readyBody))
	}

	// - /syncz alias also returns HTTP 503
	respSyncPost, err := ts.Client().Get(ts.URL + "/syncz")
	if err != nil {
		t.Fatalf("GET /syncz failed: %v", err)
	}
	defer func() { _ = respSyncPost.Body.Close() }()
	if respSyncPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("post-mismatch /syncz status = %d, want 503", respSyncPost.StatusCode)
	}

	// - /vindex/lookup/{keyhash} CONTINUES to serve valid 200 OK pinned to last verified checkpoint
	lookupResp, err := cli.Lookup(ctx, targetKey, nil, 10)
	if err != nil {
		t.Fatalf("pinned client.Lookup failed: %v", err)
	}
	if !lookupResp.Exists || lookupResp.MapRoot != expectedRoot {
		t.Fatalf("pinned lookup returned invalid proof: exists=%v, root=%x (want %x)", lookupResp.Exists, lookupResp.MapRoot, expectedRoot)
	}

	// Direct HTTP lookup also succeeds with HTTP 200
	respLookup, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexTargetKey)
	if err != nil {
		t.Fatalf("GET /vindex/lookup failed: %v", err)
	}
	defer func() { _ = respLookup.Body.Close() }()
	if respLookup.StatusCode != http.StatusOK {
		t.Fatalf("post-mismatch /vindex/lookup status = %d, want 200 (pinned serving)", respLookup.StatusCode)
	}

	// - ServingState remains populated
	if st := readServer.Publisher().GetServingState(); st == nil {
		t.Fatal("expected ServingState to remain non-nil in pinned serving mode")
	}
}

func TestVerifier_MirrorServing_ColdRestart(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	mptDir := filepath.Join(tmpDir, "mpt")

	// 1. Seed 5 leaves
	targetKey := sha256.Sum256([]byte("persistent-item-0"))
	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("persistent-item-%d", i)))
	}
	leaves5 := h.inLog.leaves[:5]
	expectedRoot := computeExpectedMapRoot(t, leaves5, h.mapper)
	signedInCP0, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(expectedRoot, signedInCP0))

	// Run 1: Initial verification pass with persistent storage
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

	// Run 2: Cold restart with same persistent storage
	// OutLog tree size is 1, and verifiedOutputSize is recovered as 1 from disk.
	// outCP.Size == verifiedOutputSize triggers cold restart rehydration.
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

	// Before VerifyOnce, ServingState is nil
	if st := readServer.Publisher().GetServingState(); st != nil {
		t.Fatalf("expected initial ServingState to be nil before VerifyOnce, got %v", st)
	}

	// Trigger VerifyOnce (outCP.Size == verifiedOutputSize -> re-hydrates serving state)
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	// Assert ServingState was re-hydrated
	st := readServer.Publisher().GetServingState()
	if st == nil {
		t.Fatal("expected ServingState to be re-hydrated, got nil")
	}
	if st.OutputLogIndex != 0 {
		t.Errorf("re-hydrated OutputLogIndex = %d, want 0", st.OutputLogIndex)
	}
	if st.MapRoot != expectedRoot {
		t.Errorf("re-hydrated MapRoot = %x, want %x", st.MapRoot, expectedRoot)
	}

	// Mount on HTTP server and verify client lookup succeeds immediately
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

	// Lookup must succeed immediately with verified inclusion proof
	resp, err := cli.Lookup(ctx, targetKey, nil, 10)
	if err != nil {
		t.Fatalf("cold restart client.Lookup failed: %v", err)
	}
	if !resp.Exists {
		t.Fatal("expected Exists=true on cold restart")
	}
	if !slices.Equal(resp.Indices, []uint64{0}) {
		t.Fatalf("cold restart indices = %v, want [0]", resp.Indices)
	}

	// Readyz must return 200
	respReady, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("HTTP GET /readyz failed: %v", err)
	}
	defer func() { _ = respReady.Body.Close() }()
	if respReady.StatusCode != http.StatusOK {
		t.Fatalf("cold restart /readyz status = %d, want 200", respReady.StatusCode)
	}
}
