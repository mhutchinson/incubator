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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
)

// TestStress_MirrorServing_ConcurrentTransitions stress-tests verifier mirror serving under
// continuous concurrent HTTP lookup traffic while dynamically transitioning through three phases:
//  1. Pre-sync (expect HTTP 503)
//  2. Verified sync (expect HTTP 200 with cryptographically verified inclusion/non-inclusion proofs)
//  3. Root mismatch (expect immediate transition back to HTTP 503, withdrawn serving state, and zero unverified responses)
//
// Concurrently checks zero data races under the Go race detector (-race).
func TestStress_MirrorServing_ConcurrentTransitions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed 10 input leaves
	aliceKey := sha256.Sum256([]byte("alice@example.com"))
	hexAlice := hex.EncodeToString(aliceKey[:])
	absentKey := sha256.Sum256([]byte("absent@example.com"))
	hexAbsent := hex.EncodeToString(absentKey[:])

	for i := 0; i < 10; i++ {
		var entry []byte
		if i%2 == 0 {
			entry = []byte("alice@example.com")
		} else {
			entry = []byte(fmt.Sprintf("user-%d@example.com", i))
		}
		h.inLog.AppendLeaf(entry)
	}

	leaves10 := h.inLog.leaves[:10]
	expectedRoot10 := computeExpectedMapRoot(t, leaves10, h.mapper)
	signedInCP10, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	rawLeaf0 := tree.FormatOutputLogLeaf(expectedRoot10, signedInCP10)

	// Prepare tampered leaf 1
	for i := 10; i < 15; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("user-%d@example.com", i)))
	}
	signedInCP15, err := h.inLog.SignCheckpoint(15)
	if err != nil {
		t.Fatalf("SignCheckpoint 15 failed: %v", err)
	}
	tamperedRoot := sha256.Sum256([]byte("bogus_forged_mpt_root_mismatch"))
	rawLeaf1Tampered := tree.FormatOutputLogLeaf(tamperedRoot, signedInCP15)

	// 2. Initialize Verifier with ServeMirror = true
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

	// Phase definitions
	const (
		PhasePreSync      int32 = 0
		PhaseVerifiedSync int32 = 1
		PhaseMismatch     int32 = 2
	)

	var (
		currentPhase                  atomic.Int32
		syncCompleted                 atomic.Bool
		mismatchCompleted             atomic.Bool
		stopTraffic                   = make(chan struct{})
		preSync503Count               atomic.Int64
		preSync200Count               atomic.Int64
		verifiedSync200Count          atomic.Int64
		verifiedSync503Count          atomic.Int64
		verifiedCryptographicFailures atomic.Int64
		postMismatch503Count          atomic.Int64
		postMismatchAfterHalt200Count atomic.Int64
		totalRequests                 atomic.Int64
		totalUnverifiedResponses      atomic.Int64
	)

	currentPhase.Store(PhasePreSync)

	var wg sync.WaitGroup
	numWorkers := 8

	// Launch concurrent lookup worker goroutines
	for workerID := 0; workerID < numWorkers; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			clientHTTP := ts.Client()

			for {
				select {
				case <-stopTraffic:
					return
				case <-ctx.Done():
					return
				default:
				}

				totalRequests.Add(1)
				startedAfterHalt := mismatchCompleted.Load()

				// Alternating queries: direct HTTP lookup, client.Lookup, and readyz
				switch id % 3 {
				case 0:
					// Direct HTTP lookup for Alice
					resp, err := clientHTTP.Get(ts.URL + "/vindex/lookup/" + hexAlice)
					if err != nil {
						continue
					}
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()

					switch resp.StatusCode {
					case http.StatusOK:
						if startedAfterHalt {
							postMismatchAfterHalt200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else if !syncCompleted.Load() {
							preSync200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else {
							verifiedSync200Count.Add(1)
						}
					case http.StatusServiceUnavailable:
						if startedAfterHalt {
							postMismatch503Count.Add(1)
						} else if !syncCompleted.Load() {
							preSync503Count.Add(1)
						} else {
							verifiedSync503Count.Add(1)
						}
					default:
						t.Errorf("worker %d: unexpected HTTP status %d: %s", id, resp.StatusCode, string(body))
					}

				case 1:
					// Cryptographically verified client lookup for Alice
					lookupResp, err := cli.Lookup(ctx, aliceKey, nil, 10)
					if err != nil {
						if startedAfterHalt {
							postMismatch503Count.Add(1)
						} else if !syncCompleted.Load() {
							preSync503Count.Add(1)
						} else {
							verifiedSync503Count.Add(1)
						}
					} else {
						if startedAfterHalt {
							postMismatchAfterHalt200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else if !syncCompleted.Load() {
							preSync200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else {
							verifiedSync200Count.Add(1)
							// Validate cryptographic correctness - must match authentic expectedRoot10
							if !lookupResp.Exists || lookupResp.MapRoot != expectedRoot10 {
								verifiedCryptographicFailures.Add(1)
								totalUnverifiedResponses.Add(1)
							}
						}
					}

				case 2:
					// Cryptographically verified client non-inclusion lookup for absentKey
					nonIncResp, err := cli.Lookup(ctx, absentKey, nil, 10)
					if err != nil {
						if startedAfterHalt {
							postMismatch503Count.Add(1)
						} else if !syncCompleted.Load() {
							preSync503Count.Add(1)
						} else {
							verifiedSync503Count.Add(1)
						}
					} else {
						if startedAfterHalt {
							postMismatchAfterHalt200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else if !syncCompleted.Load() {
							preSync200Count.Add(1)
							totalUnverifiedResponses.Add(1)
						} else {
							verifiedSync200Count.Add(1)
							if nonIncResp.Exists || nonIncResp.MapRoot != expectedRoot10 {
								verifiedCryptographicFailures.Add(1)
								totalUnverifiedResponses.Add(1)
							}
						}
					}
				}

				// Minimal yield to prevent starvation
				time.Sleep(200 * time.Microsecond)
			}
		}(workerID)
	}

	// =========================================================================
	// Phase 1: Pre-Sync Validation
	// =========================================================================
	time.Sleep(100 * time.Millisecond)
	if c200 := preSync200Count.Load(); c200 > 0 {
		t.Fatalf("Phase 1 (Pre-Sync) failure: got %d HTTP 200 responses before verification, want 0", c200)
	}
	if c503 := preSync503Count.Load(); c503 == 0 {
		t.Fatal("Phase 1 (Pre-Sync) failure: expected >0 HTTP 503 responses")
	}

	// =========================================================================
	// Phase 2: Transition to Verified Sync
	// =========================================================================
	if _, _, err := h.outLog.Append(ctx, rawLeaf0); err != nil {
		t.Fatalf("failed to append honest leaf 0: %v", err)
	}
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("Phase 2 VerifyOnce failed: %v", err)
	}
	syncCompleted.Store(true)
	currentPhase.Store(PhaseVerifiedSync)

	// Run under concurrent traffic in verified state
	time.Sleep(250 * time.Millisecond)

	if c200 := verifiedSync200Count.Load(); c200 == 0 {
		t.Fatal("Phase 2 (Verified Sync) failure: expected >0 verified HTTP 200 responses")
	}
	if cCryptoFail := verifiedCryptographicFailures.Load(); cCryptoFail > 0 {
		t.Fatalf("Phase 2 (Verified Sync) failure: got %d cryptographic proof verification failures", cCryptoFail)
	}

	// Direct endpoint sanity check in Phase 2
	respReady, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil || respReady.StatusCode != http.StatusOK {
		t.Fatalf("Phase 2 /readyz check failed: code=%v, err=%v", respReady.StatusCode, err)
	}
	_ = respReady.Body.Close()

	// =========================================================================
	// Phase 3: Transition to Root Mismatch
	// =========================================================================
	if _, _, err := h.outLog.Append(ctx, rawLeaf1Tampered); err != nil {
		t.Fatalf("failed to append tampered leaf 1: %v", err)
	}
	currentPhase.Store(PhaseMismatch)

	// VerifyOnce must detect mismatch and halt
	mismatchErr := v.VerifyOnce(ctx)
	if mismatchErr == nil || !errors.Is(mismatchErr, auditor.ErrRootMismatch) {
		t.Fatalf("Phase 3 VerifyOnce expected ErrRootMismatch, got: %v", mismatchErr)
	}
	mismatchCompleted.Store(true)

	// Run under concurrent traffic in post-mismatch halted state
	time.Sleep(250 * time.Millisecond)

	// Direct endpoint assertions in Phase 3
	respHealth, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil || respHealth.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Phase 3 /healthz check failed: code=%v, err=%v", respHealth.StatusCode, err)
	}
	_ = respHealth.Body.Close()

	respReadyPost, err := ts.Client().Get(ts.URL + "/readyz")
	if err != nil || respReadyPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Phase 3 /readyz check failed: code=%v, err=%v", respReadyPost.StatusCode, err)
	}
	_ = respReadyPost.Body.Close()

	respLookupPost, err := ts.Client().Get(ts.URL + "/vindex/lookup/" + hexAbsent)
	if err != nil || respLookupPost.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Phase 3 direct /vindex/lookup check failed: code=%v, err=%v", respLookupPost.StatusCode, err)
	}
	_ = respLookupPost.Body.Close()

	// Stop workers
	close(stopTraffic)
	wg.Wait()

	// =========================================================================
	// Final Invariant Assertions
	// =========================================================================
	if unverified := totalUnverifiedResponses.Load(); unverified > 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: %d unverified responses were served! (preSync200=%d, postMismatchAfterHalt200=%d)",
			unverified, preSync200Count.Load(), postMismatchAfterHalt200Count.Load())
	}
	if post200 := postMismatchAfterHalt200Count.Load(); post200 > 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: %d 200 responses were served after root mismatch halt!", post200)
	}
	if c503Post := postMismatch503Count.Load(); c503Post == 0 {
		t.Fatal("expected >0 HTTP 503 responses in post-mismatch phase")
	}

	// Verify serving state is completely nil
	if st := readServer.Publisher().GetServingState(); st != nil {
		t.Fatalf("expected ServingState to be nil after root mismatch halt, got: %v", st)
	}

	t.Logf("Transition stress test passed cleanly:\n"+
		"  Total requests: %d\n"+
		"  Pre-sync 503s: %d (200s: %d)\n"+
		"  Verified sync 200s: %d (crypto failures: %d)\n"+
		"  Post-mismatch 503s: %d (post-halt 200s: %d)\n"+
		"  Total unverified responses: %d",
		totalRequests.Load(),
		preSync503Count.Load(), preSync200Count.Load(),
		verifiedSync200Count.Load(), verifiedCryptographicFailures.Load(),
		postMismatch503Count.Load(), postMismatchAfterHalt200Count.Load(),
		totalUnverifiedResponses.Load(),
	)
}
