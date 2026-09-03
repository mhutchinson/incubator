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

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	vindex "github.com/transparency-dev/incubator/vindex/v1"
	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
	"golang.org/x/mod/sumdb/note"
)

// verifierTestCluster bundles an isolated Tessera cluster with live HTTP log servers
// and request inspection to verify sourcing invariants.
type verifierTestCluster struct {
	*testCluster
	inLogServer       *httptest.Server
	outLogServer      *httptest.Server
	inCheckpointCalls atomic.Int64
	outHandler        atomic.Pointer[http.Handler]
}

func newVerifierTestCluster(t *testing.T, ctx context.Context, chunkSize, bundleSize uint64) *verifierTestCluster {
	t.Helper()
	baseCluster := newTestCluster(t, ctx, chunkSize, bundleSize)

	vtc := &verifierTestCluster{
		testCluster: baseCluster,
	}

	// Intercept InputLog HTTP traffic to assert zero calls to /checkpoint (R1)
	inFs := http.FileServer(http.Dir(baseCluster.inLogDir))
	inMux := http.NewServeMux()
	inMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkpoint" || strings.HasSuffix(r.URL.Path, "/checkpoint") {
			vtc.inCheckpointCalls.Add(1)
		}
		inFs.ServeHTTP(w, r)
	})
	vtc.inLogServer = httptest.NewServer(inMux)
	t.Cleanup(vtc.inLogServer.Close)

	defaultOutHandler := http.FileServer(http.Dir(baseCluster.outLogDir))
	vtc.outHandler.Store(&defaultOutHandler)
	vtc.outLogServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*vtc.outHandler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(vtc.outLogServer.Close)

	return vtc
}

func (c *verifierTestCluster) setOutputLogDir(dir string) {
	h := http.FileServer(http.Dir(dir))
	c.outHandler.Store(&h)
}

func (c *verifierTestCluster) newVerifierConfig(t *testing.T, mapper vindex.LeafMapper, serveMirror bool) auditor.Config {
	t.Helper()
	tmpDir := t.TempDir()
	return auditor.Config{
		InputLogURL:       c.inLogServer.URL,
		InputLogOrigin:    c.config.InputLogOrigin,
		InputLogVerifier:  c.inVerifier,
		InputLogPubKey:    c.inVKey,
		OutputLogURL:      c.outLogServer.URL,
		OutputLogOrigin:   c.config.OutputLogOrigin,
		OutputLogVerifier: c.outVerifier,
		OutputLogPubKey:   c.outVKey,
		MapFn:             mapper,
		DBPath:            filepath.Join(tmpDir, "verifier_db"),
		MPTDir:            filepath.Join(tmpDir, "verifier_mpt"),
		ServeMirror:       serveMirror,
		PollInterval:      50 * time.Millisecond,
	}
}

// waitForOutputLogCheckpoint polls the OutputLog HTTP server until a valid checkpoint with size >= minSize is published.
func waitForOutputLogCheckpoint(t *testing.T, url string, minSize uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/checkpoint")
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if cp, err := tree.ParseCheckpointHeader(body); err == nil && cp.Size >= minSize {
				return
			}
		} else if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for OutputLog checkpoint size >= %d", minSize)
}

// -----------------------------------------------------------------------------
// Test 1: Honest End-to-End Sync (Oneshot and Daemon)
// -----------------------------------------------------------------------------

// TestE2E_HonestSync verifies multi-leaf sync, watermark advancement, MPT root equality,
// metrics baseline, /healthz 200 OK, and background daemon catch-up.
func TestE2E_HonestSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed initial 10 input leaves
	for i := 0; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%02d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// Start publisher engine
	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	// Wait for publisher to publish initial leaf 0 to OutputLog
	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	// 2. Initialize Verifier
	vCfg := vtc.newVerifierConfig(t, mapper, false)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	// 3. Oneshot verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	st := v.Status()
	if st.IsHalted {
		_ = v.Close()
		t.Fatalf("verifier unexpectedly halted: %v", st.HaltError)
	}
	if st.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize = %d, want 1", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 10 {
		t.Errorf("VerifiedInputSize = %d, want 10", st.VerifiedInputSize)
	}

	// 4. Assert metrics and health
	if m := testutil.ToFloat64(metrics.VerifierRootMismatch); m != 0 {
		t.Errorf("vindex_verifier_root_mismatch = %v, want 0", m)
	}
	if c := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal); c != 0 {
		t.Errorf("vindex_verifier_root_mismatches_total = %v, want 0", c)
	}
	if err := v.HealthCheck(); err != nil {
		t.Errorf("HealthCheck() = %v, want nil", err)
	}

	// Close verifier to release Pebble DB lock and inspect persisted watermarks on disk
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	db, err := kvstore.Open(vCfg.DBPath, nil)
	if err != nil {
		t.Fatalf("failed to open verifier DB: %v", err)
	}
	outBytes, closer, err := db.Pebble().Get(auditor.KeyVerifierOutputWatermark)
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to get KeyVerifierOutputWatermark: %v", err)
	}
	if binary.BigEndian.Uint64(outBytes) != 1 {
		t.Errorf("persisted output watermark = %d, want 1", binary.BigEndian.Uint64(outBytes))
	}
	_ = closer.Close()

	inBytes, closer, err := db.Pebble().Get(auditor.KeyVerifierInputWatermark)
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to get KeyVerifierInputWatermark: %v", err)
	}
	if binary.BigEndian.Uint64(inBytes) != 10 {
		t.Errorf("persisted input watermark = %d, want 10", binary.BigEndian.Uint64(inBytes))
	}
	_ = closer.Close()
	_ = db.Close()

	// 5. Reopen Verifier and verify Live Daemon background sync catch-up
	v2, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New restart failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	if v2.Status().VerifiedOutputSize != 1 || v2.Status().VerifiedInputSize != 10 {
		t.Fatalf("reopened verifier recovered status mismatch: %+v", v2.Status())
	}

	daemonCtx, daemonCancel := context.WithCancel(ctx)
	defer daemonCancel()
	go func() { _ = v2.Run(daemonCtx) }()

	// Append 10 more leaves to InputLog
	for i := 10; i < 20; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%02d", i)))
	}

	// Wait for daemon to verify leaf 1 and advance to input size 20
	catchupDeadline := time.Now().Add(10 * time.Second)
	caughtUp := false
	for time.Now().Before(catchupDeadline) {
		s := v2.Status()
		if s.VerifiedOutputSize >= 2 && s.VerifiedInputSize >= 20 {
			caughtUp = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !caughtUp {
		t.Fatalf("verifier daemon failed to catch up to leaf 1; status: %+v", v2.Status())
	}
	if v2.Status().IsHalted {
		t.Fatalf("verifier halted during daemon mode: %v", v2.Status().HaltError)
	}
}

func TestVerifierE2E_HonestSync_OneshotAndDaemon(t *testing.T) {
	TestE2E_HonestSync(t)
}

// -----------------------------------------------------------------------------
// Test 2: Tampered Root Detection & Containment
// -----------------------------------------------------------------------------

// TestE2E_TamperedRootDetection verifies that a tampered leaf committed to the OutputLog causes
// immediate engine halting, metrics vindex_verifier_root_mismatch == 1, /healthz 503, and database preservation.
func TestE2E_TamperedRootDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.ResetVerifierRootMismatch()

	// 1. Seed 5 leaves and publish honest leaf 0
	for i := 0; i < 5; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("record_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper, false)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	// Honest sync pass on leaf 0
	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}
	if v.Status().VerifiedOutputSize != 1 {
		_ = v.Close()
		t.Fatalf("VerifiedOutputSize = %d, want 1", v.Status().VerifiedOutputSize)
	}

	authenticRoot0 := v.Status().LastVerifiedRoot
	rawInCP5, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		_ = v.Close()
		t.Fatalf("failed to read initial input checkpoint: %v", err)
	}

	// Close initial verifier to release DB locks
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	// 2. Append 5 more leaves to InputLog (total 10 leaves)
	for i := 5; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("record_%d", i)))
	}

	// Read valid signed InputLog checkpoint at size 10
	rawInCP10, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("failed to read input checkpoint at size 10: %v", err)
	}

	// Construct an adversarial OutputLog with a forged MPT root in leaf 1
	advOutDir := t.TempDir()
	outSigner, err := note.NewSigner(vtc.outSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	advLog, err := tree.NewPOSIXOutputLog(ctx, advOutDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
	if err != nil {
		t.Fatalf("failed to create adversarial OutputLog: %v", err)
	}
	defer func() { _ = advLog.Close() }()

	// Leaf 0: authentic
	_, _, err = advLog.Append(ctx, tree.FormatOutputLogLeaf(authenticRoot0, rawInCP5))
	if err != nil {
		t.Fatalf("failed to append honest leaf 0: %v", err)
	}

	// Leaf 1: TAMPERED MapRoot
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	tamperedLeaf1 := tree.FormatOutputLogLeaf(tamperedRoot, rawInCP10)
	_, _, err = advLog.Append(ctx, tamperedLeaf1)
	if err != nil {
		t.Fatalf("failed to append tampered leaf 1: %v", err)
	}

	advServer := httptest.NewServer(http.FileServer(http.Dir(advOutDir)))
	defer advServer.Close()

	// Reconfigure verifier OutputLogURL to point to adversarial log, keeping DBPath
	vCfg.OutputLogURL = advServer.URL
	advVerifier, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("failed to create advVerifier: %v", err)
	}
	defer func() { _ = advVerifier.Close() }()

	// 3. Execution & Detection
	err = advVerifier.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("expected VerifyOnce to fail on tampered root, got nil")
	}
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	var mismatchErr *auditor.RootMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
	}
	if mismatchErr.CommittedMapRoot != tamperedRoot {
		t.Errorf("mismatchErr.CommittedMapRoot = %x, want %x", mismatchErr.CommittedMapRoot, tamperedRoot)
	}
	if mismatchErr.OutputIndex != 1 {
		t.Errorf("mismatchErr.OutputIndex = %d, want 1", mismatchErr.OutputIndex)
	}
	if mismatchErr.InputSize != 10 {
		t.Errorf("mismatchErr.InputSize = %d, want 10", mismatchErr.InputSize)
	}

	// 4. Metrics Assertions
	if m := testutil.ToFloat64(metrics.VerifierRootMismatch); m != 1.0 {
		t.Errorf("vindex_verifier_root_mismatch = %v, want 1.0", m)
	}
	if c := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal); c < 1.0 {
		t.Errorf("vindex_verifier_root_mismatches_total = %v, want >= 1.0", c)
	}

	// 5. Health degradation
	healthErr := advVerifier.HealthCheck()
	if healthErr == nil || !strings.Contains(healthErr.Error(), "verifier root hash mismatch") {
		t.Errorf("HealthCheck() = %v, want root mismatch error", healthErr)
	}

	// 6. Watermark containment
	status := advVerifier.Status()
	if !status.IsHalted {
		t.Error("verifier status IsHalted = false, want true")
	}
	if status.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize advanced past tampered leaf to %d, want 1", status.VerifiedOutputSize)
	}
	if status.VerifiedInputSize != 5 {
		t.Errorf("VerifiedInputSize advanced to %d, want 5", status.VerifiedInputSize)
	}

	// Subsequent calls must immediately return ErrRootMismatch without re-processing
	if err := advVerifier.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", err)
	}
}

func TestVerifierE2E_TamperedRoot_DetectionAndContainment(t *testing.T) {
	TestE2E_TamperedRootDetection(t)
}

// -----------------------------------------------------------------------------
// Test 3: Verified Mirror Serving E2E
// -----------------------------------------------------------------------------

// TestE2E_VerifiedMirrorServing verifies that the mirror HTTP server exposes /vindex/lookup/{keyhash},
// client.NewClient verifies cryptographic MPT proofs, pre-sync returns 503, and post-mismatch returns 503.
func TestE2E_VerifiedMirrorServing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.ResetVerifierRootMismatch()

	aliceKey := sha256.Sum256([]byte("alice"))
	bobKey := sha256.Sum256([]byte("bob"))
	eveKey := sha256.Sum256([]byte("eve"))

	vtc.appendLeaf([]byte("alice_item_1"))
	vtc.appendLeaf([]byte("bob_item_1"))
	vtc.appendLeaf([]byte("alice_item_2"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		s := string(leaf)
		if strings.HasPrefix(s, "alice") {
			return []vindex.MappedEntry{{KeyHash: aliceKey}}, nil
		}
		if strings.HasPrefix(s, "bob") {
			return []vindex.MappedEntry{{KeyHash: bobKey}}, nil
		}
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	// Verifier in mirror mode
	vCfg := vtc.newVerifierConfig(t, mapper, true)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	readServer := v.ReadServer()
	if readServer == nil {
		t.Fatal("ReadServer() returned nil with ServeMirror=true")
	}

	mirrorMux := http.NewServeMux()
	readServer.RegisterRoutes(mirrorMux)
	mirrorServer := httptest.NewServer(mirrorMux)
	defer mirrorServer.Close()

	cli, err := client.NewClient(mirrorServer.URL, client.VerifierConfig{
		OutputLogOrigin:   vtc.config.OutputLogOrigin,
		OutputLogVerifier: vtc.outVerifier,
		InputLogOrigin:    vtc.config.InputLogOrigin,
		InputLogVerifier:  vtc.inVerifier,
	}, mirrorServer.Client())
	if err != nil {
		t.Fatalf("client.NewClient failed: %v", err)
	}

	aliceHex := hex.EncodeToString(aliceKey[:])

	// 1. Pre-Verification checks: 503
	t.Run("PreVerification_503", func(t *testing.T) {
		resp, err := mirrorServer.Client().Get(mirrorServer.URL + "/vindex/lookup/" + aliceHex)
		if err != nil {
			t.Fatalf("GET /vindex/lookup failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("pre-sync lookup status = %d, want 503", resp.StatusCode)
		}

		respReady, _ := mirrorServer.Client().Get(mirrorServer.URL + "/readyz")
		if respReady.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("pre-sync readyz = %d, want 503", respReady.StatusCode)
		}
		_ = respReady.Body.Close()

		respHealth, _ := mirrorServer.Client().Get(mirrorServer.URL + "/healthz")
		if respHealth.StatusCode != http.StatusOK {
			t.Errorf("pre-sync healthz = %d, want 200", respHealth.StatusCode)
		}
		_ = respHealth.Body.Close()

		if _, err := cli.Lookup(ctx, aliceKey, nil, 10); err == nil {
			t.Error("expected pre-sync client.Lookup to fail, got success")
		}
	})

	var verifiedRoot0 [32]byte
	var rawInCP0 []byte

	// 2. Post-Verification: Honest Sync & Cryptographic Proof Verification
	t.Run("PostVerification_ValidProofQueries", func(t *testing.T) {
		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("VerifyOnce failed: %v", err)
		}

		respReady, _ := mirrorServer.Client().Get(mirrorServer.URL + "/readyz")
		if respReady.StatusCode != http.StatusOK {
			t.Errorf("post-sync readyz = %d, want 200", respReady.StatusCode)
		}
		_ = respReady.Body.Close()

		// Lookup existing alice -> expect indices [0, 2]
		respAlice, err := cli.Lookup(ctx, aliceKey, nil, 100)
		if err != nil {
			t.Fatalf("Lookup(alice) failed: %v", err)
		}
		if !respAlice.Exists {
			t.Fatal("Lookup(alice) Exists = false, want true")
		}
		if !slices.Equal(respAlice.Indices, []uint64{0, 2}) {
			t.Errorf("Lookup(alice) indices = %v, want [0, 2]", respAlice.Indices)
		}
		if respAlice.MapRoot == [32]byte{} {
			t.Error("Lookup(alice) returned zero MapRoot")
		}

		verifiedRoot0 = respAlice.MapRoot
		rawInCP0 = respAlice.RawInputLogCP

		// Lookup existing bob -> expect index [1]
		respBob, err := cli.Lookup(ctx, bobKey, nil, 100)
		if err != nil {
			t.Fatalf("Lookup(bob) failed: %v", err)
		}
		if !respBob.Exists || !slices.Equal(respBob.Indices, []uint64{1}) {
			t.Errorf("Lookup(bob) indices = %v, want [1]", respBob.Indices)
		}

		// Lookup absent eve -> expect verified non-inclusion
		respEve, err := cli.Lookup(ctx, eveKey, nil, 100)
		if err != nil {
			t.Fatalf("Lookup(eve) non-inclusion failed: %v", err)
		}
		if respEve.Exists {
			t.Error("Lookup(eve) Exists = true, want false")
		}
		if len(respEve.Indices) != 0 {
			t.Errorf("Lookup(eve) indices = %v, want empty", respEve.Indices)
		}

		// Checkpoint endpoints
		respCp, err := mirrorServer.Client().Get(mirrorServer.URL + "/vindex/v1/checkpoint")
		if err != nil || respCp.StatusCode != http.StatusOK {
			t.Errorf("GET /vindex/v1/checkpoint failed: status %v, err %v", respCp.StatusCode, err)
		}
		_ = respCp.Body.Close()

		respInCp, err := mirrorServer.Client().Get(mirrorServer.URL + "/inputlog_checkpoint")
		if err != nil || respInCp.StatusCode != http.StatusOK {
			t.Errorf("GET /inputlog_checkpoint failed: status %v, err %v", respInCp.StatusCode, err)
		}
		_ = respInCp.Body.Close()
	})

	var rawInCP1 []byte

	// 3. Mismatch Default Pinned Serving (FailClosed=false)
	t.Run("Mismatch_DefaultPinnedServing", func(t *testing.T) {
		vtc.appendLeaf([]byte("new_entry"))
		var err error
		rawInCP1, err = vtc.inReader.ReadCheckpoint(ctx)
		if err != nil {
			t.Fatalf("failed to read input checkpoint: %v", err)
		}

		advOutDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advOutDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		defer func() { _ = advLog.Close() }()

		// Append leaf 0 authentic
		if _, _, err := advLog.Append(ctx, tree.FormatOutputLogLeaf(verifiedRoot0, rawInCP0)); err != nil {
			t.Fatalf("failed to append honest leaf 0 to advLog: %v", err)
		}

		// Append leaf 1 tampered
		tamperedRoot := sha256.Sum256([]byte("bad_root_hash"))
		if _, _, err := advLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, rawInCP1)); err != nil {
			t.Fatalf("failed to append tampered leaf 1 to advLog: %v", err)
		}

		// Point outLogServer to advOutDir
		vtc.setOutputLogDir(advOutDir)

		// Trigger mismatch on the existing verifier v (which is backing mirrorServer)
		err = v.VerifyOnce(ctx)
		if err == nil {
			t.Fatal("expected VerifyOnce to fail on tampered root, got nil")
		}
		if !errors.Is(err, auditor.ErrRootMismatch) {
			t.Fatalf("expected ErrRootMismatch, got: %v", err)
		}

		// Direct lookup on mirrorServer continues to succeed (HTTP 200) pinned to last verified checkpoint
		resp, err := mirrorServer.Client().Get(mirrorServer.URL + "/vindex/lookup/" + aliceHex)
		if err != nil {
			t.Fatalf("GET /vindex/lookup failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("pinned lookup status = %d, want 200", resp.StatusCode)
		}

		// /healthz stays 200 OK while server is alive and serving authentic verified data
		respHealth, err := mirrorServer.Client().Get(mirrorServer.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		_ = respHealth.Body.Close()
		if respHealth.StatusCode != http.StatusOK {
			t.Errorf("pinned healthz = %d, want 200", respHealth.StatusCode)
		}

		// /readyz degrades to 503 with structured JSON diagnostics
		respReady, err := mirrorServer.Client().Get(mirrorServer.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz failed: %v", err)
		}
		readyBody, _ := io.ReadAll(respReady.Body)
		_ = respReady.Body.Close()
		if respReady.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("post-mismatch readyz = %d, want 503", respReady.StatusCode)
		}
		if !strings.Contains(string(readyBody), "degraded") || !strings.Contains(string(readyBody), "verifier root hash mismatch") {
			t.Errorf("readyz body missing diagnostics: %s", string(readyBody))
		}

		// /syncz alias also returns 503
		respSync, err := mirrorServer.Client().Get(mirrorServer.URL + "/syncz")
		if err != nil {
			t.Fatalf("GET /syncz failed: %v", err)
		}
		_ = respSync.Body.Close()
		if respSync.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("post-mismatch syncz = %d, want 503", respSync.StatusCode)
		}

		// Client lookup succeeds with cryptographically authentic proof
		cliResp, err := cli.Lookup(ctx, aliceKey, nil, 10)
		if err != nil {
			t.Fatalf("expected post-mismatch pinned cli.Lookup to succeed, got: %v", err)
		}
		if !cliResp.Exists || cliResp.MapRoot != verifiedRoot0 {
			t.Fatalf("pinned lookup returned unexpected proof: exists=%v, root=%x", cliResp.Exists, cliResp.MapRoot)
		}
	})

	// 4. Mismatch Fail-Closed Serving Revocation (FailClosed=true)
	t.Run("Mismatch_FailClosed_ImmediateRevocation", func(t *testing.T) {
		advOutDirFC := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLogFC, err := tree.NewPOSIXOutputLog(ctx, advOutDirFC, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLogFC: %v", err)
		}
		defer func() { _ = advLogFC.Close() }()

		if _, _, err := advLogFC.Append(ctx, tree.FormatOutputLogLeaf(verifiedRoot0, rawInCP0)); err != nil {
			t.Fatalf("failed to append honest leaf 0 to advLogFC: %v", err)
		}
		tamperedRoot := sha256.Sum256([]byte("bad_root_fc"))
		if _, _, err := advLogFC.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, rawInCP1)); err != nil {
			t.Fatalf("failed to append tampered leaf 1 to advLogFC: %v", err)
		}

		vtc.setOutputLogDir(advOutDirFC)

		fcCfg := vtc.newVerifierConfig(t, mapper, true)
		fcCfg.FailClosed = true
		vFC, err := auditor.New(fcCfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = vFC.Close() }()

		fcMux := http.NewServeMux()
		vFC.ReadServer().RegisterRoutes(fcMux)
		fcServer := httptest.NewServer(fcMux)
		defer fcServer.Close()

		cliFC, err := client.NewClient(fcServer.URL, client.VerifierConfig{
			OutputLogOrigin:   vtc.config.OutputLogOrigin,
			OutputLogVerifier: vtc.outVerifier,
			InputLogOrigin:    vtc.config.InputLogOrigin,
			InputLogVerifier:  vtc.inVerifier,
		}, fcServer.Client())
		if err != nil {
			t.Fatalf("client.NewClient failed: %v", err)
		}

		// VerifyOnce triggers mismatch on leaf 1
		err = vFC.VerifyOnce(ctx)
		if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
			t.Fatalf("expected ErrRootMismatch, got: %v", err)
		}

		// Direct lookup on fail-closed mirror must return 503
		resp, err := fcServer.Client().Get(fcServer.URL + "/vindex/lookup/" + aliceHex)
		if err != nil {
			t.Fatalf("GET /vindex/lookup failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("fail-closed lookup status = %d, want 503", resp.StatusCode)
		}

		// /healthz returns 503 in fail-closed mode
		respHealth, err := fcServer.Client().Get(fcServer.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		_ = respHealth.Body.Close()
		if respHealth.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("fail-closed healthz = %d, want 503", respHealth.StatusCode)
		}

		// /readyz returns 503
		respReady, err := fcServer.Client().Get(fcServer.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz failed: %v", err)
		}
		_ = respReady.Body.Close()
		if respReady.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("fail-closed readyz = %d, want 503", respReady.StatusCode)
		}

		if _, err := cliFC.Lookup(ctx, aliceKey, nil, 10); err == nil {
			t.Error("expected fail-closed cli.Lookup to fail with 503, got success")
		}
	})
}

func TestVerifierE2E_VerifiedMirrorServing(t *testing.T) {
	TestE2E_VerifiedMirrorServing(t)
}

// -----------------------------------------------------------------------------
// Test 4: Sourcing Invariant E2E (Zero Input Checkpoint Network Calls)
// -----------------------------------------------------------------------------

// TestE2E_SourcingInvariant_NoInputLogCheckpointCalls verifies Requirement R1 across the network wire:
// HTTP telemetry asserts exactly 0 calls to InputLog /checkpoint.
func TestE2E_SourcingInvariant_NoInputLogCheckpointCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.ResetVerifierRootMismatch()

	for i := 0; i < 20; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("entry_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper, false)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Execute full sync
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	// Assert that InputLog /checkpoint endpoint received exactly ZERO requests
	hits := vtc.inCheckpointCalls.Load()
	if hits != 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION (R1): InputLog /checkpoint received %d HTTP requests during sync, want 0", hits)
	}

	if v.Status().VerifiedInputSize != 20 {
		t.Errorf("VerifiedInputSize = %d, want 20", v.Status().VerifiedInputSize)
	}
}

func TestVerifierE2E_SourcingInvariant_NoInputCheckpointCalls(t *testing.T) {
	TestE2E_SourcingInvariant_NoInputLogCheckpointCalls(t)
}

// -----------------------------------------------------------------------------
// Test 5: Standalone CLI Execution (vindex-verify & vindexd --mode=verifier)
// -----------------------------------------------------------------------------

var (
	buildBinsOnce   sync.Once
	vindexVerifyBin string
	vindexdBin      string
	binBuildErr     error
)

func getCLIBinaries(t *testing.T) (string, string) {
	t.Helper()
	buildBinsOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "vindex-e2e-bins-*")
		if err != nil {
			binBuildErr = err
			return
		}
		vBin := filepath.Join(tmpDir, "vindex-auditor")
		cmdV := exec.Command("go", "build", "-o", vBin, "github.com/transparency-dev/incubator/vindex/v1/cmd/vindex-auditor")
		if out, err := cmdV.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("failed to build vindex-auditor: %v\n%s", err, string(out))
			return
		}
		dBin := filepath.Join(tmpDir, "vindexd")
		cmdD := exec.Command("go", "build", "-o", dBin, "github.com/transparency-dev/incubator/vindex/v1/cmd/vindexd")
		if out, err := cmdD.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("failed to build vindexd: %v\n%s", err, string(out))
			return
		}
		vindexVerifyBin = vBin
		vindexdBin = dBin
	})
	if binBuildErr != nil {
		t.Fatalf("getCLIBinaries failed: %v", binBuildErr)
	}
	return vindexVerifyBin, vindexdBin
}

// TestE2E_CLI_EntryPoints executes the compiled vindex-verify and vindexd --mode=verifier binaries
// as standalone subprocesses under honest, tampered, and invalid flag configurations.
func TestE2E_CLI_EntryPoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vBin, dBin := getCLIBinaries(t)
	vtc := newVerifierTestCluster(t, ctx, 64, 16)

	for i := 0; i < 10; i++ {
		vtc.appendLeaf([]byte(fmt.Sprintf("cli_entry_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	// 1. vindex-verify --oneshot Honest Execution
	t.Run("vindex-verify_Honest", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vindex-verify honest run failed: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Oneshot verification succeeded.") {
			t.Errorf("missing success log in vindex-verify output: %s", string(out))
		}

		// Verify persisted DB watermarks on disk
		db, err := kvstore.Open(filepath.Join(cliDir, "db"), nil)
		if err != nil {
			t.Fatalf("failed to open CLI DB: %v", err)
		}
		defer func() { _ = db.Close() }()
		outWatermark, closer, err := db.Pebble().Get(auditor.KeyVerifierOutputWatermark)
		if err != nil {
			t.Fatalf("failed to read persisted output watermark: %v", err)
		}
		if binary.BigEndian.Uint64(outWatermark) != 1 {
			t.Errorf("persisted output watermark = %d, want 1", binary.BigEndian.Uint64(outWatermark))
		}
		_ = closer.Close()
	})

	// 2. vindex-verify --oneshot Tampered Detection
	t.Run("vindex-verify_TamperedRoot", func(t *testing.T) {
		advDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		rawInCP, _ := vtc.inReader.ReadCheckpoint(ctx)
		_, _, _ = advLog.Append(ctx, tree.FormatOutputLogLeaf(sha256.Sum256([]byte("fake")), rawInCP))
		_ = advLog.Close()

		advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
		defer advSrv.Close()

		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+advSrv.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindex-verify against tampered root to exit with error, got 0")
		}
		if !strings.Contains(string(out), "root hash mismatch") && !strings.Contains(string(out), "oneshot verification failed") {
			t.Errorf("output missing root mismatch error: %s", string(out))
		}
	})

	// 3. vindexd --mode=verifier --oneshot Honest Execution
	t.Run("vindexd_verifier_Honest", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vindexd --mode=verifier honest run failed: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Oneshot verification succeeded.") {
			t.Errorf("missing success log in vindexd output: %s", string(out))
		}
	})

	// 4. vindexd --mode=verifier --oneshot Tampered Detection
	t.Run("vindexd_verifier_TamperedRoot", func(t *testing.T) {
		advDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		rawInCP, _ := vtc.inReader.ReadCheckpoint(ctx)
		_, _, _ = advLog.Append(ctx, tree.FormatOutputLogLeaf(sha256.Sum256([]byte("fake")), rawInCP))
		_ = advLog.Close()

		advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
		defer advSrv.Close()

		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_url="+advSrv.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--mapper=identity",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindexd to fail against tampered root, got exit 0")
		}
		if !strings.Contains(string(out), "root hash mismatch") && !strings.Contains(string(out), "oneshot verification failed") {
			t.Errorf("output missing root mismatch error: %s", string(out))
		}
	})

	// 5. vindexd --mode=verifier Rejection of --output_log_signer_key
	t.Run("vindexd_verifier_SecurityRejection", func(t *testing.T) {
		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, dBin,
			"--mode=verifier",
			"--output_log_signer_key=FORBIDDEN_KEY",
			"--output_log_url="+vtc.outLogServer.URL,
			"--input_log_url="+vtc.inLogServer.URL,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindexd to fail when --output_log_signer_key is specified in verifier mode, got exit 0")
		}
		if !strings.Contains(string(out), "--output_log_signer_key must not be specified in verifier mode") {
			t.Errorf("missing security error message: %s", string(out))
		}
	})
}

func TestVerifierE2E_StandaloneCLI_Execution(t *testing.T) {
	TestE2E_CLI_EntryPoints(t)
}
