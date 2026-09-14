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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
	"golang.org/x/mod/sumdb/note"
)

// corruptedInclusionProofLog wraps an OutputLogSource and corrupts inclusion proofs.
type corruptedInclusionProofLog struct {
	auditor.OutputLogSource
}

func (c *corruptedInclusionProofLog) InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	proofHashes, err := c.OutputLogSource.InclusionProof(ctx, leafIdx, treeSize)
	if err != nil {
		return nil, err
	}
	corrupted := make([][sha256.Size]byte, len(proofHashes))
	copy(corrupted, proofHashes)
	if len(corrupted) > 0 {
		corrupted[0][0] ^= 0xff
	} else {
		corrupted = append(corrupted, sha256.Sum256([]byte("bogus_proof_element")))
	}
	return corrupted, nil
}

// dynamicCheckpointLog allows dynamically overriding the checkpoint returned by an OutputLogSource.
type dynamicCheckpointLog struct {
	auditor.OutputLogSource
	mu        sync.Mutex
	customCP  []byte
	useCustom bool
}

func (d *dynamicCheckpointLog) SetCheckpoint(raw []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.customCP = raw
	d.useCustom = true
}

func (d *dynamicCheckpointLog) Checkpoint(ctx context.Context) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.useCustom {
		return d.customCP, nil
	}
	return d.OutputLogSource.Checkpoint(ctx)
}

// forgedCheckpointLog wraps an OutputLogSource and returns a validly signed checkpoint
// with a forged Merkle root hash.
type forgedCheckpointLog struct {
	auditor.OutputLogSource
	origin     string
	size       uint64
	forgedRoot [sha256.Size]byte
	signer     note.Signer
}

func (f *forgedCheckpointLog) Checkpoint(_ context.Context) ([]byte, error) {
	text := fmt.Sprintf("%s\n%d\n%s\n", f.origin, f.size, base64.StdEncoding.EncodeToString(f.forgedRoot[:]))
	return note.Sign(&note.Note{Text: text}, f.signer)
}

// TestStress_Tamper_ForgedOutputLogLeafRoot tests injecting a forged MPT root into an OutputLog leaf.
func TestStress_Tamper_ForgedOutputLogLeafRoot(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 1. Append authentic leaf 0
	h.inLog.AppendLeaf([]byte("authentic-leaf-0"))
	genuineRoot0 := computeExpectedMapRoot(t, [][]byte{[]byte("authentic-leaf-0")}, h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(genuineRoot0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	// 2. Append leaf 1 with forged MapRoot
	h.inLog.AppendLeaf([]byte("authentic-leaf-1"))
	forgedRoot1 := sha256.Sum256([]byte("adversarial_forged_root_seed_987"))
	signedInCP1, err := h.inLog.SignCheckpoint(2)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(forgedRoot1, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	initialMismatches := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal)

	// Verify leaf 0 and leaf 1
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	// Verify immediate halting
	st := v.Status()
	if !st.IsHalted {
		t.Fatal("verifier should be permanently halted")
	}
	if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 1 {
		t.Fatalf("watermarks incorrectly advanced on mismatch: output=%d, input=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
	}

	// Verify metric recording
	if gVal := testutil.ToFloat64(metrics.VerifierRootMismatch); gVal != 1.0 {
		t.Errorf("VerifierRootMismatch gauge = %v, want 1.0", gVal)
	}
	if cVal := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal); cVal != initialMismatches+1 {
		t.Errorf("VerifierRootMismatchesTotal = %v, want %v", cVal, initialMismatches+1)
	}

	// Verify health check returns error
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", hErr)
	}

	// Verify repeated VerifyOnce immediately returns halt error without doing work
	if secondErr := v.VerifyOnce(ctx); secondErr == nil || !errors.Is(secondErr, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", secondErr)
	}
}

// TestStress_Tamper_CorruptInputLeafData tests corrupting input leaf data against an authentic MapRoot commitment.
func TestStress_Tamper_CorruptInputLeafData(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// 5 genuine leaves
	genuineLeaves := [][]byte{
		[]byte("valid-entry-0"),
		[]byte("valid-entry-1"),
		[]byte("valid-entry-2"),
		[]byte("valid-entry-3"),
		[]byte("valid-entry-4"),
	}
	genuineRoot := computeExpectedMapRoot(t, genuineLeaves, h.mapper)

	// Feed corrupted leaves into InputLog (corrupt leaf 3)
	for i, l := range genuineLeaves {
		if i == 3 {
			h.inLog.AppendLeaf([]byte("BIT-FLIPPED-CORRUPTED-ENTRY"))
		} else {
			h.inLog.AppendLeaf(l)
		}
	}

	// OutputLog commits to the genuine root
	signedInCP, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(genuineRoot, signedInCP)); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	initialMismatches := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal)

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	// Assert immediate halting and metrics
	st := v.Status()
	if !st.IsHalted {
		t.Fatal("verifier should be halted")
	}
	if st.VerifiedOutputSize != 0 || st.VerifiedInputSize != 0 {
		t.Errorf("watermarks should remain 0, got output=%d input=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
	}
	if gVal := testutil.ToFloat64(metrics.VerifierRootMismatch); gVal != 1.0 {
		t.Errorf("VerifierRootMismatch gauge = %v, want 1.0", gVal)
	}
	if cVal := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal); cVal != initialMismatches+1 {
		t.Errorf("VerifierRootMismatchesTotal = %v, want %v", cVal, initialMismatches+1)
	}
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", hErr)
	}
}

// TestStress_Tamper_NonMonotonicTreeSize tests injecting non-monotonic tree sizes.
func TestStress_Tamper_NonMonotonicTreeSize(t *testing.T) {
	ctx := context.Background()

	t.Run("InputLog_TreeSize_Regression", func(t *testing.T) {
		h := newTestHarness(t)
		for i := 0; i < 15; i++ {
			h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
		}

		// Leaf 0: size 10
		signedCP0, _ := h.inLog.SignCheckpoint(10)
		leaves10 := make([][]byte, 10)
		for i := 0; i < 10; i++ {
			leaves10[i] = []byte(fmt.Sprintf("entry-%d", i))
		}
		root0 := computeExpectedMapRoot(t, leaves10, h.mapper)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedCP0))

		// Leaf 1: claims regressed size 5 (< 10)
		signedCP1, _ := h.inLog.SignCheckpoint(5)
		leaves5 := make([][]byte, 5)
		for i := 0; i < 5; i++ {
			leaves5[i] = []byte(fmt.Sprintf("entry-%d", i))
		}
		root1 := computeExpectedMapRoot(t, leaves5, h.mapper)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, signedCP1))

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   "example.com/test/outputlog",
			InputLogOrigin:    "example.com/test/inputlog",
			OutputLog:         h.outLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		err = v.VerifyOnce(ctx)
		if err == nil || !errors.Is(err, auditor.ErrMonotonicityBroken) {
			t.Fatalf("expected ErrMonotonicityBroken, got: %v", err)
		}

		st := v.Status()
		if !st.IsHalted {
			t.Fatal("verifier should be halted on non-monotonic input size")
		}
		if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 10 {
			t.Errorf("watermarks should freeze at leaf 0 (out=1, in=10), got out=%d in=%d", st.VerifiedOutputSize, st.VerifiedInputSize)
		}
		if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrMonotonicityBroken) {
			t.Errorf("HealthCheck() = %v, want ErrMonotonicityBroken", hErr)
		}
	})

	t.Run("OutputLog_TreeSize_Regression", func(t *testing.T) {
		h := newTestHarness(t)
		h.inLog.AppendLeaf([]byte("entry-0"))
		signedCP, _ := h.inLog.SignCheckpoint(1)
		root := computeExpectedMapRoot(t, [][]byte{[]byte("entry-0")}, h.mapper)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedCP))

		dynLog := &dynamicCheckpointLog{OutputLogSource: h.outLog}

		cfg := auditor.Config{
			InputLogVerifier:  h.inVerifier,
			OutputLogVerifier: h.outVerifier,
			OutputLogOrigin:   "example.com/test/outputlog",
			InputLogOrigin:    "example.com/test/inputlog",
			OutputLog:         dynLog,
			InputLogFetcher:   h.inLog,
			MapFn:             h.mapper,
			DBPath:            ":memory:",
			MPTDir:            ":memory:",
		}
		v, err := auditor.New(cfg)
		if err != nil {
			t.Fatalf("auditor.New failed: %v", err)
		}
		defer func() { _ = v.Close() }()

		// Run honest sync for leaf 0
		if err := v.VerifyOnce(ctx); err != nil {
			t.Fatalf("first VerifyOnce failed: %v", err)
		}
		if v.Status().VerifiedOutputSize != 1 {
			t.Fatalf("verified output size = %d, want 1", v.Status().VerifiedOutputSize)
		}

		// Inject a regressed OutputLog checkpoint with size 0 (< 1)
		emptyRoot := sha256.Sum256([]byte("empty_root"))
		text := fmt.Sprintf("%s\n%d\n%s\n", "example.com/test/outputlog", 0, base64.StdEncoding.EncodeToString(emptyRoot[:]))
		regressedCP, err := note.Sign(&note.Note{Text: text}, h.outSigner)
		if err != nil {
			t.Fatalf("note.Sign failed: %v", err)
		}
		dynLog.SetCheckpoint(regressedCP)

		// Verify that VerifyOnce detects regression and halts
		err = v.VerifyOnce(ctx)
		if err == nil || !errors.Is(err, auditor.ErrOutputLogRegressed) {
			t.Fatalf("expected ErrOutputLogRegressed, got: %v", err)
		}

		st := v.Status()
		if !st.IsHalted {
			t.Fatal("verifier should be halted on regressed output log size")
		}
		if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrOutputLogRegressed) {
			t.Errorf("HealthCheck() = %v, want ErrOutputLogRegressed", hErr)
		}
	})
}

// TestStress_Tamper_CorruptInclusionProof tests immediate halting when inclusion proofs are corrupted.
func TestStress_Tamper_CorruptInclusionProof(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	// Append 2 leaves
	for i := 0; i < 2; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
		signedCP, _ := h.inLog.SignCheckpoint(uint64(i + 1))
		leaves := make([][]byte, i+1)
		for j := 0; j <= i; j++ {
			leaves[j] = []byte(fmt.Sprintf("entry-%d", j))
		}
		root := computeExpectedMapRoot(t, leaves, h.mapper)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedCP))
	}

	// Wrap OutputLog with corrupted inclusion proof source
	corruptLog := &corruptedInclusionProofLog{
		OutputLogSource: h.outLog,
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         corruptLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrInclusionFailed) {
		t.Fatalf("VerifyOnce = %v, want ErrInclusionFailed", err)
	}

	// Verify immediate halting and watermarks frozen
	st := v.Status()
	if !st.IsHalted {
		t.Fatal("verifier should be halted on inclusion proof failure")
	}
	if st.VerifiedOutputSize != 0 {
		t.Errorf("VerifiedOutputSize = %d, want 0 (frozen)", st.VerifiedOutputSize)
	}
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrInclusionFailed) {
		t.Errorf("HealthCheck() = %v, want ErrInclusionFailed", hErr)
	}

	// Subsequent VerifyOnce must immediately return halt error
	if secondErr := v.VerifyOnce(ctx); secondErr == nil || !errors.Is(secondErr, auditor.ErrInclusionFailed) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrInclusionFailed", secondErr)
	}
}

// TestStress_Tamper_ForgedCheckpointTreeRoot tests that a validly signed OutputLog checkpoint
// that commits to a forged Merkle root hash causes inclusion proof verification to fail immediately.
func TestStress_Tamper_ForgedCheckpointTreeRoot(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	// Append 2 leaves
	for i := 0; i < 2; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
		signedCP, _ := h.inLog.SignCheckpoint(uint64(i + 1))
		leaves := make([][]byte, i+1)
		for j := 0; j <= i; j++ {
			leaves[j] = []byte(fmt.Sprintf("entry-%d", j))
		}
		root := computeExpectedMapRoot(t, leaves, h.mapper)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedCP))
	}

	// Checkpoint signer signs forged tree root
	forgedLog := &forgedCheckpointLog{
		OutputLogSource: h.outLog,
		origin:          "example.com/test/outputlog",
		size:            2,
		forgedRoot:      sha256.Sum256([]byte("forged_checkpoint_tree_root_001")),
		signer:          h.outSigner,
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         forgedLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrInclusionFailed) {
		t.Fatalf("VerifyOnce = %v, want ErrInclusionFailed", err)
	}

	st := v.Status()
	if !st.IsHalted {
		t.Fatal("verifier should be halted on forged checkpoint root")
	}
	if st.VerifiedOutputSize != 0 {
		t.Errorf("VerifiedOutputSize = %d, want 0 (frozen)", st.VerifiedOutputSize)
	}
}

// TestStress_InvariantR1_ExhaustiveNoCheckpointCalls asserts that across all sync modes
// (multi-leaf, incremental, zero-delta, mismatch, tampered, non-monotonic, corrupt inclusion),
// the verifier NEVER invokes InputLog.Checkpoint().
func TestStress_InvariantR1_ExhaustiveNoCheckpointCalls(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 30; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("leaf-%03d", i)))
	}

	// Publish 3 leaves: sizes 10, 20, 30
	for _, sz := range []uint64{10, 20, 30} {
		leaves := make([][]byte, sz)
		for i := uint64(0); i < sz; i++ {
			leaves[i] = []byte(fmt.Sprintf("leaf-%03d", i))
		}
		root := computeExpectedMapRoot(t, leaves, h.mapper)
		signedCP, _ := h.inLog.SignCheckpoint(sz)
		_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedCP))
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            ":memory:",
		MPTDir:            ":memory:",
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// 1. Initial pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	// 2. Zero-delta pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("zero-delta VerifyOnce failed: %v", err)
	}

	// Check checkpoint call count
	h.inLog.mu.Lock()
	count := h.inLog.checkpointCallCount
	h.inLog.mu.Unlock()
	if count != 0 {
		t.Fatalf("INVARIANT VIOLATION (R1): InputLog.Checkpoint was called %d times (want 0)", count)
	}

	// 3. Confirm guard panic on direct invocation
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic when calling Checkpoint on wrapped fetcher")
			}
			msg := fmt.Sprint(r)
			want := "INVARIANT VIOLATION (R1): verifier attempted to call InputLog.Checkpoint()"
			if msg != want {
				t.Errorf("got panic %q, want %q", msg, want)
			}
		}()
		_, _ = v.InputFetcher().Checkpoint(ctx)
	}()
}

// TestStress_Concurrency_RaceConditions demonstrates that concurrent calls to v.Status()
// and v.VerifyOnce() trigger a data race because verifiedInputSize and verifiedOutputSize
// in VerifyOnce are updated without holding stateMu.
func TestStress_Concurrency_RaceConditions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h := newTestHarness(t)

	// Preload 10 leaves
	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("concurrent-entry-%d", i)))
	}
	leaves10 := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		leaves10[i] = []byte(fmt.Sprintf("concurrent-entry-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves10, h.mapper)
	signedCP0, _ := h.inLog.SignCheckpoint(10)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedCP0))

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
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

	var wg sync.WaitGroup

	// Reader goroutines querying Status, HealthCheck, and HTTP /healthz
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = v.Status()
					_ = v.HealthCheck()
					if readServer != nil {
						req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
						rec := httptest.NewRecorder()
						readServer.HandleHealthz(rec, req)
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Writer/Sync goroutine running VerifyOnce periodically
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = v.VerifyOnce(ctx)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
}

// TestStress_Concurrency_HealthCheckOnly verifies whether HealthCheck and HandleHealthz
// are free from data races with VerifyOnce.
func TestStress_Concurrency_HealthCheckOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h := newTestHarness(t)

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("concurrent-entry-%d", i)))
	}
	leaves10 := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		leaves10[i] = []byte(fmt.Sprintf("concurrent-entry-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves10, h.mapper)
	signedCP0, _ := h.inLog.SignCheckpoint(10)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedCP0))

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
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
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = v.HealthCheck()
					if readServer != nil {
						req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
						rec := httptest.NewRecorder()
						readServer.HandleHealthz(rec, req)
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = v.VerifyOnce(ctx)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
}
