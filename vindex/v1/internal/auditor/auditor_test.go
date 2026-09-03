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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
	"golang.org/x/mod/sumdb/note"
)

// testIdentityMapper maps each leaf to a single search key: SHA-256 of the leaf bytes.
type testIdentityMapper struct{}

func (m *testIdentityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	h := sha256.Sum256(leaf)
	return []ingest.MappedEntry{{KeyHash: h}}, nil
}

func (m *testIdentityMapper) Close(_ context.Context) error {
	return nil
}

// memoryOutputLog implements verifier.OutputLogSource in memory with RFC 6962 inclusion proofs.
type memoryOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func (l *memoryOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	l.leaves = append(l.leaves, leafData)
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return 0, nil, err
		}
		return idx, signed, nil
	}
	raw := []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:])))
	return idx, raw, nil
}

func (l *memoryOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		return note.Sign(&note.Note{Text: text}, l.signer)
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (l *memoryOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (%d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *memoryOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if treeSize > uint64(len(l.leaves)) {
		treeSize = uint64(len(l.leaves))
	}
	var leafHashes [][sha256.Size]byte
	for _, leaf := range l.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(leaf))
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		var k uint64 = 1
		for k*2 < uint64(n) {
			k *= 2
		}
		if idx < k {
			buildProof(leaves[:k], idx)
			proof = append(proof, kvstore.BatchRootHashes(leaves[k:]))
		} else {
			buildProof(leaves[k:], idx-k)
			proof = append(proof, kvstore.BatchRootHashes(leaves[:k]))
		}
	}
	buildProof(leafHashes, leafIdx)
	return proof, nil
}

// memoryInputLog implements ingest.TileFetcher and tracks Checkpoint() call count to verify R1.
type memoryInputLog struct {
	mu                  sync.Mutex
	leaves              [][]byte
	origin              string
	signer              note.Signer
	checkpointCallCount int
	treeSize            uint64
	bundleSize          uint64
}

func (l *memoryInputLog) SetTreeSize(size uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.treeSize = size
}

func (l *memoryInputLog) AppendLeaf(leaf []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaves = append(l.leaves, leaf)
}

func (l *memoryInputLog) SignCheckpoint(size uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var leavesSlice [][]byte
	if size <= uint64(len(l.leaves)) {
		leavesSlice = l.leaves[:size]
	} else {
		leavesSlice = l.leaves
	}
	root := kvstore.BatchRoot(leavesSlice)
	text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return note.Sign(&note.Note{Text: text}, l.signer)
}

func (l *memoryInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	l.checkpointCallCount++
	l.mu.Unlock()
	return nil, errors.New("Checkpoint() should not be called in verifier mode (R1 violation)")
}

func (l *memoryInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds", idx)
	}
	return l.leaves[idx], nil
}

func (l *memoryInputLog) FetchTiles(_ context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	bundleSize := l.bundleSize
	if bundleSize == 0 {
		bundleSize = 256
	}

	maxLeaf := uint64(len(l.leaves))
	if l.treeSize > 0 && l.treeSize < maxLeaf {
		maxLeaf = l.treeSize
	}

	endIdx := startLeafIdx + count
	if endIdx > maxLeaf {
		endIdx = maxLeaf
	}
	if startLeafIdx >= endIdx {
		return nil, nil
	}

	var bundles []*ingest.LeafBundle
	startBundle := startLeafIdx / bundleSize
	endBundle := (endIdx - 1) / bundleSize

	for bIdx := startBundle; bIdx <= endBundle; bIdx++ {
		bStart := bIdx * bundleSize
		bEnd := bStart + bundleSize
		if bEnd > maxLeaf {
			bEnd = maxLeaf
		}
		if bStart >= bEnd {
			continue
		}
		bundle := &ingest.LeafBundle{
			BundleIdx:    bIdx,
			StartLeafIdx: bStart,
			Leaves:       make([][]byte, bEnd-bStart),
		}
		for i := bStart; i < bEnd; i++ {
			bundle.Leaves[i-bStart] = l.leaves[i]
		}
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

// computeExpectedMapRoot computes the authentic Merkle Patricia Trie root resulting from
// mapping and indexing the given input leaves.
func computeExpectedMapRoot(t *testing.T, leaves [][]byte, mapper ingest.LeafMapper) [sha256.Size]byte {
	t.Helper()
	db, err := kvstore.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexer := kvstore.NewKVIndexer(db, 65536)
	mptMgr := tree.NewMem()
	defer func() { _ = mptMgr.Close() }()

	allModified := make(map[[sha256.Size]byte][sha256.Size]byte)
	for i, leaf := range leaves {
		entries, err := mapper.MapLeaf(context.Background(), leaf)
		if err != nil {
			t.Fatalf("MapLeaf failed: %v", err)
		}
		keyMap := make(map[[32]byte][]uint64)
		for _, e := range entries {
			keyMap[e.KeyHash] = append(keyMap[e.KeyHash], uint64(i))
		}
		batch := &ingest.MappedBatch{
			BundleIdx:    uint64(i / 256),
			StartLeafIdx: uint64(i),
			EndLeafIdx:   uint64(i + 1),
			Count:        1,
			KeyMap:       keyMap,
		}
		res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, uint64(len(leaves)))
		if err != nil {
			t.Fatalf("IndexMappedBatch failed: %v", err)
		}
		for k, v := range res.ModifiedSubRoots {
			allModified[k] = v
		}
	}
	root, err := mptMgr.CommitWithVersion(allModified, int64(len(leaves)))
	if err != nil {
		t.Fatalf("CommitWithVersion failed: %v", err)
	}
	return root
}

type testHarness struct {
	inSigner    note.Signer
	inVerifier  note.Verifier
	outSigner   note.Signer
	outVerifier note.Verifier
	inLog       *memoryInputLog
	outLog      *memoryOutputLog
	mapper      ingest.LeafMapper
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "example.com/test/inputlog")
	if err != nil {
		t.Fatalf("GenerateKey inputlog failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner inputlog failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier inputlog failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/test/outputlog")
	if err != nil {
		t.Fatalf("GenerateKey outputlog failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("NewSigner outputlog failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier outputlog failed: %v", err)
	}

	inLog := &memoryInputLog{
		origin: "example.com/test/inputlog",
		signer: inSigner,
	}
	outLog := &memoryOutputLog{
		origin: "example.com/test/outputlog",
		signer: outSigner,
	}

	return &testHarness{
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		outSigner:   outSigner,
		outVerifier: outVerifier,
		inLog:       inLog,
		outLog:      outLog,
		mapper:      &testIdentityMapper{},
	}
}

// TestVerifier_HonestSync verifies honest progression across multiple OutputLog leaves:
// watermarks advance, calculated roots match commitments, and healthcheck remains healthy.
func TestVerifier_HonestSync(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	// Populate InputLog with 10 leaves
	var rawLeaves [][]byte
	for i := 0; i < 10; i++ {
		leaf := []byte(fmt.Sprintf("certificate-entry-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}

	// OutputLog leaf 0: commits to input size 5
	root0 := computeExpectedMapRoot(t, rawLeaves[:5], h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint(5) failed: %v", err)
	}
	leafData0 := tree.FormatOutputLogLeaf(root0, signedInCP0)
	if _, _, err := h.outLog.Append(ctx, leafData0); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	// OutputLog leaf 1: commits to input size 10
	root1 := computeExpectedMapRoot(t, rawLeaves[:10], h.mapper)
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	leafData1 := tree.FormatOutputLogLeaf(root1, signedInCP1)
	if _, _, err := h.outLog.Append(ctx, leafData1); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// Initialize verifier in memory
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

	// Initial status check
	st := v.Status()
	if st.IsHalted || st.VerifiedOutputSize != 0 || st.VerifiedInputSize != 0 {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	// Run first verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed on honest sync: %v", err)
	}

	st = v.Status()
	if st.IsHalted {
		t.Fatalf("verifier unexpectedly halted: %v", st.HaltError)
	}
	if st.VerifiedOutputSize != 2 {
		t.Errorf("VerifiedOutputSize = %d, want 2", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 10 {
		t.Errorf("VerifiedInputSize = %d, want 10", st.VerifiedInputSize)
	}
	if st.LastVerifiedRoot != root1 {
		t.Errorf("LastVerifiedRoot = %x, want %x", st.LastVerifiedRoot, root1)
	}
	if err := v.HealthCheck(); err != nil {
		t.Errorf("HealthCheck() = %v, want nil", err)
	}

	// Add 5 more leaves (total 15) and publish OutputLog leaf 2
	for i := 10; i < 15; i++ {
		leaf := []byte(fmt.Sprintf("certificate-entry-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}
	root2 := computeExpectedMapRoot(t, rawLeaves[:15], h.mapper)
	signedInCP2, err := h.inLog.SignCheckpoint(15)
	if err != nil {
		t.Fatalf("SignCheckpoint(15) failed: %v", err)
	}
	leafData2 := tree.FormatOutputLogLeaf(root2, signedInCP2)
	if _, _, err := h.outLog.Append(ctx, leafData2); err != nil {
		t.Fatalf("Append leaf 2 failed: %v", err)
	}

	// Verify incremental progression
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("second VerifyOnce failed: %v", err)
	}

	st = v.Status()
	if st.VerifiedOutputSize != 3 || st.VerifiedInputSize != 15 || st.LastVerifiedRoot != root2 {
		t.Errorf("incremental sync status incorrect: %+v", st)
	}
}

// TestVerifier_RootMismatchDetection verifies that a tampered root hash committed in an OutputLog leaf
// is detected immediately, records Prometheus metrics, sets health unhealthy, and halts progress without advancing watermarks.
func TestVerifier_RootMismatchDetection(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// Populate InputLog with 10 leaves
	var rawLeaves [][]byte
	for i := 0; i < 10; i++ {
		leaf := []byte(fmt.Sprintf("entry-%d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}

	// Leaf 0: Honest commitment (size 5)
	root0 := computeExpectedMapRoot(t, rawLeaves[:5], h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	// Leaf 1: Tampered commitment with forged MapRoot
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, signedInCP1)); err != nil {
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

	// Execute verification pass
	err = v.VerifyOnce(ctx)
	if err == nil {
		t.Fatal("VerifyOnce succeeded, want RootMismatchError")
	}
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("err = %v, want errors.Is(ErrRootMismatch)", err)
	}

	var rootErr *auditor.RootMismatchError
	if !errors.As(err, &rootErr) {
		t.Fatalf("err is not of type *RootMismatchError: %T", err)
	}
	if rootErr.OutputIndex != 1 {
		t.Errorf("mismatch OutputIndex = %d, want 1", rootErr.OutputIndex)
	}
	if rootErr.InputSize != 10 {
		t.Errorf("mismatch InputSize = %d, want 10", rootErr.InputSize)
	}
	if rootErr.CommittedMapRoot != tamperedRoot {
		t.Errorf("CommittedMapRoot = %x, want %x", rootErr.CommittedMapRoot, tamperedRoot)
	}

	// Assert Prometheus gauge is 1
	if gVal := testutil.ToFloat64(metrics.VerifierRootMismatch); gVal != 1.0 {
		t.Errorf("VerifierRootMismatch gauge = %v, want 1.0", gVal)
	}

	// Assert HealthCheck returns the error
	if hErr := v.HealthCheck(); hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", hErr)
	}

	// Assert watermarks are frozen at leaf 0 (leaf 1 did NOT advance watermarks)
	st := v.Status()
	if !st.IsHalted {
		t.Error("verifier status should be halted")
	}
	if st.VerifiedOutputSize != 1 {
		t.Errorf("VerifiedOutputSize = %d, want 1 (frozen)", st.VerifiedOutputSize)
	}
	if st.VerifiedInputSize != 5 {
		t.Errorf("VerifiedInputSize = %d, want 5 (frozen)", st.VerifiedInputSize)
	}

	// Subsequent VerifyOnce must immediately fail with the halt error
	secondErr := v.VerifyOnce(ctx)
	if secondErr == nil || !errors.Is(secondErr, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", secondErr)
	}
}

// TestVerifier_TamperedInputLeafData verifies that altering input leaf contents causes the local
// MPT root to diverge from the published commitment, triggering immediate mismatch detection.
func TestVerifier_TamperedInputLeafData(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// Populate authentic leaves
	var rawLeaves [][]byte
	for i := 0; i < 5; i++ {
		leaf := []byte(fmt.Sprintf("authentic-entry-%d", i))
		rawLeaves = append(rawLeaves, leaf)
	}

	// Genuine MPT root computed from authentic leaves
	genuineRoot := computeExpectedMapRoot(t, rawLeaves, h.mapper)

	// In the InputLog fetcher, inject tampered content for entry 2
	for i, l := range rawLeaves {
		if i == 2 {
			h.inLog.AppendLeaf([]byte("MALICIOUS-TAMPERED-CONTENT"))
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
		t.Fatalf("Append leaf failed: %v", err)
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

	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("VerifyOnce = %v, want ErrRootMismatch", err)
	}

	if hErr := v.HealthCheck(); hErr == nil {
		t.Fatal("HealthCheck() should be unhealthy on tampered input leaf")
	}

	st := v.Status()
	if st.VerifiedOutputSize != 0 {
		t.Errorf("VerifiedOutputSize = %d, want 0", st.VerifiedOutputSize)
	}
}

// TestVerifier_SourcingInvariant_NoInputLogCheckpointCalls strictly verifies Requirement R1:
// the verifier derives all target tree sizes solely from OutputLog leaves and makes ZERO calls to InputLog's checkpoint endpoint.
func TestVerifier_SourcingInvariant_NoInputLogCheckpointCalls(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 20; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	// Publish 2 OutputLog leaves
	for _, sz := range []uint64{10, 20} {
		leaves := make([][]byte, sz)
		for i := uint64(0); i < sz; i++ {
			leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
		}
		root := computeExpectedMapRoot(t, leaves, h.mapper)
		signedInCP, err := h.inLog.SignCheckpoint(sz)
		if err != nil {
			t.Fatalf("SignCheckpoint failed: %v", err)
		}
		if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedInCP)); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
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

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	// Assert zero calls to InputLog checkpoint endpoint
	h.inLog.mu.Lock()
	cpCalls := h.inLog.checkpointCallCount
	h.inLog.mu.Unlock()
	if cpCalls != 0 {
		t.Fatalf("INVARIANT VIOLATION (R1): InputLog.Checkpoint was called %d times during sync (want 0)", cpCalls)
	}

	// Assert that calling Checkpoint directly on the wrapped fetcher panics as guarded
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic when calling Checkpoint() on verifier's input fetcher")
			}
			msg := fmt.Sprint(r)
			if msg != "INVARIANT VIOLATION (R1): verifier attempted to call InputLog.Checkpoint()" {
				t.Errorf("unexpected panic message: %s", msg)
			}
		}()
		// Trigger the guard panic
		_, _ = v.InputFetcher().Checkpoint(ctx)
	}()
}

// TestVerifier_HTTPHealthzHook verifies that hooking v.HealthCheck into server.ReadServer.SetHealthChecker
// causes GET /healthz to transition from HTTP 200 OK to HTTP 503 Service Unavailable when a mismatch occurs.
func TestVerifier_HTTPHealthzHook(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves, h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
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
		t.Fatal("expected ReadServer to be initialized when ServeMirror: true")
	}

	// 1. Initial healthy state check on /healthz
	reqHealthy := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealthy := httptest.NewRecorder()
	readServer.HandleHealthz(recHealthy, reqHealthy)
	if recHealthy.Code != http.StatusOK {
		t.Fatalf("before mismatch: /healthz returned status %d, want 200 OK", recHealthy.Code)
	}

	// Verify honest leaf 0
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce leaf 0 failed: %v", err)
	}

	reqPostSync := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recPostSync := httptest.NewRecorder()
	readServer.HandleHealthz(recPostSync, reqPostSync)
	if recPostSync.Code != http.StatusOK {
		t.Fatalf("after honest sync: /healthz returned status %d, want 200 OK", recPostSync.Code)
	}

	// 2. Append tampered OutputLog leaf 1
	tamperedRoot := sha256.Sum256([]byte("corrupted_root"))
	signedInCP1, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// Execute verification to trigger mismatch
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	// 3. Verify /healthz degrades to 503 Service Unavailable
	reqUnhealthy := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recUnhealthy := httptest.NewRecorder()
	readServer.HandleHealthz(recUnhealthy, reqUnhealthy)
	if recUnhealthy.Code != http.StatusServiceUnavailable {
		t.Fatalf("after mismatch: /healthz returned status %d, want 503 Service Unavailable", recUnhealthy.Code)
	}
	body := recUnhealthy.Body.String()
	if recUnhealthy.Body.Len() == 0 {
		t.Fatal("expected non-empty error body from /healthz")
	}
	if !errors.Is(v.HealthCheck(), auditor.ErrRootMismatch) {
		t.Errorf("HealthCheck() = %v, want ErrRootMismatch", v.HealthCheck())
	}
	t.Logf("Degraded /healthz response: %s", body)
}

// TestVerifier_PrometheusMetrics verifies that Prometheus metrics vindex_verifier_root_mismatch
// and vindex_verifier_root_mismatches_total are correctly updated on mismatch events.
func TestVerifier_PrometheusMetrics(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// Initial metrics baseline
	initialTotal := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal)
	if gVal := testutil.ToFloat64(metrics.VerifierRootMismatch); gVal != 0 {
		t.Fatalf("initial VerifierRootMismatch = %v, want 0", gVal)
	}

	h.inLog.AppendLeaf([]byte("entry-0"))
	tamperedRoot := sha256.Sum256([]byte("wrong_hash"))
	signedInCP, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, signedInCP)); err != nil {
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

	_ = v.VerifyOnce(ctx)

	// Post-mismatch metrics check
	if gVal := testutil.ToFloat64(metrics.VerifierRootMismatch); gVal != 1.0 {
		t.Errorf("post-mismatch VerifierRootMismatch = %v, want 1.0", gVal)
	}
	currentTotal := testutil.ToFloat64(metrics.VerifierRootMismatchesTotal)
	if currentTotal != initialTotal+1 {
		t.Errorf("VerifierRootMismatchesTotal = %v, want %v", currentTotal, initialTotal+1)
	}
}

// TestVerifier_PersistenceAndRecovery verifies that watermarks and verified state survive restarts on disk.
func TestVerifier_PersistenceAndRecovery(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	dbDir := t.TempDir()
	mptDir := t.TempDir()

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("recovery-leaf-%d", i)))
	}

	leaves5 := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves5[i] = []byte(fmt.Sprintf("recovery-leaf-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves5, h.mapper)
	signedInCP0, err := h.inLog.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedInCP0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   h.inLog,
		MapFn:             h.mapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
	}

	// 1. First run: verify leaf 0
	v1, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}
	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}
	st1 := v1.Status()
	if st1.VerifiedOutputSize != 1 || st1.VerifiedInputSize != 5 || st1.LastVerifiedRoot != root0 {
		t.Fatalf("v1 status incorrect: %+v", st1)
	}
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// 2. Second run: initialize new verifier pointing to same storage
	v2, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	// Immediately assert watermarks were recovered from disk
	st2 := v2.Status()
	if st2.VerifiedOutputSize != 1 {
		t.Errorf("v2 recovered VerifiedOutputSize = %d, want 1", st2.VerifiedOutputSize)
	}
	if st2.VerifiedInputSize != 5 {
		t.Errorf("v2 recovered VerifiedInputSize = %d, want 5", st2.VerifiedInputSize)
	}
	if st2.LastVerifiedRoot != root0 {
		t.Errorf("v2 recovered LastVerifiedRoot = %x, want %x", st2.LastVerifiedRoot, root0)
	}

	// 3. Incremental verification: append leaf 1 (size 10) and verify with v2
	leaves10 := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		leaves10[i] = []byte(fmt.Sprintf("recovery-leaf-%d", i))
	}
	root1 := computeExpectedMapRoot(t, leaves10, h.mapper)
	signedInCP1, err := h.inLog.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, signedInCP1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	st2Updated := v2.Status()
	if st2Updated.VerifiedOutputSize != 2 || st2Updated.VerifiedInputSize != 10 || st2Updated.LastVerifiedRoot != root1 {
		t.Errorf("v2 updated status incorrect: %+v", st2Updated)
	}
}

// TestVerifier_NonMonotonicInputSize verifies that an OutputLog leaf claiming a regressed input size
// triggers ErrMonotonicityBroken and halts.
func TestVerifier_NonMonotonicInputSize(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 10; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	// Leaf 0: size 8
	signedInCP0, _ := h.inLog.SignCheckpoint(8)
	leaves8 := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		leaves8[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves8, h.mapper)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, signedInCP0))

	// Leaf 1: claims regressed size 4 (< 8)
	signedInCP1, _ := h.inLog.SignCheckpoint(4)
	leaves4 := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		leaves4[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root1 := computeExpectedMapRoot(t, leaves4, h.mapper)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, signedInCP1))

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
	if hErr := v.HealthCheck(); hErr == nil {
		t.Error("expected unhealthy healthcheck on broken monotonicity")
	}
}

// TestVerifier_ZeroDeltaSync verifies that an OutputLog leaf committing to the same input size
// as the previous leaf (zero new input leaves) correctly verifies root equality.
func TestVerifier_ZeroDeltaSync(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}

	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root := computeExpectedMapRoot(t, leaves, h.mapper)
	signedInCP, _ := h.inLog.SignCheckpoint(5)

	// Two consecutive OutputLog leaves with identical input size 5 and identical root
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedInCP))
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root, signedInCP))

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

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed on zero-delta leaves: %v", err)
	}

	st := v.Status()
	if st.VerifiedOutputSize != 2 || st.VerifiedInputSize != 5 {
		t.Errorf("status incorrect: %+v", st)
	}
}

func TestVerifier_Run_HaltOnInvariantError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newTestHarness(t)

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("entry-%d", i)))
	}
	leaves5 := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves5[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	root5 := computeExpectedMapRoot(t, leaves5, h.mapper)
	signedInCP5, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root5, signedInCP5))

	// Second leaf regressions input size from 5 to 2 (ErrMonotonicityBroken)
	signedInCP2, _ := h.inLog.SignCheckpoint(2)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root5, signedInCP2))

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
		PollInterval:      20 * time.Millisecond,
	}
	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.Run(ctx)
	}()

	// Wait for verifier to halt on the invariant error
	deadline := time.Now().Add(2 * time.Second)
	for !v.Status().IsHalted && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	st := v.Status()
	if !st.IsHalted {
		t.Fatalf("expected verifier to be halted on invariant error, but got: %+v", st)
	}
	if !errors.Is(st.HaltError, auditor.ErrMonotonicityBroken) {
		t.Fatalf("expected ErrMonotonicityBroken, got: %v", st.HaltError)
	}

	// Verify Run() has NOT exited early and is waiting on <-ctx.Done()
	select {
	case err := <-errCh:
		t.Fatalf("Run() exited prematurely before context cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
		// Expected: still waiting on ctx.Done()
	}

	// Cancel context to unblock Run()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, auditor.ErrMonotonicityBroken) && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error from Run(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() failed to return within deadline after cancel")
	}
}

