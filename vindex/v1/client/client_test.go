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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type testOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func (m *testOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *testOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var leafHashes [][sha256.Size]byte
	for _, l := range m.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(l))
	}

	// Compute RFC 6962 inclusion proof
	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		// Largest power of 2 strictly less than n
		k := uint64(1)
		for k*2 < uint64(n) {
			k *= 2
		}
		if idx < k {
			rightSubRoot := kvstore.BatchRootHashes(leaves[k:])
			buildProof(leaves[:k], idx)
			proof = append(proof, rightSubRoot)
		} else {
			leftSubRoot := kvstore.BatchRootHashes(leaves[:k])
			buildProof(leaves[k:], idx-k)
			proof = append(proof, leftSubRoot)
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}

func setupTestEnvironment(t *testing.T, chunkSize uint64) (*server.ReadServer, *kvstore.DB, *tree.Manager, *tree.OutputPublisher, *kvstore.KVIndexer) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := tree.NewMem()
	outLog := &testOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	idxer := kvstore.NewKVIndexer(db, chunkSize)
	srv := server.NewReadServer(db, mptMgr, pub, chunkSize)

	return srv, db, mptMgr, pub, idxer
}

func TestClient_PositiveInclusionAndNonInclusion(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key1 := sha256.Sum256([]byte("target_key_1"))
	key2 := sha256.Sum256([]byte("target_key_2"))
	unmappedKey := sha256.Sum256([]byte("unmapped_key"))

	// Index entries for key1 (indices: 5, 20, 35) and key2 (index: 10)
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key1: {5, 20, 35},
			key2: {10},
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

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	}, ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	// 1. Inclusion test for key1
	resp1, err := cli.Lookup(ctx, key1, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(key1) failed: %v", err)
	}
	if !resp1.Exists {
		t.Fatalf("Lookup(key1) Exists = false, want true")
	}
	if len(resp1.Indices) != 3 || resp1.Indices[0] != 5 || resp1.Indices[1] != 20 || resp1.Indices[2] != 35 {
		t.Fatalf("Lookup(key1) unexpected indices: %v", resp1.Indices)
	}
	if resp1.InputLogSize != 100 {
		t.Fatalf("Lookup(key1) InputLogSize = %d, want 100", resp1.InputLogSize)
	}

	// 2. Inclusion test for key2
	resp2, err := cli.Lookup(ctx, key2, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(key2) failed: %v", err)
	}
	if !resp2.Exists {
		t.Fatalf("Lookup(key2) Exists = false, want true")
	}
	if len(resp2.Indices) != 1 || resp2.Indices[0] != 10 {
		t.Fatalf("Lookup(key2) unexpected indices: %v", resp2.Indices)
	}

	// 3. Non-inclusion test for unmappedKey
	respNon, err := cli.Lookup(ctx, unmappedKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(unmappedKey) failed: %v", err)
	}
	if respNon.Exists {
		t.Fatalf("Lookup(unmappedKey) Exists = true, want false")
	}
	if len(respNon.Indices) != 0 {
		t.Fatalf("Lookup(unmappedKey) returned non-empty indices: %v", respNon.Indices)
	}
}

func TestClient_PaginationContinuation(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key := sha256.Sum256([]byte("paginated_key"))

	// Seed 50 indices: 0, 10, 20, ..., 490
	var indices []uint64
	for i := uint64(0); i < 50; i++ {
		indices = append(indices, i*10)
	}
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        500,
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err = pub.PublishBatch(ctx, res.ModifiedSubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 500}, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	}, ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	// Page 1: Tip query (before=nil, limit=20) -> returns latest 20 items [300..490], nextBefore=300
	page1, err := cli.Lookup(ctx, key, nil, 20)
	if err != nil {
		t.Fatalf("Page 1 lookup failed: %v", err)
	}
	if len(page1.Indices) != 20 {
		t.Fatalf("Page 1 indices len = %d, want 20", len(page1.Indices))
	}
	if page1.NextBefore == nil || *page1.NextBefore != 300 {
		t.Fatalf("Page 1 NextBefore = %v, want 300", page1.NextBefore)
	}

	// Page 2: before=300, limit=20 -> returns [100..280], nextBefore=100
	page2, err := cli.Lookup(ctx, key, page1.NextBefore, 20)
	if err != nil {
		t.Fatalf("Page 2 lookup failed: %v", err)
	}
	if len(page2.Indices) != 20 {
		t.Fatalf("Page 2 indices len = %d, want 20", len(page2.Indices))
	}
	if page2.NextBefore == nil || *page2.NextBefore != 100 {
		t.Fatalf("Page 2 NextBefore = %v, want 100", page2.NextBefore)
	}

	// Page 3: before=100, limit=20 -> returns remaining 10 items [0..90], nextBefore=nil
	page3, err := cli.Lookup(ctx, key, page2.NextBefore, 20)
	if err != nil {
		t.Fatalf("Page 3 lookup failed: %v", err)
	}
	if len(page3.Indices) != 10 {
		t.Fatalf("Page 3 indices len = %d, want 10", len(page3.Indices))
	}
	if page3.NextBefore != nil {
		t.Fatalf("Page 3 NextBefore = %v, want nil", page3.NextBefore)
	}

	// Test LookupAll -> fetches all pages backwards and returns sorted ascending indices [0..490]
	allResp, err := cli.LookupAll(ctx, key, 20)
	if err != nil {
		t.Fatalf("LookupAll failed: %v", err)
	}
	if len(allResp.Indices) != 50 {
		t.Fatalf("LookupAll indices len = %d, want 50", len(allResp.Indices))
	}
	for i, idx := range allResp.Indices {
		if idx != uint64(i*10) {
			t.Fatalf("LookupAll index[%d] = %d, want %d", i, idx, i*10)
		}
	}
}

func TestClient_NegativeTamperCases(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key := sha256.Sum256([]byte("tamper_key"))
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

	// Capture valid server response
	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:]), nil)
	w := httptest.NewRecorder()
	srv.HandleLookup(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleLookup failed: %d", w.Code)
	}
	validBody := w.Body.String()

	verifier := NewVerifier(VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	})

	// Baseline check: valid body must verify
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(validBody)); err != nil {
		t.Fatalf("Baseline valid body failed verification: %v", err)
	}

	// Tamper 1: Corrupted Output Log Root in checkpoint
	tamperedCP := strings.Replace(validBody, "example.com/output\n1\n", "example.com/output\n2\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(tamperedCP)); err == nil {
		t.Error("Tampered checkpoint size should fail verification")
	}

	// Tamper 2: Corrupted Output Log inclusion proof
	tamperedProof := strings.Replace(validBody, "— output-log-proof-v1 —\n", "— output-log-proof-v1 —\nbm9uc2Vuc2VoYXNoCg==\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(tamperedProof)); err == nil {
		t.Error("Tampered output log proof should fail verification")
	}

	// Tamper 3: Tampered Index in indices-v1 (e.g. change 20 to 21)
	tamperedIndices := strings.Replace(validBody, "20\n", "21\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(tamperedIndices)); err == nil {
		t.Error("Tampered index value should fail MPT inclusion verification")
	}

	// Tamper 4: Unordered Indices (e.g. 30 then 20)
	unorderedIndices := strings.Replace(validBody, "20\n30\n", "30\n20\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(unorderedIndices)); err == nil {
		t.Error("Unordered indices should fail verification")
	}

	// Tamper 5: Index >= InputLogSize (e.g. 150 >= 100)
	outOfBoundsIndices := strings.Replace(validBody, "30\n", "150\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(outOfBoundsIndices)); err == nil {
		t.Error("Out of bounds index >= InputLogSize should fail verification")
	}

	// Tamper 6: Corrupted MPT proof
	tamperedMPT := strings.Replace(validBody, "— mpt-proof-v1 inclusion —\n", "— mpt-proof-v1 inclusion —\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n", 1)
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(tamperedMPT)); err == nil {
		t.Error("Tampered MPT proof should fail verification")
	}

	// Tamper 7: Missing mandatory section (e.g. delete output-log-leaf-v1 section)
	lines := strings.Split(validBody, "\n")
	var filtered []string
	skip := false
	for _, l := range lines {
		if strings.HasPrefix(l, "— output-log-leaf-v1") {
			skip = true
			continue
		}
		if skip && strings.HasPrefix(l, "— ") {
			skip = false
		}
		if !skip {
			filtered = append(filtered, l)
		}
	}
	if _, err := verifier.VerifyResponse(ctx, key, nil, []byte(strings.Join(filtered, "\n"))); err == nil {
		t.Error("Missing output-log-leaf-v1 section should fail verification")
	}
}

func TestInputLogClient_Dereference_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sKey, vKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(sKey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}
	verifier, err := note.NewVerifier(vKey)
	if err != nil {
		t.Fatalf("note.NewVerifier failed: %v", err)
	}

	inLogDir := t.TempDir()
	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("tessera.NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })
	awaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, time.Millisecond)

	// Ingest 300 leaves to cross layout.EntryBundleWidth (256) boundary
	const numLeaves = 300
	var lastFut tessera.IndexFuture
	for i := 0; i < numLeaves; i++ {
		entryData := []byte(fmt.Sprintf("entry_leaf_%04d", i))
		lastFut = inAppender.Add(ctx, tessera.NewEntry(entryData))
	}
	_, lastRawCP, err := awaiter.Await(ctx, lastFut)
	if err != nil {
		t.Fatalf("Await leaf failed: %v", err)
	}

	ts := httptest.NewServer(http.FileServer(http.Dir(inLogDir)))
	defer ts.Close()

	inClient, err := NewInputLogClient(ts.URL, "test.inputlog", verifier, ts.Client())
	if err != nil {
		t.Fatalf("NewInputLogClient failed: %v", err)
	}

	// Query indices across bundle 0, cache hit on index 10, bundle 1, and boundary crossing (255 -> 256)
	pointers := []uint64{0, 10, 10, 255, 256, 299}
	var received []InputLogLeaf
	for leaf, err := range inClient.Dereference(ctx, lastRawCP, pointers) {
		if err != nil {
			t.Fatalf("Dereference error: %v", err)
		}
		received = append(received, leaf)
	}
	if len(received) != len(pointers) {
		t.Fatalf("received %d leaves, want %d", len(received), len(pointers))
	}
	for i, p := range pointers {
		wantData := fmt.Sprintf("entry_leaf_%04d", p)
		if received[i].Index != p {
			t.Errorf("leaf %d index = %d, want %d", i, received[i].Index, p)
		}
		if string(received[i].Data) != wantData {
			t.Errorf("leaf %d data = %q, want %q", i, string(received[i].Data), wantData)
		}
	}
}

func TestInputLogClient_Errors(t *testing.T) {
	ctx := context.Background()

	sKey, vKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(sKey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}
	verifier, err := note.NewVerifier(vKey)
	if err != nil {
		t.Fatalf("note.NewVerifier failed: %v", err)
	}

	cpText := fmt.Sprintf("test.inputlog\n1\n%s\n", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	rawCP, err := note.Sign(&note.Note{Text: cpText}, signer)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}

	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	// Error 1: Invalid URL
	if _, err := NewInputLogClient("://bad_url", "test.inputlog", verifier, ts.Client()); err == nil {
		t.Error("expected error for invalid URL, got nil")
	}

	inClient, err := NewInputLogClient(ts.URL, "test.inputlog", verifier, ts.Client())
	if err != nil {
		t.Fatalf("NewInputLogClient failed: %v", err)
	}

	// Error 2: Pointer out of bounds (10 >= 1)
	for _, err := range inClient.Dereference(ctx, rawCP, []uint64{10}) {
		if err == nil {
			t.Error("expected error for out of bounds pointer, got nil")
		}
	}

	// Error 3: Bad checkpoint signature
	badCP := []byte("test.inputlog\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n\n— bad_verifier bad_signature\n")
	for _, err := range inClient.Dereference(ctx, badCP, []uint64{0}) {
		if err == nil {
			t.Error("expected error for bad checkpoint signature, got nil")
		}
	}
}

func TestClient_LookupAll_ContinuationRootMismatch(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key := sha256.Sum256([]byte("mismatch_key"))
	var indices []uint64
	for i := uint64(0); i < 50; i++ {
		indices = append(indices, i*10)
	}
	batch := &ingest.MappedBatch{
		Count: 500,
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err = pub.PublishBatch(ctx, res.ModifiedSubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 500}, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	// Proxy server that tampers continuation pages (Page 2)
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	tamperedMux := http.NewServeMux()
	tamperedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		body := rec.Body.String()
		if r.URL.Query().Get("before") != "" {
			// Tamper continuation page's index value so mini-log root diverges
			body = strings.Replace(body, "200\n", "201\n", 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body))
	})

	ts := httptest.NewServer(tamperedMux)
	defer ts.Close()

	cli, err := New(ts.URL, VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	}, ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	_, err = cli.LookupAll(ctx, key, 20)
	if err == nil || !strings.Contains(err.Error(), "continuation mini-log root mismatch") {
		t.Fatalf("expected continuation mini-log root mismatch error, got: %v", err)
	}
}

func TestClient_CheckpointsAndSecondaryEndpoints(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	key := sha256.Sum256([]byte("secondary_test_key"))
	batch := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			key: {5, 15, 25},
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

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	}, ts.Client())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// 1. GetCheckpoint
	outCP, err := cli.GetCheckpoint(ctx)
	if err != nil || !strings.Contains(string(outCP), "example.com/output") {
		t.Fatalf("GetCheckpoint failed: %v, body: %s", err, string(outCP))
	}

	// 2. GetInputLogCheckpoint
	inCP, err := cli.GetInputLogCheckpoint(ctx)
	if err != nil || !strings.Contains(string(inCP), "example.com/input") {
		t.Fatalf("GetInputLogCheckpoint failed: %v, body: %s", err, string(inCP))
	}

	// 3. LookupKey and LookupAllKey
	respKey, err := cli.LookupKey(ctx, "secondary_test_key", nil, 100)
	if err != nil || !respKey.Exists || len(respKey.Indices) != 3 {
		t.Fatalf("LookupKey failed: %v, resp: %+v", err, respKey)
	}

	respAllKey, err := cli.LookupAllKey(ctx, "secondary_test_key", 10)
	if err != nil || !respAllKey.Exists || len(respAllKey.Indices) != 3 {
		t.Fatalf("LookupAllKey failed: %v, resp: %+v", err, respAllKey)
	}

	// 4. VIndexClient and VerifyLookupResponse
	vClient, err := NewVIndexClient(ts.URL, nil, nil)
	if err != nil {
		t.Fatalf("NewVIndexClient failed: %v", err)
	}
	indices, rawCPRes, err := vClient.Lookup(ctx, "secondary_test_key")
	if err != nil || len(indices) != 3 {
		t.Fatalf("vClient.Lookup failed: %v, indices: %v", err, indices)
	}
	if len(rawCPRes) == 0 {
		t.Fatal("empty raw input checkpoint from vClient.Lookup")
	}

	vClientWithOrigin, err := NewVIndexClientWithOrigin(ts.URL, nil, nil, "example.com/input")
	if err != nil {
		t.Fatalf("NewVIndexClientWithOrigin failed: %v", err)
	}
	if vClientWithOrigin == nil {
		t.Fatal("NewVIndexClientWithOrigin returned nil")
	}
}

func TestVerifyLookupResponse_Cases(t *testing.T) {
	inSKey, inVKey, _ := note.GenerateKey(rand.Reader, "input.test")
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	outSKey, outVKey, _ := note.GenerateKey(rand.Reader, "output.test")
	outSigner, _ := note.NewSigner(outSKey)
	outVerifier, _ := note.NewVerifier(outVKey)

	keyHash := sha256.Sum256([]byte("legacy_key"))
	indices := []uint64{1, 2, 3}
	miniRoot, _ := computeMiniLogRoot(nil, 0, indices)

	mpt := tree.NewMem()
	_, _ = mpt.Commit(map[[32]byte][32]byte{keyHash: miniRoot})
	proof, _, _, _ := mpt.Prove(keyHash)

	rawInCP, _ := note.Sign(&note.Note{Text: "input.test\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"}, inSigner)

	mptRoot := mpt.Root()
	outLeaf := []byte(hex.EncodeToString(mptRoot[:]) + "\n" + string(rawInCP))
	outLeafHash := leafHash(outLeaf)

	rawOutCP, _ := note.Sign(&note.Note{Text: "output.test\n1\n" + base64.StdEncoding.EncodeToString(outLeafHash[:]) + "\n"}, outSigner)

	validLegacy := LegacyLookupResponse{
		OutputLogCP:    rawOutCP,
		OutputLogLeaf:  outLeaf,
		OutputLogProof: nil,
		IndexValue:     indices,
		IndexProof:     proof,
	}

	// 1. Valid verification
	gotIndices, gotInCP, err := VerifyLookupResponse(keyHash, validLegacy, inVerifier, outVerifier, "input.test")
	if err != nil {
		t.Fatalf("VerifyLookupResponse failed: %v", err)
	}
	if len(gotIndices) != 3 || len(gotInCP) == 0 {
		t.Fatalf("unexpected result: indices=%v, cp=%s", gotIndices, string(gotInCP))
	}

	// 2. Tampered output log checkpoint
	tamperedLegacy := validLegacy
	tamperedLegacy.OutputLogCP = []byte("output.test\n1\nAAAA\n\n— bad sig\n")
	if _, _, err := VerifyLookupResponse(keyHash, tamperedLegacy, inVerifier, outVerifier, "input.test"); err == nil {
		t.Error("expected error for tampered output log checkpoint, got nil")
	}

	// 3. Malformed output leaf
	tamperedLegacy = validLegacy
	tamperedLegacy.OutputLogLeaf = []byte("short")
	if _, _, err := VerifyLookupResponse(keyHash, tamperedLegacy, inVerifier, outVerifier, "input.test"); err == nil {
		t.Error("expected error for malformed output leaf, got nil")
	}
}


