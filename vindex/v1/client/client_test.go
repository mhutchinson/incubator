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

func setupTestEnvironment(t testing.TB, chunkSize uint64) (*server.ReadServer, *kvstore.DB, *tree.Manager, *tree.OutputPublisher, *kvstore.KVIndexer) {
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
	const chunkSize = 100
	srv, db, _, pub, idxer := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

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

	// Backlog 2.6.1: Calling Lookup with before != nil without expectedSubRoot must fail
	if _, err := cli.Lookup(ctx, key, page1.NextBefore, 20); err == nil {
		t.Fatal("expected error when calling Lookup with before != nil and no expectedSubRoot, got nil")
	}

	page1NextRoot, err := page1.NextExpectedSubRoot()
	if err != nil {
		t.Fatalf("page1.NextExpectedSubRoot failed: %v", err)
	}

	// Page 2: before=300, limit=20 -> returns [100..280], nextBefore=100
	page2, err := cli.Lookup(ctx, key, page1.NextBefore, 20, page1NextRoot)
	if err != nil {
		t.Fatalf("Page 2 lookup failed: %v", err)
	}
	if len(page2.Indices) != 20 {
		t.Fatalf("Page 2 indices len = %d, want 20", len(page2.Indices))
	}
	if page2.NextBefore == nil || *page2.NextBefore != 100 {
		t.Fatalf("Page 2 NextBefore = %v, want 100", page2.NextBefore)
	}

	page2NextRoot, err := page2.NextExpectedSubRoot()
	if err != nil {
		t.Fatalf("page2.NextExpectedSubRoot failed: %v", err)
	}

	// Page 3: before=100, limit=20 -> returns remaining 10 items [0..90], nextBefore=nil
	page3, err := cli.Lookup(ctx, key, page2.NextBefore, 20, page2NextRoot)
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
	const chunkSize = 100
	srv, db, _, pub, idxer := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

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

	keyStr := "secondary_test_key"
	key := sha256.Sum256([]byte(keyStr))
	batch := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			key: {5, 15, 25},
		},
		CanonicalKeys: map[[32]byte]string{
			key: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP := []byte("example.com/input\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err = pub.PublishKeyBatch(ctx, res.ModifiedKeySubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 100}, rawInCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
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
	respKey, err := cli.LookupKey(ctx, keyStr, nil, 100)
	if err != nil || !respKey.Exists || len(respKey.Indices) != 3 {
		t.Fatalf("LookupKey failed: %v, resp: %+v", err, respKey)
	}

	respAllKey, err := cli.LookupAllKey(ctx, keyStr, 10)
	if err != nil || !respAllKey.Exists || len(respAllKey.Indices) != 3 {
		t.Fatalf("LookupAllKey failed: %v, resp: %+v", err, respAllKey)
	}

	// 4. VIndexClient
	vClient, err := NewVIndexClient(ts.URL, nil, nil)
	if err != nil {
		t.Fatalf("NewVIndexClient failed: %v", err)
	}
	indices, rawCPRes, err := vClient.Lookup(ctx, keyStr)
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

func TestClient_PrefixLookupAndTwoSidedSoundness(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer := setupTestEnvironment(t, chunkSize)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."
	kSibling := "com.googleapis.www."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))
	khSibling := sha256.Sum256([]byte(kSibling))

	batch := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			khApex:    {1, 10},
			khMail:    {2, 20, 30},
			khDocs:    {3},
			khWild:    {4, 40},
			khSibling: {99},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex:    kApex,
			khMail:    kMail,
			khDocs:    kDocs,
			khWild:    kWild,
			khSibling: kSibling,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP := []byte("example.com/input\n100\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err = pub.PublishKeyBatch(ctx, res.ModifiedKeySubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 100}, rawInCP)
	if err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
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

	// 1. LookupPrefixAll("com.google.") -> must return 4 keys in ascending order and exclude "com.googleapis.www."
	prefixResp, err := cli.LookupPrefixAll(ctx, "com.google.", 10)
	if err != nil {
		t.Fatalf("LookupPrefixAll failed: %v", err)
	}
	if len(prefixResp.Results) != 4 {
		t.Fatalf("expected 4 matched keys, got %d: %+v", len(prefixResp.Results), prefixResp.Results)
	}
	wantOrder := []string{kApex, kWild, kDocs, kMail}
	for i, wantKey := range wantOrder {
		if prefixResp.Results[i].Key != wantKey {
			t.Errorf("Result[%d].Key = %q, want %q", i, prefixResp.Results[i].Key, wantKey)
		}
	}
	if len(prefixResp.Results[3].Indices) != 3 || prefixResp.Results[3].Indices[2] != 30 {
		t.Errorf("unexpected indices for %s: %v", kMail, prefixResp.Results[3].Indices)
	}

	// 2. Non-existent prefix ("com.nonexistent.") -> verified empty subtree
	emptyPrefixResp, err := cli.LookupPrefixAll(ctx, "com.nonexistent.", 10)
	if err != nil {
		t.Fatalf("LookupPrefixAll(com.nonexistent.) failed: %v", err)
	}
	if len(emptyPrefixResp.Results) != 0 {
		t.Fatalf("expected 0 results for nonexistent prefix, got %d", len(emptyPrefixResp.Results))
	}

	// 3. Adversarial two-sided soundness check: if a buggy/malicious server returns a broader prefix proof
	// (e.g. proof for "com." including "com.googleapis.www.") when the client queried "com.google.",
	// VerifyKeysResponse MUST reject it because "com.googleapis.www." fails HasPrefix("com.google.").
	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.?prefix=true", nil)
	w := httptest.NewRecorder()
	// Temporarily bypass prefix policy on srv to generate a raw "com." response
	srv.SetPrefixPolicy(nil)
	srv.HandleKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleKeys(com.) failed: %d", w.Code)
	}
	if _, err := cli.verifier.VerifyKeysResponse(ctx, "com.google.", true, w.Body.Bytes()); err == nil {
		t.Fatal("VerifyKeysResponse must reject broader subtree containing keys outside query prefix")
	}
}

func TestClient_EntriesTruncationAndCompactRangeValidation(t *testing.T) {
	ctx := context.Background()
	verifier := NewVerifier(VerifierConfig{})

	indices := []uint64{10, 20}
	subRoot, err := computeMiniLogRoot(nil, 0, indices)
	if err != nil {
		t.Fatalf("computeMiniLogRoot failed: %v", err)
	}

	// 1. Valid single-page entries response
	validBody := "— indices-v1 —\n10\n20\n"
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, subRoot, []byte(validBody)); err != nil {
		t.Fatalf("expected valid entries response to pass, got: %v", err)
	}

	// 1b. Zero expectedSubRoot must be rejected by VerifyEntriesResponse (Backlog 2.6.1)
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, [32]byte{}, []byte(validBody)); err == nil {
		t.Fatal("expected VerifyEntriesResponse to reject zero expectedSubRoot")
	}

	// 2. Truncated page: prefix-compact-range-v1 present with covered_size > 0, but next_before omitted from indices-v1 (Backlog 2.6.2)
	dummyHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	truncatedBody := fmt.Sprintf("— prefix-compact-range-v1 1 —\n%s\n\n— indices-v1 —\n10\n20\n", dummyHash)
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, subRoot, []byte(truncatedBody)); err == nil || !strings.Contains(err.Error(), "truncated response") {
		t.Fatalf("expected truncated response error when next_before is omitted with non-empty prefix range, got: %v", err)
	}

	// 3. Mismatched coveredSize > 0 with 0 hashes (Backlog 2.6.2)
	mismatchedBody := "— prefix-compact-range-v1 5 —\n\n— indices-v1 10 —\n10\n20\n"
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, subRoot, []byte(mismatchedBody)); err == nil || !strings.Contains(err.Error(), "mismatched prefix-compact-range-v1") {
		t.Fatalf("expected mismatched prefix-compact-range-v1 error, got: %v", err)
	}

	// 4. next_before does not match first index in indices-v1 (Backlog 2.6.2)
	wrongNextBefore := fmt.Sprintf("— prefix-compact-range-v1 1 —\n%s\n\n— indices-v1 9 —\n10\n20\n", dummyHash)
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, subRoot, []byte(wrongNextBefore)); err == nil || !strings.Contains(err.Error(), "must equal first returned index") {
		t.Fatalf("expected next_before mismatch error, got: %v", err)
	}

	// 5. Total entries (coveredSize + len(indices)) > before
	overflowBody := fmt.Sprintf("— prefix-compact-range-v1 99 —\n%s\n\n— indices-v1 10 —\n10\n20\n", dummyHash)
	if _, err := verifier.VerifyEntriesResponse(ctx, 100, subRoot, []byte(overflowBody)); err == nil || !strings.Contains(err.Error(), "exceed upperBound") {
		t.Fatalf("expected exceed upperBound error, got: %v", err)
	}
}

func BenchmarkClient_VerifyKeysAndEntries(b *testing.B) {
	ctx := context.Background()
	srv, _, _, pub, idxer := setupTestEnvironment(b, 64)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))

	var mailIndices []uint64
	for i := uint64(0); i < 128; i++ {
		mailIndices = append(mailIndices, i*10+1)
	}

	batch := &ingest.MappedBatch{
		Count: 2000,
		KeyMap: map[[32]byte][]uint64{
			khApex: {1, 10},
			khMail: mailIndices,
			khDocs: {3},
			khWild: {4, 40},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex: kApex,
			khMail: kMail,
			khDocs: kDocs,
			khWild: kWild,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		b.Fatalf("IndexBatch failed: %v", err)
	}
	rawInCP := []byte("example.com/input\n2000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeySubRoots, &log.Checkpoint{Origin: "example.com/input", Size: 2000}, rawInCP); err != nil {
		b.Fatalf("PublishKeyBatch failed: %v", err)
	}

	wPoint := httptest.NewRecorder()
	srv.HandleKeys(wPoint, httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.mail.", nil))
	pointBytes := wPoint.Body.Bytes()

	wPrefix := httptest.NewRecorder()
	srv.HandleKeys(wPrefix, httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.?prefix=true", nil))
	prefixBytes := wPrefix.Body.Bytes()

	wEntries := httptest.NewRecorder()
	srv.HandleEntries(wEntries, httptest.NewRequest(http.MethodGet, "/vindex/v1/entries/com.google.mail.?before=2000&limit=64", nil))
	entriesBytes := wEntries.Body.Bytes()

	verifier := NewVerifier(VerifierConfig{
		OutputLogOrigin: "example.com/output",
		InputLogOrigin:  "example.com/input",
	})
	keysResp, err := verifier.VerifyKeysResponse(ctx, kMail, false, pointBytes)
	if err != nil {
		b.Fatalf("VerifyKeysResponse failed: %v", err)
	}
	mailSubRoot := keysResp.Keys[0].SubRoot

	b.Run("VerifyKeysResponse_Point", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := verifier.VerifyKeysResponse(ctx, kMail, false, pointBytes); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyKeysResponse_Prefix4Keys", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := verifier.VerifyKeysResponse(ctx, kApex, true, prefixBytes); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyEntriesResponse_ZeroMPTContinuation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := verifier.VerifyEntriesResponse(ctx, 2000, mailSubRoot, entriesBytes); err != nil {
				b.Fatal(err)
			}
		}
	})
}



