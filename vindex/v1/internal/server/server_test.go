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

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

type mockOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func (m *mockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n\n— test_sig\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *mockOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	var proof [][sha256.Size]byte
	if treeSize > 1 {
		proof = append(proof, sha256.Sum256([]byte("sibling")))
	}
	return proof, nil
}

func setupTestServer(t *testing.T, chunkSize uint64) (*ReadServer, *kvstore.DB, *tree.Manager, *tree.OutputPublisher) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mptMgr := tree.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv := NewReadServer(db, mptMgr, pub, chunkSize)
	return srv, db, mptMgr, pub
}

func TestReadServer_Checkpoints(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)

	// Before serving state initialized -> 503
	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/checkpoint", nil)
	w := httptest.NewRecorder()
	srv.HandleCheckpoint(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("HandleCheckpoint uninitialized = %d, want 503", w.Code)
	}

	// Initialize serving state
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Output log checkpoint
	w = httptest.NewRecorder()
	srv.HandleCheckpoint(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleCheckpoint = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "example.com/output") {
		t.Fatalf("HandleCheckpoint body missing origin: %s", w.Body.String())
	}

	// Input log checkpoint
	inReq := httptest.NewRequest(http.MethodGet, "/vindex/v1/inputlog_checkpoint", nil)
	inW := httptest.NewRecorder()
	srv.HandleInputLogCheckpoint(inW, inReq)
	if inW.Code != http.StatusOK {
		t.Fatalf("HandleInputLogCheckpoint = %d, want 200", inW.Code)
	}
	if !strings.Contains(inW.Body.String(), "example.com/input") {
		t.Fatalf("HandleInputLogCheckpoint body missing input origin: %s", inW.Body.String())
	}
}

func TestReadServer_HealthAndReadiness(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)

	// Healthz probe -> always 200 OK for GET
	hReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	hW := httptest.NewRecorder()
	srv.HandleHealthz(hW, hReq)
	if hW.Code != http.StatusOK {
		t.Fatalf("HandleHealthz GET = %d, want 200", hW.Code)
	}

	// Healthz probe with POST -> 405
	hPostReq := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	hPostW := httptest.NewRecorder()
	srv.HandleHealthz(hPostW, hPostReq)
	if hPostW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleHealthz POST = %d, want 405", hPostW.Code)
	}

	// Readyz before initialization -> 503
	rReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rW := httptest.NewRecorder()
	srv.HandleReadyz(rW, rReq)
	if rW.Code != http.StatusServiceUnavailable {
		t.Fatalf("HandleReadyz uninitialized = %d, want 503", rW.Code)
	}

	// Readyz with POST -> 405
	rPostReq := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	rPostW := httptest.NewRecorder()
	srv.HandleReadyz(rPostW, rPostReq)
	if rPostW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleReadyz POST = %d, want 405", rPostW.Code)
	}

	// Initialize serving state
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Readyz after initialization -> 200 OK
	rW2 := httptest.NewRecorder()
	srv.HandleReadyz(rW2, rReq)
	if rW2.Code != http.StatusOK {
		t.Fatalf("HandleReadyz initialized = %d, want 200", rW2.Code)
	}
}

func TestReadServer_ValidationErrors(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, _ = pub.Publish(context.Background(), rawInCP, 500, nil)

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "missing key", path: "/vindex/v1/lookup/"},
		{name: "short hex", path: "/vindex/v1/lookup/abcdef"},
		{name: "non-hex chars", path: "/vindex/v1/lookup/gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"},
		{name: "uppercase hex", path: "/vindex/v1/lookup/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "invalid before", path: "/vindex/v1/lookup/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?before=invalid"},
		{name: "invalid limit", path: "/vindex/v1/lookup/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?limit=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			srv.HandleLookup(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("HandleLookup(%q) = %d, want 400", tc.path, w.Code)
			}
		})
	}
}

func TestReadServer_NonInclusionLookup(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)

	rawInCP := []byte("example.com/input\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 1000, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	absentKey := sha256.Sum256([]byte("absent_key_search"))
	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(absentKey[:]), nil)
	w := httptest.NewRecorder()
	srv.HandleLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HandleLookup = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "— mpt-proof-v1 non-inclusion —") {
		t.Fatalf("expected non-inclusion proof section, got: %s", body)
	}
	if !strings.Contains(body, "— indices-v1 —") {
		t.Fatalf("expected empty indices section, got: %s", body)
	}
}

func TestReadServer_InclusionLookupAndPagination(t *testing.T) {
	srv, db, mptMgr, pub := setupTestServer(t, 0)
	indexer := kvstore.NewKVIndexer(db, 0)

	key := sha256.Sum256([]byte("searchable_domain.com"))
	var indices []uint64
	for i := uint64(0); i < 150; i++ {
		indices = append(indices, i*2)
	}

	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 500)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}
	subRoot := res.ModifiedSubRoots[key]

	// Publish to Output Log and MPT
	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 500, Hash: make([]byte, 32)}
	_, err = pub.PublishBatch(context.Background(), map[[32]byte][32]byte{key: subRoot}, inCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}
	_ = mptMgr
	_ = indexer

	// Query 1: Tip page, limit 50 -> returns latest 50 entries [200..298], prefix covers [0..198] (100 entries)
	req1 := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:])+"?limit=50", nil)
	w1 := httptest.NewRecorder()
	srv.HandleLookup(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Query 1 status = %d, want 200", w1.Code)
	}

	body1 := w1.Body.String()
	if !strings.Contains(body1, "— mpt-proof-v1 inclusion —") {
		t.Fatalf("expected inclusion proof section: %s", body1)
	}
	if !strings.Contains(body1, "— prefix-compact-range-v1 100 —") {
		t.Fatalf("expected prefix-compact-range-v1 with size 100: %s", body1)
	}
	if !strings.Contains(body1, "— indices-v1 200 —") { // NextBefore = 200
		t.Fatalf("expected next_before = 200 in indices header: %s", body1)
	}

	// Query 2: Page 2 before=200, limit 50 -> returns [100..198], prefix covers [0..98] (50 entries)
	req2 := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:])+"?before=200&limit=50", nil)
	w2 := httptest.NewRecorder()
	srv.HandleLookup(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Query 2 status = %d, want 200", w2.Code)
	}

	body2 := w2.Body.String()
	if !strings.Contains(body2, "— prefix-compact-range-v1 50 —") {
		t.Fatalf("expected prefix-compact-range-v1 with size 50: %s", body2)
	}
	if !strings.Contains(body2, "— indices-v1 100 —") {
		t.Fatalf("expected next_before = 100 in indices header: %s", body2)
	}

	// Query 3: Watermark filter - verify indices >= serving size (500) are excluded
	// Add index 600
	batch2 := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: {600},
		},
	}
	_, err = indexer.IndexMappedBatch(context.Background(), batch2, nil, 700)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:])+"?limit=200", nil)
	w3 := httptest.NewRecorder()
	srv.HandleLookup(w3, req3)

	body3 := w3.Body.String()
	if strings.Contains(body3, "\n600\n") {
		t.Fatalf("index 600 (ahead of serving size 500) should have been filtered: %s", body3)
	}
}

func TestReadServer_MetricsEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	srv := NewReadServer(nil, nil, nil, 64)
	srv.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	expectedMetrics := []string{
		"vindex_input_tree_size",
		"vindex_kv_committed_size",
		"vindex_output_tree_size",
		"vindex_serving_tree_size",
		"vindex_leaves_downloaded_total",
		"vindex_leaves_mapped_total",
		"vindex_leaves_indexed_total",
		"vindex_keys_mapped_total",
		"vindex_input_fetch_errors_total",
		"vindex_witness_signatures_count",
		"vindex_witness_errors_total",
		"vindex_tile_cache_bytes",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("/metrics missing expected metric %q", m)
		}
	}
}
func TestReadServer_CustomChunkSize(t *testing.T) {
	const customChunkSize = 64
	srv, db, _, pub := setupTestServer(t, customChunkSize)
	indexer := kvstore.NewKVIndexer(db, customChunkSize)

	key := sha256.Sum256([]byte("custom_chunk_test.com"))
	indices := []uint64{0, 65, 130}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 200)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}
	subRoot := res.ModifiedSubRoots[key]

	rawInCP := []byte("example.com/input\n200\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 200, Hash: make([]byte, 32)}
	_, err = pub.PublishBatch(context.Background(), map[[32]byte][32]byte{key: subRoot}, inCP, rawInCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+hex.EncodeToString(key[:])+"?limit=100", nil)
	w := httptest.NewRecorder()
	srv.HandleLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HandleLookup status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	for _, idx := range indices {
		expectedLine := fmt.Sprintf("%d", idx)
		found := false
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == expectedLine {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("HandleLookup response missing index %d: %s", idx, body)
		}
	}
}

func TestReadServer_UI(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// GET /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / content-type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "VIndex Web") {
		t.Fatalf("GET / body does not contain 'VIndex Web': %s", w.Body.String())
	}

	// GET /index.html
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /index.html status = %d, want 200", w2.Code)
	}

	// Test disabling UI
	srvDisabled, _, _, _ := setupTestServer(t, 256)
	srvDisabled.SetEnableUI(false)
	muxDisabled := http.NewServeMux()
	srvDisabled.RegisterRoutes(muxDisabled)

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	muxDisabled.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("GET / with disabled UI status = %d, want 404", w3.Code)
	}
}
