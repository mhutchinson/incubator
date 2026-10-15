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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
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

func TestReadServer_AsyncBackendAndGenesisBackfillDiagnostics(t *testing.T) {
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// 1. Start ReadServer before MPT/OutputPublisher are attached (mptMgr == nil, pub == nil)
	srv := NewReadServer(db, nil, nil, 256)

	// /healthz must immediately return 200 OK
	hW := httptest.NewRecorder()
	srv.HandleHealthz(hW, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hW.Code != http.StatusOK {
		t.Fatalf("HandleHealthz before backend attach = %d, want 200", hW.Code)
	}

	// /readyz, /syncz, and /vindex/v1/lookup/ must return 503 with Retry-After: 30 and JSON mpt_initializing
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/readyz", srv.HandleReadyz},
		{"/syncz", srv.HandleReadyz},
		{"/vindex/v1/lookup/" + strings.Repeat("a", 64), srv.HandleLookup},
	} {
		w := httptest.NewRecorder()
		endpoint.handler(w, httptest.NewRequest(http.MethodGet, endpoint.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s before backend attach = %d, want 503", endpoint.path, w.Code)
		}
		if w.Header().Get("Retry-After") != "30" {
			t.Fatalf("%s Retry-After = %q, want 30", endpoint.path, w.Header().Get("Retry-After"))
		}
		if !strings.Contains(w.Body.String(), `"status":"mpt_initializing"`) {
			t.Fatalf("%s body = %q, want mpt_initializing JSON", endpoint.path, w.Body.String())
		}
	}

	// 2. Attach backend and ReadyChecker simulating Genesis Backfill in progress
	mptMgr := tree.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv.SetReadyChecker(func() error {
		return fmt.Errorf(`{"status":"genesis_backfill","genesis_backfill":true,"leaves_indexed":500,"target_leaves":10000}`)
	})
	srv.SetBackend(mptMgr, pub)

	rW := httptest.NewRecorder()
	srv.HandleReadyz(rW, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rW.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz during genesis backfill = %d, want 503", rW.Code)
	}
	if !strings.Contains(rW.Body.String(), `"genesis_backfill":true`) {
		t.Fatalf("/readyz body = %q, want genesis_backfill JSON", rW.Body.String())
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
	const chunkSize = 100
	srv, db, mptMgr, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

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

func TestCleanPathPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"///", ""},
		{"  ", ""},
		{"indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb", "/indices/sumdb"},
		{"/indices/sumdb/", "/indices/sumdb"},
		{"///indices/sumdb///", "/indices/sumdb"},
	}

	for _, tc := range tests {
		got := CleanPathPrefix(tc.input)
		if got != tc.want {
			t.Errorf("CleanPathPrefix(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadServer_PathPrefix(t *testing.T) {
	srv, _, _, pub := setupTestServer(t, 256)
	srv.SetPathPrefix("/indices/sumdb")

	rawInCP := []byte("example.com/input\n500\n" + strings.Repeat("A", 44) + "\n")
	_, err := pub.Publish(context.Background(), rawInCP, 500, nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Root-level redirect /indices/sumdb -> /indices/sumdb/
	reqRedirect := httptest.NewRequest(http.MethodGet, "/indices/sumdb", nil)
	recRedirect := httptest.NewRecorder()
	mux.ServeHTTP(recRedirect, reqRedirect)
	if recRedirect.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /indices/sumdb = %d, want 301", recRedirect.Code)
	}
	if loc := recRedirect.Header().Get("Location"); loc != "/indices/sumdb/" {
		t.Fatalf("GET /indices/sumdb Location = %q, want /indices/sumdb/", loc)
	}

	// 2. Prefixed Checkpoint: /indices/sumdb/vindex/v1/checkpoint
	reqCP := httptest.NewRequest(http.MethodGet, "/indices/sumdb/vindex/v1/checkpoint", nil)
	recCP := httptest.NewRecorder()
	mux.ServeHTTP(recCP, reqCP)
	if recCP.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb/vindex/v1/checkpoint = %d, want 200", recCP.Code)
	}

	// 3. Unprefixed Checkpoint should 404
	reqOldCP := httptest.NewRequest(http.MethodGet, "/vindex/v1/checkpoint", nil)
	recOldCP := httptest.NewRecorder()
	mux.ServeHTTP(recOldCP, reqOldCP)
	if recOldCP.Code != http.StatusNotFound {
		t.Fatalf("GET /vindex/v1/checkpoint without prefix = %d, want 404", recOldCP.Code)
	}

	// 4. Prefixed UI: /indices/sumdb/
	reqUI := httptest.NewRequest(http.MethodGet, "/indices/sumdb/", nil)
	recUI := httptest.NewRecorder()
	mux.ServeHTTP(recUI, reqUI)
	if recUI.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb/ = %d, want 200", recUI.Code)
	}

	// 5. Healthz at both root and under prefix
	reqRootHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recRootHealth := httptest.NewRecorder()
	mux.ServeHTTP(recRootHealth, reqRootHealth)
	if recRootHealth.Code != http.StatusOK {
		t.Fatalf("GET /healthz at root = %d, want 200", recRootHealth.Code)
	}

	reqPrefixedHealth := httptest.NewRequest(http.MethodGet, "/indices/sumdb/healthz", nil)
	recPrefixedHealth := httptest.NewRecorder()
	mux.ServeHTTP(recPrefixedHealth, reqPrefixedHealth)
	if recPrefixedHealth.Code != http.StatusOK {
		t.Fatalf("GET /indices/sumdb/healthz = %d, want 200", recPrefixedHealth.Code)
	}
}

func TestReadServer_RegisterRoutesWithOutputLog(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, 256)
	srv.SetPathPrefix("/myindex")

	tmpDir := t.TempDir()
	tilePath := filepath.Join(tmpDir, "tile", "test.txt")
	if err := os.MkdirAll(filepath.Dir(tilePath), 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(tilePath, []byte("tile content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutesWithOutputLog(mux, tmpDir)

	// Fetch tile under prefix: /myindex/tile/test.txt
	req := httptest.NewRequest(http.MethodGet, "/myindex/tile/test.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /myindex/tile/test.txt = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "tile content" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestReadServer_HandleKeys_PointAndPrefix(t *testing.T) {
	const chunkSize = 100
	srv, db, _, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	srv.SetPrefixPolicy(DomainETLDP1PrefixPolicy)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	domainKeys := []string{
		"com.google.",
		"com.google.*.",
		"com.google.docs.",
		"com.google.mail.",
		"com.googleapis.",
	}
	keyMap := make(map[[32]byte][]uint64, len(domainKeys))
	canonMap := make(map[[32]byte]string, len(domainKeys))
	for i, dk := range domainKeys {
		kh := sha256.Sum256([]byte(dk))
		keyMap[kh] = []uint64{uint64(i * 10), uint64(i*10 + 5)}
		canonMap[kh] = dk
	}

	batch := &ingest.MappedBatch{
		KeyMap:        keyMap,
		CanonicalKeys: canonMap,
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 500)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 500, Hash: make([]byte, 32)}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeySubRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Point lookup inclusion
	t.Run("point_inclusion", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.mail.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "— mpt-proof-v1 inclusion —") {
			t.Fatalf("missing inclusion proof header: %s", body)
		}
		sr := res.ModifiedKeySubRoots["com.google.mail."]
		wantSubRoot := hex.EncodeToString(sr[:])
		if !strings.Contains(body, "— keys-v1 —\ncom.google.mail. "+wantSubRoot+"\n") {
			t.Fatalf("keys-v1 section mismatch, got:\n%s", body)
		}
	})

	// 2. Point lookup non-inclusion
	t.Run("point_non_inclusion", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.absent.", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "— mpt-proof-v1 non-inclusion —") {
			t.Fatalf("missing non-inclusion proof header: %s", body)
		}
		if !strings.HasSuffix(body, "— keys-v1 —\n") {
			t.Fatalf("expected empty keys-v1 section, got:\n%s", body)
		}
	})

	// 3. Prefix discovery matching 4 keys in ascending order
	t.Run("prefix_discovery_matches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.?prefix=true", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "— mpt-proof-v1 prefix —") {
			t.Fatalf("missing prefix proof header: %s", body)
		}
		for _, wantKey := range []string{"com.google.", "com.google.*.", "com.google.docs.", "com.google.mail."} {
			if !strings.Contains(body, "\n"+wantKey+" ") {
				t.Errorf("missing expected key %q in prefix response:\n%s", wantKey, body)
			}
		}
		if strings.Contains(body, "com.googleapis.") {
			t.Errorf("unexpected sibling key com.googleapis. in prefix response:\n%s", body)
		}
	})

	// 4. Empty prefix discovery
	t.Run("prefix_discovery_empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.nonexistent.?prefix=true", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "— mpt-proof-v1 prefix —") {
			t.Fatalf("missing prefix proof header: %s", body)
		}
		if !strings.HasSuffix(body, "— keys-v1 —\n") {
			t.Fatalf("expected empty keys-v1 section, got:\n%s", body)
		}
	})

	// 5. Prefix policy rejections (bare TLDs, public suffixes, missing trailing dot)
	t.Run("prefix_policy_rejections", func(t *testing.T) {
		for _, badPrefix := range []string{
			"com.",
			"uk.co.",
			"io.github.",
			"com.*.",
			"com.g*o.",
			"com.*google.",
			"com.Google.",
			"com.foo$bar.",
			"com.google", // missing trailing dot
		} {
			req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/"+badPrefix+"?prefix=true", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("GET /vindex/v1/keys/%s?prefix=true status = %d, want 400", badPrefix, w.Code)
			}
		}
		// Valid eTLD+1 prefixes under multi-label public suffixes must pass policy
		for _, goodPrefix := range []string{
			"uk.co.bbc.news.",
			"io.github.myorg.",
			"com.google.*.",
		} {
			req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/"+goodPrefix+"?prefix=true", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("GET /vindex/v1/keys/%s?prefix=true status = %d, want 200: %s", goodPrefix, w.Code, w.Body.String())
			}
		}
	})

	// 6. Prefix cardinality limit (HTTP 413 Content Too Large)
	t.Run("prefix_cardinality_cap_413", func(t *testing.T) {
		srv.SetMaxPrefixKeys(3)
		defer srv.SetMaxPrefixKeys(DefaultMaxPrefixKeys)

		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.?prefix=true", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 Content Too Large", w.Code)
		}
	})
}

func TestReadServer_HandleEntries_LockFreeAndPagination(t *testing.T) {
	const chunkSize = 100
	srv, db, mptMgr, pub := setupTestServer(t, chunkSize)
	db.SetChunkSize(chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	// Use a key containing slashes (like a Go module path) to verify path extraction
	keyStr := "github.com/google/uuid"
	keyHash := sha256.Sum256([]byte(keyStr))
	var indices []uint64
	for i := uint64(0); i < 150; i++ {
		indices = append(indices, i*2)
	}

	batch := &ingest.MappedBatch{
		KeyMap:        map[[32]byte][]uint64{keyHash: indices},
		CanonicalKeys: map[[32]byte]string{keyHash: keyStr},
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 500)
	if err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 500, Hash: make([]byte, 32)}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeySubRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	// 1. Missing mandatory 'before' parameter -> HTTP 400
	reqNoBefore := httptest.NewRequest(http.MethodGet, "/vindex/v1/entries/"+keyStr, nil)
	wNoBefore := httptest.NewRecorder()
	mux.ServeHTTP(wNoBefore, reqNoBefore)
	if wNoBefore.Code != http.StatusBadRequest {
		t.Fatalf("missing before status = %d, want 400", wNoBefore.Code)
	}

	// 2. Hold exclusive write lock on mptMgr while calling HandleEntries to prove zero MPT lock acquisition!
	mptMgr.Lock()
	reqPage1 := httptest.NewRequest(http.MethodGet, "/vindex/v1/entries/"+keyStr+"?before=500&limit=50", nil)
	wPage1 := httptest.NewRecorder()
	mux.ServeHTTP(wPage1, reqPage1)
	mptMgr.Unlock()

	if wPage1.Code != http.StatusOK {
		t.Fatalf("Page 1 status = %d, want 200: %s", wPage1.Code, wPage1.Body.String())
	}
	body1 := wPage1.Body.String()
	if strings.Contains(body1, "vindex/v1") || strings.Contains(body1, "mpt-proof-v1") {
		t.Fatalf("entries response must not contain checkpoint or MPT proof sections:\n%s", body1)
	}
	if !strings.Contains(body1, "— prefix-compact-range-v1 100 —") {
		t.Fatalf("expected prefix-compact-range-v1 100, got:\n%s", body1)
	}
	if !strings.Contains(body1, "— indices-v1 200 —") {
		t.Fatalf("expected indices-v1 200, got:\n%s", body1)
	}

	// 3. Page 2: before=200&limit=100 -> reaches start of mini-log (covered_size == 0, omits prefix-compact-range-v1)
	reqPage2 := httptest.NewRequest(http.MethodGet, "/vindex/v1/entries/"+keyStr+"?before=200&limit=100", nil)
	wPage2 := httptest.NewRecorder()
	mux.ServeHTTP(wPage2, reqPage2)
	if wPage2.Code != http.StatusOK {
		t.Fatalf("Page 2 status = %d, want 200", wPage2.Code)
	}
	body2 := wPage2.Body.String()
	if strings.Contains(body2, "prefix-compact-range-v1") {
		t.Fatalf("expected prefix-compact-range-v1 to be omitted when covered_size == 0, got:\n%s", body2)
	}
	if !strings.HasPrefix(body2, "— indices-v1 —\n0\n") {
		t.Fatalf("expected indices-v1 starting at 0 with no next_before, got:\n%s", body2)
	}
}

func BenchmarkReadServer_TwoEndpointVsCombined(b *testing.B) {
	dir := b.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		b.Fatalf("kvstore.Open failed: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })

	const chunkSize = 1024
	db.SetChunkSize(chunkSize)
	mptMgr := tree.NewMem()
	outLog := &mockOutputLog{origin: "example.com/output"}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	srv := NewReadServer(db, mptMgr, pub, chunkSize)
	indexer := kvstore.NewKVIndexer(db, chunkSize)

	keyMap := make(map[[32]byte][]uint64, 500)
	canonMap := make(map[[32]byte]string, 500)
	for i := 0; i < 500; i++ {
		var k string
		if i < 25 {
			k = fmt.Sprintf("com.google.sub%03d.", i)
		} else {
			k = fmt.Sprintf("org.other%03d.svc.", i)
		}
		kh := sha256.Sum256([]byte(k))
		indices := make([]uint64, 64)
		for j := range indices {
			indices[j] = uint64(j*10 + (i % 7))
		}
		keyMap[kh] = indices
		canonMap[kh] = k
	}

	batch := &ingest.MappedBatch{
		KeyMap:        keyMap,
		CanonicalKeys: canonMap,
	}
	res, err := indexer.IndexMappedBatch(context.Background(), batch, nil, 10000)
	if err != nil {
		b.Fatalf("IndexMappedBatch failed: %v", err)
	}

	rawInCP := []byte("example.com/input\n10000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 10000, Hash: make([]byte, 32)}
	// Also populate legacy 32-byte key in MPT for BenchmarkReadServer_HandleLookup_Combined comparison
	targetKey := "com.google.sub000."
	targetHash := sha256.Sum256([]byte(targetKey))
	if _, err := mptMgr.Commit(map[[32]byte][32]byte{targetHash: res.ModifiedSubRoots[targetHash]}); err != nil {
		b.Fatalf("Commit failed: %v", err)
	}
	if _, err := pub.PublishKeyBatch(context.Background(), res.ModifiedKeySubRoots, inCP, rawInCP); err != nil {
		b.Fatalf("PublishKeyBatch failed: %v", err)
	}

	targetHex := hex.EncodeToString(targetHash[:])

	b.Run("Legacy_HandleLookup_Combined", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/lookup/"+targetHex+"?limit=100", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleLookup(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("HandleKeys_Point", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/"+targetKey, nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleKeys(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("HandleKeys_Prefix25", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/keys/com.google.?prefix=true", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleKeys(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})

	b.Run("HandleEntries_LockFree", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/vindex/v1/entries/"+targetKey+"?before=10000&limit=100", nil)
		b.ReportAllocs()
		for b.Loop() {
			w := httptest.NewRecorder()
			srv.HandleEntries(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status = %d", w.Code)
			}
		}
	})
}
