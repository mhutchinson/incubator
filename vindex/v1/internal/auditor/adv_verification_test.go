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
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
)

// trackingMapper wraps ingest.LeafMapper and tracks which leaf indices were mapped.
type trackingMapper struct {
	mu           sync.Mutex
	mappedLeaves []string
	callCount    int
}

func (m *trackingMapper) MapLeaf(ctx context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	m.mu.Lock()
	m.callCount++
	m.mappedLeaves = append(m.mappedLeaves, string(leaf))
	m.mu.Unlock()
	h := sha256.Sum256(leaf)
	return []ingest.MappedEntry{{KeyHash: h}}, nil
}

func (m *trackingMapper) Close(ctx context.Context) error {
	return nil
}

func (m *trackingMapper) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *trackingMapper) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mappedLeaves = nil
	m.callCount = 0
}

// trackingInputLog wraps memoryInputLog and tracks requested leaf index ranges in FetchTiles.
type trackingInputLog struct {
	*memoryInputLog
	mu            sync.Mutex
	fetchedRanges [][2]uint64
	fetchedLeaves []uint64
}

func newTrackingInputLog(inLog *memoryInputLog) *trackingInputLog {
	return &trackingInputLog{
		memoryInputLog: inLog,
	}
}

func (t *trackingInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	t.mu.Lock()
	t.fetchedRanges = append(t.fetchedRanges, [2]uint64{startLeafIdx, startLeafIdx + count})
	for i := startLeafIdx; i < startLeafIdx+count; i++ {
		t.fetchedLeaves = append(t.fetchedLeaves, i)
	}
	t.mu.Unlock()
	return t.memoryInputLog.FetchTiles(ctx, startLeafIdx, count)
}

func (t *trackingInputLog) ResetTracking() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fetchedRanges = nil
	t.fetchedLeaves = nil
}

func (t *trackingInputLog) GetFetchedLeaves() []uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]uint64(nil), t.fetchedLeaves...)
}

// parseMetricsOutput extracts named metrics from Prometheus text exposition.
func parseMetricsOutput(body string) map[string]float64 {
	results := make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			if val, err := strconv.ParseFloat(parts[1], 64); err == nil {
				results[name] = val
			}
		}
	}
	return results
}

// TestAdv_HealthCheckReadServerIntegration empirically tests Task 1:
// Verify HealthCheck() integration with server.ReadServer over real HTTP connections:
// /healthz returns HTTP 200 before mismatch and HTTP 503 after mismatch, including under concurrent traffic.
func TestAdv_HealthCheckReadServerIntegration(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	// Populate authentic leaves
	var rawLeaves [][]byte
	for i := 0; i < 6; i++ {
		leaf := []byte(fmt.Sprintf("health-check-leaf-%d", i))
		rawLeaves = append(rawLeaves, leaf)
		h.inLog.AppendLeaf(leaf)
	}

	// Honest leaf 0
	root0 := computeExpectedMapRoot(t, rawLeaves[:3], h.mapper)
	cp0, err := h.inLog.SignCheckpoint(3)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0)); err != nil {
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
		t.Fatal("ReadServer must not be nil when ServeMirror is enabled")
	}

	mux := http.NewServeMux()
	readServer.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Step 1: Query /healthz BEFORE any verification pass
	resp1, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer func() { _ = resp1.Body.Close() }()
	body1, _ := io.ReadAll(resp1.Body)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("before verification: /healthz status = %d (body %q), want 200 OK", resp1.StatusCode, string(body1))
	}
	if string(body1) != "ok\n" {
		t.Fatalf("before verification: /healthz body = %q, want 'ok\\n'", string(body1))
	}
	if err := v.HealthCheck(); err != nil {
		t.Fatalf("v.HealthCheck() returned error before mismatch: %v", err)
	}

	// Step 2: Honest verification pass
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce honest leaf failed: %v", err)
	}

	resp2, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz after honest sync failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("after honest sync: /healthz status = %d (body %q), want 200 OK", resp2.StatusCode, string(body2))
	}
	if string(body2) != "ok\n" {
		t.Fatalf("after honest sync: /healthz body = %q, want 'ok\\n'", string(body2))
	}

	// Step 3: Append tampered leaf 1
	tamperedRoot := sha256.Sum256([]byte("tampered_map_root"))
	cp1, err := h.inLog.SignCheckpoint(6)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(tamperedRoot, cp1)); err != nil {
		t.Fatalf("Append tampered leaf failed: %v", err)
	}

	// Step 4: Verify concurrent health querying during mismatch detection
	var wg sync.WaitGroup
	var concurrentErrors int
	stopProbe := make(chan struct{})

	// Fire background probe goroutines against /healthz
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopProbe:
					return
				default:
					resp, err := http.Get(ts.URL + "/healthz")
					if err == nil {
						_ = resp.Body.Close()
						if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
							t.Errorf("unexpected status code during transition: %d", resp.StatusCode)
						}
					} else {
						concurrentErrors++
					}
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}

	// Execute mismatching verification
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		close(stopProbe)
		wg.Wait()
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	close(stopProbe)
	wg.Wait()

	// Step 5: Query /healthz AFTER mismatch — must return HTTP 503 Service Unavailable
	resp3, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz after mismatch failed: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()
	body3, _ := io.ReadAll(resp3.Body)

	if resp3.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("after mismatch: /healthz status = %d, want 503 Service Unavailable", resp3.StatusCode)
	}
	if !strings.Contains(string(body3), "unhealthy: verifier root hash mismatch") {
		t.Fatalf("after mismatch: /healthz body = %q, want error containing 'unhealthy: verifier root hash mismatch'", string(body3))
	}

	// Direct HealthCheck() call must also return ErrRootMismatch
	hErr := v.HealthCheck()
	if hErr == nil || !errors.Is(hErr, auditor.ErrRootMismatch) {
		t.Fatalf("v.HealthCheck() = %v, want ErrRootMismatch", hErr)
	}
}

// TestAdv_PersistenceNoDuplicateIndexing empirically tests Task 2:
// Stop verifier, restart on disk DB, ensure it resumes from watermarks without duplicate indexing.
func TestAdv_PersistenceNoDuplicateIndexing(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	trackerFetcher := newTrackingInputLog(h.inLog)
	trackerMapper := &trackingMapper{}

	dbDir := t.TempDir()
	mptDir := t.TempDir()

	// Prepare 15 leaves in total
	var rawLeaves [][]byte
	for i := 0; i < 15; i++ {
		leaf := []byte(fmt.Sprintf("disk-persist-leaf-%04d", i))
		rawLeaves = append(rawLeaves, leaf)
		trackerFetcher.AppendLeaf(leaf)
	}

	// Leaf 0 commits to first 5 leaves [0..5)
	root0 := computeExpectedMapRoot(t, rawLeaves[:5], trackerMapper)
	cp0, err := trackerFetcher.SignCheckpoint(5)
	if err != nil {
		t.Fatalf("SignCheckpoint(5) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0)); err != nil {
		t.Fatalf("Append leaf 0 failed: %v", err)
	}

	cfg := auditor.Config{
		InputLogVerifier:  h.inVerifier,
		OutputLogVerifier: h.outVerifier,
		OutputLogOrigin:   "example.com/test/outputlog",
		InputLogOrigin:    "example.com/test/inputlog",
		OutputLog:         h.outLog,
		InputLogFetcher:   trackerFetcher,
		MapFn:             trackerMapper,
		DBPath:            dbDir,
		MPTDir:            mptDir,
	}

	// --- Phase 1: First Run ---
	v1, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v1 New failed: %v", err)
	}

	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	if err := v1.VerifyOnce(ctx); err != nil {
		t.Fatalf("v1 VerifyOnce failed: %v", err)
	}

	st1 := v1.Status()
	if st1.VerifiedOutputSize != 1 || st1.VerifiedInputSize != 5 || st1.LastVerifiedRoot != root0 {
		t.Fatalf("v1 status incorrect: %+v", st1)
	}

	// Assert that leaves 0..4 were mapped
	mappedCount1 := trackerMapper.GetCallCount()
	if mappedCount1 != 5 {
		t.Fatalf("v1 mapped %d leaves, want 5", mappedCount1)
	}
	fetched1 := trackerFetcher.GetFetchedLeaves()
	if len(fetched1) != 5 {
		t.Fatalf("v1 fetched %d leaves, want 5", len(fetched1))
	}

	// Close v1
	if err := v1.Close(); err != nil {
		t.Fatalf("v1 Close failed: %v", err)
	}

	// --- Phase 2: Add OutputLog Leaf 1 (leaves 5..10) and Restart on Disk DB ---
	root1 := computeExpectedMapRoot(t, rawLeaves[:10], trackerMapper)
	cp1, err := trackerFetcher.SignCheckpoint(10)
	if err != nil {
		t.Fatalf("SignCheckpoint(10) failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root1, cp1)); err != nil {
		t.Fatalf("Append leaf 1 failed: %v", err)
	}

	// Reset trackers to monitor ONLY what happens during the restarted session
	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	v2, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v2 New failed: %v", err)
	}

	// Verify watermarks were recovered from disk before running VerifyOnce
	st2Initial := v2.Status()
	if st2Initial.VerifiedOutputSize != 1 {
		t.Fatalf("v2 recovered VerifiedOutputSize = %d, want 1", st2Initial.VerifiedOutputSize)
	}
	if st2Initial.VerifiedInputSize != 5 {
		t.Fatalf("v2 recovered VerifiedInputSize = %d, want 5", st2Initial.VerifiedInputSize)
	}
	if st2Initial.LastVerifiedRoot != root0 {
		t.Fatalf("v2 recovered LastVerifiedRoot = %x, want %x", st2Initial.LastVerifiedRoot, root0)
	}

	// Run verification on v2
	if err := v2.VerifyOnce(ctx); err != nil {
		t.Fatalf("v2 VerifyOnce failed: %v", err)
	}

	st2Updated := v2.Status()
	if st2Updated.VerifiedOutputSize != 2 || st2Updated.VerifiedInputSize != 10 || st2Updated.LastVerifiedRoot != root1 {
		t.Fatalf("v2 status after sync incorrect: %+v", st2Updated)
	}

	// CRITICAL ASSERTION: Ensure NO DUPLICATE INDEXING or duplicate mapping occurred
	mappedCount2 := trackerMapper.GetCallCount()
	if mappedCount2 != 5 {
		t.Fatalf("v2 mapped %d leaves, want exactly 5 new leaves (no duplicates of leaves 0..4)", mappedCount2)
	}

	fetched2 := trackerFetcher.GetFetchedLeaves()
	for _, idx := range fetched2 {
		if idx < 5 {
			t.Fatalf("DUPLICATE FETCH DETECTED: leaf index %d was fetched during resume (watermark was 5)", idx)
		}
		if idx >= 10 {
			t.Fatalf("OUT-OF-BOUNDS FETCH DETECTED: leaf index %d was fetched beyond target size 10", idx)
		}
	}

	// --- Phase 3: Zero-Delta Restart (already caught up) ---
	if err := v2.Close(); err != nil {
		t.Fatalf("v2 Close failed: %v", err)
	}

	trackerMapper.Reset()
	trackerFetcher.ResetTracking()

	v3, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("v3 New failed: %v", err)
	}
	defer func() { _ = v3.Close() }()

	st3 := v3.Status()
	if st3.VerifiedOutputSize != 2 || st3.VerifiedInputSize != 10 {
		t.Fatalf("v3 recovered status incorrect: %+v", st3)
	}

	// Calling VerifyOnce with no new output log leaves must do ZERO fetches and ZERO mappings
	if err := v3.VerifyOnce(ctx); err != nil {
		t.Fatalf("v3 VerifyOnce failed on zero delta: %v", err)
	}

	if count := trackerMapper.GetCallCount(); count != 0 {
		t.Fatalf("zero-delta run mapped %d leaves, want 0", count)
	}
	if fetched := trackerFetcher.GetFetchedLeaves(); len(fetched) != 0 {
		t.Fatalf("zero-delta run fetched %d leaves, want 0", len(fetched))
	}
}

// TestAdv_PrometheusMetricsScraping empirically tests Task 3:
// Verify Prometheus metrics scraping: verify vindex_verifier_root_mismatch and vindex_verifier_root_mismatches_total
// via real HTTP GET /metrics scraping.
func TestAdv_PrometheusMetricsScraping(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	h.inLog.AppendLeaf([]byte("metrics-test-leaf-0"))

	// Format OutputLog leaf 0 with mismatched root
	wrongRoot := sha256.Sum256([]byte("intentionally-wrong-mpt-root"))
	cp, err := h.inLog.SignCheckpoint(1)
	if err != nil {
		t.Fatalf("SignCheckpoint failed: %v", err)
	}
	if _, _, err := h.outLog.Append(ctx, tree.FormatOutputLogLeaf(wrongRoot, cp)); err != nil {
		t.Fatalf("Append leaf failed: %v", err)
	}

	// Pick free port for metrics server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	metricsAddr := l.Addr().String()
	_ = l.Close()

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
		MetricsAddr:       metricsAddr,
		PollInterval:      100 * time.Millisecond,
	}

	v, err := auditor.New(cfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// Test scraping via ReadServer routes
	readServer := v.ReadServer()
	readMux := http.NewServeMux()
	readServer.RegisterRoutes(readMux)
	readTS := httptest.NewServer(readMux)
	defer readTS.Close()

	// Scrape metrics before mismatch
	respBefore, err := http.Get(readTS.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics before mismatch failed: %v", err)
	}
	defer func() { _ = respBefore.Body.Close() }()
	bodyBytesBefore, _ := io.ReadAll(respBefore.Body)
	mBefore := parseMetricsOutput(string(bodyBytesBefore))

	gaugeBefore, ok := mBefore["vindex_verifier_root_mismatch"]
	if !ok {
		t.Fatal("metric 'vindex_verifier_root_mismatch' not found in scraped /metrics output before mismatch")
	}
	if gaugeBefore != 0.0 {
		t.Fatalf("vindex_verifier_root_mismatch = %v before mismatch, want 0.0", gaugeBefore)
	}

	counterBefore := mBefore["vindex_verifier_root_mismatches_total"]

	// Trigger mismatch via VerifyOnce
	err = v.VerifyOnce(ctx)
	if err == nil || !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}

	// Scrape metrics after mismatch
	respAfter, err := http.Get(readTS.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics after mismatch failed: %v", err)
	}
	defer func() { _ = respAfter.Body.Close() }()
	bodyBytesAfter, _ := io.ReadAll(respAfter.Body)
	mAfter := parseMetricsOutput(string(bodyBytesAfter))

	gaugeAfter, ok := mAfter["vindex_verifier_root_mismatch"]
	if !ok {
		t.Fatal("metric 'vindex_verifier_root_mismatch' not found in scraped /metrics output after mismatch")
	}
	if gaugeAfter != 1.0 {
		t.Fatalf("vindex_verifier_root_mismatch = %v after mismatch, want 1.0", gaugeAfter)
	}

	counterAfter, ok := mAfter["vindex_verifier_root_mismatches_total"]
	if !ok {
		t.Fatal("metric 'vindex_verifier_root_mismatches_total' not found in scraped /metrics output after mismatch")
	}
	if counterAfter != counterBefore+1 {
		t.Fatalf("vindex_verifier_root_mismatches_total = %v, want %v (incremented by 1)", counterAfter, counterBefore+1)
	}
}

// TestAdv_ConcurrentHealthCheckStress tests concurrent verification and health probing.
// HealthCheck() only inspects isHalted and haltErr, which are synchronized via stateMu.
func TestAdv_ConcurrentHealthCheckStress(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("stress-leaf-%d", i)))
	}
	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("stress-leaf-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves, h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0))

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
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	var wg sync.WaitGroup
	// 10 concurrent callers of VerifyOnce
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = v.VerifyOnce(ctx)
		}()
	}
	// 10 concurrent callers of HealthCheck
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = v.HealthCheck()
		}()
	}
	wg.Wait()

	if err := v.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

// TestAdv_StatusDataRace exposes the data race between VerifyOnce() updating
// verifiedInputSize / verifiedOutputSize and Status() reading them.
// This test documents a defect in auditor.go where watermarks are updated
// outside stateMu.Lock() while Status() reads them under stateMu.RLock().
func TestAdv_StatusDataRace(t *testing.T) {
	ctx := context.Background()
	h := newTestHarness(t)
	metrics.ResetVerifierRootMismatch()

	for i := 0; i < 5; i++ {
		h.inLog.AppendLeaf([]byte(fmt.Sprintf("status-race-leaf-%d", i)))
	}
	leaves := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		leaves[i] = []byte(fmt.Sprintf("status-race-leaf-%d", i))
	}
	root0 := computeExpectedMapRoot(t, leaves, h.mapper)
	cp0, _ := h.inLog.SignCheckpoint(5)
	_, _, _ = h.outLog.Append(ctx, tree.FormatOutputLogLeaf(root0, cp0))

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
		t.Fatalf("New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	var wg sync.WaitGroup
	// Concurrent callers of VerifyOnce and Status()
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = v.VerifyOnce(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = v.Status()
		}()
	}
	wg.Wait()
}
