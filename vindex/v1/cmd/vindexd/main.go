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

// vindexd is the Verifiable Index daemon.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/hammer"
	"github.com/transparency-dev/incubator/vindex/v1/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	inputLogURL        = flag.String("input_log_url", "", "Base URL of the Input Log.")
	inputLogOrigin     = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey     = flag.String("input_log_pubkey", "", "Public key for Input Log checkpoint verification.")
	outputLogDir       = flag.String("output_log_dir", "", "Path for local Output Log storage.")
	outputLogOrigin    = flag.String("output_log_origin", "example.com/vindex/output", "Origin string for Output Log.")
	outputLogSignerKey = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	dbPath             = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A).")
	mptDir             = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B).")
	wasmPath           = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary.")
	mapper             = flag.String("mapper", "identity", "Leaf mapper implementation: identity, ct, or sumdb.")
	listenAddr         = flag.String("listen_addr", ":8080", "HTTP Read Server address.")
	metricsAddr        = flag.String("metrics_addr", ":9090", "Prometheus metrics scrape address.")
	chunkSize          = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	tileCacheDir       = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval       = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
	enableUI           = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html.")
	backfill           = flag.Bool("backfill", false, "Run in standalone batch backfill mode to catch up to target checkpoint, publish root, and exit.")
	backfillCheckpoint = flag.String("backfill_checkpoint", "", "Optional target checkpoint file path or note-signed text for backfill. If unset, fetches latest from input log.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("vindexd failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}

	// 1. Open Pebble DB
	db, err := kvstore.Open(*dbPath, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("failed to open Pebble DB at %q: %w", *dbPath, err)
	}
	defer func() { _ = db.Close() }()

	// 2. Open MPT Manager
	mptMgr, err := tree.Open(*mptDir)
	if err != nil {
		return fmt.Errorf("failed to open MPT at %q: %w", *mptDir, err)
	}
	defer func() { _ = mptMgr.Close() }()

	// 3. Setup WASM Mapper
	var leafMapper ingest.LeafMapper
	if *wasmPath != "" {
		wasmBytes, err := os.ReadFile(*wasmPath)
		if err != nil {
			return fmt.Errorf("failed to read WASM binary %q: %w", *wasmPath, err)
		}
		host, err := ingest.NewWASMHost(ctx, wasmBytes, 0)
		if err != nil {
			return fmt.Errorf("failed to initialize WASM host: %w", err)
		}
		defer func() { _ = host.Close(ctx) }()
		leafMapper = host
	} else {
		switch *mapper {
		case "sumdb":
			leafMapper = &sumdbLeafMapper{}
		case "ct":
			leafMapper = &ctLeafMapper{}
		case "identity", "":
			leafMapper = &defaultIdentityMapper{}
		default:
			return fmt.Errorf("unknown mapper %q (expected identity, ct, sumdb)", *mapper)
		}
	}

	// 4. Setup Output Log
	var signer note.Signer
	if *outputLogSignerKey != "" {
		s, err := note.NewSigner(*outputLogSignerKey)
		if err != nil {
			// Try reading from file
			keyBytes, fErr := os.ReadFile(*outputLogSignerKey)
			if fErr == nil {
				s, err = note.NewSigner(string(bytes.TrimSpace(keyBytes)))
			}
		}
		if err != nil {
			return fmt.Errorf("failed to construct output log signer: %w", err)
		}
		signer = s
	}

	outputLog := newLocalOutputLog(*outputLogOrigin, *outputLogDir, signer)
	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	idxer := kvstore.NewKVIndexer(db, *chunkSize)

	// Setup Tile Cache & Fetcher
	tileCache, err := ingest.NewManagedTileCache(*tileCacheDir, 0)
	if err != nil {
		return fmt.Errorf("failed to initialize tile cache: %w", err)
	}
	if sz, err := tileCache.DirSize(); err == nil {
		metrics.TileCacheBytes.Set(float64(sz))
	}

	var verifier note.Verifier
	if *inputLogPubKey != "" {
		v, err := note.NewVerifier(*inputLogPubKey)
		if err != nil {
			return fmt.Errorf("failed to create input log verifier: %w", err)
		}
		verifier = v
	}

	var fetcher ingest.TileFetcher
	if *inputLogURL != "" {
		u, err := url.Parse(*inputLogURL)
		if err != nil {
			return fmt.Errorf("invalid input log URL %q: %w", *inputLogURL, err)
		}

		tf, err := hammer.NewTiledFetcher(u, verifier, *inputLogOrigin, nil)
		if err != nil {
			return fmt.Errorf("failed to create input log fetcher: %w", err)
		}
		fetcher = tf
	}

	// 5. Start Metrics HTTP Server
	if *metricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		metricsMux.HandleFunc("/debug/pprof/", pprof.Index)
		metricsMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		metricsMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		metricsMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		metricsMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		metricsServer := &http.Server{
			Addr:    *metricsAddr,
			Handler: metricsMux,
		}
		go func() {
			klog.Infof("Serving Prometheus metrics at http://%s/metrics", *metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				klog.Errorf("Metrics server error: %v", err)
			}
		}()
		defer func() { _ = metricsServer.Close() }()
	}

	// 6. Run 3-Phase Crash Recovery
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	klog.Info("Running 3-phase startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed successfully.")

	// 7. Handle Standalone Backfill Mode
	if *backfill {
		var targetCP *log.Checkpoint
		if *backfillCheckpoint != "" {
			cpBytes, err := os.ReadFile(*backfillCheckpoint)
			if err != nil {
				// Treat value as raw text if not a file
				cpBytes = []byte(*backfillCheckpoint)
			}
			if verifier != nil {
				parsed, _, _, err := log.ParseCheckpoint(cpBytes, *inputLogOrigin, verifier)
				if err != nil {
					return fmt.Errorf("failed to verify backfill checkpoint signature: %w", err)
				}
				targetCP = parsed
			} else {
				parsed, err := parseCheckpointHeaderOnly(cpBytes)
				if err != nil {
					return fmt.Errorf("failed to parse backfill checkpoint: %w", err)
				}
				targetCP = parsed
			}
			klog.Infof("Target backfill checkpoint provided: origin=%q size=%d", targetCP.Origin, targetCP.Size)
		}

		startTime := time.Now()
		klog.Info("Starting coordinator backfill execution...")
		if err := coord.Backfill(ctx, targetCP); err != nil {
			return fmt.Errorf("backfill failed: %w", err)
		}
		elapsed := time.Since(startTime)
		klog.Infof("Backfill completed successfully in %v.", elapsed)
		return nil
	}

	// 8. Start Read Server
	readSrv := server.NewReadServer(db, mptMgr, pub, *chunkSize)
	readSrv.SetEnableUI(*enableUI)
	readMux := http.NewServeMux()
	readSrv.RegisterRoutes(readMux)
	httpServer := &http.Server{
		Addr:    *listenAddr,
		Handler: readMux,
	}

	go func() {
		klog.Infof("Serving VIndex Read API at http://%s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("Read server error: %v", err)
		}
	}()
	defer func() { _ = httpServer.Close() }()

	// 9. Start Background Tile Reaper
	tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
	go func() {
		_ = tileReaper.Run(ctx, 60*time.Second)
	}()

	// 10. Start Ingestion & Commit Pipeline Loop
	if fetcher != nil {
		klog.Infof("Starting zero-WAL ingestion pipeline polling %q every %v", *inputLogURL, *pollInterval)
		if err := coord.Run(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("coordinator run failed: %w", err)
		}
	} else {
		<-ctx.Done()
	}

	klog.Info("Shutting down vindexd gracefully...")
	return nil
}

func parseCheckpointHeaderOnly(rawCP []byte) (*log.Checkpoint, error) {
	lines := strings.Split(string(bytes.TrimRight(rawCP, "\n")), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("checkpoint header has %d lines, want at least 3", len(lines))
	}
	origin := lines[0]
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size %q: %w", lines[1], err)
	}
	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 hash %q: %w", lines[2], err)
	}
	return &log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hashBytes,
	}, nil
}

type defaultIdentityMapper struct{}

func (m *defaultIdentityMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	kh := sha256.Sum256(leaf)
	return []ingest.MappedEntry{{KeyHash: kh}}, nil
}

func (m *defaultIdentityMapper) Close(_ context.Context) error { return nil }

type ctLeafMapper struct{}

func (m *ctLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	lines := strings.Split(string(leaf), "\n")
	seen := make(map[string]struct{})
	var entries []ingest.MappedEntry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ".")
		var etld1 string
		if len(parts) >= 2 {
			etld1 = parts[len(parts)-2] + "." + parts[len(parts)-1]
		} else {
			etld1 = line
		}
		if _, exists := seen[etld1]; !exists {
			seen[etld1] = struct{}{}
			entries = append(entries, ingest.MappedEntry{
				KeyHash: sha256.Sum256([]byte(etld1)),
			})
		}
	}
	return entries, nil
}

func (m *ctLeafMapper) Close(_ context.Context) error { return nil }

type sumdbLeafMapper struct{}

func (m *sumdbLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	keys := mapSumDBLeaf(leaf)
	if len(keys) == 0 {
		return nil, nil
	}
	entries := make([]ingest.MappedEntry, len(keys))
	for i, k := range keys {
		entries[i] = ingest.MappedEntry{KeyHash: k}
	}
	return entries, nil
}

func (m *sumdbLeafMapper) MapBundle(_ context.Context, leaves [][]byte) ([][]ingest.MappedEntry, error) {
	results := make([][]ingest.MappedEntry, len(leaves))
	for i, leaf := range leaves {
		keys := mapSumDBLeaf(leaf)
		if len(keys) > 0 {
			entries := make([]ingest.MappedEntry, len(keys))
			for j, k := range keys {
				entries[j] = ingest.MappedEntry{KeyHash: k}
			}
			results[i] = entries
		}
	}
	return results, nil
}

func (m *sumdbLeafMapper) Close(_ context.Context) error { return nil }

func mapSumDBLeaf(data []byte) [][sha256.Size]byte {
	var results [8][sha256.Size]byte
	n := 0

	for len(data) > 0 {
		var line []byte
		idx := bytes.IndexByte(data, '\n')
		if idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			line = data
			data = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		modEnd := bytes.IndexByte(line, ' ')
		if modEnd == -1 {
			continue
		}
		modPath := line[:modEnd]

		verStart := modEnd + 1
		if verStart >= len(line) {
			continue
		}
		verLen := bytes.IndexByte(line[verStart:], ' ')
		var verBytes []byte
		if verLen == -1 {
			verBytes = line[verStart:]
		} else {
			verBytes = line[verStart : verStart+verLen]
		}
		verBytes = bytes.TrimSuffix(verBytes, []byte("/go.mod"))

		// Filter out ephemeral pseudo-versions
		if isPseudoVersion(verBytes) {
			continue
		}

		h := sha256.Sum256(modPath)
		duplicate := false
		for i := 0; i < n; i++ {
			if results[i] == h {
				duplicate = true
				break
			}
		}
		if !duplicate && n < len(results) {
			results[n] = h
			n++
		}
	}

	return results[:n]
}

func isPseudoVersion(v []byte) bool {
	if len(v) < 30 || v[0] != 'v' {
		return false
	}
	if idx := bytes.IndexByte(v, '+'); idx != -1 {
		build := v[idx+1:]
		if len(build) == 0 {
			return false
		}
		for _, b := range build {
			if !isIdentChar(b) && b != '.' {
				return false
			}
		}
		v = v[:idx]
	}
	lastDash := bytes.LastIndexByte(v, '-')
	if lastDash == -1 {
		return false
	}
	rev := v[lastDash+1:]
	if len(rev) == 0 {
		return false
	}
	for _, b := range rev {
		if !isAlnum(b) {
			return false
		}
	}
	rest := v[:lastDash]
	secondDash := bytes.LastIndexByte(rest, '-')
	if secondDash == -1 {
		return false
	}
	var timestamp, prefix []byte
	dotAfterDash := bytes.LastIndexByte(rest[secondDash:], '.')
	if dotAfterDash != -1 {
		dotPos := secondDash + dotAfterDash
		timestamp = rest[dotPos+1:]
		prefix = rest[:dotPos]
	} else {
		timestamp = rest[secondDash+1:]
		prefix = rest[:secondDash]
	}
	if len(timestamp) != 14 {
		return false
	}
	for _, b := range timestamp {
		if b < '0' || b > '9' {
			return false
		}
	}
	if dotAfterDash == -1 {
		return isMajorDotZeroDotZero(prefix)
	}
	if !bytes.HasSuffix(prefix, []byte(".0")) && !bytes.HasSuffix(prefix, []byte("-0")) {
		return false
	}
	dashIdx := bytes.IndexByte(prefix, '-')
	if dashIdx == -1 {
		return false
	}
	return isBaseSemver(prefix[:dashIdx])
}

func isMajorDotZeroDotZero(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' || !bytes.HasSuffix(s, []byte(".0.0")) {
		return false
	}
	major := s[1 : len(s)-4]
	if len(major) == 0 || (len(major) > 1 && major[0] == '0') {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isBaseSemver(s []byte) bool {
	if len(s) < 6 || s[0] != 'v' {
		return false
	}
	s = s[1:]
	dot1 := bytes.IndexByte(s, '.')
	if dot1 <= 0 {
		return false
	}
	major := s[:dot1]
	if len(major) > 1 && major[0] == '0' {
		return false
	}
	for _, b := range major {
		if b < '0' || b > '9' {
			return false
		}
	}
	s = s[dot1+1:]
	dot2 := bytes.IndexByte(s, '.')
	if dot2 <= 0 {
		return false
	}
	minor := s[:dot2]
	if len(minor) > 1 && minor[0] == '0' {
		return false
	}
	for _, b := range minor {
		if b < '0' || b > '9' {
			return false
		}
	}
	patch := s[dot2+1:]
	if len(patch) == 0 || (len(patch) > 1 && patch[0] == '0') {
		return false
	}
	for _, b := range patch {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentChar(b byte) bool {
	return isAlnum(b) || b == '-'
}

type localOutputLog struct {
	mu     sync.Mutex
	origin string
	dir    string
	signer note.Signer
	leaves [][]byte
}

func newLocalOutputLog(origin, dir string, signer note.Signer) *localOutputLog {
	l := &localOutputLog{
		origin: origin,
		dir:    dir,
		signer: signer,
	}
	if dir != "" {
		leavesPath := filepath.Join(dir, "leaves.dat")
		data, err := os.ReadFile(leavesPath)
		if err == nil && len(data) > 0 {
			offset := 0
			for offset+4 <= len(data) {
				sz := int(binary.BigEndian.Uint32(data[offset : offset+4]))
				offset += 4
				if offset+sz > len(data) {
					break
				}
				leaf := make([]byte, sz)
				copy(leaf, data[offset:offset+sz])
				l.leaves = append(l.leaves, leaf)
				offset += sz
			}
		}
	}
	return l
}

func (l *localOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	l.leaves = append(l.leaves, leafData)
	size := uint64(len(l.leaves))

	root := kvstore.BatchRoot(l.leaves)
	var rawCP []byte
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to sign checkpoint note: %w", err)
		}
		rawCP = signed
	} else {
		rawCP = []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:])))
	}

	if l.dir != "" {
		_ = os.MkdirAll(l.dir, 0o755)
		_ = os.WriteFile(filepath.Join(l.dir, "checkpoint"), rawCP, 0o644)
		if f, err := os.OpenFile(filepath.Join(l.dir, "leaves.dat"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(leafData)))
			_, _ = f.Write(lenBuf[:])
			_, _ = f.Write(leafData)
			_ = f.Close()
		}
	}

	return idx, rawCP, nil
}

func (l *localOutputLog) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves)), nil
}

func (l *localOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *localOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
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

func (l *localOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

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
