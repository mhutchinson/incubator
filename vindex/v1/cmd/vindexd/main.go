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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
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
	mode               = flag.String("mode", "publisher", "Daemon operation mode: 'publisher' (default), 'auditor', or 'verifier'.")
	inputLogURL        = flag.String("input_log_url", "", "Base URL of the Input Log.")
	inputLogOrigin     = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey     = flag.String("input_log_pubkey", "", "Public key for Input Log checkpoint verification.")
	outputLogDir       = flag.String("output_log_dir", "", "Path for local Output Log storage.")
	outputLogOrigin    = flag.String("output_log_origin", "example.com/vindex/output", "Origin string for Output Log.")
	outputLogSignerKey = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	outputLogURL       = flag.String("output_log_url", "", "Base URL of Output Log to verify (auditor/verifier mode).")
	outputLogPubKey    = flag.String("output_log_pubkey", "", "Public key for Output Log checkpoint verification (auditor/verifier mode).")
	serveMirror        = flag.Bool("serve_mirror", false, "Enable verified mirror serving mode on listen_addr (auditor/verifier mode).")
	failClosed         = flag.Bool("fail_closed", false, "Immediately revoke mirror serving on verification mismatch instead of serving last verified checkpoint (auditor/verifier mode).")
	oneShot            = flag.Bool("oneshot", false, "Run verification once against log tip and exit (auditor/verifier mode).")
	dbPath             = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A).")
	mptDir             = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B).")
	wasmPath           = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary.")
	mapper             = flag.String("mapper", "identity", "Leaf mapper implementation: identity or ct.")
	listenAddr         = flag.String("listen_addr", ":8080", "HTTP Read Server address.")
	metricsAddr        = flag.String("metrics_addr", ":9090", "Prometheus metrics scrape address.")
	chunkSize          = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	tileCacheDir       = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval       = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
	enableUI           = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html.")
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
	switch strings.ToLower(*mode) {
	case "publisher", "coordinator", "":
		return runPublisher(ctx)
	case "auditor", "verifier":
		return runAuditor(ctx)
	default:
		return fmt.Errorf("unknown mode %q: expected 'publisher', 'auditor', or 'verifier'", *mode)
	}
}

func runPublisher(ctx context.Context) error {
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

	// 3. Setup Mapper
	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *mapper)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
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

	var fetcher ingest.TileFetcher
	if *inputLogURL != "" {
		u, err := url.Parse(*inputLogURL)
		if err != nil {
			return fmt.Errorf("invalid input log URL %q: %w", *inputLogURL, err)
		}

		var verifier note.Verifier
		if *inputLogPubKey != "" {
			v, err := note.NewVerifier(*inputLogPubKey)
			if err != nil {
				return fmt.Errorf("failed to create input log verifier: %w", err)
			}
			verifier = v
		}

		tf, err := ingest.NewTiledFetcher(u, verifier, *inputLogOrigin, nil)
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

	// 6. Start Read Server
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

	// 7. Run 3-Phase Crash Recovery
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	klog.Info("Running 3-phase startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed successfully.")

	// 8. Start Background Tile Reaper
	tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
	go func() {
		_ = tileReaper.Run(ctx, 60*time.Second)
	}()

	// 9. Start Ingestion & Commit Pipeline Loop
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

func runAuditor(ctx context.Context) error {
	if *outputLogSignerKey != "" {
		return errors.New("security invariant violation: --output_log_signer_key must not be specified in verifier mode; verifiers/auditors must never sign output logs")
	}
	if *outputLogURL == "" {
		return errors.New("--output_log_url is required in verifier mode")
	}
	if *inputLogURL == "" {
		return errors.New("--input_log_url is required in verifier mode")
	}
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *mptDir == "" {
		return errors.New("--mpt_dir flag is required")
	}
	if *serveMirror && *listenAddr == "" {
		return errors.New("--listen_addr cannot be empty when --serve_mirror is enabled")
	}

	resolvedInPubKey, err := resolveKey(*inputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve input log pubkey: %w", err)
	}
	resolvedOutPubKey, err := resolveKey(*outputLogPubKey)
	if err != nil {
		return fmt.Errorf("failed to resolve output log pubkey: %w", err)
	}

	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *mapper)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
	}

	cfg := auditor.Config{
		InputLogURL:     *inputLogURL,
		InputLogPubKey:  resolvedInPubKey,
		InputLogOrigin:  *inputLogOrigin,
		OutputLogURL:    *outputLogURL,
		OutputLogPubKey: resolvedOutPubKey,
		OutputLogOrigin: *outputLogOrigin,
		MapFn:           leafMapper,
		DBPath:          *dbPath,
		MPTDir:          *mptDir,
		ServeMirror:     *serveMirror,
		FailClosed:      *failClosed,
		ListenAddr:      *listenAddr,
		MetricsAddr:     *metricsAddr,
		PollInterval:    *pollInterval,
		CommitBatchSize: *chunkSize,
	}

	v, err := auditor.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize auditor engine: %w", err)
	}
	defer func() { _ = v.Close() }()

	if *oneShot {
		klog.Info("Running oneshot verification...")
		if err := v.VerifyOnce(ctx); err != nil {
			return fmt.Errorf("oneshot verification failed: %w", err)
		}
		klog.Info("Oneshot verification succeeded.")
		return nil
	}

	klog.Infof("Starting auditor daemon (poll interval: %v, mirror: %v)...", *pollInterval, *serveMirror)
	return v.Run(ctx)
}

func resolveKey(keyOrPath string) (string, error) {
	keyOrPath = strings.TrimSpace(keyOrPath)
	if keyOrPath == "" {
		return "", nil
	}
	if data, err := os.ReadFile(keyOrPath); err == nil {
		return string(bytes.TrimSpace(data)), nil
	}
	return keyOrPath, nil
}

func initMapper(ctx context.Context, wasm, mapperName string) (ingest.LeafMapper, func(), error) {
	if wasm != "" {
		wasmBytes, err := os.ReadFile(wasm)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read WASM binary %q: %w", wasm, err)
		}
		host, err := ingest.NewWASMHost(ctx, wasmBytes, 4)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
		}
		return host, func() { _ = host.Close(ctx) }, nil
	}

	switch strings.ToLower(mapperName) {
	case "ct":
		return &ctLeafMapper{}, nil, nil
	case "identity", "":
		return &defaultIdentityMapper{}, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown mapper %q (expected identity, ct)", mapperName)
	}
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

type localOutputLog struct {
	mu     sync.Mutex
	origin string
	dir    string
	signer note.Signer
	leaves [][]byte
}

func newLocalOutputLog(origin, dir string, signer note.Signer) *localOutputLog {
	return &localOutputLog{
		origin: origin,
		dir:    dir,
		signer: signer,
	}
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
