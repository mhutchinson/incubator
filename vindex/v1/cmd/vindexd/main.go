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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/v1/internal/budget"
	"github.com/transparency-dev/incubator/vindex/v1/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/internal/verifier"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	mode               = flag.String("mode", "publisher", "Daemon operation mode: 'publisher' (default), 'auditor', or 'verifier'.")
	maxMemory          = flag.String("max_memory", "", "Maximum RAM budget (e.g. '32GB', '16GiB', '8000M'). If unset, defaults to 16GB (or host physical limit if lower).")
	maxCPUs            = flag.Int("max_cpus", 0, "Maximum CPU core allocation. 0 defaults to runtime.GOMAXPROCS(0).")
	tune               = flag.String("tune", "", "Fine-grained resource tuning parameters in key=value format (e.g. 'genesis_key_buffer=25M,db_cache=4096MB').")
	inputLogURL        = flag.String("input_log_url", "", "Base URL of the Input Log.")
	inputLogOrigin     = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey     = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>).")
	outputLogDir       = flag.String("output_log_dir", "", "Path for local Output Log storage.")
	outputLogOrigin    = flag.String("output_log_origin", "", "Origin string for Output Log. If unset, defaults to signer name.")
	outputLogSignerKey = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	outputLogURL       = flag.String("output_log_url", "", "Base URL of Output Log to verify (auditor/verifier mode).")
	outputLogPubKey    = flag.String("output_log_pubkey", "", "Public key for Output Log checkpoint verification (auditor/verifier mode).")
	serveMirror        = flag.Bool("serve_mirror", false, "Enable verified mirror serving mode on listen_addr (auditor/verifier mode).")
	failClosed         = flag.Bool("fail_closed", false, "Immediately revoke mirror serving on verification mismatch instead of serving last verified checkpoint (auditor/verifier mode).")
	oneShot            = flag.Bool("oneshot", false, "Run synchronization once against log tip and exit (supported in publisher, auditor, and verifier modes).")
	dbPath             = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A).")
	mptDir             = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B).")
	wasmPath           = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	listenAddr         = flag.String("listen_addr", ":8080", "HTTP Read Server address.")
	metricsAddr        = flag.String("metrics_addr", ":9090", "Prometheus metrics scrape address.")
	chunkSize          = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	tileCacheDir       = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval         = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
	disableReaper        = flag.Bool("disable_reaper", false, "Disable background tile cache reaper to keep tiles cached indefinitely.")
	kvIndexerWorkers     = flag.Int("kv_indexer_workers", 0, "Number of worker goroutines for parallel key indexing (0 defaults to min(8, max(1, GOMAXPROCS/2))).")
	fetchBatchBundles    = flag.Int("fetch_batch_bundles", 50, "Number of leaf bundles fetched per worker batch in Stage 1 (defaults to 50, ~12,800 leaves).")
	dbMaxOpenFiles       = flag.Int("db_max_open_files", 0, "Maximum open files for Pebble DB (0 auto-tunes based on system ulimit -n).")
	dbCacheSizeMB        = flag.Int("db_cache_size_mb", 0, "Pebble block cache size in megabytes (0 defaults to 512 MB, recommend 4096-16384 on large memory hosts).")
	enableUI             = flag.Bool("enable_ui", true, "Set to true to serve the single-page HTML UI at / and /index.html.")
	wasmWorkers          = flag.Int("wasm_workers", 0, "Number of concurrent WASM worker instances (0 defaults to GOMAXPROCS - 1).")
	fetchWorkers         = flag.Int("fetch_workers", 4, "Number of concurrent tile fetch workers (defaults to 4, 1 disables parallel fetching).")
	inputLogType         = flag.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'.")
	mutexProfileFraction = flag.Int("mutex_profile_fraction", 0, "If > 0, enable mutex contention profiling sampling 1/N events.")
	blockProfileRate         = flag.Int("block_profile_rate", 0, "If > 0, enable goroutine blocking profiling with nanosecond rate.")
	cleanDirs                = flag.Bool("clean", false, "Clean db_path, mpt_dir, output_log_dir, and tile_cache_dir on startup.")
	backfillMaxPendingKeys   = flag.Int("backfill_max_pending_keys", 50000000, "Maximum deduplicated keys buffered in memory during Genesis Backfill before flushing to MPT (defaults to 50,000,000, ~5.5 GB RAM).")
	coarseCheckpointInterval = flag.Int("coarse_checkpoint_interval", 50000000, "Maximum leaves between coarse checkpoints during Genesis Backfill (defaults to 50,000,000).")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *mutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(*mutexProfileFraction)
	}
	if *blockProfileRate > 0 {
		runtime.SetBlockProfileRate(*blockProfileRate)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("vindexd failed: %v", err)
	}
}

func validatePublisherFlags() error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	if *outputLogDir == "" {
		return errors.New("--output_log_dir flag is required in publisher mode")
	}
	if *outputLogSignerKey == "" {
		return errors.New("--output_log_signer_key flag is required in publisher mode")
	}
	return nil
}

func cleanDirectories() error {
	for _, d := range []string{*dbPath, *mptDir, *outputLogDir, *tileCacheDir} {
		if d != "" {
			if err := os.RemoveAll(d); err != nil {
				return fmt.Errorf("failed to clean directory %q: %w", d, err)
			}
			if err := os.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %q: %w", d, err)
			}
		}
	}
	return nil
}

func run(ctx context.Context) error {
	switch strings.ToLower(*mode) {
	case "publisher", "coordinator", "":
		if err := validatePublisherFlags(); err != nil {
			return err
		}
		if *cleanDirs {
			if err := cleanDirectories(); err != nil {
				return err
			}
		}
		return runPublisher(ctx)
	case "auditor", "verifier":
		if *cleanDirs {
			return errors.New("--clean is not permitted in auditor or verifier mode to protect forensic state")
		}
		return runAuditor(ctx)
	default:
		return fmt.Errorf("unknown mode %q: expected 'publisher', 'auditor', or 'verifier'", *mode)
	}
}

func runPublisher(ctx context.Context) error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}

	// 0. Resolve Resource Budget
	resBudget, err := budget.Resolve(budget.ResourceBudget{
		MaxMemory: *maxMemory,
		MaxCPUs:   *maxCPUs,
		Tune:      *tune,
	})
	if err != nil {
		return fmt.Errorf("failed to resolve resource budget: %w", err)
	}

	// Apply CLI flag direct overrides if explicitly provided
	if *dbCacheSizeMB > 0 {
		resBudget.PebbleBlockCacheSizeMB = *dbCacheSizeMB
	}
	if *dbMaxOpenFiles > 0 {
		resBudget.PebbleMaxOpenFiles = *dbMaxOpenFiles
	}
	if *wasmWorkers > 0 {
		resBudget.WASMWorkers = *wasmWorkers
	}
	if isFlagPassed("fetch_workers") && *fetchWorkers > 0 {
		resBudget.FetchWorkers = *fetchWorkers
	}
	if isFlagPassed("fetch_batch_bundles") && *fetchBatchBundles > 0 {
		resBudget.FetchBatchBundles = *fetchBatchBundles
	}
	if *kvIndexerWorkers > 0 {
		resBudget.KVIndexerWorkers = *kvIndexerWorkers
	}

	klog.Info(resBudget.LogSummary())

	// 1. Open Pebble DB
	pebbleOpts := &pebble.Options{}
	if resBudget.PebbleMaxOpenFiles > 0 {
		pebbleOpts.MaxOpenFiles = resBudget.PebbleMaxOpenFiles
	}
	if resBudget.PebbleBlockCacheSizeMB > 0 {
		cache := pebble.NewCache(int64(resBudget.PebbleBlockCacheSizeMB) << 20)
		defer cache.Unref()
		pebbleOpts.Cache = cache
	}
	if resBudget.PebbleMemTableSizeMB > 0 {
		pebbleOpts.MemTableSize = uint64(resBudget.PebbleMemTableSizeMB) << 20
	}
	if resBudget.PebbleMemTableStopWrites > 0 {
		pebbleOpts.MemTableStopWritesThreshold = resBudget.PebbleMemTableStopWrites
	}
	if resBudget.ConcurrentCompactions > 0 {
		compactions := resBudget.ConcurrentCompactions
		pebbleOpts.MaxConcurrentCompactions = func() int { return compactions }
	}
	db, err := kvstore.Open(*dbPath, pebbleOpts)

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
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, resBudget.WASMWorkers)
	if err != nil {
		return err
	}
	if closeMapper != nil {
		defer closeMapper()
	}

	// 4. Setup Output Log
	if *outputLogDir == "" {
		return errors.New("--output_log_dir flag is required in publisher mode")
	}
	if *outputLogSignerKey == "" {
		return errors.New("--output_log_signer_key flag is required in publisher mode")
	}

	signerKey := *outputLogSignerKey
	keyBytes, fErr := os.ReadFile(signerKey)
	if fErr == nil {
		signerKey = string(bytes.TrimSpace(keyBytes))
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		return fmt.Errorf("failed to construct output log signer: %w", err)
	}

	var posixOpts []tree.POSIXOption
	if *outputLogOrigin != "" {
		posixOpts = append(posixOpts, tree.WithOrigin(*outputLogOrigin))
	}

	outputLog, err := tree.NewPOSIXOutputLog(ctx, *outputLogDir, signer, posixOpts...)
	if err != nil {
		return fmt.Errorf("failed to open POSIX output log at %q: %w", *outputLogDir, err)
	}
	defer func() { _ = outputLog.Close() }()

	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	idxer := kvstore.NewKVIndexer(db, *chunkSize)
	idxer.SetNumWorkers(resBudget.KVIndexerWorkers)

	// Setup Tile Cache & Fetcher
	if *tileCacheDir == "" {
		klog.Warning("--tile_cache_dir is not set; local disk tile caching is disabled. Historical crash recovery will require re-fetching from upstream.")
	}
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

		var inVerifier note.Verifier
		if *inputLogPubKey != "" {
			v, err := verifier.ParseVerifier(*inputLogPubKey)
			if err != nil {
				return fmt.Errorf("failed to create input log verifier: %w", err)
			}
			inVerifier = v
		}

		tf, err := ingest.NewTiledFetcher(u, inVerifier, *inputLogOrigin, nil)
		if err != nil {
			return fmt.Errorf("failed to create input log fetcher: %w", err)
		}
		switch strings.ToLower(*inputLogType) {
		case "static-ct", "ct":
			tf.SetStaticCT(true)
		case "tessera":
			tf.SetStaticCT(false)
		case "auto", "":
			// retain auto-detected value
		default:
			return fmt.Errorf("unknown input_log_type %q: expected 'auto', 'tessera', or 'static-ct'", *inputLogType)
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
	readMux.Handle("/tile/", http.FileServer(http.Dir(*outputLogDir)))
	readMux.Handle("/outputlog/", http.StripPrefix("/outputlog/", http.FileServer(http.Dir(*outputLogDir))))
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
	coord.SetFetchWorkers(resBudget.FetchWorkers)
	coord.SetFetchBatchBundles(resBudget.FetchBatchBundles)
	coord.SetPipelineChannelCapacity(resBudget.PipelineChannelCapacity)
	if *backfillMaxPendingKeys > 0 {
		coord.SetBackfillMaxPendingKeys(uint64(*backfillMaxPendingKeys))
	}
	if isFlagPassed("coarse_checkpoint_interval") && *coarseCheckpointInterval > 0 {
		coord.SetCoarseCheckpointInterval(uint64(*coarseCheckpointInterval))
	} else if resBudget.CoarseCheckpointInterval > 0 {
		coord.SetCoarseCheckpointInterval(resBudget.CoarseCheckpointInterval)
	}
	coord.SetCommitBatchSize(resBudget.CommitBatchSize)
	klog.Info("Running 3-phase startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed successfully.")

	// 8. Start Background Tile Reaper
	if !*disableReaper {
		tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
		go func() {
			_ = tileReaper.Run(ctx, 60*time.Second)
		}()
	} else {
		klog.Info("Tile cache reaper disabled via --disable_reaper; cached tiles will be retained indefinitely.")
	}

	// 9. Start Ingestion & Commit Pipeline Loop
	if fetcher != nil {
		if *oneShot {
			klog.Info("Running oneshot publisher sync...")
			syncStart := time.Now()
			if err := coord.SyncOnce(ctx); err != nil {
				return fmt.Errorf("oneshot publisher sync failed: %w", err)
			}
			elapsed := time.Since(syncStart)
			klog.Infof("Oneshot publisher sync completed in %v.", elapsed)
			return nil
		}
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

	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	leafMapper, closeMapper, err := initMapper(ctx, *wasmPath, *wasmWorkers)
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

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func initMapper(ctx context.Context, wasm string, numWorkers int) (ingest.LeafMapper, func(), error) {
	if wasm == "" {
		return nil, nil, errors.New("--wasm_path flag is required")
	}
	wasmBytes, err := os.ReadFile(wasm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read WASM binary %q: %w", wasm, err)
	}
	host, err := ingest.NewWASMHost(ctx, wasmBytes, numWorkers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	return host, func() { _ = host.Close(ctx) }, nil
}

