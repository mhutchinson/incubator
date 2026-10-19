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

// vindexd is the Verifiable Index indexing and HTTP serving daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"k8s.io/klog/v2"
)

var (
	inputLogURL              = flag.String("input_log_url", "", "Base URL of the Input Log.")
	inputLogOrigin           = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey           = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>).")
	inputLogPolicy           = flag.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	insecureSkipVerify       = flag.Bool("insecure_skip_verify", false, "Allow unverified Input Log checkpoints when --input_log_policy and --input_log_pubkey are unset (for local testing only).")
	outputLogDir             = flag.String("output_log_dir", "", "Path for local Output Log storage.")
	outputLogOrigin          = flag.String("output_log_origin", "", "Origin string for Output Log. If unset, defaults to signer name.")
	outputLogSignerKey       = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	outputLogPolicy          = flag.String("output_log_policy", "", "Path to C2SP tlog-policy file configuring Output Log witness quorum cosigning and verification.")
	witnessURLs              = flag.String("witness_urls", "", "Comma-separated list of witness HTTP base URLs for N-of-N Output Log cosigning.")
	witnessPubKeys           = flag.String("witness_pubkeys", "", "Comma-separated list of witness verifier public keys matching --witness_urls.")
	oneShot                  = flag.Bool("oneshot", false, "Run synchronization once against log tip and exit.")
	dbPath                   = flag.String("db_path", "", "Directory path for Pebble KV store.")
	mptDir                   = flag.String("mpt_dir", "", "Directory path for MPT persistence files.")
	wasmPath                 = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	listenAddr               = flag.String("listen_addr", ":8080", "Public HTTP Read Server address.")
	metricsAddr              = flag.String("metrics_addr", ":9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	pathPrefix               = flag.String("path_prefix", "", "Base URL path prefix to host vindex endpoints under (defaults to root).")
	chunkSize                = flag.Uint64("chunk_size", 65536, "Logical value-log chunk size.")
	commitBatchSize          = flag.Uint64("commit_batch_size", 4096, "Number of leaves accumulated per batch commit.")
	tileCacheDir             = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval             = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
	disableReaper            = flag.Bool("disable_reaper", false, "Disable background tile cache reaper to keep tiles cached indefinitely.")
	kvIndexerWorkers         = flag.Int("kv_indexer_workers", 0, "Number of worker goroutines for parallel key indexing (0 = auto).")
	fetchBatchBundles        = flag.Int("fetch_batch_bundles", 50, "Number of leaf bundles fetched per worker batch.")
	dbMaxOpenFiles           = flag.Int("db_max_open_files", 0, "Maximum open files for Pebble DB (0 auto-tunes based on system ulimit -n).")
	dbCacheSizeMB            = flag.Int("db_cache_size_mb", 512, "Pebble block cache size in megabytes.")
	enableUI                 = flag.Bool("enable_ui", true, "Serve the raw wire inspector HTML UI at / and /index.html.")
	wasmWorkers              = flag.Int("wasm_workers", 0, "Number of concurrent WASM worker instances (0 = auto).")
	fetchWorkers             = flag.Int("fetch_workers", 4, "Number of concurrent tile fetch workers.")
	inputLogType             = flag.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'.")
	mutexProfileFraction     = flag.Int("mutex_profile_fraction", 0, "If > 0, enable mutex contention profiling sampling 1/N events.")
	blockProfileRate         = flag.Int("block_profile_rate", 0, "If > 0, enable goroutine blocking profiling with nanosecond rate.")
	cleanDirs                = flag.Bool("clean", false, "Clean db_path, mpt_dir, output_log_dir, and tile_cache_dir on startup.")
	backfillMaxPendingKeys   = flag.Uint64("backfill_max_pending_keys", 50000000, "Maximum deduplicated keys buffered in memory during Genesis Backfill before flushing to MPT.")
	coarseCheckpointInterval = flag.Uint64("coarse_checkpoint_interval", 50000000, "Maximum leaves between coarse checkpoints during Genesis Backfill.")
	prefixPolicyFlag         = flag.String("prefix_policy", "allow", "Prefix query policy for /keys?prefix=<prefix>: 'allow' (default), 'reversed-dns' ('domain'), or 'none'.")
	maxPrefixKeysFlag        = flag.Int("max_prefix_keys", server.DefaultMaxPrefixKeys, "Maximum matching keys returned by a single /keys?prefix=<prefix> query before returning HTTP 413.")
	fromFlag                 = flag.Uint64("from", 0, "Starting Input Log leaf index (from) for Output Log commitments.")

	boundListenAddr  atomic.Pointer[string]
	boundMetricsAddr atomic.Pointer[string]
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

func validateFlags() error {
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}
	if *outputLogDir == "" {
		return errors.New("--output_log_dir flag is required")
	}
	if *outputLogSignerKey == "" {
		return errors.New("--output_log_signer_key flag is required")
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
	if err := validateFlags(); err != nil {
		return err
	}
	if *cleanDirs {
		if err := cleanDirectories(); err != nil {
			return err
		}
	}
	if *tileCacheDir == "" {
		klog.Warning("--tile_cache_dir is not set; local disk tile caching is disabled.")
	}

	explicitFrom := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "from" {
			explicitFrom = true
		}
	})

	ui := *enableUI
	engine, err := vindex.New(vindex.Config{
		DBPath:                   *dbPath,
		DBCacheSizeMB:            *dbCacheSizeMB,
		DBMaxOpenFiles:           *dbMaxOpenFiles,
		MPTDir:                   *mptDir,
		TileCacheDir:             *tileCacheDir,
		DisableReaper:            *disableReaper,
		WASMPath:                 *wasmPath,
		ListenAddr:               *listenAddr,
		MetricsAddr:              *metricsAddr,
		PathPrefix:               *pathPrefix,
		EnableUI:                 &ui,
		ServeOutputTiles:         true,
		ChunkSize:                *chunkSize,
		CommitBatchSize:          *commitBatchSize,
		CoarseCheckpointInterval: *coarseCheckpointInterval,
		BackfillMaxPendingKeys:   *backfillMaxPendingKeys,
		Workers:                  *wasmWorkers,
		KVIndexerWorkers:         *kvIndexerWorkers,
		FetchWorkers:             *fetchWorkers,
		FetchBatchBundles:        *fetchBatchBundles,
		PollInterval:             *pollInterval,
		InputLogURL:              *inputLogURL,
		InputLogOrigin:           *inputLogOrigin,
		InputLogPubKey:           *inputLogPubKey,
		InputLogPolicyPath:       *inputLogPolicy,
		InputLogType:             *inputLogType,
		InsecureSkipVerify:       *insecureSkipVerify,
		OutputLogDir:             *outputLogDir,
		OutputLogOrigin:          *outputLogOrigin,
		OutputLogSignerKey:       *outputLogSignerKey,
		OutputLogPolicyPath:      *outputLogPolicy,
		WitnessURLs:              splitNonEmptyCSV(*witnessURLs),
		WitnessPubKeys:           splitNonEmptyCSV(*witnessPubKeys),
		PrefixPolicy:             *prefixPolicyFlag,
		MaxPrefixKeys:            *maxPrefixKeysFlag,
		From:                     *fromFlag,
		ExplicitFrom:             explicitFrom,
	}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = engine.Close() }()

	if lAddr := engine.ListenAddr(); lAddr != "" {
		boundListenAddr.Store(&lAddr)
	}
	if mAddr := engine.MetricsAddr(); mAddr != "" {
		boundMetricsAddr.Store(&mAddr)
	}

	if *oneShot {
		klog.Info("Running oneshot synchronization...")
		syncStart := time.Now()
		if err := engine.SyncOnce(ctx); err != nil {
			return fmt.Errorf("oneshot sync failed: %w", err)
		}
		klog.Infof("Oneshot sync completed in %v.", time.Since(syncStart))
		return nil
	}

	return engine.Run(ctx)
}

func splitNonEmptyCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
