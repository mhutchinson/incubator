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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	outputLogOrigin    = flag.String("output_log_origin", "", "Origin string for Output Log. If unset, defaults to signer name.")
	outputLogSignerKey = flag.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints.")
	dbPath             = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A).")
	mptDir             = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B).")
	wasmPath           = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary.")
	mapper             = flag.String("mapper", "identity", "Leaf mapper implementation: identity or ct.")
	listenAddr         = flag.String("listen_addr", ":8080", "HTTP Read Server address.")
	metricsAddr        = flag.String("metrics_addr", ":9090", "Prometheus metrics scrape address.")
	chunkSize          = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	tileCacheDir       = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval       = flag.Duration("poll_interval", 10*time.Second, "Ingestion polling interval.")
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
		host, err := ingest.NewWASMHost(ctx, wasmBytes, 4)
		if err != nil {
			return fmt.Errorf("failed to initialize WASM host: %w", err)
		}
		defer func() { _ = host.Close(ctx) }()
		leafMapper = host
	} else {
		switch *mapper {
		case "ct":
			leafMapper = &ctLeafMapper{}
		case "identity", "":
			leafMapper = &defaultIdentityMapper{}
		default:
			return fmt.Errorf("unknown mapper %q (expected identity, ct)", *mapper)
		}
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
		if *oneShot {
			klog.Info("Running oneshot publisher sync...")
			if err := coord.SyncOnce(ctx); err != nil {
				return fmt.Errorf("oneshot publisher sync failed: %w", err)
			}
			klog.Info("Oneshot publisher sync completed.")
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

