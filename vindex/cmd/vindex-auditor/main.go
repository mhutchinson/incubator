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

// vindex-auditor is the dedicated standalone Verifiable Index auditor and verifier.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	outputLogURL     = flag.String("output_log_url", "", "Base URL of Output Log to verify (required).")
	outputLogPolicy  = flag.String("output_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
	outputLogPubKey  = flag.String("output_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	outputLogOrigin  = flag.String("output_log_origin", "", "Expected origin string for Output Log (inferred from --output_log_policy or --output_log_pubkey when unset).")
	witnessPubKeys   = flag.String("witness_pubkeys", "", "Comma-separated list of witness verifier public keys for Output Log checkpoint verification.")
	witnessThreshold = flag.Int("witness_threshold", 0, "Required witness signature quorum threshold for Output Log (0 = all --witness_pubkeys).")
	inputLogURL      = flag.String("input_log_url", "", "Base URL of the Input Log (required).")
	inputLogPolicy   = flag.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	inputLogPubKey   = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification.")
	inputLogOrigin   = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogType     = flag.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'.")
	dbPath           = flag.String("db_path", "", "Directory path for Pebble KV store (required).")
	dbCacheSizeMB    = flag.Int("db_cache_size_mb", 512, "Pebble block cache size in megabytes.")
	dbMaxOpenFiles   = flag.Int("db_max_open_files", 0, "Maximum open files for Pebble DB (0 auto-tunes).")
	mptDir           = flag.String("mpt_dir", "", "Directory path for MPT persistence files (required).")
	wasmPath         = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	wasmWorkers      = flag.Int("wasm_workers", 0, "Number of concurrent WASM worker instances (0 = auto).")
	fetchWorkers     = flag.Int("fetch_workers", 4, "Number of concurrent tile fetch workers.")
	metricsAddr      = flag.String("metrics_addr", "127.0.0.1:9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	chunkSize        = flag.Uint64("chunk_size", 65536, "Logical value-log chunk size.")
	commitBatchSize  = flag.Uint64("commit_batch_size", 4096, "Number of leaves accumulated per batch commit.")
	tileCacheDir     = flag.String("tile_cache_dir", "", "Path for local tile cache directory.")
	pollInterval     = flag.Duration("poll_interval", 10*time.Second, "Polling interval for new Output Log checkpoints.")
	oneShot          = flag.Bool("oneshot", false, "Run verification once against log tip and exit.")
	fromFlag         = flag.Uint64("from", 0, "Expected starting Input Log leaf index (from) in Output Log leaves.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("vindex-auditor failed: %v", err)
	}
}

func buildLogPolicy(policyPath, pubKey, origin string, witnesses []note.Verifier, threshold int, label string) (wire.Policy, string, error) {
	policyPath = strings.TrimSpace(policyPath)
	pubKey = strings.TrimSpace(pubKey)
	origin = strings.TrimSpace(origin)
	if policyPath == "" && pubKey == "" {
		return nil, "", fmt.Errorf("--%s_policy or --%s_pubkey is required", label, label)
	}
	pol, err := wire.ParsePolicyOrVerifier(policyPath, pubKey, origin, witnesses, threshold)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build %s policy: %w", label, err)
	}
	if origin == "" {
		origin = wire.PolicyOrigin(pol)
	}
	if origin == "" {
		return nil, "", fmt.Errorf("--%s_origin is required when --%s_policy does not specify a single log", label, label)
	}
	return pol, origin, nil
}

func run(ctx context.Context) error {
	if *outputLogURL == "" {
		return errors.New("--output_log_url is required")
	}
	if *inputLogURL == "" {
		return errors.New("--input_log_url is required")
	}
	if *dbPath == "" {
		return errors.New("--db_path flag is required")
	}
	if *mptDir == "" {
		return errors.New("--mpt_dir flag is required")
	}
	if *wasmPath == "" {
		return errors.New("--wasm_path flag is required")
	}

	var witnessVerifiers []note.Verifier
	for _, wk := range splitNonEmptyCSV(*witnessPubKeys) {
		wv, err := wire.ParseWitnessVerifier(wk)
		if err != nil {
			return fmt.Errorf("failed to parse witness verifier %q: %w", wk, err)
		}
		witnessVerifiers = append(witnessVerifiers, wv)
	}
	threshold := *witnessThreshold
	if threshold == 0 {
		threshold = len(witnessVerifiers)
	}

	inPolicy, inOrigin, err := buildLogPolicy(*inputLogPolicy, *inputLogPubKey, *inputLogOrigin, nil, 0, "input_log")
	if err != nil {
		return err
	}
	outPolicy, outOrigin, err := buildLogPolicy(*outputLogPolicy, *outputLogPubKey, *outputLogOrigin, witnessVerifiers, threshold, "output_log")
	if err != nil {
		return err
	}

	wasmHost, closeMapper, err := initMapper(ctx, *wasmPath, *wasmWorkers)
	if err != nil {
		return err
	}
	defer closeMapper()

	fromVal := *fromFlag
	cfg := auditor.Config{
		InputLogURL:     *inputLogURL,
		InputLogOrigin:  inOrigin,
		InputLogPolicy:  inPolicy,
		InputLogType:    *inputLogType,
		OutputLogURL:    *outputLogURL,
		OutputLogOrigin: outOrigin,
		OutputLogPolicy: outPolicy,
		WASMHost:        wasmHost,
		ExpectedFrom:    &fromVal,
		DBPath:          *dbPath,
		DBCacheSizeMB:   *dbCacheSizeMB,
		DBMaxOpenFiles:  *dbMaxOpenFiles,
		MPTDir:          *mptDir,
		TileCacheDir:    *tileCacheDir,
		MetricsAddr:     *metricsAddr,
		PollInterval:    *pollInterval,
		ChunkSize:       *chunkSize,
		CommitBatchSize: *commitBatchSize,
		WASMWorkers:     *wasmWorkers,
		FetchWorkers:    *fetchWorkers,
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

	klog.Infof("Starting auditor daemon (poll interval: %v)...", *pollInterval)
	return v.Run(ctx)
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

func initMapper(ctx context.Context, wasm string, workers int) (*wasmhost.WASMHost, func(), error) {
	wasmBytes, err := os.ReadFile(wasm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read WASM binary %q: %w", wasm, err)
	}
	host, err := wasmhost.NewWASMHost(ctx, wasmBytes, workers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	return host, func() { _ = host.Close(ctx) }, nil
}
