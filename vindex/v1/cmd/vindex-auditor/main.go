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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"k8s.io/klog/v2"
)

var (
	outputLogURL    = flag.String("output_log_url", "", "Base URL of Output Log to verify (required).")
	outputLogPubKey = flag.String("output_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	outputLogOrigin = flag.String("output_log_origin", "example.com/vindex/output", "Origin string for Output Log.")
	inputLogURL     = flag.String("input_log_url", "", "Base URL of the Input Log (required).")
	inputLogPubKey  = flag.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification.")
	inputLogOrigin  = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	dbPath          = flag.String("db_path", "", "NVMe path for Pebble DB (Disk A) (required).")
	mptDir          = flag.String("mpt_dir", "", "Isolated NVMe path for MPT mmap files (Disk B) (required).")
	wasmPath        = flag.String("wasm_path", "", "Path to compiled MapFn WASM binary.")
	mapper          = flag.String("mapper", "identity", "Leaf mapper implementation: identity, ct, or sumdb.")
	serveMirror     = flag.Bool("serve_mirror", false, "Enable verified mirror serving mode on listen_addr.")
	failClosed      = flag.Bool("fail_closed", false, "Immediately revoke mirror serving on verification mismatch instead of serving last verified checkpoint.")
	listenAddr      = flag.String("listen_addr", ":8080", "HTTP Read Server address for mirror lookups.")
	metricsAddr     = flag.String("metrics_addr", ":9090", "Prometheus metrics scrape address.")
	chunkSize       = flag.Uint64("chunk_size", 65536, "Logical chunk size.")
	pollInterval    = flag.Duration("poll_interval", 10*time.Second, "Polling interval for new Output Log checkpoints.")
	oneShot         = flag.Bool("oneshot", false, "Run verification once against log tip and exit.")
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
		host, err := ingest.NewWASMHost(ctx, wasmBytes, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize WASM host: %w", err)
		}
		return host, func() { _ = host.Close(ctx) }, nil
	}

	switch strings.ToLower(mapperName) {
	case "sumdb":
		return &sumdbLeafMapper{}, nil, nil
	case "ct":
		return &ctLeafMapper{}, nil, nil
	case "identity", "":
		return &defaultIdentityMapper{}, nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown mapper %q (expected identity, ct, sumdb)", mapperName)
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
