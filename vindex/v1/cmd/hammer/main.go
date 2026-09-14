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

// hammer is the high-throughput synthetic load-testing and verification tool for VIndex.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/hammer"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	storageDir      = flag.String("storage_dir", "", "Path for local Tessera POSIX input log storage.")
	vindexURL       = flag.String("vindex_url", "http://localhost:8080", "Base URL of the target vindexd instance.")
	listenAddr      = flag.String("listen_addr", ":8085", "HTTP address to host hammer tlog-tiles and drip checkpoints.")
	numReaders      = flag.Int("num_readers", 8, "Number of concurrent verifying reader workers.")
	maxReadQPS      = flag.Float64("max_read_qps", 200, "Maximum total read queries per second.")
	writeRate       = flag.Float64("write_rate", 500, "Target write rate (leaves/sec) into the local Input Log.")
	writeGoal       = flag.Uint64("write_goal", 0, "Target number of leaves to write and verify before stopping (0 = continuous).")
	dripRate        = flag.Float64("drip_rate", 2.0, "Checkpoint drip-feed rate (CP/sec) released to vindexd.")
	burstSize       = flag.Int("burst_size", 1, "Number of checkpoints released per burst.")
	burstInterval   = flag.Duration("burst_interval", 0, "Interval between checkpoint burst releases (0 = steady drip).")
	keyDistribution = flag.String("key_distribution", "zipf", "Key distribution: zipf, pareto, or uniform.")
	numKeys         = flag.Uint64("num_keys", 10000, "Number of unique keys in the active working set.")
	zipfS           = flag.Float64("zipf_s", 1.2, "Zipfian skew parameter (s > 1.0).")
	zipfV           = flag.Float64("zipf_v", 1.0, "Zipfian scale parameter (v >= 1.0).")
	runtime         = flag.Duration("runtime", 0, "Test duration (e.g. 30s, 2m; 0 = run until interrupted).")
	statsInterval   = flag.Duration("stats_interval", 1*time.Second, "Terminal stats dashboard refresh interval.")
	logOrigin       = flag.String("log_origin", "example.com/hammer/inputlog", "Input Log origin string.")
	logSignerKey    = flag.String("log_signer_key", "", "Optional private note signer key for Input Log checkpoints.")
	outLogOrigin    = flag.String("out_log_origin", "", "Expected Output Log origin string.")
	outLogPubKey    = flag.String("out_log_pubkey", "", "Public key for verifying Output Log checkpoint signatures.")
	leafFormat      = flag.String("leaf_format", "raw", "Synthetic leaf format: raw, sumdb, or ct.")
	ctMinDomains    = flag.Int("ct_min_domains", 1, "Minimum number of domains per CT leaf.")
	ctMaxDomains    = flag.Int("ct_max_domains", 50, "Maximum number of domains per CT leaf.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *runtime > 0 {
		var runtimeCancel context.CancelFunc
		ctx, runtimeCancel = context.WithTimeout(ctx, *runtime)
		defer runtimeCancel()
	}

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		klog.Exitf("Hammer failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *storageDir == "" {
		return errors.New("--storage_dir flag is required")
	}

	// 1. Initialize Generator
	var dist hammer.Distribution
	switch *keyDistribution {
	case "uniform":
		dist = hammer.DistUniform
	case "pareto":
		dist = hammer.DistPareto
	case "zipf":
		dist = hammer.DistZipf
	default:
		return fmt.Errorf("unknown key_distribution %q (expected zipf, pareto, uniform)", *keyDistribution)
	}

	var lFormat hammer.LeafFormat
	switch *leafFormat {
	case "raw", "":
		lFormat = hammer.FormatRaw
	case "sumdb":
		lFormat = hammer.FormatSumDB
	case "ct":
		lFormat = hammer.FormatCT
	default:
		return fmt.Errorf("unknown leaf_format %q (expected raw, sumdb, ct)", *leafFormat)
	}

	genCfg := hammer.GeneratorConfig{
		Distribution: dist,
		NumKeys:      *numKeys,
		ZipfS:        *zipfS,
		ZipfV:        *zipfV,
		Seed:         time.Now().UnixNano(),
		LeafFormat:   lFormat,
		CTMinDomains: *ctMinDomains,
		CTMaxDomains: *ctMaxDomains,
	}
	generator := hammer.NewGenerator(genCfg)

	// 2. Initialize Queue and Sequencer
	queue := hammer.NewCheckpointQueue()
	seqCfg := hammer.SequencerConfig{
		StorageDir: *storageDir,
		Origin:     *logOrigin,
		SignerKey:  *logSignerKey,
		WriteRate:  *writeRate,
		WriteGoal:  *writeGoal,
	}

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		return fmt.Errorf("failed to initialize sequencer: %w", err)
	}
	defer func() {
		_ = sequencer.Close(context.Background())
	}()

	// 3. Initialize Drip Server
	srvCfg := hammer.ServerConfig{
		ListenAddr:    *listenAddr,
		StorageDir:    *storageDir,
		DripRate:      *dripRate,
		BurstSize:     *burstSize,
		BurstInterval: *burstInterval,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start drip server: %w", err)
	}
	defer func() {
		_ = dripServer.Close(context.Background())
	}()

	// 4. Initialize Analyzer
	analyzer := hammer.NewAnalyzer(sequencer)

	// 5. Initialize Reader Pool
	var outVerifier note.Verifier
	if *outLogPubKey != "" {
		v, err := note.NewVerifier(*outLogPubKey)
		if err != nil {
			return fmt.Errorf("failed to create output log verifier: %w", err)
		}
		outVerifier = v
	}

	readerCfg := hammer.ReaderConfig{
		VIndexURL:         *vindexURL,
		NumWorkers:        *numReaders,
		MaxReadQPS:        *maxReadQPS,
		OutputLogOrigin:   *outLogOrigin,
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    sequencer.Origin(),
		InputLogVerifier:  sequencer.Verifier(),
		HotKeyRatio:       0.60,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.05,
		PageSize:          100,
	}

	readers, err := hammer.NewReaderPool(readerCfg, generator, analyzer)
	if err != nil {
		return fmt.Errorf("failed to create reader pool: %w", err)
	}

	fmt.Println("========================================================================")
	fmt.Printf("Starting VIndex Hammer Load Test\n")
	fmt.Printf("Input Log Server:   %s\n", dripServer.URL())
	fmt.Printf("Target vindexd URL: %s\n", *vindexURL)
	if *writeGoal > 0 {
		fmt.Printf("Write Goal:         %d leaves\n", *writeGoal)
	}
	fmt.Printf("Write Target:       %.1f leaves/sec | Drip Rate: %.1f CP/sec\n", *writeRate, *dripRate)
	fmt.Printf("Reader Workers:     %d (Max Read QPS: %.1f)\n", *numReaders, *maxReadQPS)
	fmt.Printf("Keyspace:           %d keys (%s distribution)\n", *numKeys, *keyDistribution)
	fmt.Printf("Verifier Key:       %s\n", sequencer.VerifierKey())
	fmt.Println("========================================================================")

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	// 6. Launch concurrent loops
	go func() {
		_ = sequencer.RunLoop(runCtx)
	}()

	go func() {
		readers.Start(runCtx)
	}()

	go func() {
		analyzer.RunDashboard(runCtx, *statsInterval)
	}()

	if *writeGoal > 0 {
		monitorTicker := time.NewTicker(100 * time.Millisecond)
		defer monitorTicker.Stop()

		httpClient := &http.Client{Timeout: 3 * time.Second}
		for {
			select {
			case <-ctx.Done():
				cancelRun()
				return ctx.Err()
			case <-monitorTicker.C:
				size, err := queryVindexInputLogSize(ctx, httpClient, *vindexURL)
				if err == nil && size >= *writeGoal {
					klog.Infof("Target write goal reached: %d / %d indexed by vindexd", size, *writeGoal)
					// Wait 2s for reader metrics to settle
					select {
					case <-ctx.Done():
						cancelRun()
						return ctx.Err()
					case <-time.After(2 * time.Second):
					}
					cancelRun()
					goto done
				}
			}
		}
	} else {
		<-ctx.Done()
	}

done:
	fmt.Println("\nStopping hammer load generation...")
	analyzer.PrintSummary()

	if analyzer.InvariantViolationCount() > 0 {
		return fmt.Errorf("hammer finished with %d invariant violations", analyzer.InvariantViolationCount())
	}

	return nil
}

func queryVindexInputLogSize(ctx context.Context, client *http.Client, vindexURL string) (uint64, error) {
	endpoints := []string{
		"/vindex/v1/inputlog_checkpoint",
		"/inputlog_checkpoint",
		"/vindex/v1/checkpoint",
		"/checkpoint",
	}

	baseURL := strings.TrimSuffix(vindexURL, "/")
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+ep, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			cp, err := tree.ParseCheckpointHeader(body)
			if err == nil {
				return cp.Size, nil
			}
		}
	}
	return 0, errors.New("unable to retrieve checkpoint from vindexd")
}
