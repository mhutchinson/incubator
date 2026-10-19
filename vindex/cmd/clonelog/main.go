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

// clonelog mirrors a tlog-tiles log to local disk with high concurrency.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	inputLogURL        = flag.String("input_log_url", "https://bootstrap-mtca-shard3.cloudflareresearch.com/", "Base URL of the remote tlog-tiles Input Log")
	inputLogOrigin     = flag.String("input_log_origin", "", "Expected origin string for Input Log checkpoint verification")
	inputLogPubKey     = flag.String("input_log_pubkey", "", "Optional public key or key file to verify the fetched checkpoint before cloning")
	inputLogPolicy     = flag.String("input_log_policy", "", "Optional path to C2SP tlog-policy file to verify the fetched checkpoint before cloning")
	inputLogType       = flag.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'")
	outDir             = flag.String("out_dir", "", "Local directory to store mirrored log tiles (required)")
	numWorkers         = flag.Int("workers", 64, "Number of concurrent download workers")
	maxRetries         = flag.Int("max_retries", 10, "Maximum retry attempts per tile on transient network/server errors")
	progressInterval   = flag.Duration("progress_interval", 5*time.Second, "Interval for logging periodic progress")
	tileLevel          = flag.Int("tile_level", -2, "Tile level to clone (-2 for entry bundles + all hash tile levels, -1 for entry bundles only, 0..6 for a single hash tile level)")
	useLocalCheckpoint = flag.Bool("use_local_checkpoint", false, "Use existing local checkpoint file to determine tree size without overwriting it")
)

type tileJob struct {
	level int // -1 for entry bundles, >= 0 for hash tiles
	index uint64
}

type cloneStats struct {
	downloadedTiles atomic.Uint64
	skippedTiles    atomic.Uint64
	downloadedBytes atomic.Uint64
	downloadedCerts atomic.Uint64
	skippedCerts    atomic.Uint64
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("clonelog failed: %v", err)
	}
}

func buildTileJobs(treeSize uint64, levelFlag int) []tileJob {
	if treeSize == 0 {
		return nil
	}
	bundleWidth := max(uint64(layout.EntryBundleWidth), 256)
	var jobs []tileJob
	if levelFlag == -2 || levelFlag == -1 {
		numEntries := (treeSize + bundleWidth - 1) / bundleWidth
		for idx := range numEntries {
			jobs = append(jobs, tileJob{level: -1, index: idx})
		}
	}
	if levelFlag == -2 {
		for lvl := 0; lvl <= 6; lvl++ {
			levelHashes := treeSize >> (uint(lvl) * 8)
			if levelHashes == 0 {
				break
			}
			numTiles := (levelHashes + 255) / 256
			for idx := range numTiles {
				jobs = append(jobs, tileJob{level: lvl, index: idx})
			}
		}
	} else if levelFlag >= 0 {
		levelHashes := treeSize >> (uint(levelFlag) * 8)
		numTiles := (levelHashes + 255) / 256
		for idx := range numTiles {
			jobs = append(jobs, tileJob{level: levelFlag, index: idx})
		}
	}
	return jobs
}

func run(ctx context.Context) error {
	if *outDir == "" {
		return errors.New("--out_dir must be specified")
	}
	if *numWorkers <= 0 {
		return errors.New("--workers must be > 0")
	}
	if *tileLevel < -2 || *tileLevel > 6 {
		return fmt.Errorf("--tile_level must be between -2 and 6, got %d", *tileLevel)
	}

	var cpPolicy wire.Policy
	if strings.TrimSpace(*inputLogPolicy) != "" || strings.TrimSpace(*inputLogPubKey) != "" {
		var err error
		cpPolicy, err = wire.ParsePolicyOrVerifier(*inputLogPolicy, *inputLogPubKey, *inputLogOrigin, nil, 0)
		if err != nil {
			return fmt.Errorf("invalid input log checkpoint policy/pubkey: %w", err)
		}
	}

	baseURL, err := url.Parse(*inputLogURL)
	if err != nil {
		return fmt.Errorf("invalid input_log_url %q: %w", *inputLogURL, err)
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("failed to create out_dir %q: %w", *outDir, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        *numWorkers * 4,
			MaxIdleConnsPerHost: *numWorkers * 2,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		Timeout: 60 * time.Second,
	}

	var cpBytes []byte
	var treeSize uint64
	if *useLocalCheckpoint {
		cpPath := filepath.Join(*outDir, "checkpoint")
		var rErr error
		cpBytes, rErr = os.ReadFile(cpPath)
		if rErr != nil {
			return fmt.Errorf("failed to read local checkpoint %q: %w", cpPath, rErr)
		}
		ts, vErr := parseAndVerifyCheckpoint(cpBytes, cpPolicy, strings.TrimSpace(*inputLogOrigin))
		if vErr != nil {
			return fmt.Errorf("invalid local checkpoint: %w", vErr)
		}
		treeSize = ts
		klog.Infof("Using local checkpoint: treeSize = %d", treeSize)
	} else {
		var fErr error
		cpBytes, treeSize, fErr = fetchCheckpoint(ctx, httpClient, baseURL, cpPolicy, strings.TrimSpace(*inputLogOrigin), *maxRetries)
		if fErr != nil {
			return fmt.Errorf("failed to fetch checkpoint: %w", fErr)
		}
		klog.Infof("Fetched checkpoint: treeSize = %d (%d bytes)", treeSize, len(cpBytes))
	}

	tileJobs := buildTileJobs(treeSize, *tileLevel)
	totalJobs := uint64(len(tileJobs))

	var stats cloneStats
	startTime := time.Now()
	stopProgress := make(chan struct{})
	var wgProgress sync.WaitGroup
	wgProgress.Add(1)
	go func() {
		defer wgProgress.Done()
		logProgressLoop(ctx, stopProgress, startTime, totalJobs, &stats)
	}()

	g, gCtx := errgroup.WithContext(ctx)
	jobs := make(chan tileJob, *numWorkers*4)
	g.Go(func() error {
		defer close(jobs)
		for _, job := range tileJobs {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			case jobs <- job:
			}
		}
		return nil
	})
	for range *numWorkers {
		g.Go(func() error {
			for job := range jobs {
				if err := downloadTileJob(gCtx, httpClient, baseURL, *outDir, job, treeSize, *maxRetries, &stats); err != nil {
					return fmt.Errorf("failed on level %d tile %d: %w", job.level, job.index, err)
				}
			}
			return nil
		})
	}

	workErr := g.Wait()
	close(stopProgress)
	wgProgress.Wait()
	if workErr != nil {
		return workErr
	}

	if !*useLocalCheckpoint {
		if err := atomicWriteFile(filepath.Join(*outDir, "checkpoint"), cpBytes); err != nil {
			return fmt.Errorf("failed to persist checkpoint after clone: %w", err)
		}
	}

	elapsed := time.Since(startTime)
	dlTiles := stats.downloadedTiles.Load()
	skTiles := stats.skippedTiles.Load()
	totalMB := float64(stats.downloadedBytes.Load()) / (1024 * 1024)
	klog.Infof("Clone completed in %s: %d tiles (%d downloaded, %d skipped), %d entries, %.2f MB",
		elapsed.Truncate(time.Second), dlTiles+skTiles, dlTiles, skTiles, stats.downloadedCerts.Load(), totalMB)
	return nil
}

func logProgressLoop(ctx context.Context, stop <-chan struct{}, startTime time.Time, numBundles uint64, stats *cloneStats) {
	ticker := time.NewTicker(*progressInterval)
	defer ticker.Stop()

	var lastBytes, lastCerts uint64
	lastTime := startTime
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			dlTiles := stats.downloadedTiles.Load()
			skTiles := stats.skippedTiles.Load()
			dlBytes := stats.downloadedBytes.Load()
			dlCerts := stats.downloadedCerts.Load()
			deltaSec := max(now.Sub(lastTime).Seconds(), 1e-3)

			pct := 0.0
			if numBundles > 0 {
				pct = float64(dlTiles+skTiles) / float64(numBundles) * 100.0
			}
			rateMB := float64(dlBytes-lastBytes) / (1024 * 1024 * deltaSec)
			rateItems := float64(dlCerts-lastCerts) / deltaSec
			klog.Infof("[Progress %5.1f%%] %d/%d tiles (%d downloaded, %d skipped) | %.1f MB | %.2f MB/s, %.0f items/s | %s",
				pct, dlTiles+skTiles, numBundles, dlTiles, skTiles, float64(dlBytes)/(1024*1024), rateMB, rateItems, time.Since(startTime).Truncate(time.Second))

			lastBytes, lastCerts, lastTime = dlBytes, dlCerts, now
		}
	}
}

func fetchWithRetry(ctx context.Context, client *http.Client, reqURL, fallbackURL string, retries int) ([]byte, bool, error) {
	var lastErr error
	for attempt := range max(retries, 1) {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if attempt > 0 {
			backoff := min(time.Duration(100*(1<<attempt))*time.Millisecond+time.Duration(rand.Intn(100))*time.Millisecond, 10*time.Second)
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, status, err := httpGetStatus(ctx, client, reqURL)
		if err == nil && status == http.StatusOK {
			return data, false, nil
		}
		if status == http.StatusNotFound && fallbackURL != "" {
			if fbData, fbStatus, fbErr := httpGetStatus(ctx, client, fallbackURL); fbErr == nil && fbStatus == http.StatusOK {
				return fbData, true, nil
			}
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d from %s", status, reqURL)
		}
	}
	return nil, false, fmt.Errorf("failed after %d attempts: %w", retries, lastErr)
}

func httpGetStatus(ctx context.Context, client *http.Client, reqURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func atomicWriteFile(destPath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	tmpPath := destPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, destPath)
}

func parseAndVerifyCheckpoint(rawData []byte, pol wire.Policy, expectedOrigin string) (uint64, error) {
	if pol != nil {
		cp, err := pol.Verify(rawData)
		if err != nil {
			return 0, fmt.Errorf("checkpoint verification failed: %w", err)
		}
		if expectedOrigin != "" && cp.Origin != expectedOrigin {
			return 0, fmt.Errorf("checkpoint origin %q != expected %q", cp.Origin, expectedOrigin)
		}
		return cp.Size, nil
	}
	cp, err := wire.ParseCheckpointHeader(rawData)
	if err != nil {
		return 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if expectedOrigin != "" && cp.Origin != expectedOrigin {
		return 0, fmt.Errorf("checkpoint origin %q != expected %q", cp.Origin, expectedOrigin)
	}
	return cp.Size, nil
}

func fetchCheckpoint(ctx context.Context, client *http.Client, baseURL *url.URL, pol wire.Policy, expectedOrigin string, retries int) ([]byte, uint64, error) {
	rawData, _, err := fetchWithRetry(ctx, client, baseURL.JoinPath("checkpoint").String(), "", retries)
	if err != nil {
		return nil, 0, err
	}
	size, err := parseAndVerifyCheckpoint(rawData, pol, expectedOrigin)
	if err != nil {
		return nil, 0, err
	}
	return rawData, size, nil
}

func bundleCertsCount(bIdx, treeSize uint64) uint64 {
	bundleWidth := max(uint64(layout.EntryBundleWidth), 256)
	start := bIdx * bundleWidth
	if start >= treeSize {
		return 0
	}
	return min(bundleWidth, treeSize-start)
}

func downloadTileJob(ctx context.Context, client *http.Client, baseURL *url.URL, outDir string, job tileJob, treeSize uint64, retries int, stats *cloneStats) error {
	isStaticCT := false
	switch strings.ToLower(*inputLogType) {
	case "static-ct", "ct":
		isStaticCT = true
	case "auto":
		isStaticCT = strings.Contains(baseURL.Host, "certificate.transparency") || strings.Contains(baseURL.Path, "static-ct")
	}

	bIdx := job.index
	var p uint8
	var relPath, fullRelPath string
	var certsInBundle uint64
	if job.level >= 0 {
		lvl := uint64(job.level)
		p = layout.PartialTileSize(lvl, bIdx, treeSize)
		relPath = layout.TilePath(lvl, bIdx, p)
		fullRelPath = layout.TilePath(lvl, bIdx, 0)
	} else if isStaticCT {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		relPath = "tile/data/" + layout.TilePath(0, bIdx, p)[7:]
		fullRelPath = "tile/data/" + layout.TilePath(0, bIdx, 0)[7:]
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	} else {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		relPath = layout.EntriesPath(bIdx, p)
		fullRelPath = layout.EntriesPath(bIdx, 0)
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	}

	destPath := filepath.Join(outDir, relPath)
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		stats.skippedTiles.Add(1)
		stats.skippedCerts.Add(certsInBundle)
		return nil
	}
	if p != 0 {
		if info, err := os.Stat(filepath.Join(outDir, fullRelPath)); err == nil && info.Size() > 0 {
			stats.skippedTiles.Add(1)
			stats.skippedCerts.Add(certsInBundle)
			return nil
		}
	}

	var fallbackURL string
	if p != 0 {
		fallbackURL = baseURL.JoinPath(fullRelPath).String()
	}
	data, usedFallback, err := fetchWithRetry(ctx, client, baseURL.JoinPath(relPath).String(), fallbackURL, retries)
	if err != nil {
		return err
	}
	if usedFallback {
		if err := atomicWriteFile(filepath.Join(outDir, fullRelPath), data); err != nil {
			return err
		}
	} else {
		if err := atomicWriteFile(destPath, data); err != nil {
			return err
		}
	}

	stats.downloadedTiles.Add(1)
	stats.downloadedBytes.Add(uint64(len(data)))
	stats.downloadedCerts.Add(certsInBundle)
	return nil
}
