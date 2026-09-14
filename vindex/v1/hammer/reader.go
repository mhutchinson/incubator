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

package hammer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// ReaderConfig configures the concurrent reader pool.
type ReaderConfig struct {
	VIndexURL         string
	NumWorkers        int
	MaxReadQPS        float64
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
	HotKeyRatio       float64
	UniformRatio      float64
	NonInclusionRatio float64
	PaginationRatio   float64
	PageSize          uint64
}

// DefaultReaderConfig returns default configuration for readers.
func DefaultReaderConfig(vindexURL string) ReaderConfig {
	return ReaderConfig{
		VIndexURL:         vindexURL,
		NumWorkers:        8,
		MaxReadQPS:        200,
		HotKeyRatio:       0.60,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.05,
		PageSize:          100,
	}
}

// KeyHistory tracks prior lookup results for monotonicity verification.
type KeyHistory struct {
	LastTreeSize uint64
	Indices      []uint64
}

// ReaderPool manages concurrent reader workers querying vindexd with cryptographic verification.
type ReaderPool struct {
	cfg        ReaderConfig
	generator  *Generator
	client     *client.Client
	analyzer   *Analyzer
	mu         sync.RWMutex
	history    map[[sha256.Size]byte]KeyHistory
	totalReads uint64
	stopCh     chan struct{}
}

// NewReaderPool creates a new ReaderPool instance.
func NewReaderPool(cfg ReaderConfig, gen *Generator, an *Analyzer) (*ReaderPool, error) {
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = 8
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}

	cliCfg := client.VerifierConfig{
		OutputLogOrigin:   cfg.OutputLogOrigin,
		OutputLogVerifier: cfg.OutputLogVerifier,
		InputLogOrigin:    cfg.InputLogOrigin,
		InputLogVerifier:  cfg.InputLogVerifier,
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.NumWorkers * 4,
			MaxIdleConnsPerHost: cfg.NumWorkers * 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	cli, err := client.New(cfg.VIndexURL, cliCfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &ReaderPool{
		cfg:       cfg,
		generator: gen,
		client:    cli,
		analyzer:  an,
		history:   make(map[[sha256.Size]byte]KeyHistory),
		stopCh:    make(chan struct{}),
	}, nil
}

// Start launches worker goroutines and runs until ctx is cancelled.
func (p *ReaderPool) Start(ctx context.Context) {
	// Wait for vindexd to publish its initial serving state
	if _, err := p.client.GetCheckpoint(ctx); err == nil {
		goto Ready
	}
	{
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.NewTimer(15 * time.Second)
		defer timeout.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timeout.C:
				return
			case <-ticker.C:
				if _, err := p.client.GetCheckpoint(ctx); err == nil {
					goto Ready
				}
			}
		}
	}
Ready:

	var wg sync.WaitGroup

	// Global rate limiter across workers
	var rateLimiter <-chan time.Time
	if p.cfg.MaxReadQPS > 0 {
		interval := time.Duration(float64(time.Second) / p.cfg.MaxReadQPS)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	for i := 0; i < p.cfg.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			p.runWorker(ctx, workerID, rateLimiter)
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
}

func (p *ReaderPool) runWorker(ctx context.Context, workerID int, rateLimiter <-chan time.Time) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID*1000)))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if rateLimiter != nil {
			select {
			case <-ctx.Done():
				return
			case <-rateLimiter:
			}
		}

		p.executeOneQuery(ctx, rng)
	}
}

func (p *ReaderPool) executeOneQuery(ctx context.Context, rng *rand.Rand) {
	dice := rng.Float64()
	var queryType string
	var keyStr string
	var keyHash [sha256.Size]byte
	var isNonInclusion bool
	var isPagination bool

	if dice < p.cfg.HotKeyRatio {
		queryType = "hot"
		keyStr, keyHash = p.generator.SampleHotKey()
	} else if dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio {
		queryType = "uniform"
		keyStr, keyHash = p.generator.SampleExistingKey()
	} else if dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio+p.cfg.NonInclusionRatio {
		queryType = "non_inclusion"
		keyStr, keyHash = p.generator.SampleNonInclusionKey()
		isNonInclusion = true
	} else {
		queryType = "pagination"
		keyStr, keyHash = p.generator.SampleHotKey()
		isPagination = true
	}

	start := time.Now()
	var resp *client.LookupResponse
	var err error

	if isPagination {
		resp, err = p.client.LookupAll(ctx, keyHash, p.cfg.PageSize)
	} else {
		resp, err = p.client.Lookup(ctx, keyHash, nil, p.cfg.PageSize)
	}
	latency := time.Since(start)

	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if p.analyzer != nil {
			p.analyzer.RecordReadError(err, latency)
		}
		klog.V(2).Infof("Read error [%s] key %s: %v", queryType, keyStr, err)
		return
	}

	// Update serving lag telemetry
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, resp.InputLogSize)
	}

	// Verify non-inclusion invariant
	if isNonInclusion {
		if resp.Exists {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s exists in response with %d indices", keyStr, len(resp.Indices)))
			}
			return
		}
		if len(resp.Indices) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s returned non-empty indices: %v", keyStr, resp.Indices))
			}
			return
		}
		return
	}

	// Verify index bounds and intra-response sort order
	if !slices.IsSorted(resp.Indices) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("SortViolation: indices not sorted for key %s: %v", keyStr, resp.Indices))
		}
		return
	}
	for _, idx := range resp.Indices {
		if idx >= resp.InputLogSize {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("BoundsViolation: index %d >= InputLogSize %d for key %s", idx, resp.InputLogSize, keyStr))
			}
			return
		}
	}

	// Verify monotonicity
	p.verifyMonotonicity(keyHash, keyStr, resp, isPagination)
}

func (p *ReaderPool) verifyMonotonicity(keyHash [sha256.Size]byte, keyStr string, resp *client.LookupResponse, isCumulative bool) {
	// Monotonic prefix growth can only be validated against cumulative full-history responses (LookupAll)
	// or complete responses where all matches fit on a single page (NextBefore == nil && len(resp.Indices) < p.cfg.PageSize).
	// Single-page queries on keys exceeding PageSize return a sliding window from the log tip.
	if !isCumulative && (resp.NextBefore != nil || uint64(len(resp.Indices)) == p.cfg.PageSize) {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hist, exists := p.history[keyHash]
	if !exists {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: resp.InputLogSize,
			Indices:      slices.Clone(resp.Indices),
		}
		return
	}

	// 1. Verify that the total count of indices never shrinks as the log advances.
	if len(resp.Indices) < len(hist.Indices) && resp.InputLogSize >= hist.LastTreeSize {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s indices shrank from %d (size %d) to %d (size %d)", keyStr, len(hist.Indices), hist.LastTreeSize, len(resp.Indices), resp.InputLogSize))
		}
		return
	}

	// 2. Verify prefix consistency: previously observed history must match the new history prefix identically.
	checkLen := min(len(resp.Indices), len(hist.Indices))
	if !slices.Equal(resp.Indices[:checkLen], hist.Indices[:checkLen]) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s prefix mismatch: old %v, new %v", keyStr, hist.Indices[:checkLen], resp.Indices[:checkLen]))
		}
		return
	}

	if resp.InputLogSize >= hist.LastTreeSize {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: resp.InputLogSize,
			Indices:      slices.Clone(resp.Indices),
		}
	}
}

