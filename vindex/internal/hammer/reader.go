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
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
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
	OutputLogPolicy   client.CheckpointPolicy
	InputLogOrigin    string
	HotKeyRatio       float64
	UniformRatio      float64
	NonInclusionRatio float64
	PaginationRatio   float64
	PrefixRatio       float64
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
	cfg          ReaderConfig
	generator    *Generator
	clients      []*client.Client
	analyzer     *Analyzer
	mu           sync.Mutex
	hasFrom      bool
	verifiedFrom uint64
	history      map[string]KeyHistory
	totalReads   uint64
}

// NewReaderPool creates a new ReaderPool instance.
func NewReaderPool(cfg ReaderConfig, gen *Generator, an *Analyzer) (*ReaderPool, error) {
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = 8
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}

	outPolicy := cfg.OutputLogPolicy
	if outPolicy == nil && cfg.OutputLogVerifier != nil {
		var err error
		outPolicy, err = client.SingleKeyPolicy(cfg.OutputLogOrigin, cfg.OutputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to construct output log policy: %w", err)
		}
	}
	outOrigin := cfg.OutputLogOrigin
	if outOrigin == "" && outPolicy != nil {
		if op, ok := outPolicy.(interface{ Origin() string }); ok {
			outOrigin = op.Origin()
		}
	}

	cliCfg := client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  cfg.InputLogOrigin,
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.NumWorkers * 4,
			MaxIdleConnsPerHost: cfg.NumWorkers * 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	clients := make([]*client.Client, cfg.NumWorkers)
	for i := range cfg.NumWorkers {
		cli, err := client.New(cfg.VIndexURL, cliCfg, client.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
		clients[i] = cli
	}

	return &ReaderPool{
		cfg:       cfg,
		generator: gen,
		clients:   clients,
		analyzer:  an,
		history:   make(map[string]KeyHistory),
	}, nil
}

// Start launches worker goroutines and runs until ctx is cancelled.
func (p *ReaderPool) Start(ctx context.Context) error {
	probeKey := p.generator.SampleNonInclusionKey()
	if _, err := p.clients[0].LookupKey(ctx, probeKey); err != nil {
		if !errors.Is(err, client.ErrUnavailable) {
			p.recordViolation("ReadinessProbeError: %v", err)
			return fmt.Errorf("initial readiness probe failed: %w", err)
		}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.NewTimer(15 * time.Second)
		defer timeout.Stop()
	WaitReady:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timeout.C:
				p.recordViolation("ReadinessTimeout: vindexd did not become ready within 15s")
				return errors.New("timed out waiting 15s for vindexd readiness")
			case <-ticker.C:
				_, pErr := p.clients[0].LookupKey(ctx, probeKey)
				if pErr == nil {
					break WaitReady
				}
				if !errors.Is(pErr, client.ErrUnavailable) && ctx.Err() == nil {
					p.recordViolation("ReadinessProbeError: %v", pErr)
					return fmt.Errorf("readiness probe failed: %w", pErr)
				}
			}
		}
	}

	var rateLimiter <-chan time.Time
	if p.cfg.MaxReadQPS > 0 {
		interval := max(time.Duration(float64(time.Second)/p.cfg.MaxReadQPS), time.Microsecond)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	var wg sync.WaitGroup
	for i, cli := range p.clients {
		wg.Add(1)
		go func(workerID int, c *client.Client) {
			defer wg.Done()
			p.runWorker(ctx, workerID, c, rateLimiter)
		}(i, cli)
	}

	<-ctx.Done()
	wg.Wait()
	return nil
}

func (p *ReaderPool) runWorker(ctx context.Context, workerID int, cli *client.Client, rateLimiter <-chan time.Time) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID*1000)))
	for {
		if rateLimiter != nil {
			select {
			case <-ctx.Done():
				return
			case <-rateLimiter:
			}
		} else if ctx.Err() != nil {
			return
		}
		p.executeOneQuery(ctx, cli, rng)
	}
}

func (p *ReaderPool) recordViolation(format string, args ...any) {
	if p.analyzer != nil {
		p.analyzer.RecordInvariantViolation(fmt.Sprintf(format, args...))
	}
}

func (p *ReaderPool) verifyHorizon(from uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasFrom {
		p.hasFrom = true
		p.verifiedFrom = from
		return
	}
	if from != p.verifiedFrom {
		p.recordViolation("HorizonViolation: index start horizon changed from %d to %d", p.verifiedFrom, from)
	}
}

func (p *ReaderPool) executeOneQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	dice := rng.Float64()
	if p.cfg.PrefixRatio > 0 && dice < p.cfg.PrefixRatio {
		p.executePrefixQuery(ctx, cli, rng)
		return
	}
	if p.cfg.PrefixRatio > 0 && p.cfg.PrefixRatio < 1.0 {
		dice = (dice - p.cfg.PrefixRatio) / (1.0 - p.cfg.PrefixRatio)
	}

	var queryType, keyStr string
	var isNonInclusion, isPagination bool

	switch {
	case dice < p.cfg.HotKeyRatio:
		queryType = "hot"
		keyStr = p.generator.SampleHotKey()
	case dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio:
		queryType = "uniform"
		keyStr = p.generator.SampleExistingKey()
	case dice < p.cfg.HotKeyRatio+p.cfg.UniformRatio+p.cfg.NonInclusionRatio:
		queryType = "non_inclusion"
		keyStr = p.generator.SampleNonInclusionKey()
		isNonInclusion = true
	default:
		queryType = "pagination"
		keyStr = p.generator.SampleHotKey()
		isPagination = true
	}

	start := time.Now()
	kr, err := cli.LookupKey(ctx, keyStr)
	var indices []uint64
	isComplete := true
	if err == nil {
		p.verifyHorizon(kr.From)
		if len(kr.Keys) > 0 {
			pageLimit := p.cfg.PageSize
			if isPagination {
				pageLimit = 0
			}
			indices, isComplete, err = collectIndices(ctx, kr.Keys[0], pageLimit)
		}
	}
	latency := time.Since(start)
	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		p.handleQueryError(ctx, queryType, keyStr, err, latency)
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}

	if isNonInclusion {
		if len(kr.Keys) > 0 || len(indices) > 0 {
			p.recordViolation("NonInclusionViolation: key %s exists in response with %d indices", keyStr, len(indices))
		}
		return
	}

	p.verifyKeyIndices(keyStr, kr.From, kr.InputSize, indices, isComplete)
}

func (p *ReaderPool) executePrefixQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	isNonInc := rng.Intn(4) == 0
	var prefix string
	if isNonInc {
		prefix = p.generator.SampleNonInclusionKey()
	} else {
		prefix = p.generator.SampleHotKey()
	}

	start := time.Now()
	kr, err := cli.LookupPrefix(ctx, prefix)
	if err == nil {
		p.verifyHorizon(kr.From)
		if isNonInc && len(kr.Keys) > 0 {
			p.recordViolation("PrefixNonInclusionViolation: prefix %s matched %d keys", prefix, len(kr.Keys))
		}
		fetchValues := rng.Intn(2) == 1
		const maxPrefixValueScans = 5
		scanned := 0
		for _, m := range kr.Keys {
			if !strings.HasPrefix(m.Key, prefix) {
				p.recordViolation("PrefixMatchViolation: key %s does not have prefix %s", m.Key, prefix)
			}
			if fetchValues && scanned < maxPrefixValueScans {
				scanned++
				indices, isComplete, vErr := collectIndices(ctx, m, p.cfg.PageSize)
				if vErr != nil {
					err = vErr
					break
				}
				p.verifyKeyIndices(m.Key, kr.From, kr.InputSize, indices, isComplete)
			}
		}
	}
	latency := time.Since(start)
	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		p.handleQueryError(ctx, "prefix", prefix, err, latency)
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}
}

func collectIndices(ctx context.Context, m client.MatchedKey, maxCount uint64) ([]uint64, bool, error) {
	var revIndices []uint64
	complete := true
	for idx, err := range m.Values(ctx) {
		if err != nil {
			return nil, false, err
		}
		revIndices = append(revIndices, idx)
		if maxCount > 0 && uint64(len(revIndices)) >= maxCount {
			complete = false
			break
		}
	}
	slices.Reverse(revIndices)
	return revIndices, complete, nil
}

func (p *ReaderPool) handleQueryError(ctx context.Context, queryType, target string, err error, latency time.Duration) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadError(err, latency)
		switch {
		case errors.Is(err, client.ErrVerificationFailed):
			p.recordViolation("CryptographicViolation [%s] %s: %v", queryType, target, err)
		case errors.Is(err, client.ErrUnavailable):
			// Transient HTTP 503 during cold startup is tracked in read failure telemetry without failing invariants.
		case queryType == "prefix" && errors.Is(err, client.ErrTooManyKeys):
			// Expected HTTP 413 when a broad synthetic prefix exceeds MaxPrefixKeys.
		default:
			p.recordViolation("UnexpectedQueryError [%s] %s: %v", queryType, target, err)
		}
	}
	klog.V(2).Infof("Read error [%s] %s: %v", queryType, target, err)
}

func (p *ReaderPool) verifyKeyIndices(keyStr string, from, inputSize uint64, indices []uint64, isComplete bool) {
	if !slices.IsSorted(indices) {
		p.recordViolation("SortViolation: indices not sorted for key %s: %v", keyStr, indices)
		return
	}
	for _, idx := range indices {
		if idx < from || idx >= inputSize {
			p.recordViolation("BoundsViolation: index %d out of range [%d, %d) for key %s", idx, from, inputSize, keyStr)
			return
		}
	}
	p.verifyMonotonicity(keyStr, inputSize, indices, isComplete)
}

func (p *ReaderPool) verifyMonotonicity(keyStr string, inputLogSize uint64, indices []uint64, isComplete bool) {
	if !isComplete {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hist, exists := p.history[keyStr]
	if !exists {
		p.history[keyStr] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      indices,
		}
		return
	}

	checkLen := min(len(indices), len(hist.Indices))
	if !slices.Equal(indices[:checkLen], hist.Indices[:checkLen]) {
		p.recordViolation("MonotonicityViolation: key %s prefix mismatch: old %v, new %v", keyStr, hist.Indices[:checkLen], indices[:checkLen])
		return
	}

	switch {
	case inputLogSize == hist.LastTreeSize:
		if len(indices) != len(hist.Indices) {
			p.recordViolation("MonotonicityViolation: key %s count mismatch at same tree size %d: old %d, new %d", keyStr, inputLogSize, len(hist.Indices), len(indices))
		}
	case inputLogSize > hist.LastTreeSize:
		if len(indices) < len(hist.Indices) {
			p.recordViolation("MonotonicityViolation: key %s indices shrank from %d (size %d) to %d (size %d)", keyStr, len(hist.Indices), hist.LastTreeSize, len(indices), inputLogSize)
			return
		}
		for _, idx := range indices[len(hist.Indices):] {
			if idx < hist.LastTreeSize {
				p.recordViolation("MonotonicityViolation: key %s new index %d < prior tree size %d", keyStr, idx, hist.LastTreeSize)
				return
			}
		}
		p.history[keyStr] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      indices,
		}
	case inputLogSize < hist.LastTreeSize:
		if len(indices) > len(hist.Indices) {
			p.recordViolation("MonotonicityViolation: key %s older snapshot (size %d) has more indices (%d) than newer snapshot (size %d, count %d)", keyStr, inputLogSize, len(indices), hist.LastTreeSize, len(hist.Indices))
			return
		}
		if len(hist.Indices) > len(indices) && hist.Indices[len(indices)] < inputLogSize {
			p.recordViolation("MonotonicityViolation: key %s historical index %d < older snapshot tree size %d", keyStr, hist.Indices[len(indices)], inputLogSize)
		}
	}
}
