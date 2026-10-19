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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/torchwood"
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
	OutputLogPolicy   torchwood.Policy
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
	InputLogPolicy    torchwood.Policy
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
	cfg        ReaderConfig
	generator  *Generator
	clients    []*client.Client
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

	outPolicy := cfg.OutputLogPolicy
	if outPolicy == nil && cfg.OutputLogVerifier != nil {
		var err error
		outPolicy, err = client.SingleKeyPolicy(cfg.OutputLogOrigin, cfg.OutputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to construct output log policy: %w", err)
		}
	}
	inPolicy := cfg.InputLogPolicy
	if inPolicy == nil && cfg.InputLogVerifier != nil {
		var err error
		inPolicy, err = client.SingleKeyPolicy(cfg.InputLogOrigin, cfg.InputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to construct input log policy: %w", err)
		}
	}

	cliCfg := client.VerifierConfig{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
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
	for i := 0; i < cfg.NumWorkers; i++ {
		cli, err := client.New(cfg.VIndexURL, cliCfg, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
		cli.SetStateTracker(client.NewStateTracker())
		clients[i] = cli
	}

	return &ReaderPool{
		cfg:       cfg,
		generator: gen,
		clients:   clients,
		analyzer:  an,
		history:   make(map[[sha256.Size]byte]KeyHistory),
		stopCh:    make(chan struct{}),
	}, nil
}

// Start launches worker goroutines and runs until ctx is cancelled.
func (p *ReaderPool) Start(ctx context.Context) {
	// Wait for vindexd to publish its initial serving state
	probeKey, _ := p.generator.SampleNonInclusionKey()
	if _, err := p.clients[0].LookupKey(ctx, probeKey); err == nil {
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
				if _, err := p.clients[0].LookupKey(ctx, probeKey); err == nil {
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
		go func(workerID int, cli *client.Client) {
			defer wg.Done()
			p.runWorker(ctx, workerID, cli, rateLimiter)
		}(i, p.clients[i])
	}

	<-ctx.Done()
	wg.Wait()
}

func (p *ReaderPool) runWorker(ctx context.Context, workerID int, cli *client.Client, rateLimiter <-chan time.Time) {
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

		p.executeOneQuery(ctx, cli, rng)
	}
}

func isCryptographicOrConsistencyFault(err error) bool {
	return errors.Is(err, client.ErrCheckpointFailed) ||
		errors.Is(err, client.ErrCheckpointRegressed) ||
		errors.Is(err, client.ErrConsistencyFault) ||
		errors.Is(err, client.ErrInclusionFailed) ||
		errors.Is(err, client.ErrMPTFailed) ||
		errors.Is(err, client.ErrCryptographicFault) ||
		errors.Is(err, client.ErrIndexOrder) ||
		errors.Is(err, client.ErrIndexRange)
}

func (p *ReaderPool) executeOneQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	dice := rng.Float64()
	if p.cfg.PrefixRatio > 0 && dice < p.cfg.PrefixRatio {
		p.executePrefixQuery(ctx, cli, rng)
		return
	}
	// Rescale remaining dice into [0, 1)
	if p.cfg.PrefixRatio > 0 && p.cfg.PrefixRatio < 1.0 {
		dice = (dice - p.cfg.PrefixRatio) / (1.0 - p.cfg.PrefixRatio)
	}

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
	var kr *client.KeysResponse
	var indices []uint64
	var isComplete bool
	var err error

	if isPagination {
		if rng.Intn(2) == 0 {
			indices, err = cli.LookupAllValues(ctx, keyStr, p.cfg.PageSize)
			if err == nil {
				kr, err = cli.LookupKey(ctx, keyStr)
				// LookupKey occurred at >= the InputSize used by LookupAllValues; if new entries
				// were appended in between, indices reflects the earlier complete snapshot, so
				// only treat as complete at kr.InputSize when the count matches or don't overwrite
				// newer watermark if LookupKey advanced past LookupAllValues.
				isComplete = false
			}
		} else {
			kr, err = cli.LookupKey(ctx, keyStr)
			if err == nil {
				isComplete = true
				if len(kr.Keys) > 0 {
					var pages [][]uint64
					before := kr.InputSize
					expectedRoot := kr.Keys[0].ValueRoot
					for {
						var vr *client.ValuesResponse
						vr, err = cli.LookupValues(ctx, keyStr, expectedRoot, kr.From, before, p.cfg.PageSize)
						if err != nil {
							break
						}
						pages = append(pages, vr.Indices)
						nextBefore, nextRoot, ok := vr.NextPage()
						if !ok {
							break
						}
						before = nextBefore
						expectedRoot = nextRoot
					}
					if err == nil {
						for i := len(pages) - 1; i >= 0; i-- {
							indices = append(indices, pages[i]...)
						}
					}
				}
			}
		}
	} else {
		kr, err = cli.LookupKey(ctx, keyStr)
		if err == nil {
			if len(kr.Keys) == 0 {
				isComplete = true
			} else {
				var vr *client.ValuesResponse
				vr, err = cli.LookupValues(ctx, keyStr, kr.Keys[0].ValueRoot, kr.From, kr.InputSize, p.cfg.PageSize)
				if err == nil {
					indices = vr.Indices
					_, _, hasMore := vr.NextPage()
					isComplete = !hasMore
				}
			}
		}
	}
	latency := time.Since(start)

	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if p.analyzer != nil {
			p.analyzer.RecordReadError(err, latency)
			if isCryptographicOrConsistencyFault(err) {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("CryptographicViolation [%s] key %s: %v", queryType, keyStr, err))
			}
		}
		klog.V(2).Infof("Read error [%s] key %s: %v", queryType, keyStr, err)
		return
	}

	// Update serving lag telemetry
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, kr.InputSize)
	}

	// Verify non-inclusion invariant
	if isNonInclusion {
		if len(kr.Keys) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s exists in response with %d indices", keyStr, len(indices)))
			}
			return
		}
		if len(indices) > 0 {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("NonInclusionViolation: key %s returned non-empty indices: %v", keyStr, indices))
			}
			return
		}
		return
	}

	// Verify index bounds and intra-response sort order
	if !slices.IsSorted(indices) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("SortViolation: indices not sorted for key %s: %v", keyStr, indices))
		}
		return
	}
	for _, idx := range indices {
		if idx >= kr.InputSize {
			if p.analyzer != nil {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("BoundsViolation: index %d >= InputSize %d for key %s", idx, kr.InputSize, keyStr))
			}
			return
		}
	}

	// Verify monotonicity
	p.verifyMonotonicity(keyHash, keyStr, kr.InputSize, indices, isComplete)
}

func (p *ReaderPool) executePrefixQuery(ctx context.Context, cli *client.Client, rng *rand.Rand) {
	isNonInc := rng.Intn(4) == 0
	var prefix string
	if isNonInc {
		nonKey, _ := p.generator.SampleNonInclusionKey()
		prefix = nonKey
	} else {
		sampleKey, _ := p.generator.SampleHotKey()
		prefix = sampleKey
	}

	start := time.Now()
	var inputSize uint64
	var err error
	if rng.Intn(2) == 0 {
		var kr *client.KeysResponse
		kr, err = cli.LookupPrefix(ctx, prefix)
		if err == nil {
			inputSize = kr.InputSize
			if isNonInc && len(kr.Keys) > 0 {
				if p.analyzer != nil {
					p.analyzer.RecordInvariantViolation(fmt.Sprintf("PrefixNonInclusionViolation: prefix %s matched %d keys", prefix, len(kr.Keys)))
				}
			}
			for _, m := range kr.Keys {
				if !strings.HasPrefix(m.Key, prefix) {
					if p.analyzer != nil {
						p.analyzer.RecordInvariantViolation(fmt.Sprintf("PrefixMatchViolation: key %s does not have prefix %s", m.Key, prefix))
					}
				}
			}
		}
	} else {
		var pr *client.PrefixLookupResponse
		pr, err = cli.LookupPrefixAll(ctx, prefix, p.cfg.PageSize)
		if err == nil {
			inputSize = pr.InputSize
			if isNonInc && len(pr.Results) > 0 {
				if p.analyzer != nil {
					p.analyzer.RecordInvariantViolation(fmt.Sprintf("PrefixAllNonInclusionViolation: prefix %s matched %d keys", prefix, len(pr.Results)))
				}
			}
			for _, res := range pr.Results {
				kh := sha256.Sum256([]byte(res.Key))
				p.verifyMonotonicity(kh, res.Key, pr.InputSize, res.Indices, true)
			}
		}
	}
	latency := time.Since(start)
	atomic.AddUint64(&p.totalReads, 1)

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if p.analyzer != nil {
			p.analyzer.RecordReadError(err, latency)
			if isCryptographicOrConsistencyFault(err) {
				p.analyzer.RecordInvariantViolation(fmt.Sprintf("CryptographicViolation [prefix] %s: %v", prefix, err))
			}
		}
		return
	}
	if p.analyzer != nil {
		p.analyzer.RecordReadSuccess(latency, inputSize)
	}
}

func (p *ReaderPool) verifyMonotonicity(keyHash [sha256.Size]byte, keyStr string, inputLogSize uint64, indices []uint64, isComplete bool) {
	if !isComplete {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hist, exists := p.history[keyHash]
	if !exists {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      slices.Clone(indices),
		}
		return
	}

	// 1. Verify that the total count of indices never shrinks as the log advances.
	if len(indices) < len(hist.Indices) && inputLogSize >= hist.LastTreeSize {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s indices shrank from %d (size %d) to %d (size %d)", keyStr, len(hist.Indices), hist.LastTreeSize, len(indices), inputLogSize))
		}
		return
	}

	// 2. Verify prefix consistency: previously observed history must match the new history prefix identically.
	checkLen := min(len(indices), len(hist.Indices))
	if !slices.Equal(indices[:checkLen], hist.Indices[:checkLen]) {
		if p.analyzer != nil {
			p.analyzer.RecordInvariantViolation(fmt.Sprintf("MonotonicityViolation: key %s prefix mismatch: old %v, new %v", keyStr, hist.Indices[:checkLen], indices[:checkLen]))
		}
		return
	}

	if inputLogSize >= hist.LastTreeSize {
		p.history[keyHash] = KeyHistory{
			LastTreeSize: inputLogSize,
			Indices:      slices.Clone(indices),
		}
	}
}
