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

// Package vindex provides the public embedder API and configuration for the Verifiable Index.
package vindex

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// MappedEntry represents a single search key produced by a WASM map function.
type MappedEntry = wasmhost.MappedEntry

// WASMHost manages compiled WebAssembly modules and a bounded pool of reusable instances for bundle mapping.
type WASMHost = wasmhost.WASMHost

// CheckpointPolicy verifies signed checkpoints (primary signature + optional witness quorum).
type CheckpointPolicy = wire.Policy

// NewWASMHost compiles a WASM binary and initializes a pool of instances.
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	return wasmhost.NewWASMHost(ctx, wasmBytes, poolSize)
}

// Config defines the configuration for running or embedding a Verifiable Index node.
type Config struct {
	DBPath         string
	DBCacheSizeMB  int
	DBMaxOpenFiles int

	MPTDir        string
	TileCacheDir  string
	DisableReaper bool

	WASMPath string

	ListenAddr       string
	MetricsAddr      string
	PathPrefix       string
	EnableUI         *bool
	ServeOutputTiles bool

	ChunkSize                uint64
	CommitBatchSize          uint64
	CoarseCheckpointInterval uint64
	BackfillMaxPendingKeys   uint64

	Workers           int
	KVIndexerWorkers  int
	FetchWorkers      int
	FetchBatchBundles int
	PollInterval      time.Duration

	InputLogURL        string
	InputLogOrigin     string
	InputLogPubKey     string
	InputLogPolicyPath string
	InputLogVerifier   note.Verifier
	InputLogPolicy     CheckpointPolicy
	InputLogType       string
	InsecureSkipVerify bool

	OutputLogDir         string
	OutputLogOrigin      string
	OutputLogSignerKey   string
	OutputLogPolicyPath  string
	OutputLogPolicyBytes []byte
	WitnessURLs          []string
	WitnessPubKeys       []string

	PrefixPolicy     string
	PrefixPolicyFunc func(prefix string) error
	MaxPrefixKeys    int
	From             uint64
	ExplicitFrom     bool
}

// DefaultConfig returns standard default configuration values.
func DefaultConfig() Config {
	workers := max(runtime.GOMAXPROCS(0)-1, 1)
	return Config{
		ChunkSize:         kvstore.ChunkSize,
		Workers:           workers,
		FetchWorkers:      ingest.DefaultFetchWorkers(),
		FetchBatchBundles: ingest.DefaultFetchBatchBundles(),
		PollInterval:      10 * time.Second,
		PrefixPolicy:      "allow",
		MaxPrefixKeys:     server.DefaultMaxPrefixKeys,
	}
}

// Engine encapsulates the Verifiable Index storage, MPT, coordinator, and HTTP server subsystems.
type Engine struct {
	cfg          Config
	db           *kvstore.DB
	mptMgr       *mpt.Manager
	cache        *ingest.ManagedTileCache
	indexer      *kvstore.KVIndexer
	outLog       *tree.POSIXOutputLog
	outVerifier  note.Verifier
	pub          *tree.OutputPublisher
	fetcher      ingest.TileFetcher
	wasmHost     *WASMHost
	ownsWASMHost bool
	coord        *coordinator.Coordinator
	server       *server.ReadServer
	reaper       *ingest.TileReaper

	httpServer    *http.Server
	metricsServer *http.Server
	listenAddr    string
	metricsAddr   string

	opMu      sync.Mutex
	mu        sync.Mutex
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	recovered bool
	running   bool
	closed    bool
}

func parseSignerAndVerifier(rawOrPath string) (note.Signer, note.Verifier, error) {
	keyStr := strings.TrimSpace(rawOrPath)
	if keyStr == "" {
		return nil, nil, errors.New("signer key is empty")
	}
	if data, err := os.ReadFile(keyStr); err == nil {
		keyStr = string(bytes.TrimSpace(data))
	}
	if s, v, err := fnote.NewEd25519SignerVerifier(keyStr); err == nil {
		return s, v, nil
	}
	s, err := note.NewSigner(keyStr)
	if err != nil {
		return nil, nil, err
	}
	// Derive matching Ed25519 note.Verifier from standard PRIVATE+KEY+<name>+<hash>+<base64(0x01||seed)>.
	parts := strings.SplitN(keyStr, "+", 5)
	if len(parts) == 5 && parts[0] == "PRIVATE" && parts[1] == "KEY" {
		if raw, decErr := base64.StdEncoding.DecodeString(parts[4]); decErr == nil && len(raw) == 1+ed25519.SeedSize && raw[0] == 0x01 {
			pub := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
			if vkey, vErr := note.NewEd25519VerifierKey(s.Name(), pub); vErr == nil {
				if v, nvErr := note.NewVerifier(vkey); nvErr == nil {
					return s, v, nil
				}
			}
		}
	}
	return s, nil, nil
}

// New initializes and wires all Engine subsystems.
func New(cfg Config, wasmHost *WASMHost) (*Engine, error) {
	if cfg.OutputLogDir == "" {
		return nil, errors.New("OutputLogDir is required")
	}
	if strings.TrimSpace(cfg.OutputLogSignerKey) == "" {
		return nil, errors.New("OutputLogSignerKey is required")
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = kvstore.ChunkSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = max(runtime.GOMAXPROCS(0)-1, 1)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}

	prefixPol := cfg.PrefixPolicyFunc
	if prefixPol == nil {
		var err error
		prefixPol, err = server.ParsePrefixPolicy(cfg.PrefixPolicy)
		if err != nil {
			return nil, err
		}
	}

	switch strings.ToLower(strings.TrimSpace(cfg.InputLogType)) {
	case "", "auto", "tessera", "static-ct", "ct":
	default:
		return nil, fmt.Errorf("unknown InputLogType %q: expected 'auto', 'tessera', or 'static-ct'", cfg.InputLogType)
	}

	var cleanups []func()
	runCleanups := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	// 1. Open Pebble KV store
	db, err := kvstore.Open(cfg.DBPath, &kvstore.Options{
		CacheSizeMB:  cfg.DBCacheSizeMB,
		MaxOpenFiles: cfg.DBMaxOpenFiles,
		ChunkSize:    cfg.ChunkSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open KV store at %q: %w", cfg.DBPath, err)
	}
	cleanups = append(cleanups, func() { _ = db.Close() })

	// 2. Initialize HTTP ReadServer and bind optional early listeners before MPT mmap open
	tileDir := ""
	if cfg.ServeOutputTiles {
		tileDir = cfg.OutputLogDir
	}
	srv := server.New(server.Config{
		Store:         db,
		OutputLogDir:  tileDir,
		PathPrefix:    cfg.PathPrefix,
		DisableUI:     cfg.EnableUI != nil && !*cfg.EnableUI,
		PrefixPolicy:  prefixPol,
		MaxPrefixKeys: cfg.MaxPrefixKeys,
	})

	var metricsServer *http.Server
	var boundMetricsAddr string
	if cfg.MetricsAddr != "" {
		metricsLn, err := net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to bind MetricsAddr %q: %w", cfg.MetricsAddr, err)
		}
		boundMetricsAddr = metricsLn.Addr().String()
		metricsServer = server.NewHTTPServer(cfg.MetricsAddr, srv.AdminHandler())
		go func() {
			klog.Infof("Serving operational endpoints (/metrics, /healthz, /readyz, pprof) at http://%s", boundMetricsAddr)
			if sErr := metricsServer.Serve(metricsLn); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				klog.Errorf("Metrics server error: %v", sErr)
			}
		}()
		cleanups = append(cleanups, func() { _ = metricsServer.Close() })
	}

	var httpServer *http.Server
	var boundListenAddr string
	if cfg.ListenAddr != "" {
		readLn, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to bind ListenAddr %q: %w", cfg.ListenAddr, err)
		}
		boundListenAddr = readLn.Addr().String()
		httpServer = server.NewHTTPServer(cfg.ListenAddr, srv.Handler())
		go func() {
			klog.Infof("Serving VIndex Read API at http://%s", boundListenAddr)
			if sErr := httpServer.Serve(readLn); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				klog.Errorf("Read server error: %v", sErr)
			}
		}()
		cleanups = append(cleanups, func() { _ = httpServer.Close() })
	}

	// 3. Open Merkle Patricia Trie Manager
	mptMgr, err := mpt.Open(cfg.MPTDir)
	if err != nil {
		runCleanups()
		return nil, fmt.Errorf("failed to open MPT at %q: %w", cfg.MPTDir, err)
	}
	cleanups = append(cleanups, func() { _ = mptMgr.Close() })

	// 4. Compile WASM host if WASMPath was provided instead of an explicit *WASMHost
	ownsWASM := false
	if wasmHost == nil && cfg.WASMPath != "" {
		wasmBytes, err := os.ReadFile(cfg.WASMPath)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to read WASM binary %q: %w", cfg.WASMPath, err)
		}
		wasmHost, err = wasmhost.NewWASMHost(context.Background(), wasmBytes, cfg.Workers)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to initialize WASM host from %q: %w", cfg.WASMPath, err)
		}
		ownsWASM = true
		cleanups = append(cleanups, func() { _ = wasmHost.Close(context.Background()) })
	}
	if cfg.InputLogURL != "" && wasmHost == nil {
		runCleanups()
		return nil, errors.New("wasmHost or WASMPath is required when InputLogURL is configured")
	}

	// 5. Initialize Managed Tile Cache & KV Indexer
	cache, err := ingest.NewManagedTileCache(cfg.TileCacheDir, 0)
	if err != nil {
		runCleanups()
		return nil, fmt.Errorf("failed to initialize tile cache at %q: %w", cfg.TileCacheDir, err)
	}
	if sz, err := cache.DirSize(); err == nil {
		metrics.TileCacheBytes.Set(float64(sz))
	}

	indexer := kvstore.NewKVIndexer(db)
	if cfg.KVIndexerWorkers > 0 {
		indexer.SetNumWorkers(cfg.KVIndexerWorkers)
	} else if cfg.Workers == 1 {
		indexer.SetNumWorkers(1)
	}

	// 6. Initialize Output Log & Output Publisher
	signer, outVerifier, err := parseSignerAndVerifier(cfg.OutputLogSignerKey)
	if err != nil {
		runCleanups()
		return nil, fmt.Errorf("failed to parse output log signer key: %w", err)
	}
	origin := cfg.OutputLogOrigin
	if origin == "" {
		origin = signer.Name()
	}

	outPolicyBytes := cfg.OutputLogPolicyBytes
	if strings.TrimSpace(cfg.OutputLogPolicyPath) != "" {
		if len(outPolicyBytes) > 0 {
			runCleanups()
			return nil, errors.New("cannot specify both OutputLogPolicyPath and OutputLogPolicyBytes")
		}
		b, pErr := os.ReadFile(strings.TrimSpace(cfg.OutputLogPolicyPath))
		if pErr != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to read output log policy %q: %w", cfg.OutputLogPolicyPath, pErr)
		}
		outPolicyBytes = b
	}
	if len(outPolicyBytes) > 0 && (len(cfg.WitnessURLs) > 0 || len(cfg.WitnessPubKeys) > 0) {
		runCleanups()
		return nil, errors.New("cannot combine OutputLogPolicy with WitnessURLs/WitnessPubKeys")
	}

	posixOpts := []tree.POSIXOption{tree.WithOrigin(origin)}
	var configuredOutPolicy wire.Policy
	if len(outPolicyBytes) > 0 {
		wg, wErr := tree.BuildWitnessGroupFromPolicy(outPolicyBytes)
		if wErr != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to build witness group from output log policy: %w", wErr)
		}
		posixOpts = append(posixOpts, tree.WithWitnessGroup(wg))
		parsedOutPol, pErr := wire.ParsePolicy(outPolicyBytes)
		if pErr != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to parse output log policy: %w", pErr)
		}
		if polOrigin := wire.PolicyOrigin(parsedOutPol); polOrigin != "" && polOrigin != origin {
			runCleanups()
			return nil, fmt.Errorf("output log policy origin %q does not match signer/configured origin %q", polOrigin, origin)
		}
		configuredOutPolicy = parsedOutPol
	} else if len(cfg.WitnessURLs) > 0 || len(cfg.WitnessPubKeys) > 0 {
		wg, wErr := tree.BuildWitnessGroup(cfg.WitnessURLs, cfg.WitnessPubKeys)
		if wErr != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to build witness group: %w", wErr)
		}
		posixOpts = append(posixOpts, tree.WithWitnessGroup(wg))
	}
	posixLog, err := tree.NewPOSIXOutputLog(context.Background(), cfg.OutputLogDir, signer, posixOpts...)
	if err != nil {
		runCleanups()
		return nil, fmt.Errorf("failed to open POSIX output log at %q: %w", cfg.OutputLogDir, err)
	}
	cleanups = append(cleanups, func() { _ = posixLog.Close() })

	pub := tree.NewOutputPublisher(mptMgr, posixLog)
	if cfg.InputLogOrigin != "" {
		pub.SetInputOrigin(cfg.InputLogOrigin)
	}
	if cfg.From > 0 {
		pub.SetFrom(cfg.From)
	}
	if configuredOutPolicy != nil {
		pub.SetOutputLogPolicy(configuredOutPolicy)
	} else if outVerifier != nil || len(cfg.WitnessPubKeys) > 0 {
		var witnessVerifiers []note.Verifier
		for _, wpk := range cfg.WitnessPubKeys {
			wv, err := fnote.NewVerifierForCosignatureV1(strings.TrimSpace(wpk))
			if err != nil {
				wv, err = wire.ParseWitnessVerifier(wpk)
			}
			if err != nil {
				runCleanups()
				return nil, fmt.Errorf("failed to parse witness public key %q: %w", wpk, err)
			}
			witnessVerifiers = append(witnessVerifiers, wv)
		}
		if outVerifier == nil {
			runCleanups()
			return nil, errors.New("could not derive Output Log verifier needed to enforce witness policy")
		}
		outPolicy, err := wire.BuildPolicy(origin, outVerifier, witnessVerifiers, len(witnessVerifiers))
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to build output log policy: %w", err)
		}
		pub.SetOutputLogPolicy(outPolicy)
	}

	// 7. Initialize Input Log Tile Fetcher if configured
	var fetcher ingest.TileFetcher
	if cfg.InputLogURL != "" {
		u, err := url.Parse(cfg.InputLogURL)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("invalid input log URL %q: %w", cfg.InputLogURL, err)
		}

		inVerifier := cfg.InputLogVerifier
		inPolicy := cfg.InputLogPolicy
		inOrigin := cfg.InputLogOrigin
		pubKey := strings.TrimSpace(cfg.InputLogPubKey)
		if pubKey != "" {
			if data, fErr := os.ReadFile(pubKey); fErr == nil {
				pubKey = string(bytes.TrimSpace(data))
			}
		}

		if inPolicy == nil {
			switch {
			case strings.TrimSpace(cfg.InputLogPolicyPath) != "":
				p, err := wire.ParsePolicyOrVerifier(cfg.InputLogPolicyPath, pubKey, inOrigin, nil, 0)
				if err != nil {
					runCleanups()
					return nil, fmt.Errorf("failed to parse input log policy: %w", err)
				}
				inPolicy = p
			case pubKey != "":
				v, err := wire.ParseVerifier(pubKey)
				if err != nil {
					runCleanups()
					return nil, fmt.Errorf("failed to parse input log pubkey: %w", err)
				}
				inVerifier = v
				if inOrigin == "" {
					inOrigin = v.Name()
				}
				pub.SetInputOrigin(inOrigin)
				p, err := wire.ParsePolicyOrVerifier("", pubKey, inOrigin, nil, 0)
				if err != nil {
					runCleanups()
					return nil, fmt.Errorf("failed to build input log policy: %w", err)
				}
				inPolicy = p
			case inVerifier != nil:
				if inOrigin == "" {
					inOrigin = inVerifier.Name()
				}
				pub.SetInputOrigin(inOrigin)
				p, err := wire.BuildPolicy(inOrigin, inVerifier, nil, 0)
				if err != nil {
					runCleanups()
					return nil, fmt.Errorf("failed to build input log policy: %w", err)
				}
				inPolicy = p
			case u.Scheme != "file" && !cfg.InsecureSkipVerify:
				runCleanups()
				return nil, errors.New("InputLogPolicy, InputLogPolicyPath, InputLogPubKey, or InputLogVerifier is required for non-file InputLogURL (or set InsecureSkipVerify)")
			}
		}

		if inPolicy != nil && inOrigin == "" {
			inOrigin = wire.PolicyOrigin(inPolicy)
			if inOrigin != "" {
				pub.SetInputOrigin(inOrigin)
			}
		}

		tFetcher, err := ingest.NewTiledFetcher(u, inVerifier, inOrigin, nil)
		if err != nil {
			runCleanups()
			return nil, fmt.Errorf("failed to create tile fetcher for %q: %w", cfg.InputLogURL, err)
		}
		if inPolicy != nil {
			tFetcher.SetPolicy(inPolicy)
		} else if cfg.InsecureSkipVerify {
			tFetcher.SetAllowUnverifiedCheckpoints(true)
		}
		switch strings.ToLower(strings.TrimSpace(cfg.InputLogType)) {
		case "static-ct", "ct":
			tFetcher.SetStaticCT(true)
		case "tessera":
			tFetcher.SetStaticCT(false)
		}
		fetcher = tFetcher
	}

	// 8. Initialize Coordinator, ReadServer readiness, and optional TileReaper
	coord := coordinator.New(coordinator.Config{
		DB:                       db,
		MPT:                      mptMgr,
		OutputLog:                posixLog,
		Publisher:                pub,
		Indexer:                  indexer,
		Fetcher:                  fetcher,
		Cache:                    cache,
		WASMHost:                 wasmHost,
		CommitBatchSize:          cfg.CommitBatchSize,
		CoarseCheckpointInterval: cfg.CoarseCheckpointInterval,
		BackfillMaxPendingKeys:   cfg.BackfillMaxPendingKeys,
		Workers:                  cfg.Workers,
		FetchWorkers:             cfg.FetchWorkers,
		FetchBatchBundles:        cfg.FetchBatchBundles,
		ExplicitFrom:             cfg.ExplicitFrom || cfg.From > 0,
	})
	srv.SetBackend(mptMgr, pub, coord.ReadinessCheck)

	var reaper *ingest.TileReaper
	if !cfg.DisableReaper {
		reaper = ingest.NewTileReaper(coord.SafeWatermark, cache)
	}

	return &Engine{
		cfg:           cfg,
		db:            db,
		mptMgr:        mptMgr,
		cache:         cache,
		indexer:       indexer,
		outLog:        posixLog,
		outVerifier:   outVerifier,
		pub:           pub,
		fetcher:       fetcher,
		wasmHost:      wasmHost,
		ownsWASMHost:  ownsWASM,
		coord:         coord,
		server:        srv,
		reaper:        reaper,
		httpServer:    httpServer,
		metricsServer: metricsServer,
		listenAddr:    boundListenAddr,
		metricsAddr:   boundMetricsAddr,
	}, nil
}

func (e *Engine) ensureRecoveredLocked(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	alreadyRecovered := e.recovered
	e.mu.Unlock()
	if alreadyRecovered {
		return nil
	}
	if err := e.coord.Recover(ctx); err != nil {
		fErr := fmt.Errorf("startup recovery failed: %w", err)
		e.coord.RecordFatalError(fErr)
		return fErr
	}
	e.mu.Lock()
	e.recovered = true
	e.mu.Unlock()
	return nil
}

// SyncOnce executes startup recovery (if not yet run) followed by a single synchronization pass.
func (e *Engine) SyncOnce(ctx context.Context) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	if err := e.ensureRecoveredLocked(ctx); err != nil {
		return err
	}
	err := e.coord.SyncOnce(ctx)
	if err != nil && coordinator.IsFatalSyncError(err) {
		e.coord.RecordFatalError(err)
	}
	return err
}

// Start executes startup crash recovery, runs an initial sync pass, and starts background loops
// scoped to ctx (and halted on Close).
func (e *Engine) Start(ctx context.Context) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	if e.running {
		e.mu.Unlock()
		return errors.New("engine is already running")
	}
	e.mu.Unlock()

	if err := e.ensureRecoveredLocked(ctx); err != nil {
		return err
	}

	if e.fetcher != nil {
		if err := e.coord.SyncOnce(ctx); err != nil {
			if coordinator.IsFatalSyncError(err) {
				fErr := fmt.Errorf("fatal initial sync error: %w", err)
				e.coord.RecordFatalError(fErr)
				return fErr
			}
			klog.Warningf("Initial sync error: %v", err)
		}
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("engine is closed")
	}
	bgCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.running = true

	if e.fetcher != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := e.coord.RunPollLoop(bgCtx, e.cfg.PollInterval); err != nil {
				klog.Errorf("Fatal background sync error, halting engine: %v", err)
				cancel()
			}
		}()
	}

	if e.reaper != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			_ = e.reaper.Run(bgCtx, 60*time.Second)
		}()
	}
	e.mu.Unlock()

	return nil
}

// Run executes startup recovery and runs the coordinator synchronization loop synchronously until ctx is canceled.
func (e *Engine) Run(ctx context.Context) error {
	e.opMu.Lock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		e.opMu.Unlock()
		return errors.New("engine is closed")
	}
	if e.running {
		e.mu.Unlock()
		e.opMu.Unlock()
		return errors.New("engine is already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.running = true
	e.wg.Add(1)
	if e.reaper != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			_ = e.reaper.Run(runCtx, 60*time.Second)
		}()
	}
	e.mu.Unlock()

	defer func() {
		cancel()
		e.wg.Done()
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	if err := e.ensureRecoveredLocked(runCtx); err != nil {
		e.opMu.Unlock()
		return err
	}
	if e.fetcher != nil {
		if err := e.coord.SyncOnce(runCtx); err != nil {
			if coordinator.IsFatalSyncError(err) {
				fErr := fmt.Errorf("fatal initial sync error: %w", err)
				e.coord.RecordFatalError(fErr)
				e.opMu.Unlock()
				return fErr
			}
			if runCtx.Err() == nil {
				klog.Warningf("Initial sync error: %v", err)
			}
		}
	}
	e.opMu.Unlock()

	return e.coord.RunPollLoop(runCtx, e.cfg.PollInterval)
}

// Close gracefully closes the engine, halting background loops and releasing owned resources.
// A caller-supplied *WASMHost passed to New is NOT closed by Close; only a WASMHost created internally
// from Config.WASMPath is closed.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}
	e.closed = true

	if e.cancel != nil {
		e.cancel()
	}
	if e.httpServer != nil {
		_ = e.httpServer.Close()
	}
	if e.metricsServer != nil {
		_ = e.metricsServer.Close()
	}
	e.wg.Wait()
	e.running = false

	var errs []error
	if e.outLog != nil {
		if err := e.outLog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close output log: %w", err))
		}
	}
	if e.mptMgr != nil {
		if err := e.mptMgr.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close MPT: %w", err))
		}
	}
	if e.db != nil {
		if err := e.db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close KV store: %w", err))
		}
	}
	if e.ownsWASMHost && e.wasmHost != nil {
		if err := e.wasmHost.Close(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("failed to close WASM host: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Handler returns an http.Handler exposing the public read server endpoints (/keys, /values, /checkpoint, etc.).
func (e *Engine) Handler() http.Handler {
	if e.server == nil {
		return http.NewServeMux()
	}
	return e.server.Handler()
}

// AdminHandler returns an http.Handler exposing the internal operational endpoints (/healthz, /readyz, /metrics, /debug/pprof/*).
func (e *Engine) AdminHandler() http.Handler {
	if e.server == nil {
		return http.NewServeMux()
	}
	return e.server.AdminHandler()
}

// ListenAddr returns the bound address of the public HTTP listener when Config.ListenAddr was set.
func (e *Engine) ListenAddr() string {
	return e.listenAddr
}

// MetricsAddr returns the bound address of the internal metrics/admin listener when Config.MetricsAddr was set.
func (e *Engine) MetricsAddr() string {
	return e.metricsAddr
}

// OutputLogVerifier returns the derived note.Verifier for the Output Log.
func (e *Engine) OutputLogVerifier() note.Verifier {
	return e.outVerifier
}
