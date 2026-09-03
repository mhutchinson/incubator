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

// Package verifier implements the VIndex Independent Verifier engine.
// It verifies published OutputLogs against InputLogs using a provided MapFn,
// checks cryptographic root hashes after calculation, signals mismatches immediately,
// and optionally mirrors/serves verified state.
package auditor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	// ErrRootMismatch is returned when the calculated local MPT root hash diverges from the root hash committed to in the OutputLog leaf.
	ErrRootMismatch = errors.New("verifier root hash mismatch")

	// ErrInclusionFailed indicates that an OutputLog leaf inclusion proof could not be verified against the OutputLog checkpoint tree root.
	ErrInclusionFailed = errors.New("output log inclusion proof invalid")

	// ErrCheckpointFailed indicates a cryptographic signature verification failure on an OutputLog checkpoint or an embedded InputLog checkpoint.
	ErrCheckpointFailed = errors.New("checkpoint signature verification failed")

	// ErrMonotonicityBroken indicates that an OutputLog leaf published a target input log size smaller than the currently verified input log size.
	ErrMonotonicityBroken = errors.New("input log size non-monotonic")

	// ErrOutputLogRegressed indicates that the discovered OutputLog tree size is smaller than the verified output log size.
	ErrOutputLogRegressed = errors.New("output log tree size regressed")

	// ErrOutputLogCorrupted indicates that an OutputLog leaf payload could not be parsed or is malformed.
	ErrOutputLogCorrupted = tree.ErrOutputLogCorrupted
)

var (
	// KeyVerifierOutputWatermark stores the number of verified OutputLog leaves.
	KeyVerifierOutputWatermark = []byte("meta:verifier:output_watermark")

	// KeyVerifierInputWatermark stores the number of verified InputLog leaves.
	KeyVerifierInputWatermark = []byte("meta:verifier:input_watermark")

	// KeyVerifierLastRoot stores the latest verified MPT root hash.
	KeyVerifierLastRoot = []byte("meta:verifier:last_root")
)

// RootMismatchError provides structured diagnostic details when a local MPT root calculation
// diverges from the state commitment in an OutputLog leaf.
type RootMismatchError struct {
	OutputIndex      uint64
	InputSize        uint64
	LocalMapRoot     [sha256.Size]byte
	CommittedMapRoot [sha256.Size]byte
	DetectedAt       time.Time
}

func (e *RootMismatchError) Error() string {
	return fmt.Sprintf("%v: output leaf %d (input size %d): calculated local MPT root %x != committed map root %x",
		ErrRootMismatch, e.OutputIndex, e.InputSize, e.LocalMapRoot, e.CommittedMapRoot)
}

func (e *RootMismatchError) Unwrap() error {
	return ErrRootMismatch
}

type rootMismatchDiag struct {
	Status        string `json:"status"`
	Error         string `json:"error"`
	OutputIndex   uint64 `json:"output_index"`
	InputSize     uint64 `json:"input_size"`
	LocalRoot     string `json:"local_root"`
	CommittedRoot string `json:"committed_root"`
}

// JSONDiagnostics formats the root mismatch details as JSON for degraded status responses on /readyz.
func (e *RootMismatchError) JSONDiagnostics() []byte {
	d := rootMismatchDiag{
		Status:        "degraded",
		Error:         "verifier root hash mismatch",
		OutputIndex:   e.OutputIndex,
		InputSize:     e.InputSize,
		LocalRoot:     fmt.Sprintf("%x", e.LocalMapRoot),
		CommittedRoot: fmt.Sprintf("%x", e.CommittedMapRoot),
	}
	b, _ := json.Marshal(d)
	return b
}

// OutputLogSource abstracts reading checkpoint notes, leaf payloads, and inclusion proofs from an Output Log.
type OutputLogSource interface {
	Checkpoint(ctx context.Context) ([]byte, error)
	GetLeaf(ctx context.Context, idx uint64) ([]byte, error)
	InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error)
}

// Config defines the runtime configuration for the VIndex Verifier.
type Config struct {
	// Log endpoints and keys
	InputLogURL     string
	InputLogPubKey  string
	InputLogOrigin  string
	OutputLogURL    string
	OutputLogPubKey string
	OutputLogOrigin string

	// Mapping function
	MapFn ingest.LeafMapper

	// Storage paths (use empty string or ":memory:" for in-memory operation)
	DBPath string
	MPTDir string

	// Operational settings
	ServeMirror     bool
	FailClosed      bool
	ListenAddr      string
	MetricsAddr     string
	PollInterval    time.Duration
	CommitBatchSize uint64

	// Optional dependency injection (for tests and custom clients)
	InputLogVerifier  note.Verifier
	OutputLogVerifier note.Verifier
	OutputLog         OutputLogSource
	OutputLogClient   OutputLogSource
	InputLogFetcher   ingest.TileFetcher
	Fetcher           ingest.TileFetcher
	DB                *kvstore.DB
	MPTMgr            *tree.Manager
}

// AuditorConfig defines the runtime configuration for the VIndex Auditor (Verifier).
type AuditorConfig = Config

// Status represents an instantaneous snapshot of the verifier's operational state.
type Status struct {
	IsHalted           bool
	HaltError          error
	VerifiedOutputSize uint64
	VerifiedInputSize  uint64
	LastVerifiedRoot   [sha256.Size]byte
	LastVerifiedAt     time.Time
}

// Auditor audits the Output Log against the Input Log and optionally serves verified lookups.
type Auditor = Verifier

// Verifier implements the independent verification engine for VIndex.
type Verifier struct {
	cfg Config

	// Cryptographic note verifiers
	inputLogVerifier  note.Verifier
	outputLogVerifier note.Verifier

	// Log sources
	outputLog    OutputLogSource
	inputFetcher ingest.TileFetcher

	// Storage and Trees
	db       *kvstore.DB
	mptMgr   *tree.Manager
	indexer  *kvstore.KVIndexer
	pipeline *ingest.IngestionPipeline
	ownsDB   bool
	ownsMPT  bool

	// Mirror serving mode
	publisher  *tree.OutputPublisher
	readServer *server.ReadServer

	// Batch configuration
	commitBatchSize uint64

	// Sync execution serialization
	syncMu             sync.Mutex
	verifiedOutputSize uint64
	verifiedInputSize  uint64

	// State and Health status
	stateMu          sync.RWMutex
	isHalted         bool
	haltErr          error
	lastVerifiedRoot [sha256.Size]byte
	lastVerifiedAt   time.Time
}

// NoCheckpointFetcher wraps an ingest.TileFetcher and panics if Checkpoint() is ever called.
// This enforces Requirement R1 at the architecture and runtime level.
type NoCheckpointFetcher struct {
	ingest.TileFetcher
}

func (f *NoCheckpointFetcher) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	panic("INVARIANT VIOLATION (R1): verifier attempted to call InputLog.Checkpoint()")
}

func (f *NoCheckpointFetcher) SetTreeSize(size uint64) {
	if sizer, ok := f.TileFetcher.(interface{ SetTreeSize(uint64) }); ok {
		sizer.SetTreeSize(size)
	}
}

// WrapNoCheckpointFetcher wraps any TileFetcher with NoCheckpointFetcher.
func WrapNoCheckpointFetcher(f ingest.TileFetcher) *NoCheckpointFetcher {
	return &NoCheckpointFetcher{TileFetcher: f}
}

// tiledOutputLogSource adapts a Tessera TiledReader to the OutputLogSource interface.
type tiledOutputLogSource struct {
	reader ingest.TiledReader
}

func (s *tiledOutputLogSource) Checkpoint(ctx context.Context) ([]byte, error) {
	return s.reader.ReadCheckpoint(ctx)
}

func (s *tiledOutputLogSource) GetLeaf(ctx context.Context, idx uint64) ([]byte, error) {
	rawCP, err := s.reader.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	cp, err := tree.ParseCheckpointHeader(rawCP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if idx >= cp.Size {
		return nil, fmt.Errorf("leaf index %d out of bounds (size %d)", idx, cp.Size)
	}
	bundleIdx := idx / layout.EntryBundleWidth
	offset := idx % layout.EntryBundleWidth
	bundle, err := tclient.GetEntryBundle(ctx, s.reader.ReadEntryBundle, bundleIdx, cp.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry bundle %d: %w", bundleIdx, err)
	}
	if int(offset) >= len(bundle.Entries) {
		return nil, fmt.Errorf("leaf offset %d out of bounds in bundle %d", offset, bundleIdx)
	}
	return bundle.Entries[offset], nil
}

func (s *tiledOutputLogSource) InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	pb, err := tclient.NewProofBuilder(ctx, treeSize, s.reader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder: %w", err)
	}
	proofHashes, err := pb.InclusionProof(ctx, leafIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to build inclusion proof: %w", err)
	}
	out := make([][sha256.Size]byte, len(proofHashes))
	for i, p := range proofHashes {
		if len(p) != sha256.Size {
			return nil, fmt.Errorf("invalid proof element size %d, want 32", len(p))
		}
		copy(out[i][:], p)
	}
	return out, nil
}

// New initializes and returns a new Verifier instance.
func New(cfg Config) (*Verifier, error) {
	if cfg.MapFn == nil {
		return nil, errors.New("verifier requires non-nil MapFn")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	commitBatchSize := cfg.CommitBatchSize
	if commitBatchSize == 0 {
		commitBatchSize = 4096
	}

	v := &Verifier{
		cfg:             cfg,
		commitBatchSize: commitBatchSize,
	}

	// 1. Initialize note verifiers
	if cfg.OutputLogVerifier != nil {
		v.outputLogVerifier = cfg.OutputLogVerifier
	} else if cfg.OutputLogPubKey != "" {
		nv, err := note.NewVerifier(cfg.OutputLogPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse output log pub key: %w", err)
		}
		v.outputLogVerifier = nv
	}

	if cfg.InputLogVerifier != nil {
		v.inputLogVerifier = cfg.InputLogVerifier
	} else if cfg.InputLogPubKey != "" {
		nv, err := note.NewVerifier(cfg.InputLogPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input log pub key: %w", err)
		}
		v.inputLogVerifier = nv
	}

	// 2. Initialize Pebble DB (persistent or in-memory)
	if cfg.DB != nil {
		v.db = cfg.DB
		v.ownsDB = false
	} else if cfg.DBPath == "" || cfg.DBPath == ":memory:" {
		memOpts := &pebble.Options{
			FS: vfs.NewMem(),
		}
		db, err := kvstore.Open("", memOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to open in-memory Pebble DB: %w", err)
		}
		v.db = db
		v.ownsDB = true
	} else {
		db, err := kvstore.Open(cfg.DBPath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to open Pebble DB at %q: %w", cfg.DBPath, err)
		}
		v.db = db
		v.ownsDB = true
	}

	// 3. Initialize MPT Manager (mmap disk or in-memory)
	if cfg.MPTMgr != nil {
		v.mptMgr = cfg.MPTMgr
		v.ownsMPT = false
	} else if cfg.MPTDir == "" || cfg.MPTDir == ":memory:" {
		v.mptMgr = tree.NewMem()
		v.ownsMPT = true
	} else {
		mptMgr, err := tree.Open(cfg.MPTDir)
		if err != nil {
			if v.ownsDB && v.db != nil {
				_ = v.db.Close()
			}
			return nil, fmt.Errorf("failed to open MPT at %q: %w", cfg.MPTDir, err)
		}
		v.mptMgr = mptMgr
		v.ownsMPT = true
	}

	// 4. Initialize KVIndexer
	v.indexer = kvstore.NewKVIndexer(v.db, v.db.ChunkSize())

	// 5. Recover persisted watermarks
	if outBytes, closer, err := v.db.Pebble().Get(KeyVerifierOutputWatermark); err == nil {
		if len(outBytes) == 8 {
			v.verifiedOutputSize = binary.BigEndian.Uint64(outBytes)
		}
		_ = closer.Close()
	}
	if inBytes, closer, err := v.db.Pebble().Get(KeyVerifierInputWatermark); err == nil {
		if len(inBytes) == 8 {
			v.verifiedInputSize = binary.BigEndian.Uint64(inBytes)
		}
		_ = closer.Close()
	}
	if rootBytes, closer, err := v.db.Pebble().Get(KeyVerifierLastRoot); err == nil {
		if len(rootBytes) == sha256.Size {
			copy(v.lastVerifiedRoot[:], rootBytes)
		}
		_ = closer.Close()
	}

	// 6. Setup OutputLogSource
	if cfg.OutputLog != nil {
		v.outputLog = cfg.OutputLog
	} else if cfg.OutputLogClient != nil {
		v.outputLog = cfg.OutputLogClient
	} else if cfg.OutputLogURL != "" {
		u, err := url.Parse(cfg.OutputLogURL)
		if err != nil {
			_ = v.Close()
			return nil, fmt.Errorf("invalid output log URL %q: %w", cfg.OutputLogURL, err)
		}
		var reader ingest.TiledReader
		if u.Scheme == "file" {
			reader = &tclient.FileFetcher{Root: u.Path}
		} else {
			httpReader, err := tclient.NewHTTPFetcher(u, nil)
			if err != nil {
				_ = v.Close()
				return nil, fmt.Errorf("failed to create output log HTTP fetcher: %w", err)
			}
			reader = httpReader
		}
		v.outputLog = &tiledOutputLogSource{reader: reader}
	} else {
		_ = v.Close()
		return nil, errors.New("verifier requires OutputLog, OutputLogClient, or OutputLogURL")
	}

	// 7. Setup InputLog TileFetcher
	var rawFetcher ingest.TileFetcher
	if cfg.InputLogFetcher != nil {
		rawFetcher = cfg.InputLogFetcher
	} else if cfg.Fetcher != nil {
		rawFetcher = cfg.Fetcher
	} else if cfg.InputLogURL != "" {
		u, err := url.Parse(cfg.InputLogURL)
		if err != nil {
			_ = v.Close()
			return nil, fmt.Errorf("invalid input log URL %q: %w", cfg.InputLogURL, err)
		}
		tf, err := ingest.NewTiledFetcher(u, v.inputLogVerifier, cfg.InputLogOrigin, nil)
		if err != nil {
			_ = v.Close()
			return nil, fmt.Errorf("failed to create input log fetcher: %w", err)
		}
		rawFetcher = tf
	} else {
		_ = v.Close()
		return nil, errors.New("verifier requires InputLogFetcher, Fetcher, or InputLogURL")
	}

	// Wrap raw fetcher to enforce Sourcing Invariant (R1)
	v.inputFetcher = WrapNoCheckpointFetcher(rawFetcher)

	// 8. Setup Ingestion Pipeline
	v.pipeline = ingest.NewPipeline(v.inputFetcher, nil, v.cfg.MapFn, 0)

	// 9. Reset baseline Prometheus metrics
	metrics.ResetVerifierRootMismatch()

	// 10. Setup Mirror Serving if requested (R3)
	if cfg.ServeMirror {
		v.publisher = tree.NewOutputPublisher(v.db, v.mptMgr, nil, nil)
		v.readServer = server.NewReadServer(v.db, v.mptMgr, v.publisher, v.db.ChunkSize())
		v.readServer.SetReadyChecker(v.HealthCheck)
		v.readServer.SetHealthChecker(func() error {
			if v.cfg.FailClosed {
				return v.HealthCheck()
			}
			return nil
		})
	}

	return v, nil
}

// ReadServer returns the mirror ReadServer if mirror mode is enabled, or nil otherwise.
func (v *Verifier) ReadServer() *server.ReadServer {
	return v.readServer
}

// InputFetcher returns the wrapped InputLog tile fetcher used by the verifier engine.
func (v *Verifier) InputFetcher() ingest.TileFetcher {
	return v.inputFetcher
}

// halt marks the verifier as permanently halted due to a critical verification error.
func (v *Verifier) halt(err error) error {
	v.stateMu.Lock()
	v.isHalted = true
	v.haltErr = err
	v.stateMu.Unlock()
	return err
}

// handleRootMismatch processes an MPT root hash mismatch: records Prometheus metrics,
// logs structured critical errors, transitions to a permanent halted state, and returns RootMismatchError.
func (v *Verifier) handleRootMismatch(leafIdx, targetInputSize uint64, localRoot, committedRoot [sha256.Size]byte) error {
	metrics.RecordVerifierRootMismatch()

	klog.Errorf(
		"CRITICAL ROOT MISMATCH DETECTED: output_leaf_index=%d target_input_size=%d local_map_root=%x committed_map_root=%x output_log_url=%q input_log_url=%q. Halting verifier sync engine immediately.",
		leafIdx, targetInputSize, localRoot, committedRoot, v.cfg.OutputLogURL, v.cfg.InputLogURL,
	)

	mismatchErr := &RootMismatchError{
		OutputIndex:      leafIdx,
		InputSize:        targetInputSize,
		LocalMapRoot:     localRoot,
		CommittedMapRoot: committedRoot,
		DetectedAt:       time.Now().UTC(),
	}

	if v.cfg.FailClosed && v.publisher != nil {
		v.publisher.SetServingState(nil)
	}

	v.stateMu.Lock()
	v.isHalted = true
	v.haltErr = mismatchErr
	v.stateMu.Unlock()

	return mismatchErr
}

// VerifyOnce executes a single verification pass over newly published OutputLog leaves.
// It strictly enforces R1 (zero calls to InputLog checkpoint endpoint) and R2 (immediate mismatch discovery and halting).
func (v *Verifier) VerifyOnce(ctx context.Context) error {
	v.stateMu.RLock()
	if v.isHalted {
		err := v.haltErr
		v.stateMu.RUnlock()
		return fmt.Errorf("verifier halted: %w", err)
	}
	v.stateMu.RUnlock()

	v.syncMu.Lock()
	defer v.syncMu.Unlock()

	// Re-verify halt state after acquiring sync lock
	v.stateMu.RLock()
	if v.isHalted {
		err := v.haltErr
		v.stateMu.RUnlock()
		return fmt.Errorf("verifier halted: %w", err)
	}
	v.stateMu.RUnlock()

	// 1. Fetch OutputLog Checkpoint (R1: derive all state strictly from OutputLog)
	rawOutCP, err := v.outputLog.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	if len(rawOutCP) == 0 {
		return nil
	}

	var outCP *log.Checkpoint
	if v.outputLogVerifier != nil {
		origin := v.cfg.OutputLogOrigin
		if origin == "" {
			origin = v.outputLogVerifier.Name()
		}
		parsed, _, _, err := log.ParseCheckpoint(rawOutCP, origin, v.outputLogVerifier)
		if err != nil {
			return v.halt(fmt.Errorf("%w: output log checkpoint signature: %v", ErrCheckpointFailed, err))
		}
		outCP = parsed
	} else {
		parsed, err := tree.ParseCheckpointHeader(rawOutCP)
		if err != nil {
			return v.halt(fmt.Errorf("%w: output log checkpoint header: %v", ErrCheckpointFailed, err))
		}
		outCP = parsed
	}

	if outCP.Size < v.verifiedOutputSize {
		return v.halt(fmt.Errorf("%w: published size %d < verified size %d", ErrOutputLogRegressed, outCP.Size, v.verifiedOutputSize))
	}
	if outCP.Size == v.verifiedOutputSize {
		if v.cfg.ServeMirror && v.publisher != nil && v.verifiedOutputSize > 0 && v.publisher.GetServingState() == nil {
			lastIdx := v.verifiedOutputSize - 1
			leafData, err := v.outputLog.GetLeaf(ctx, lastIdx)
			if err != nil {
				return fmt.Errorf("failed to fetch output log leaf %d for mirror rehydration: %w", lastIdx, err)
			}
			proofHashes, err := v.outputLog.InclusionProof(ctx, lastIdx, outCP.Size)
			if err != nil {
				return fmt.Errorf("failed to fetch inclusion proof for output leaf %d for mirror rehydration: %w", lastIdx, err)
			}
			committedMapRoot, inCPHeader, rawInCP, err := tree.ParseOutputLogLeaf(leafData)
			if err != nil {
				return v.halt(fmt.Errorf("leaf %d format corrupted during mirror rehydration: %w", lastIdx, err))
			}
			var inCP *log.Checkpoint
			if v.inputLogVerifier != nil {
				origin := v.cfg.InputLogOrigin
				if origin == "" {
					origin = v.inputLogVerifier.Name()
				}
				parsed, _, _, err := log.ParseCheckpoint(rawInCP, origin, v.inputLogVerifier)
				if err != nil {
					return v.halt(fmt.Errorf("%w: embedded input log checkpoint signature invalid in leaf %d during mirror rehydration: %v", ErrCheckpointFailed, lastIdx, err))
				}
				inCP = parsed
			} else {
				inCP = inCPHeader
			}
			v.publisher.SetServingState(&tree.ServingState{
				OutputLogIndex: lastIdx,
				OutputLogSize:  v.verifiedOutputSize,
				OutputLogCP:    outCP,
				RawCheckpoint:  rawOutCP,
				OutputLogProof: proofHashes,
				InputLogCP:     inCP,
				RawInputLogCP:  rawInCP,
				InputLogSize:   inCP.Size,
				MapRoot:        committedMapRoot,
			})
		}
		return nil
	}

	// 2. Sequentially verify each OutputLog leaf [v.verifiedOutputSize .. outCP.Size)
	for leafIdx := v.verifiedOutputSize; leafIdx < outCP.Size; leafIdx++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Fetch leaf data and inclusion proof
		leafData, err := v.outputLog.GetLeaf(ctx, leafIdx)
		if err != nil {
			return fmt.Errorf("failed to fetch output log leaf %d: %w", leafIdx, err)
		}
		proofHashes, err := v.outputLog.InclusionProof(ctx, leafIdx, outCP.Size)
		if err != nil {
			return fmt.Errorf("failed to fetch inclusion proof for output leaf %d: %w", leafIdx, err)
		}

		// Parse leaf payload
		committedMapRoot, inCPHeader, rawInCP, err := tree.ParseOutputLogLeaf(leafData)
		if err != nil {
			return v.halt(fmt.Errorf("leaf %d format corrupted: %w", leafIdx, err))
		}

		// Verify RFC 6962 leaf inclusion proof against OutputLog tree root
		canonicalLeaf := tree.FormatOutputLogLeaf(committedMapRoot, rawInCP)
		leafHash := rfc6962.DefaultHasher.HashLeaf(canonicalLeaf)
		proofBytes := make([][]byte, len(proofHashes))
		for i := range proofHashes {
			proofBytes[i] = proofHashes[i][:]
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, leafIdx, outCP.Size, leafHash, proofBytes, outCP.Hash); err != nil {
			return v.halt(fmt.Errorf("%w for leaf %d: %v", ErrInclusionFailed, leafIdx, err))
		}

		// Verify embedded InputLog Checkpoint signature with note.Verifier
		var inCP *log.Checkpoint
		if v.inputLogVerifier != nil {
			origin := v.cfg.InputLogOrigin
			if origin == "" {
				origin = v.inputLogVerifier.Name()
			}
			parsed, _, _, err := log.ParseCheckpoint(rawInCP, origin, v.inputLogVerifier)
			if err != nil {
				return v.halt(fmt.Errorf("%w: embedded input log checkpoint signature invalid in leaf %d: %v", ErrCheckpointFailed, leafIdx, err))
			}
			inCP = parsed
		} else {
			inCP = inCPHeader
		}

		targetInputSize := inCP.Size
		if targetInputSize < v.verifiedInputSize {
			return v.halt(fmt.Errorf("%w: leaf %d target size %d < verified size %d", ErrMonotonicityBroken, leafIdx, targetInputSize, v.verifiedInputSize))
		}

		// 3. Ingest input leaves strictly up to targetInputSize (R1: zero calls to InputLog checkpoint)
		allModifiedSubRoots := make(map[[sha256.Size]byte][sha256.Size]byte)
		if targetInputSize > v.verifiedInputSize {
			if sizer, ok := v.inputFetcher.(interface{ SetTreeSize(uint64) }); ok {
				sizer.SetTreeSize(targetInputSize)
			}

			batchChan, errChan := v.pipeline.StreamBatches(ctx, v.verifiedInputSize, targetInputSize)

			var pendingBatch *ingest.MappedBatch
			flush := func() error {
				if pendingBatch == nil || pendingBatch.EndLeafIdx <= pendingBatch.StartLeafIdx {
					return nil
				}
				res, err := v.indexer.IndexMappedBatch(ctx, pendingBatch, rawInCP, targetInputSize)
				if err != nil {
					return fmt.Errorf("indexing error [%d, %d): %w", pendingBatch.StartLeafIdx, pendingBatch.EndLeafIdx, err)
				}
				for k, subRoot := range res.ModifiedSubRoots {
					allModifiedSubRoots[k] = subRoot
				}
				pendingBatch = nil
				return nil
			}

			for batch := range batchChan {
				if batch.EndLeafIdx == 0 && batch.Count > 0 {
					batch.EndLeafIdx = batch.StartLeafIdx + uint64(batch.Count)
				}
				if pendingBatch == nil {
					pendingBatch = &ingest.MappedBatch{
						BundleIdx:    batch.BundleIdx,
						StartLeafIdx: batch.StartLeafIdx,
						EndLeafIdx:   batch.EndLeafIdx,
						Count:        batch.Count,
						KeyMap:       make(map[[32]byte][]uint64),
					}
					for k, indices := range batch.KeyMap {
						pendingBatch.KeyMap[k] = append([]uint64(nil), indices...)
					}
				} else {
					pendingBatch.Merge(batch)
				}
				if pendingBatch.EndLeafIdx-pendingBatch.StartLeafIdx >= v.commitBatchSize {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			if err := <-errChan; err != nil {
				return fmt.Errorf("input streaming failed for leaf %d [%d, %d): %w", leafIdx, v.verifiedInputSize, targetInputSize, err)
			}
			if err := flush(); err != nil {
				return err
			}
		}

		// 4. Predict local MPT root without mutating tree state
		var localMapRoot [sha256.Size]byte
		if targetInputSize > v.verifiedInputSize {
			predRoot, err := v.mptMgr.Predict(allModifiedSubRoots)
			if err != nil {
				return fmt.Errorf("MPT predict failed at leaf %d: %w", leafIdx, err)
			}
			localMapRoot = predRoot
		} else {
			localMapRoot = v.mptMgr.Root()
		}

		// 5. Cryptographic Root Hash Assertion (R2)
		if localMapRoot != committedMapRoot {
			return v.handleRootMismatch(leafIdx, targetInputSize, localMapRoot, committedMapRoot)
		}

		// 6. Match Path: commit MPT mutations now that root is cryptographically verified
		if targetInputSize > v.verifiedInputSize {
			if _, err := v.mptMgr.CommitWithVersion(allModifiedSubRoots, int64(targetInputSize)); err != nil {
				return fmt.Errorf("MPT commit failed at leaf %d: %w", leafIdx, err)
			}
		}

		// 6. Match Path: advance watermarks, persist state, update metrics
		v.stateMu.Lock()
		v.verifiedInputSize = targetInputSize
		v.verifiedOutputSize = leafIdx + 1
		v.lastVerifiedRoot = localMapRoot
		v.lastVerifiedAt = time.Now().UTC()
		v.stateMu.Unlock()

		// Persist watermarks to Pebble
		wb := v.db.Pebble().NewBatch()
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v.verifiedOutputSize)
		_ = wb.Set(KeyVerifierOutputWatermark, buf[:], nil)
		binary.BigEndian.PutUint64(buf[:], v.verifiedInputSize)
		_ = wb.Set(KeyVerifierInputWatermark, buf[:], nil)
		_ = wb.Set(KeyVerifierLastRoot, localMapRoot[:], nil)
		if err := wb.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit verifier watermarks to Pebble: %w", err)
		}

		// Persist MPT changes to disk
		if err := v.mptMgr.Persist(); err != nil {
			return fmt.Errorf("failed to persist MPT: %w", err)
		}

		// Metrics updates
		metrics.ResetVerifierRootMismatch()
		metrics.OutputTreeSize.Set(float64(v.verifiedOutputSize))
		metrics.ServingTreeSize.Set(float64(v.verifiedInputSize))
		metrics.KVCommittedSize.Set(float64(v.verifiedInputSize))
		metrics.IndexingLag.Set(0)

		// Mirror serving ratchet if enabled (R3)
		if v.cfg.ServeMirror && v.publisher != nil {
			v.publisher.SetServingState(&tree.ServingState{
				OutputLogIndex: leafIdx,
				OutputLogSize:  v.verifiedOutputSize,
				OutputLogCP:    outCP,
				RawCheckpoint:  rawOutCP,
				OutputLogProof: proofHashes,
				InputLogCP:     inCP,
				RawInputLogCP:  rawInCP,
				InputLogSize:   targetInputSize,
				MapRoot:        localMapRoot,
			})
		}
	}

	return nil
}

// Run executes the periodic polling loop and starts HTTP servers for metrics and mirror lookup.
func (v *Verifier) Run(ctx context.Context) error {
	var g errgroup.Group

	// 1. Background Metrics HTTP Server
	if v.cfg.MetricsAddr != "" {
		mMux := http.NewServeMux()
		mMux.Handle("/metrics", promhttp.Handler())
		mServer := &http.Server{Addr: v.cfg.MetricsAddr, Handler: mMux}
		g.Go(func() error {
			klog.Infof("Serving verifier metrics at http://%s/metrics", v.cfg.MetricsAddr)
			errCh := make(chan error, 1)
			go func() {
				if err := mServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
				close(errCh)
			}()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return mServer.Shutdown(shutdownCtx)
			case err := <-errCh:
				return err
			}
		})
	}

	// 2. Background Mirror Read Server (R3)
	if v.cfg.ServeMirror && v.readServer != nil && v.cfg.ListenAddr != "" {
		rMux := http.NewServeMux()
		v.readServer.RegisterRoutes(rMux)
		rServer := &http.Server{Addr: v.cfg.ListenAddr, Handler: rMux}
		g.Go(func() error {
			klog.Infof("Serving verifier read mirror at http://%s", v.cfg.ListenAddr)
			errCh := make(chan error, 1)
			go func() {
				if err := rServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
				close(errCh)
			}()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return rServer.Shutdown(shutdownCtx)
			case err := <-errCh:
				return err
			}
		})
	}

	// 3. Polling and verification loop
	g.Go(func() error {
		// Initial sync pass
		if err := v.VerifyOnce(ctx); err != nil {
			v.stateMu.RLock()
			halted := v.isHalted
			v.stateMu.RUnlock()
			if halted || errors.Is(err, ErrRootMismatch) {
				klog.Errorf("Initial verification halted: %v", err)
				// Block until context cancellation to keep metrics and /healthz endpoints responsive
				<-ctx.Done()
				return err
			}
			klog.Warningf("Initial verification pass warning: %v", err)
		}

		v.stateMu.RLock()
		if v.isHalted {
			v.stateMu.RUnlock()
			<-ctx.Done()
			return ctx.Err()
		}
		v.stateMu.RUnlock()

		ticker := time.NewTicker(v.cfg.PollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				v.stateMu.RLock()
				halted := v.isHalted
				v.stateMu.RUnlock()
				if halted {
					<-ctx.Done()
					return ctx.Err()
				}

				if err := v.VerifyOnce(ctx); err != nil {
					v.stateMu.RLock()
					halted := v.isHalted
					v.stateMu.RUnlock()
					if halted || errors.Is(err, ErrRootMismatch) {
						klog.Errorf("Verifier sync engine permanently halted: %v", err)
						<-ctx.Done()
						return err
					}
					klog.Warningf("Verifier transient poll error: %v", err)
				}
			}
		}
	})

	return g.Wait()
}

// HealthCheck returns nil if healthy, or the halting error if halted.
func (v *Verifier) HealthCheck() error {
	v.stateMu.RLock()
	defer v.stateMu.RUnlock()
	if v.isHalted {
		return v.haltErr
	}
	return nil
}

// Status returns a thread-safe snapshot of the verifier's operational status.
func (v *Verifier) Status() Status {
	v.stateMu.RLock()
	defer v.stateMu.RUnlock()
	return Status{
		IsHalted:           v.isHalted,
		HaltError:          v.haltErr,
		VerifiedOutputSize: v.verifiedOutputSize,
		VerifiedInputSize:  v.verifiedInputSize,
		LastVerifiedRoot:   v.lastVerifiedRoot,
		LastVerifiedAt:     v.lastVerifiedAt,
	}
}

// Close closes owned storage resources (Pebble database and MPT manager).
func (v *Verifier) Close() error {
	var errs []error
	if v.ownsDB && v.db != nil {
		if err := v.db.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if v.ownsMPT && v.mptMgr != nil {
		if err := v.mptMgr.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
