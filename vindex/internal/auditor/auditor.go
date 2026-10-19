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

// Package auditor implements the VIndex Independent Auditor engine.
// It verifies published OutputLogs against InputLogs using a provided MapFn,
// checks cryptographic root hashes after calculation, and signals mismatches immediately.
package auditor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"sync"
	"time"

	"filippo.io/torchwood"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
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
	ErrRootMismatch = errors.New("auditor root hash mismatch")

	// ErrInclusionFailed indicates that an OutputLog leaf inclusion proof could not be verified against the OutputLog checkpoint tree root.
	ErrInclusionFailed = errors.New("output log inclusion proof invalid")

	// ErrConsistencyFailed indicates that a Merkle consistency proof between consecutive OutputLog or InputLog checkpoints failed verification.
	ErrConsistencyFailed = errors.New("log consistency proof invalid")

	// ErrCheckpointFailed indicates a cryptographic signature or policy verification failure on an OutputLog checkpoint or an embedded InputLog checkpoint.
	ErrCheckpointFailed = errors.New("checkpoint signature verification failed")

	// ErrMonotonicityBroken indicates that an OutputLog leaf published a target input log size smaller than the currently verified input log size.
	ErrMonotonicityBroken = errors.New("input log size non-monotonic")

	// ErrOutputLogRegressed indicates that the discovered OutputLog tree size is smaller than the verified output log size.
	ErrOutputLogRegressed = errors.New("output log tree size regressed")

	// ErrOutputLogCorrupted indicates that an OutputLog leaf payload could not be parsed or is malformed.
	ErrOutputLogCorrupted = wire.ErrOutputLogCorrupted
)

var (
	// KeyVerifierOutputWatermark stores the number of verified OutputLog leaves.
	KeyVerifierOutputWatermark = []byte("meta:verifier:output_watermark")

	// KeyVerifierInputWatermark stores the number of verified InputLog leaves.
	KeyVerifierInputWatermark = []byte("meta:verifier:input_watermark")

	// KeyVerifierLastRoot stores the latest verified MPT root hash.
	KeyVerifierLastRoot = []byte("meta:verifier:last_root")

	// KeyVerifierLastOutCP stores the raw bytes of the last verified OutputLog checkpoint.
	KeyVerifierLastOutCP = []byte("meta:verifier:last_out_cp")

	// KeyVerifierFrom stores the verified starting InputLog index (from).
	KeyVerifierFrom = []byte("meta:verifier:from")

	// KeyVerifierMapFn stores the verified 32-byte MapFn digest.
	KeyVerifierMapFn = []byte("meta:verifier:map_fn")
)

// RootMismatchError provides structured diagnostic details when a local MPT root calculation
// diverges from the state commitment in an OutputLog leaf.
type RootMismatchError struct {
	OutputIndex      uint64
	InputSize        uint64
	LocalMPTRoot     [sha256.Size]byte
	CommittedMPTRoot [sha256.Size]byte
	DetectedAt       time.Time
}

func (e *RootMismatchError) Error() string {
	return fmt.Sprintf("%v: output leaf %d (input size %d): calculated local MPT root %x != committed MPT root %x",
		ErrRootMismatch, e.OutputIndex, e.InputSize, e.LocalMPTRoot, e.CommittedMPTRoot)
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

// JSONDiagnostics formats the root mismatch details as JSON for structured diagnostic reporting.
func (e *RootMismatchError) JSONDiagnostics() []byte {
	d := rootMismatchDiag{
		Status:        "degraded",
		Error:         "auditor root hash mismatch",
		OutputIndex:   e.OutputIndex,
		InputSize:     e.InputSize,
		LocalRoot:     fmt.Sprintf("%x", e.LocalMPTRoot),
		CommittedRoot: fmt.Sprintf("%x", e.CommittedMPTRoot),
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

// ConsistencyProver is an optional interface implemented by OutputLogSource or TileFetcher
// implementations that can build RFC 6962 Merkle consistency proofs between tree sizes.
type ConsistencyProver interface {
	ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error)
}

// WitnessPolicy configures optional witness cosignature verification on checkpoints.
type WitnessPolicy struct {
	// Threshold is the minimum number of distinct witness signatures required.
	Threshold int
	// Verifiers is the list of accepted witness note verifiers.
	Verifiers []note.Verifier
}

// Verify checks that rawCP carries at least p.Threshold valid signatures from distinct verifiers in p.Verifiers.
func (p *WitnessPolicy) Verify(rawCP []byte) error {
	if p == nil || p.Threshold <= 0 {
		return nil
	}
	if len(p.Verifiers) == 0 {
		return fmt.Errorf("witness policy requires %d witness signatures, but 0 witness verifiers are configured", p.Threshold)
	}
	n, err := note.Open(rawCP, note.VerifierList(p.Verifiers...))
	if err != nil {
		var uErr *note.UnverifiedNoteError
		if errors.As(err, &uErr) && uErr.Note != nil {
			n = uErr.Note
		} else {
			return fmt.Errorf("failed to verify witness signatures on checkpoint: %w", err)
		}
	}
	seen := make(map[uint32]struct{}, len(n.Sigs))
	for _, sig := range n.Sigs {
		seen[sig.Hash] = struct{}{}
	}
	if len(seen) < p.Threshold {
		return fmt.Errorf("insufficient witness signatures: verified %d, required %d", len(seen), p.Threshold)
	}
	return nil
}

// Config defines the runtime configuration for the VIndex Auditor.
type Config struct {
	// Log endpoints and keys
	InputLogURL     string
	InputLogPubKey  string
	InputLogOrigin  string
	OutputLogURL    string
	OutputLogPubKey string
	OutputLogOrigin string

	// C2SP tlog-policy verification policies (preferred; synthesized from verifiers/witnesses when nil)
	OutputLogPolicy torchwood.Policy
	InputLogPolicy  torchwood.Policy

	// Mapping function and starting index expectations
	MapFn         wasmhost.LeafMapper
	ExpectedMapFn *[sha256.Size]byte
	ExpectedFrom  *uint64

	// Optional witness policies for OutputLog and InputLog checkpoints
	OutputLogWitnessPolicy *WitnessPolicy
	InputLogWitnessPolicy  *WitnessPolicy

	// Storage paths (use empty string or ":memory:" for in-memory operation)
	DBPath       string
	MPTDir       string
	TileCacheDir string

	// Operational settings
	MetricsAddr     string
	PollInterval    time.Duration
	ChunkSize       uint64
	CommitBatchSize uint64

	// Optional dependency injection (for tests and custom clients)
	InputLogVerifier  note.Verifier
	OutputLogVerifier note.Verifier
	OutputLog         OutputLogSource
	OutputLogClient   OutputLogSource
	InputLogFetcher   ingest.TileFetcher
	Fetcher           ingest.TileFetcher
	TileCache         *ingest.ManagedTileCache
	DB                *kvstore.DB
	MPTMgr            *mpt.Manager
}

// AuditorConfig defines the runtime configuration for the VIndex Auditor (Verifier).
type AuditorConfig = Config

// Status represents an instantaneous snapshot of the auditor's operational state.
type Status struct {
	IsHalted           bool
	HaltError          error
	VerifiedOutputSize uint64
	VerifiedInputSize  uint64
	LastVerifiedRoot   [sha256.Size]byte
	LastVerifiedAt     time.Time
}

// Auditor audits the Output Log against the Input Log.
type Auditor = Verifier

// Verifier implements the independent audit engine for VIndex.
type Verifier struct {
	cfg Config

	// Cryptographic note verifiers & torchwood policies
	inputLogVerifier  note.Verifier
	outputLogVerifier note.Verifier
	inputLogPolicy    torchwood.Policy
	outputLogPolicy   torchwood.Policy

	// Log sources
	outputLog              OutputLogSource
	inputFetcher           ingest.TileFetcher
	inputConsistencyProver ConsistencyProver

	// Storage and Trees
	db       *kvstore.DB
	mptMgr   *mpt.Manager
	indexer  *kvstore.KVIndexer
	pipeline *ingest.IngestionPipeline
	ownsDB   bool
	ownsMPT  bool

	// Batch configuration
	commitBatchSize uint64

	// Sync execution serialization
	syncMu               sync.Mutex
	verifiedOutputSize   uint64
	verifiedOutputCPSize uint64
	verifiedOutputCPHash [sha256.Size]byte
	verifiedInputSize    uint64
	verifiedInputHash    [sha256.Size]byte
	hasFrom              bool
	verifiedFrom         uint64
	verifiedMapFn        [sha256.Size]byte

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

func (f *NoCheckpointFetcher) SetTreeState(size uint64, hash [32]byte) {
	if stater, ok := f.TileFetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok {
		stater.SetTreeState(size, hash)
	} else if sizer, ok := f.TileFetcher.(interface{ SetTreeSize(uint64) }); ok {
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
	cp, err := wire.ParseCheckpointHeader(rawCP)
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

func (s *tiledOutputLogSource) ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error) {
	pb, err := tclient.NewProofBuilder(ctx, larger, s.reader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder for consistency proof (%d -> %d): %w", smaller, larger, err)
	}
	return pb.ConsistencyProof(ctx, smaller, larger)
}

// New initializes and returns a new Auditor (Verifier) instance.
func New(cfg Config) (*Verifier, error) {
	if cfg.MapFn == nil {
		return nil, errors.New("auditor requires non-nil MapFn")
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

	// 1. Initialize note verifiers and torchwood policies
	if cfg.OutputLogVerifier != nil {
		v.outputLogVerifier = cfg.OutputLogVerifier
	} else if cfg.OutputLogPubKey != "" {
		nv, err := wire.ParseVerifier(cfg.OutputLogPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse output log pub key: %w", err)
		}
		v.outputLogVerifier = nv
	}

	if cfg.OutputLogPolicy != nil {
		v.outputLogPolicy = cfg.OutputLogPolicy
	} else if v.outputLogVerifier != nil {
		var outWitnesses []note.Verifier
		var outThreshold int
		if cfg.OutputLogWitnessPolicy != nil && cfg.OutputLogWitnessPolicy.Threshold > 0 {
			outWitnesses = cfg.OutputLogWitnessPolicy.Verifiers
			outThreshold = cfg.OutputLogWitnessPolicy.Threshold
		}
		pol, err := wire.BuildPolicy(cfg.OutputLogOrigin, v.outputLogVerifier, outWitnesses, outThreshold)
		if err != nil {
			return nil, fmt.Errorf("failed to build output log policy: %w", err)
		}
		v.outputLogPolicy = pol
	}

	if cfg.InputLogVerifier != nil {
		v.inputLogVerifier = cfg.InputLogVerifier
	} else if cfg.InputLogPubKey != "" {
		nv, err := wire.ParseVerifier(cfg.InputLogPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input log pub key: %w", err)
		}
		v.inputLogVerifier = nv
	}

	if cfg.InputLogPolicy != nil {
		v.inputLogPolicy = cfg.InputLogPolicy
	} else if v.inputLogVerifier != nil {
		var inWitnesses []note.Verifier
		var inThreshold int
		if cfg.InputLogWitnessPolicy != nil && cfg.InputLogWitnessPolicy.Threshold > 0 {
			inWitnesses = cfg.InputLogWitnessPolicy.Verifiers
			inThreshold = cfg.InputLogWitnessPolicy.Threshold
		}
		pol, err := wire.BuildPolicy(cfg.InputLogOrigin, v.inputLogVerifier, inWitnesses, inThreshold)
		if err != nil {
			return nil, fmt.Errorf("failed to build input log policy: %w", err)
		}
		v.inputLogPolicy = pol
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

	if cfg.ChunkSize > 0 {
		v.db.SetChunkSize(cfg.ChunkSize)
	}

	// 3. Initialize MPT Manager (mmap disk or in-memory)
	if cfg.MPTMgr != nil {
		v.mptMgr = cfg.MPTMgr
		v.ownsMPT = false
	} else if cfg.MPTDir == "" || cfg.MPTDir == ":memory:" {
		v.mptMgr = mpt.NewMem()
		v.ownsMPT = true
	} else {
		mptMgr, err := mpt.Open(cfg.MPTDir)
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
	if outCPBytes, closer, err := v.db.Pebble().Get(KeyVerifierLastOutCP); err == nil {
		rawCP := append([]byte(nil), outCPBytes...)
		_ = closer.Close()
		if cp, err := wire.ParseCheckpointHeader(rawCP); err == nil && len(cp.Hash) == sha256.Size {
			v.verifiedOutputCPSize = cp.Size
			copy(v.verifiedOutputCPHash[:], cp.Hash)
		}
	}
	if inCPBytes, closer, err := v.db.Pebble().Get(kvstore.KeyMetaKVCheckpoint); err == nil {
		rawInCP := append([]byte(nil), inCPBytes...)
		_ = closer.Close()
		if cp, err := wire.ParseCheckpointHeader(rawInCP); err == nil && len(cp.Hash) == sha256.Size {
			copy(v.verifiedInputHash[:], cp.Hash)
		}
	}
	if fromBytes, closer, err := v.db.Pebble().Get(KeyVerifierFrom); err == nil {
		if len(fromBytes) == 8 {
			v.verifiedFrom = binary.BigEndian.Uint64(fromBytes)
			v.hasFrom = true
		}
		_ = closer.Close()
	}
	if mapFnBytes, closer, err := v.db.Pebble().Get(KeyVerifierMapFn); err == nil {
		if len(mapFnBytes) == sha256.Size {
			copy(v.verifiedMapFn[:], mapFnBytes)
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
		return nil, errors.New("auditor requires OutputLog, OutputLogClient, or OutputLogURL")
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
		if v.inputLogPolicy != nil {
			tf.SetPolicy(v.inputLogPolicy)
		}
		rawFetcher = tf
	} else {
		_ = v.Close()
		return nil, errors.New("auditor requires InputLogFetcher, Fetcher, or InputLogURL")
	}

	if cpProver, ok := rawFetcher.(ConsistencyProver); ok {
		v.inputConsistencyProver = cpProver
	}

	// Wrap raw fetcher to enforce Sourcing Invariant (R1)
	v.inputFetcher = WrapNoCheckpointFetcher(rawFetcher)

	// 8. Setup TileCache & Ingestion Pipeline
	var tileCache ingest.TileCache
	if cfg.TileCache != nil {
		tileCache = cfg.TileCache
	} else if cfg.TileCacheDir != "" {
		tc, err := ingest.NewManagedTileCache(cfg.TileCacheDir, 0)
		if err != nil {
			_ = v.Close()
			return nil, fmt.Errorf("failed to initialize tile cache at %q: %w", cfg.TileCacheDir, err)
		}
		tileCache = tc
	}
	v.pipeline = ingest.NewPipeline(v.inputFetcher, tileCache, v.cfg.MapFn, 0)

	// 9. Reset baseline Prometheus metrics
	metrics.ResetAuditorRootMismatch()

	return v, nil
}

// InputFetcher returns the wrapped InputLog tile fetcher used by the auditor engine.
func (v *Verifier) InputFetcher() ingest.TileFetcher {
	return v.inputFetcher
}

// halt marks the auditor as permanently halted due to a critical verification error.
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
	metrics.RecordAuditorRootMismatch()

	klog.Errorf(
		"CRITICAL ROOT MISMATCH DETECTED: output_leaf_index=%d target_input_size=%d local_mpt_root=%x committed_mpt_root=%x output_log_url=%q input_log_url=%q. Halting auditor sync engine immediately.",
		leafIdx, targetInputSize, localRoot, committedRoot, v.cfg.OutputLogURL, v.cfg.InputLogURL,
	)

	mismatchErr := &RootMismatchError{
		OutputIndex:      leafIdx,
		InputSize:        targetInputSize,
		LocalMPTRoot:     localRoot,
		CommittedMPTRoot: committedRoot,
		DetectedAt:       time.Now().UTC(),
	}

	v.stateMu.Lock()
	v.isHalted = true
	v.haltErr = mismatchErr
	v.stateMu.Unlock()

	return mismatchErr
}

func (v *Verifier) verifyOutputCheckpoint(rawOutCP []byte) (*log.Checkpoint, error) {
	if v.outputLogPolicy != nil {
		twCP, _, err := torchwood.VerifyCheckpoint(rawOutCP, v.outputLogPolicy)
		if err != nil {
			return nil, v.halt(fmt.Errorf("%w: output log checkpoint policy verification failed: %v", ErrCheckpointFailed, err))
		}
		hashBytes := make([]byte, sha256.Size)
		copy(hashBytes, twCP.Hash[:])
		return &log.Checkpoint{
			Origin: twCP.Origin,
			Size:   uint64(twCP.N),
			Hash:   hashBytes,
		}, nil
	}
	outCP, err := wire.ParseCheckpointHeader(rawOutCP)
	if err != nil {
		return nil, v.halt(fmt.Errorf("%w: output log checkpoint header: %v", ErrCheckpointFailed, err))
	}
	if v.cfg.OutputLogWitnessPolicy != nil {
		if err := v.cfg.OutputLogWitnessPolicy.Verify(rawOutCP); err != nil {
			return nil, v.halt(fmt.Errorf("%w: output log witness policy: %v", ErrCheckpointFailed, err))
		}
	}
	return outCP, nil
}

func (v *Verifier) verifyInputCheckpoint(leafIdx uint64, rawInCP []byte, inCPHeader *log.Checkpoint) (*log.Checkpoint, error) {
	if v.inputLogPolicy != nil {
		twCP, _, err := torchwood.VerifyCheckpoint(rawInCP, v.inputLogPolicy)
		if err != nil {
			return nil, v.halt(fmt.Errorf("%w: embedded input log checkpoint policy verification failed in leaf %d: %v", ErrCheckpointFailed, leafIdx, err))
		}
		hashBytes := make([]byte, sha256.Size)
		copy(hashBytes, twCP.Hash[:])
		return &log.Checkpoint{
			Origin: twCP.Origin,
			Size:   uint64(twCP.N),
			Hash:   hashBytes,
		}, nil
	}
	if v.cfg.InputLogWitnessPolicy != nil {
		if err := v.cfg.InputLogWitnessPolicy.Verify(rawInCP); err != nil {
			return nil, v.halt(fmt.Errorf("%w: embedded input log checkpoint witness policy invalid in leaf %d: %v", ErrCheckpointFailed, leafIdx, err))
		}
	}
	return inCPHeader, nil
}

func (v *Verifier) verifyLeafMetadata(leafIdx uint64, outLeaf *wire.OutputLogLeaf, targetInputSize uint64) error {
	if v.cfg.ExpectedMapFn != nil {
		if outLeaf.MapFn != *v.cfg.ExpectedMapFn {
			return v.halt(fmt.Errorf("leaf %d map-fn mismatch: got %x, expected %x", leafIdx, outLeaf.MapFn, *v.cfg.ExpectedMapFn))
		}
	} else if hp, ok := v.cfg.MapFn.(wasmhost.MapFnHashProvider); ok && outLeaf.MapFn != ([sha256.Size]byte{}) {
		if expected := hp.MapFnHash(); expected != ([sha256.Size]byte{}) && outLeaf.MapFn != expected {
			return v.halt(fmt.Errorf("leaf %d map-fn mismatch against configured WASM binary: got %x, expected %x", leafIdx, outLeaf.MapFn, expected))
		}
	}
	if outLeaf.From > targetInputSize {
		return v.halt(fmt.Errorf("leaf %d invalid from %d > input log size %d", leafIdx, outLeaf.From, targetInputSize))
	}
	if v.cfg.ExpectedFrom != nil && outLeaf.From != *v.cfg.ExpectedFrom {
		return v.halt(fmt.Errorf("leaf %d from mismatch: got %d, expected %d", leafIdx, outLeaf.From, *v.cfg.ExpectedFrom))
	}
	if v.hasFrom {
		if v.verifiedFrom != outLeaf.From {
			return v.halt(fmt.Errorf("leaf %d from mismatch: got %d, expected %d", leafIdx, outLeaf.From, v.verifiedFrom))
		}
		if v.verifiedMapFn != outLeaf.MapFn {
			return v.halt(fmt.Errorf("leaf %d map-fn mismatch: got %x, expected %x", leafIdx, outLeaf.MapFn, v.verifiedMapFn))
		}
	}
	v.hasFrom = true
	v.verifiedFrom = outLeaf.From
	v.verifiedMapFn = outLeaf.MapFn
	return nil
}

// catchUpMPT replays [max(MPT_Durable_Size, from), verifiedInputSize) against already-persisted
// Pebble chunks if the process crashed between the atomic Pebble batch commit and MPT Persist.
func (v *Verifier) catchUpMPT(ctx context.Context) error {
	replayStart := v.mptMgr.PersistedSize()
	if !v.mptMgr.IsExact() && replayStart == v.verifiedInputSize {
		replayStart = 0
	}
	if v.hasFrom && replayStart < v.verifiedFrom {
		replayStart = v.verifiedFrom
	}
	if v.cfg.ExpectedFrom != nil && replayStart < *v.cfg.ExpectedFrom {
		replayStart = *v.cfg.ExpectedFrom
	}

	var mutations map[string][sha256.Size]byte
	if replayStart < v.verifiedInputSize {
		if stater, ok := v.inputFetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok && v.verifiedInputHash != ([sha256.Size]byte{}) {
			stater.SetTreeState(v.verifiedInputSize, v.verifiedInputHash)
		} else if sizer, ok := v.inputFetcher.(interface{ SetTreeSize(uint64) }); ok {
			sizer.SetTreeSize(v.verifiedInputSize)
		}

		batchChan, errChan := v.pipeline.StreamBatches(ctx, replayStart, v.verifiedInputSize)
		modifiedKeys := make(map[[sha256.Size]byte]string)
		for batch := range batchChan {
			for kh := range batch.KeyMap {
				if ck, ok := batch.CanonicalKeys[kh]; ok && ck != "" {
					modifiedKeys[kh] = ck
				} else if _, exists := modifiedKeys[kh]; !exists {
					modifiedKeys[kh] = hex.EncodeToString(kh[:])
				}
			}
		}
		if err := <-errChan; err != nil {
			return fmt.Errorf("startup MPT catch-up streaming failed [%d, %d): %w", replayStart, v.verifiedInputSize, err)
		}

		var err error
		mutations, err = v.indexer.GetKeyValueRoots(ctx, modifiedKeys, v.verifiedInputSize)
		if err != nil {
			return fmt.Errorf("startup MPT catch-up GetKeyValueRoots failed: %w", err)
		}
	}

	if _, err := v.mptMgr.CommitKeysWithVersion(mutations, int64(v.verifiedInputSize)); err != nil {
		return fmt.Errorf("startup MPT catch-up commit failed: %w", err)
	}
	if err := v.mptMgr.Persist(); err != nil {
		return fmt.Errorf("startup MPT catch-up persist failed: %w", err)
	}
	return nil
}

// VerifyOnce executes a single audit pass over newly published OutputLog leaves.
// It strictly enforces R1 (zero calls to InputLog checkpoint endpoint) and R2 (immediate mismatch discovery and halting).
func (v *Verifier) VerifyOnce(ctx context.Context) error {
	v.stateMu.RLock()
	if v.isHalted {
		err := v.haltErr
		v.stateMu.RUnlock()
		return fmt.Errorf("auditor halted: %w", err)
	}
	v.stateMu.RUnlock()

	v.syncMu.Lock()
	defer v.syncMu.Unlock()

	// Re-verify halt state after acquiring sync lock
	v.stateMu.RLock()
	if v.isHalted {
		err := v.haltErr
		v.stateMu.RUnlock()
		return fmt.Errorf("auditor halted: %w", err)
	}
	v.stateMu.RUnlock()

	// Startup Phase 2 MPT catch-up if Pebble committed ahead of MPT fsync on a prior crash
	if v.verifiedInputSize > 0 && (v.mptMgr.PersistedSize() < v.verifiedInputSize || !v.mptMgr.IsExact()) {
		if err := v.catchUpMPT(ctx); err != nil {
			return err
		}
	}

	// 1. Fetch OutputLog Checkpoint (R1: derive all state strictly from OutputLog)
	rawOutCP, err := v.outputLog.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	if len(rawOutCP) == 0 {
		return nil
	}

	outCP, err := v.verifyOutputCheckpoint(rawOutCP)
	if err != nil {
		return err
	}

	if outCP.Size < v.verifiedOutputSize || outCP.Size < v.verifiedOutputCPSize {
		return v.halt(fmt.Errorf("%w: published size %d < verified size %d", ErrOutputLogRegressed, outCP.Size, max(v.verifiedOutputSize, v.verifiedOutputCPSize)))
	}

	// Verify OutputLog consistency against last verified OutputLog checkpoint
	if v.verifiedOutputCPSize > 0 && v.verifiedOutputCPHash != ([sha256.Size]byte{}) {
		if outCP.Size == v.verifiedOutputCPSize {
			if !bytes.Equal(outCP.Hash, v.verifiedOutputCPHash[:]) {
				return v.halt(fmt.Errorf("%w: output log checkpoint hash mismatch at size %d: got %x, expected %x", ErrConsistencyFailed, outCP.Size, outCP.Hash, v.verifiedOutputCPHash))
			}
		} else if cpProver, ok := v.outputLog.(ConsistencyProver); ok {
			consProof, err := cpProver.ConsistencyProof(ctx, v.verifiedOutputCPSize, outCP.Size)
			if err != nil {
				return fmt.Errorf("failed to fetch output log consistency proof (%d -> %d): %w", v.verifiedOutputCPSize, outCP.Size, err)
			}
			if err := proof.VerifyConsistency(rfc6962.DefaultHasher, v.verifiedOutputCPSize, outCP.Size, consProof, v.verifiedOutputCPHash[:], outCP.Hash); err != nil {
				return v.halt(fmt.Errorf("%w: output log consistency proof (%d -> %d) invalid: %v", ErrConsistencyFailed, v.verifiedOutputCPSize, outCP.Size, err))
			}
		}
	}

	if outCP.Size == v.verifiedOutputSize {
		return nil
	}

	// 2. Sequentially verify each OutputLog leaf [v.verifiedOutputSize .. outCP.Size)
	for leafIdx := v.verifiedOutputSize; leafIdx < outCP.Size; leafIdx++ {
		if err := v.verifyLeaf(ctx, leafIdx, outCP, rawOutCP); err != nil {
			return err
		}
	}

	return nil
}

func (v *Verifier) verifyLeaf(ctx context.Context, leafIdx uint64, outCP *log.Checkpoint, rawOutCP []byte) error {
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
	outLeaf, err := wire.ParseOutputLogLeafFull(leafData)
	if err != nil {
		return v.halt(fmt.Errorf("leaf %d format corrupted: %w", leafIdx, err))
	}
	inCPHeader := outLeaf.InCP
	committedMPTRoot := outLeaf.MPTRoot
	rawInCP := outLeaf.RawInCP

	// Verify RFC 6962 leaf inclusion proof against OutputLog tree root
	canonicalLeaf := wire.FormatOutputLogLeafFull(committedMPTRoot, outLeaf.MapFn, outLeaf.From, rawInCP)
	leafHash := rfc6962.DefaultHasher.HashLeaf(canonicalLeaf)
	proofBytes := make([][]byte, len(proofHashes))
	for i := range proofHashes {
		proofBytes[i] = proofHashes[i][:]
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, leafIdx, outCP.Size, leafHash, proofBytes, outCP.Hash); err != nil {
		return v.halt(fmt.Errorf("%w for leaf %d: %v", ErrInclusionFailed, leafIdx, err))
	}

	// Verify embedded InputLog Checkpoint against InputLog policy
	inCP, err := v.verifyInputCheckpoint(leafIdx, rawInCP, inCPHeader)
	if err != nil {
		return err
	}

	targetInputSize := inCP.Size
	if err := v.verifyLeafMetadata(leafIdx, outLeaf, targetInputSize); err != nil {
		return err
	}
	if targetInputSize < v.verifiedInputSize {
		return v.halt(fmt.Errorf("%w: leaf %d target size %d < verified size %d", ErrMonotonicityBroken, leafIdx, targetInputSize, v.verifiedInputSize))
	}

	// Verify InputLog consistency against previous verified InputLog checkpoint
	if v.verifiedInputSize > 0 && v.verifiedInputHash != ([sha256.Size]byte{}) {
		if targetInputSize == v.verifiedInputSize {
			if !bytes.Equal(inCP.Hash, v.verifiedInputHash[:]) {
				return v.halt(fmt.Errorf("%w: leaf %d embedded input log checkpoint hash mismatch at size %d: got %x, expected %x", ErrConsistencyFailed, leafIdx, targetInputSize, inCP.Hash, v.verifiedInputHash))
			}
		} else {
			if stater, ok := v.inputFetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok && len(inCP.Hash) == sha256.Size {
				stater.SetTreeState(targetInputSize, [32]byte(inCP.Hash))
			}
			if v.inputConsistencyProver != nil {
				consProof, err := v.inputConsistencyProver.ConsistencyProof(ctx, v.verifiedInputSize, targetInputSize)
				if err != nil {
					return fmt.Errorf("failed to fetch input log consistency proof (%d -> %d) for leaf %d: %w", v.verifiedInputSize, targetInputSize, leafIdx, err)
				}
				if err := proof.VerifyConsistency(rfc6962.DefaultHasher, v.verifiedInputSize, targetInputSize, consProof, v.verifiedInputHash[:], inCP.Hash); err != nil {
					return v.halt(fmt.Errorf("%w: input log consistency proof (%d -> %d) invalid in leaf %d: %v", ErrConsistencyFailed, v.verifiedInputSize, targetInputSize, leafIdx, err))
				}
			}
		}
	}

	// 3. Stage input leaves strictly up to targetInputSize into an uncommitted indexed Pebble batch.
	// Forensic State Freeze Invariant: zero unverified chunk or watermark writes touch v.db
	// until localMPTRoot == committedMPTRoot is cryptographically confirmed.
	stagedBatch := v.db.Pebble().NewIndexedBatch()
	leafCommitted := false
	defer func() {
		_ = stagedBatch.Close()
		if !leafCommitted {
			v.indexer.ClearCache()
		}
	}()

	startInputSize := v.verifiedInputSize
	if startInputSize < outLeaf.From {
		startInputSize = outLeaf.From
	}

	allModifiedValueRoots := make(map[string][sha256.Size]byte)
	if targetInputSize > startInputSize {
		if stater, ok := v.inputFetcher.(interface{ SetTreeState(uint64, [32]byte) }); ok && len(inCP.Hash) == sha256.Size {
			stater.SetTreeState(targetInputSize, [32]byte(inCP.Hash))
		} else if sizer, ok := v.inputFetcher.(interface{ SetTreeSize(uint64) }); ok {
			sizer.SetTreeSize(targetInputSize)
		}

		batchChan, errChan := v.pipeline.StreamBatches(ctx, startInputSize, targetInputSize)

		stagedKVSize := startInputSize
		var pendingBatch *ingest.MappedBatch
		flush := func() error {
			if pendingBatch == nil || pendingBatch.EndLeafIdx <= pendingBatch.StartLeafIdx {
				return nil
			}
			res, err := v.indexer.StageMappedBatch(ctx, stagedBatch, stagedKVSize, pendingBatch, targetInputSize)
			if err != nil {
				return fmt.Errorf("indexing error [%d, %d): %w", pendingBatch.StartLeafIdx, pendingBatch.EndLeafIdx, err)
			}
			stagedKVSize = res.NewKVSize
			for k, valueRoot := range res.ModifiedKeyValueRoots {
				allModifiedValueRoots[k] = valueRoot
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
				if len(batch.CanonicalKeys) > 0 {
					pendingBatch.CanonicalKeys = make(map[[32]byte]string, len(batch.CanonicalKeys))
					for kh, ck := range batch.CanonicalKeys {
						pendingBatch.CanonicalKeys[kh] = ck
					}
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
			return fmt.Errorf("input streaming failed for leaf %d [%d, %d): %w", leafIdx, startInputSize, targetInputSize, err)
		}
		if err := flush(); err != nil {
			return err
		}
	}

	// 4. Predict local MPT root without mutating tree state
	var localMPTRoot [sha256.Size]byte
	if targetInputSize > startInputSize {
		predRoot, err := v.mptMgr.PredictKeys(allModifiedValueRoots)
		if err != nil {
			return fmt.Errorf("MPT predict failed at leaf %d: %w", leafIdx, err)
		}
		localMPTRoot = predRoot
	} else {
		localMPTRoot = v.mptMgr.Root()
	}

	// 5. Cryptographic Root Hash Assertion (R2)
	if localMPTRoot != committedMPTRoot {
		return v.handleRootMismatch(leafIdx, targetInputSize, localMPTRoot, committedMPTRoot)
	}

	// 6. Match Path: atomically commit staged Pebble chunks together with audited watermarks
	// before committing and syncing MPT mutations (KV_CP >= MPT_Durable_Size).
	nextOutputSize := leafIdx + 1
	var buf [8]byte
	if targetInputSize > v.verifiedInputSize {
		binary.BigEndian.PutUint64(buf[:], targetInputSize)
		_ = stagedBatch.Set(kvstore.KeyMetaKVSize, append([]byte(nil), buf[:]...), nil)
	}
	if len(rawInCP) > 0 {
		_ = stagedBatch.Set(kvstore.KeyMetaKVCheckpoint, rawInCP, nil)
	}
	binary.BigEndian.PutUint64(buf[:], nextOutputSize)
	_ = stagedBatch.Set(KeyVerifierOutputWatermark, append([]byte(nil), buf[:]...), nil)
	binary.BigEndian.PutUint64(buf[:], targetInputSize)
	_ = stagedBatch.Set(KeyVerifierInputWatermark, append([]byte(nil), buf[:]...), nil)
	_ = stagedBatch.Set(KeyVerifierLastRoot, localMPTRoot[:], nil)
	if len(rawOutCP) > 0 {
		_ = stagedBatch.Set(KeyVerifierLastOutCP, rawOutCP, nil)
	}
	binary.BigEndian.PutUint64(buf[:], outLeaf.From)
	_ = stagedBatch.Set(KeyVerifierFrom, append([]byte(nil), buf[:]...), nil)
	_ = stagedBatch.Set(KeyVerifierMapFn, outLeaf.MapFn[:], nil)

	if err := v.db.Pebble().Apply(stagedBatch, pebble.Sync); err != nil {
		return fmt.Errorf("failed to commit verified chunks and watermarks to Pebble: %w", err)
	}
	leafCommitted = true

	// 7. Commit and persist MPT mutations.
	if targetInputSize > startInputSize || (targetInputSize > 0 && (v.mptMgr.PersistedSize() < targetInputSize || !v.mptMgr.IsExact())) {
		if _, err := v.mptMgr.CommitKeysWithVersion(allModifiedValueRoots, int64(targetInputSize)); err != nil {
			return fmt.Errorf("MPT commit failed at leaf %d: %w", leafIdx, err)
		}
		if err := v.mptMgr.Persist(); err != nil {
			return fmt.Errorf("failed to persist MPT: %w", err)
		}
	}

	if len(inCP.Hash) == sha256.Size {
		copy(v.verifiedInputHash[:], inCP.Hash)
	}
	if len(outCP.Hash) == sha256.Size {
		v.verifiedOutputCPSize = outCP.Size
		copy(v.verifiedOutputCPHash[:], outCP.Hash)
	}

	v.stateMu.Lock()
	v.verifiedInputSize = targetInputSize
	v.verifiedOutputSize = nextOutputSize
	v.lastVerifiedRoot = localMPTRoot
	v.lastVerifiedAt = time.Now().UTC()
	v.stateMu.Unlock()

	// Metrics updates
	metrics.ResetAuditorRootMismatch()
	metrics.OutputTreeSize.Set(float64(nextOutputSize))
	metrics.ServingTreeSize.Set(float64(targetInputSize))
	metrics.KVCommittedSize.Set(float64(targetInputSize))
	metrics.IndexingLag.Set(0)

	return nil
}

// Run executes the periodic polling loop and optionally starts an HTTP server for Prometheus metrics.
func (v *Verifier) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	// 1. Background Admin/Metrics HTTP Server
	if v.cfg.MetricsAddr != "" {
		ln, err := net.Listen("tcp", v.cfg.MetricsAddr)
		if err != nil {
			return fmt.Errorf("auditor admin listener failed on %s: %w", v.cfg.MetricsAddr, err)
		}
		actualAddr := ln.Addr().String()
		mMux := http.NewServeMux()
		v.RegisterAdminRoutes(mMux)
		mServer := &http.Server{Addr: actualAddr, Handler: mMux}
		g.Go(func() error {
			klog.Infof("Serving auditor metrics at http://%s/metrics", actualAddr)
			errCh := make(chan error, 1)
			go func() {
				if err := mServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					klog.Errorf("Auditor admin server failed on %s: %v", actualAddr, err)
					errCh <- err
				}
				close(errCh)
			}()
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return mServer.Shutdown(shutdownCtx)
			case err, ok := <-errCh:
				if !ok {
					return nil
				}
				return err
			}
		})
	}

	// 2. Polling and audit loop
	g.Go(func() error {
		// Initial sync pass
		if err := v.VerifyOnce(ctx); err != nil {
			v.stateMu.RLock()
			halted := v.isHalted
			v.stateMu.RUnlock()
			if halted || errors.Is(err, ErrRootMismatch) {
				klog.Errorf("Initial audit halted: %v", err)
				// Block until context cancellation to keep metrics endpoint responsive
				<-ctx.Done()
				return err
			}
			klog.Warningf("Initial audit pass warning: %v", err)
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
						klog.Errorf("Auditor sync engine permanently halted: %v", err)
						<-ctx.Done()
						return err
					}
					klog.Warningf("Auditor transient poll error: %v", err)
				}
			}
		}
	})

	return g.Wait()
}

// HandleHealthz handles GET/HEAD /healthz (liveness probe).
// It returns 200 OK even when the auditor is forensically halted so container
// orchestrators do not restart-loop a halted auditor.
func (v *Verifier) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// HandleReadyz handles GET/HEAD /readyz (readiness probe).
func (v *Verifier) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := v.Status()
	if st.IsHalted {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method == http.MethodGet {
			var rmErr *RootMismatchError
			if errors.As(st.HaltError, &rmErr) {
				_, _ = w.Write(append(rmErr.JSONDiagnostics(), '\n'))
			} else {
				errMsg := "auditor halted"
				if st.HaltError != nil {
					errMsg = st.HaltError.Error()
				}
				b, _ := json.Marshal(map[string]any{"status": "halted", "error": errMsg})
				_, _ = w.Write(append(b, '\n'))
			}
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// RegisterAdminRoutes registers internal operational endpoints (/metrics, /healthz, /readyz, /debug/pprof/*)
// onto an internal administrative/metrics ServeMux (--metrics_addr).
func (v *Verifier) RegisterAdminRoutes(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", v.HandleHealthz)
	mux.HandleFunc("/readyz", v.HandleReadyz)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
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

// Status returns a thread-safe snapshot of the auditor's operational status.
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
