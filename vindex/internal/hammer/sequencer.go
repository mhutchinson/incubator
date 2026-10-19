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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// SequencerConfig configures the Tessera input log sequencer.
type SequencerConfig struct {
	StorageDir         string
	Origin             string
	SignerKey          string
	WriteRate          float64 // Leaves per second (0 = unconstrained)
	WriteGoal          uint64  // Total leaves to write before stopping (0 = continuous)
	BatchSize          uint
	BatchTimeout       time.Duration
	CheckpointInterval time.Duration
	AwaitPollPeriod    time.Duration
}

// DefaultSequencerConfig returns sensible defaults for the sequencer.
func DefaultSequencerConfig(storageDir string) SequencerConfig {
	return SequencerConfig{
		StorageDir:         storageDir,
		Origin:             "example.com/hammer/inputlog",
		WriteRate:          500,
		BatchSize:          4096,
		BatchTimeout:       10 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond,
		AwaitPollPeriod:    10 * time.Millisecond,
	}
}

// SequencerStats holds atomic telemetry counters.
type SequencerStats struct {
	LeavesWritten      uint64
	CheckpointsCreated uint64
	LatestTreeSize     uint64
}

// Sequencer writes generated leaves to a local Tessera POSIX log.
type Sequencer struct {
	cfg          SequencerConfig
	generator    *Generator
	appender     *tessera.Appender
	shutdownFn   func(context.Context) error
	reader       tessera.LogReader
	awaiter      *tessera.PublicationAwaiter
	signer       note.Signer
	verifier     note.Verifier
	verifierKey  string
	stats        SequencerStats
	lastSeenSize uint64
	mu           sync.Mutex
}

// NewSequencer initializes a new Tessera POSIX sequencer.
func NewSequencer(ctx context.Context, cfg SequencerConfig, gen *Generator) (*Sequencer, error) {
	if cfg.Origin == "" {
		cfg.Origin = "example.com/hammer/inputlog"
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 4096
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 10 * time.Millisecond
	}
	if cfg.CheckpointInterval < 100*time.Millisecond {
		cfg.CheckpointInterval = 100 * time.Millisecond
	}
	if cfg.AwaitPollPeriod == 0 {
		cfg.AwaitPollPeriod = 10 * time.Millisecond
	}

	signer, verifier, vkey, err := parseOrGenerateKey(cfg.SignerKey, cfg.Origin)
	if err != nil {
		return nil, err
	}

	driver, err := posix.New(ctx, posix.Config{Path: cfg.StorageDir})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize POSIX log at %q: %w", cfg.StorageDir, err)
	}

	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(cfg.CheckpointInterval).
		WithBatching(cfg.BatchSize, cfg.BatchTimeout)

	appender, shutdownFn, reader, err := tessera.NewAppender(ctx, driver, appendOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tessera appender: %w", err)
	}

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, cfg.AwaitPollPeriod)

	return &Sequencer{
		cfg:         cfg,
		generator:   gen,
		appender:    appender,
		shutdownFn:  shutdownFn,
		reader:      reader,
		awaiter:     awaiter,
		signer:      signer,
		verifier:    verifier,
		verifierKey: vkey,
	}, nil
}

func parseOrGenerateKey(rawOrPath, origin string) (note.Signer, note.Verifier, string, error) {
	skey := strings.TrimSpace(rawOrPath)
	if skey == "" {
		var vkey string
		var err error
		skey, vkey, err = note.GenerateKey(rand.Reader, origin)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to generate note key: %w", err)
		}
		signer, verifier, err := fnote.NewEd25519SignerVerifier(skey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create signer/verifier: %w", err)
		}
		return signer, verifier, vkey, nil
	}

	if data, err := os.ReadFile(skey); err == nil {
		skey = string(bytes.TrimSpace(data))
	}
	signer, verifier, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse signer key: %w", err)
	}

	var vkey string
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) == 5 && parts[0] == "PRIVATE" && parts[1] == "KEY" {
		if raw, decErr := base64.StdEncoding.DecodeString(parts[4]); decErr == nil && len(raw) == 1+ed25519.SeedSize && raw[0] == 0x01 {
			pub := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
			vkey, _ = note.NewEd25519VerifierKey(signer.Name(), pub)
		}
	}
	return signer, verifier, vkey, nil
}

// Verifier returns the note verifier for Input Log checkpoints.
func (s *Sequencer) Verifier() note.Verifier { return s.verifier }

// VerifierKey returns the public note verifier key string.
func (s *Sequencer) VerifierKey() string { return s.verifierKey }

// Origin returns the origin string for the Input Log.
func (s *Sequencer) Origin() string { return s.cfg.Origin }

// Stats returns a snapshot of current sequencer stats.
func (s *Sequencer) Stats() SequencerStats {
	return SequencerStats{
		LeavesWritten:      atomic.LoadUint64(&s.stats.LeavesWritten),
		CheckpointsCreated: atomic.LoadUint64(&s.stats.CheckpointsCreated),
		LatestTreeSize:     atomic.LoadUint64(&s.stats.LatestTreeSize),
	}
}

// ReadCheckpoint reads the latest signed checkpoint from the underlying Tessera POSIX log.
func (s *Sequencer) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	rawCP, err := s.reader.ReadCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if len(rawCP) > 0 {
		s.observeCheckpoint(rawCP)
	}
	return rawCP, nil
}

// WriteLeaf appends a single leaf to the log and waits for it to be integrated and published.
func (s *Sequencer) WriteLeaf(ctx context.Context, leafData []byte) (uint64, []byte, error) {
	fut := s.appender.Add(ctx, tessera.NewEntry(leafData))
	idx, cpBytes, err := s.awaiter.Await(ctx, fut)
	if err != nil {
		return 0, nil, err
	}
	atomic.AddUint64(&s.stats.LeavesWritten, 1)
	s.observeCheckpoint(cpBytes)
	return idx.Index, cpBytes, nil
}

// RunLoop continuously writes generated leaves at cfg.WriteRate until ctx is cancelled or WriteGoal is reached.
func (s *Sequencer) RunLoop(ctx context.Context) error {
	var writeTicker *time.Ticker
	if s.cfg.WriteRate > 0 {
		interval := max(time.Duration(float64(time.Second)/s.cfg.WriteRate), time.Microsecond)
		writeTicker = time.NewTicker(interval)
		defer writeTicker.Stop()
	}

	cpTicker := time.NewTicker(s.cfg.CheckpointInterval)
	defer cpTicker.Stop()

	var lastFut tessera.IndexFuture
	for {
		if s.cfg.WriteGoal > 0 && atomic.LoadUint64(&s.stats.LeavesWritten) >= s.cfg.WriteGoal {
			if lastFut != nil {
				if _, cpBytes, err := s.awaiter.Await(ctx, lastFut); err == nil && len(cpBytes) > 0 {
					s.observeCheckpoint(cpBytes)
				}
			}
			return nil
		}

		if writeTicker != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-cpTicker.C:
				_, _ = s.ReadCheckpoint(ctx)
				continue
			case <-writeTicker.C:
			}
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-cpTicker.C:
				_, _ = s.ReadCheckpoint(ctx)
			default:
			}
		}

		leaf := s.generator.NextLeaf()
		lastFut = s.appender.Add(ctx, tessera.NewEntry(leaf.LeafData))
		atomic.AddUint64(&s.stats.LeavesWritten, 1)
	}
}

func (s *Sequencer) observeCheckpoint(rawCP []byte) {
	parsed, _, _, err := log.ParseCheckpoint(rawCP, s.cfg.Origin, s.verifier)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if parsed.Size > s.lastSeenSize {
		s.lastSeenSize = parsed.Size
		atomic.StoreUint64(&s.stats.LatestTreeSize, parsed.Size)
		atomic.AddUint64(&s.stats.CheckpointsCreated, 1)
		klog.V(2).Infof("Sequencer observed checkpoint size %d", parsed.Size)
	}
}

// Close shuts down the Tessera appender gracefully.
func (s *Sequencer) Close(ctx context.Context) error {
	if s.shutdownFn != nil {
		return s.shutdownFn(ctx)
	}
	return nil
}
