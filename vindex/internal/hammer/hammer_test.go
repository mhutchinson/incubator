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

package hammer_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"golang.org/x/mod/sumdb/note"
)

func TestGenerator_Distributions(t *testing.T) {
	t.Parallel()

	t.Run("Zipfian Skew", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistZipf,
			NumKeys:      100,
			ZipfS:        1.5,
			ZipfV:        1.0,
			Seed:         12345,
			LeafFormat:   hammer.FormatRaw,
		})

		counts := make(map[string]int)
		for range 1000 {
			entry := gen.NextLeaf()
			counts[entry.Key]++
		}

		hotKey := hammer.KeyForID(0)
		if counts[hotKey] < 50 {
			t.Fatalf("expected hot key %s to have high count (>50), got %d", hotKey, counts[hotKey])
		}
	})

	t.Run("Pareto Alias Skew", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistPareto,
			NumKeys:      100,
			ZipfS:        1.5,
			Seed:         12345,
			LeafFormat:   hammer.FormatRaw,
		})

		counts := make(map[string]int)
		for range 1000 {
			entry := gen.NextLeaf()
			counts[entry.Key]++
		}

		hotKey := hammer.KeyForID(0)
		if counts[hotKey] < 50 {
			t.Fatalf("expected Pareto hot key %s to have high count (>50), got %d", hotKey, counts[hotKey])
		}
	})

	t.Run("Uniform Distribution", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      20,
			Seed:         54321,
			LeafFormat:   hammer.FormatRaw,
		})

		counts := make(map[string]int)
		for range 1000 {
			entry := gen.NextLeaf()
			counts[entry.Key]++
		}
		if len(counts) != 20 {
			t.Fatalf("expected all 20 keys to be hit under uniform, got %d", len(counts))
		}
	})

	t.Run("NonInclusion Keys", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      50,
			Seed:         999,
		})

		for range 20 {
			nonKey := gen.SampleNonInclusionKey()
			for id := range uint64(50) {
				if nonKey == hammer.KeyForID(id) {
					t.Fatalf("non-inclusion key %s matched existing key ID %d", nonKey, id)
				}
			}
		}
	})

	t.Run("SumDB Leaf Format", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      10,
			Seed:         101,
			LeafFormat:   hammer.FormatSumDB,
		})
		entry := gen.NextLeaf()
		var mod, ver, h string
		if _, err := fmt.Sscanf(string(entry.LeafData), "%s %s %s", &mod, &ver, &h); err != nil {
			t.Fatalf("failed to parse SumDB leaf format: %v (raw: %q)", err, string(entry.LeafData))
		}
	})

	t.Run("CT Leaf Format", func(t *testing.T) {
		t.Parallel()
		gen := hammer.NewGenerator(hammer.GeneratorConfig{
			Distribution: hammer.DistUniform,
			NumKeys:      20,
			Seed:         202,
			LeafFormat:   hammer.FormatCT,
			CTMinDomains: 2,
			CTMaxDomains: 5,
		})
		entry := gen.NextLeaf()
		if len(entry.LeafData) < 17 || entry.LeafData[0] != 0 || entry.LeafData[1] != 0 || binary.BigEndian.Uint16(entry.LeafData[10:12]) != 0 {
			t.Fatalf("expected RFC 6962 x509_entry MerkleTreeLeaf header, got len=%d", len(entry.LeafData))
		}
		certLen := int(entry.LeafData[12])<<16 | int(entry.LeafData[13])<<8 | int(entry.LeafData[14])
		cert, err := x509.ParseCertificate(entry.LeafData[15 : 15+certLen])
		if err != nil {
			t.Fatalf("x509.ParseCertificate failed on synthetic CT leaf: %v", err)
		}
		if len(cert.DNSNames) < 4 || len(cert.DNSNames) > 10 {
			t.Fatalf("expected 4-10 SAN DNSNames (2 per sampled domain), got %d (%v)", len(cert.DNSNames), cert.DNSNames)
		}
		key := gen.SampleExistingKey()
		if !strings.HasPrefix(key, "com.domain-") || !strings.HasSuffix(key, ".") {
			t.Fatalf("unexpected reversed-DNS SampleExistingKey: %q", key)
		}
		nonKey := gen.SampleNonInclusionKey()
		if !strings.HasPrefix(nonKey, "com.nonexistent-domain-") || !strings.HasSuffix(nonKey, ".") {
			t.Fatalf("unexpected reversed-DNS SampleNonInclusionKey: %q", nonKey)
		}
	})
}

func TestSequencer_AppendPublishAndExplicitSignerKey(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	origin := "example.com/hammer/explicit"
	skey, wantVKey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	gen := hammer.NewGenerator(hammer.DefaultGeneratorConfig())
	seqCfg := hammer.DefaultSequencerConfig(tempDir)
	seqCfg.Origin = origin
	seqCfg.SignerKey = skey
	seqCfg.BatchSize = 10
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 100 * time.Millisecond

	seq, err := hammer.NewSequencer(ctx, seqCfg, gen)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = seq.Close(ctx) }()

	// Bug #6 regression check: VerifierKey() must be derived even when SignerKey is passed explicitly.
	if seq.VerifierKey() != wantVKey {
		t.Fatalf("VerifierKey() = %q, want %q", seq.VerifierKey(), wantVKey)
	}

	for i := range 5 {
		leaf := gen.NextLeaf()
		idx, rawCP, err := seq.WriteLeaf(ctx, leaf.LeafData)
		if err != nil {
			t.Fatalf("WriteLeaf %d failed: %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("expected leaf index %d, got %d", i, idx)
		}
		if len(rawCP) == 0 {
			t.Fatalf("empty checkpoint returned for leaf %d", i)
		}
	}

	stats := seq.Stats()
	if stats.LeavesWritten != 5 || stats.LatestTreeSize != 5 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	latestCP, err := seq.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpoint failed: %v", err)
	}
	parsed, _, _, err := log.ParseCheckpoint(latestCP, seq.Origin(), seq.Verifier())
	if err != nil {
		t.Fatalf("ParseCheckpoint failed: %v", err)
	}
	if parsed.Size != 5 {
		t.Fatalf("checkpoint size = %d, want 5", parsed.Size)
	}
}

func TestDripServer_PublishesLatestCheckpointWithoutFIFOLag(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	var currentCP atomic.Value
	currentCP.Store([]byte("example.com/hammer\n10\nhash1\n"))

	srv := hammer.NewDripServer(hammer.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		StorageDir:   tempDir,
		DripRate:     40.0,
		InitialPause: 30 * time.Millisecond,
	}, func(context.Context) ([]byte, error) {
		return currentCP.Load().([]byte), nil
	})
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("DripServer.Start failed: %v", err)
	}
	defer func() { _ = srv.Close(ctx) }()

	// During InitialPause, /checkpoint returns 503 while /checkpoint_direct serves the live tip.
	resp503, err := http.Get(srv.URL() + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	_ = resp503.Body.Close()
	if resp503.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during InitialPause, got %d", resp503.StatusCode)
	}

	// Advance upstream tip multiple times before pause expires; DripServer must jump directly to latest (30), not FIFO (10).
	currentCP.Store([]byte("example.com/hammer\n20\nhash2\n"))
	currentCP.Store([]byte("example.com/hammer\n30\nhash3\n"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if string(srv.GetPublishedCheckpoint()) == "example.com/hammer\n30\nhash3\n" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get(srv.URL() + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(body) != "example.com/hammer\n30\nhash3\n" {
		t.Fatalf("GET /checkpoint = %q, want latest size-30 checkpoint", string(body))
	}
}

func TestSequencer_WriteGoal(t *testing.T) {
	ctx := t.Context()
	tempDir := t.TempDir()

	gen := hammer.NewGenerator(hammer.DefaultGeneratorConfig())
	seqCfg := hammer.DefaultSequencerConfig(tempDir)
	seqCfg.BatchSize = 8
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.WriteRate = 0
	seqCfg.WriteGoal = 25

	seq, err := hammer.NewSequencer(ctx, seqCfg, gen)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = seq.Close(ctx) }()

	if err := seq.RunLoop(ctx); err != nil {
		t.Fatalf("RunLoop failed: %v", err)
	}

	stats := seq.Stats()
	if stats.LeavesWritten != 25 || stats.LatestTreeSize != 25 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestAnalyzer_ExportStats(t *testing.T) {
	t.Parallel()
	analyzer := hammer.NewAnalyzer(nil)

	analyzer.RecordReadSuccess(100*time.Microsecond, 50)
	analyzer.RecordReadSuccess(200*time.Microsecond, 60)
	analyzer.RecordReadSuccess(500*time.Microsecond, 60)
	analyzer.RecordReadError(fmt.Errorf("simulated timeout"), 1*time.Millisecond)
	analyzer.RecordInvariantViolation("test violation 1")

	stats := analyzer.ExportStats()
	if stats.TotalReads != 4 || stats.ReadSuccesses != 3 || stats.ReadFailures != 1 {
		t.Fatalf("unexpected read counts: %+v", stats)
	}
	if stats.ServingTreeSize != 60 {
		t.Fatalf("stats.ServingTreeSize = %d, want 60", stats.ServingTreeSize)
	}
	if stats.InvariantViolations != 1 || len(stats.ViolationSamples) != 2 {
		t.Fatalf("unexpected violations: %+v", stats)
	}
	if stats.LatencyMax != 1*time.Millisecond {
		t.Fatalf("stats.LatencyMax = %v, want 1ms", stats.LatencyMax)
	}
}

func TestEndToEnd_HammerWithVIndex(t *testing.T) {
	ctx := t.Context()
	rootDir := t.TempDir()
	posixDir := filepath.Join(rootDir, "posix_inlog")

	generator := hammer.NewGenerator(hammer.GeneratorConfig{
		Distribution: hammer.DistZipf,
		NumKeys:      20,
		ZipfS:        1.3,
		ZipfV:        1.0,
		Seed:         42,
		LeafFormat:   hammer.FormatRaw,
	})

	seqCfg := hammer.DefaultSequencerConfig(posixDir)
	seqCfg.BatchSize = 16
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 100 * time.Millisecond
	seqCfg.WriteRate = 0
	seqCfg.WriteGoal = 50

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = sequencer.Close(ctx) }()

	dripServer := hammer.NewDripServer(hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixDir,
		DripRate:   100.0,
	}, sequencer.ReadCheckpoint)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() { _ = dripServer.Close(ctx) }()

	if err := sequencer.RunLoop(ctx); err != nil {
		t.Fatalf("sequencer.RunLoop failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cp := dripServer.GetPublishedCheckpoint(); len(cp) > 0 {
			if p, _, _, err := log.ParseCheckpoint(cp, sequencer.Origin(), sequencer.Verifier()); err == nil && p.Size >= 50 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	outOrigin := "example.com/vindex/output"
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, outOrigin)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	engine, err := vindex.New(vindex.Config{
		DBPath:             filepath.Join(rootDir, "pebble_db"),
		MPTDir:             filepath.Join(rootDir, "mpt_tree"),
		TileCacheDir:       filepath.Join(rootDir, "tilecache"),
		ChunkSize:          16,
		InputLogURL:        dripServer.URL(),
		InputLogOrigin:     sequencer.Origin(),
		InputLogVerifier:   sequencer.Verifier(),
		OutputLogDir:       filepath.Join(rootDir, "posix_outlog"),
		OutputLogOrigin:    outOrigin,
		OutputLogSignerKey: outSKey,
		PrefixPolicyFunc: func(prefix string) error {
			if len(prefix) < 3 {
				return fmt.Errorf("prefix %q shorter than 3 bytes", prefix)
			}
			return nil
		},
	}, wasmhosttest.Host())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	vindexHTTP := httptest.NewServer(engine.Handler())
	defer vindexHTTP.Close()

	analyzer := hammer.NewAnalyzer(sequencer)
	readers, err := hammer.NewReaderPool(hammer.ReaderConfig{
		VIndexURL:         vindexHTTP.URL,
		NumWorkers:        4,
		MaxReadQPS:        100,
		OutputLogOrigin:   outOrigin,
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    sequencer.Origin(),
		HotKeyRatio:       0.50,
		UniformRatio:      0.25,
		NonInclusionRatio: 0.10,
		PaginationRatio:   0.15,
		PrefixRatio:       0.15,
		PageSize:          10,
	}, generator, analyzer)
	if err != nil {
		t.Fatalf("NewReaderPool failed: %v", err)
	}

	testCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if err := readers.Start(testCtx); err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("readers.Start failed: %v", err)
	}

	snap := analyzer.Snapshot()
	if snap.TotalReads == 0 {
		t.Fatal("expected reader workers to execute queries, got 0")
	}
	if snap.ReadSuccesses == 0 {
		t.Fatalf("expected successful reads, got 0 (failures: %d)", snap.ReadFailures)
	}
	if snap.InvariantViolations != 0 {
		t.Fatalf("expected 0 invariant violations, got %d (samples: %v)", snap.InvariantViolations, snap.ViolationSamples)
	}
}
