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

package vindex_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	vindex "github.com/transparency-dev/incubator/vindex/v1"
	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func TestVIndex_PublicAPI(t *testing.T) {
	cfg := vindex.DefaultConfig()
	if cfg.ChunkSize == 0 || cfg.BundleSize == 0 {
		t.Fatalf("invalid default config: %+v", cfg)
	}

	mapper := vindex.IdentityMapper()
	entries, err := mapper.MapLeaf(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(entries) != 1 || entries[0].KeyHash != sha256.Sum256([]byte("hello")) {
		t.Fatalf("unexpected entries: %+v", entries)
	}

	fnMapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})
	fnEntries, err := fnMapper.MapLeaf(context.Background(), []byte("world"))
	if err != nil {
		t.Fatalf("FuncMapper failed: %v", err)
	}
	if len(fnEntries) != 1 || fnEntries[0].KeyHash != sha256.Sum256([]byte("world")) {
		t.Fatalf("unexpected fnEntries: %+v", fnEntries)
	}
}

func TestEngine_Lifecycle_EndToEndIngestionAndLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Generate cryptographic signers and verifiers for Input and Output logs
	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("failed to generate input log key: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("failed to create input log signer: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("failed to create input log verifier: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("failed to generate output log key: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("failed to create output log verifier: %v", err)
	}

	// 2. Setup isolated storage directories
	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")
	inLogDir := filepath.Join(rootDir, "inlog")

	// 3. Create POSIX-backed Tessera Input Log
	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("failed to initialize input log storage: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create input log appender: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	// Append initial 3 leaves:
	// Leaf 0: "apple_alpha"
	// Leaf 1: "banana_beta"
	// Leaf 2: "apple_gamma"
	appendLeaf := func(payload []byte) uint64 {
		idx, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(payload)))
		if err != nil {
			t.Fatalf("failed to append leaf %q: %v", string(payload), err)
		}
		if len(rawCP) == 0 {
			t.Fatalf("empty checkpoint after appending leaf %q", string(payload))
		}
		return idx.Index
	}

	idx0 := appendLeaf([]byte("apple_alpha"))
	idx1 := appendLeaf([]byte("banana_beta"))
	idx2 := appendLeaf([]byte("apple_gamma"))
	if idx0 != 0 || idx1 != 1 || idx2 != 2 {
		t.Fatalf("unexpected indices: %d, %d, %d", idx0, idx1, idx2)
	}

	// 4. Configure VIndex Engine
	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          64,
		BundleSize:         16,
		PollInterval:       50 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.inputlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.outputlog",
		OutputLogSignerKey: outSKey,
	}

	// Custom mapper categorizing "apple" and "banana"
	appleKey := sha256.Sum256([]byte("apple"))
	bananaKey := sha256.Sum256([]byte("banana"))
	cherryKey := sha256.Sum256([]byte("cherry"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		if bytes.HasPrefix(leaf, []byte("apple")) {
			return []vindex.MappedEntry{{KeyHash: appleKey}}, nil
		}
		if bytes.HasPrefix(leaf, []byte("banana")) {
			return []vindex.MappedEntry{{KeyHash: bananaKey}}, nil
		}
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// 5. Instantiate Engine
	engine, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	// 6. Start Engine and verify initial recovery and sync
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	// 7. Expose Handler via httptest.Server and query using Client
	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli, err := client.New(ts.URL, client.VerifierConfig{
		OutputLogOrigin:   "test.outputlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.inputlog",
		InputLogVerifier:  inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// Query "apple" -> expect indices [0, 2]
	respApple, err := cli.Lookup(ctx, appleKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(apple) failed: %v", err)
	}
	if !respApple.Exists {
		t.Fatalf("Lookup(apple) Exists = false, want true")
	}
	if len(respApple.Indices) != 2 || respApple.Indices[0] != 0 || respApple.Indices[1] != 2 {
		t.Fatalf("Lookup(apple) indices = %v, want [0, 2]", respApple.Indices)
	}

	// Query "banana" -> expect index [1]
	respBanana, err := cli.Lookup(ctx, bananaKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(banana) failed: %v", err)
	}
	if !respBanana.Exists {
		t.Fatalf("Lookup(banana) Exists = false, want true")
	}
	if len(respBanana.Indices) != 1 || respBanana.Indices[0] != 1 {
		t.Fatalf("Lookup(banana) indices = %v, want [1]", respBanana.Indices)
	}

	// Query non-existent "cherry" -> expect non-inclusion
	respCherry, err := cli.Lookup(ctx, cherryKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(cherry) failed: %v", err)
	}
	if respCherry.Exists {
		t.Fatalf("Lookup(cherry) Exists = true, want false")
	}
	if len(respCherry.Indices) != 0 {
		t.Fatalf("Lookup(cherry) returned non-empty indices: %v", respCherry.Indices)
	}

	// 8. Feed a new leaf into the input log dynamically while Engine is running
	idx3 := appendLeaf([]byte("apple_delta"))
	if idx3 != 3 {
		t.Fatalf("unexpected idx3 = %d, want 3", idx3)
	}

	// Poll until client sees updated indices [0, 2, 3]
	deadline := time.Now().Add(5 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		resp, err := cli.Lookup(ctx, appleKey, nil, 100)
		if err == nil && resp.Exists && len(resp.Indices) == 3 {
			if resp.Indices[0] == 0 && resp.Indices[1] == 2 && resp.Indices[2] == 3 {
				updated = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of dynamic leaf 3")
	}

	// 9. Stop Engine
	if err := engine.Stop(); err != nil {
		t.Fatalf("engine.Stop failed: %v", err)
	}

	// 10. Verify crash-recovery / persistent restart
	engine2, err := vindex.New(cfg, mapper)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	if err := engine2.Start(ctx); err != nil {
		t.Fatalf("engine2.Start failed: %v", err)
	}
	defer func() { _ = engine2.Stop() }()

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()

	cli2, err := client.New(ts2.URL, client.VerifierConfig{
		OutputLogOrigin:   "test.outputlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.inputlog",
		InputLogVerifier:  inVerifier,
	}, ts2.Client())
	if err != nil {
		t.Fatalf("client.New (restart) failed: %v", err)
	}

	respRestart, err := cli2.Lookup(ctx, appleKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(apple) after restart failed: %v", err)
	}
	if !respRestart.Exists || len(respRestart.Indices) != 3 {
		t.Fatalf("Lookup(apple) after restart: exists=%v, indices=%v (want [0, 2, 3])", respRestart.Exists, respRestart.Indices)
	}
}

func TestEngine_InMemoryOutputLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	inLogDir := filepath.Join(rootDir, "inlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "inmem.inputlog")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("tessera.NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })
	awaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, time.Millisecond)

	// Append 2 leaves
	_, _, err = awaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte("mem_leaf_0"))))
	if err != nil {
		t.Fatalf("append leaf 0 failed: %v", err)
	}
	_, _, err = awaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte("mem_leaf_1"))))
	if err != nil {
		t.Fatalf("append leaf 1 failed: %v", err)
	}

	// In-memory output log config: OutputLogDir and OutputLogSignerKey are empty
	cfg := vindex.Config{
		DBPath:           dbDir,
		MPTDir:           mptDir,
		TileCacheDir:     cacheDir,
		ChunkSize:        64,
		BundleSize:       16,
		PollInterval:     50 * time.Millisecond,
		InputLogURL:      fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:   "inmem.inputlog",
		InputLogVerifier: inVerifier,
	}

	engine, err := vindex.New(cfg, nil) // tests mapper == nil fallback to IdentityMapper
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	cli, err := client.New(ts.URL, client.VerifierConfig{
		InputLogOrigin:   "inmem.inputlog",
		InputLogVerifier: inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// Query leaf_0 by identity hash
	key0 := sha256.Sum256([]byte("mem_leaf_0"))
	resp0, err := cli.Lookup(ctx, key0, nil, 10)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !resp0.Exists || len(resp0.Indices) != 1 || resp0.Indices[0] != 0 {
		t.Fatalf("unexpected Lookup result: exists=%v, indices=%v", resp0.Exists, resp0.Indices)
	}
}

func TestEngine_Run_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	rootDir := t.TempDir()
	cfg := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       filepath.Join(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
		PollInterval: 10 * time.Millisecond,
	}

	engine, err := vindex.New(cfg, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- engine.Run(ctx)
	}()

	cancel()

	err = <-runErrCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
}

func TestEngine_LifecycleGuardsAndGetters(t *testing.T) {
	ctx := context.Background()
	rootDir := t.TempDir()
	cfg := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db"),
		MPTDir:       filepath.Join(rootDir, "mpt"),
		TileCacheDir: filepath.Join(rootDir, "cache"),
	}

	engine, err := vindex.New(cfg, vindex.IdentityMapper())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}

	// Verify getters
	if engine.DB() == nil {
		t.Error("engine.DB() is nil")
	}
	if engine.MPT() == nil {
		t.Error("engine.MPT() is nil")
	}
	if engine.Publisher() == nil {
		t.Error("engine.Publisher() is nil")
	}
	if engine.Coordinator() == nil {
		t.Error("engine.Coordinator() is nil")
	}
	if engine.Server() == nil {
		t.Error("engine.Server() is nil")
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	// Guard: Start when already running
	if err := engine.Start(ctx); err == nil {
		t.Error("expected error calling Start() when running, got nil")
	}

	// Guard: Run when already running
	if err := engine.Run(ctx); err == nil {
		t.Error("expected error calling Run() when running, got nil")
	}

	// Close
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close failed: %v", err)
	}

	// Close idempotency
	if err := engine.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	// Guard: Start when closed
	if err := engine.Start(ctx); err == nil {
		t.Error("expected error calling Start() after Close, got nil")
	}

	// Guard: Run when closed
	if err := engine.Run(ctx); err == nil {
		t.Error("expected error calling Run() after Close, got nil")
	}
}

func TestEngine_ConfigValidationErrors(t *testing.T) {
	rootDir := t.TempDir()

	// 1. Invalid OutputLogSignerKey
	cfg1 := vindex.Config{
		DBPath:             filepath.Join(rootDir, "db1"),
		MPTDir:             filepath.Join(rootDir, "mpt1"),
		TileCacheDir:       filepath.Join(rootDir, "cache1"),
		OutputLogDir:       filepath.Join(rootDir, "out1"),
		OutputLogSignerKey: "invalid_key_string",
	}
	if _, err := vindex.New(cfg1, nil); err == nil {
		t.Error("expected error for invalid OutputLogSignerKey, got nil")
	}

	// 2. Invalid InputLogURL
	cfg2 := vindex.Config{
		DBPath:       filepath.Join(rootDir, "db2"),
		MPTDir:       filepath.Join(rootDir, "mpt2"),
		TileCacheDir: filepath.Join(rootDir, "cache2"),
		InputLogURL:  "://invalid_url",
	}
	if _, err := vindex.New(cfg2, nil); err == nil {
		t.Error("expected error for invalid InputLogURL, got nil")
	}
}

