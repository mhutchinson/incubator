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

func TestBackfill_StandaloneIngestion_ThenStartEngine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Generate keys
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

	// 3. Create POSIX Input Log
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

	// Append 5 initial leaves:
	// Leaf 0: "cat_0"
	// Leaf 1: "dog_1"
	// Leaf 2: "cat_2"
	// Leaf 3: "dog_3"
	// Leaf 4: "cat_4"
	for i := 0; i < 5; i++ {
		var payload []byte
		if i%2 == 0 {
			payload = []byte(fmt.Sprintf("cat_%d", i))
		} else {
			payload = []byte(fmt.Sprintf("dog_%d", i))
		}
		if _, _, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(payload))); err != nil {
			t.Fatalf("failed to append initial leaf %d: %v", i, err)
		}
	}

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

	catKey := sha256.Sum256([]byte("cat"))
	dogKey := sha256.Sum256([]byte("dog"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		if bytes.HasPrefix(leaf, []byte("cat")) {
			return []vindex.MappedEntry{{KeyHash: catKey}}, nil
		}
		if bytes.HasPrefix(leaf, []byte("dog")) {
			return []vindex.MappedEntry{{KeyHash: dogKey}}, nil
		}
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// 4. Run standalone Backfill
	if err := vindex.Backfill(ctx, cfg, mapper, nil); err != nil {
		t.Fatalf("vindex.Backfill failed: %v", err)
	}

	// 5. Start Engine in Normal Serving Mode on top of backfilled database
	engine, err := vindex.New(cfg, mapper)
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
		OutputLogOrigin:   "test.outputlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.inputlog",
		InputLogVerifier:  inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// Verify backfilled data: "cat" -> [0, 2, 4], "dog" -> [1, 3]
	respCat, err := cli.Lookup(ctx, catKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(cat) failed: %v", err)
	}
	if !respCat.Exists || len(respCat.Indices) != 3 {
		t.Fatalf("Lookup(cat) exists=%v, indices=%v (want [0, 2, 4])", respCat.Exists, respCat.Indices)
	}
	if respCat.Indices[0] != 0 || respCat.Indices[1] != 2 || respCat.Indices[2] != 4 {
		t.Fatalf("Lookup(cat) indices = %v, want [0, 2, 4]", respCat.Indices)
	}

	respDog, err := cli.Lookup(ctx, dogKey, nil, 100)
	if err != nil {
		t.Fatalf("Lookup(dog) failed: %v", err)
	}
	if !respDog.Exists || len(respDog.Indices) != 2 {
		t.Fatalf("Lookup(dog) exists=%v, indices=%v (want [1, 3])", respDog.Exists, respDog.Indices)
	}

	// 6. Dynamically append new leaf 5: "cat_5"
	if _, _, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte("cat_5")))); err != nil {
		t.Fatalf("failed to append leaf 5: %v", err)
	}

	// Poll until client sees updated indices [0, 2, 4, 5]
	deadline := time.Now().Add(5 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		resp, err := cli.Lookup(ctx, catKey, nil, 100)
		if err == nil && resp.Exists && len(resp.Indices) == 4 {
			if resp.Indices[0] == 0 && resp.Indices[1] == 2 && resp.Indices[2] == 4 && resp.Indices[3] == 5 {
				updated = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of dynamic leaf 5 after backfill")
	}
}
