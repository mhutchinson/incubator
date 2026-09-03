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

package client_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vindex "github.com/transparency-dev/incubator/vindex/v1"
	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// In-memory brute force oracle for differential verification
type readOracle struct {
	mu      sync.RWMutex
	indices map[[32]byte][]uint64
}

func newOracle() *readOracle {
	return &readOracle{
		indices: make(map[[32]byte][]uint64),
	}
}

func (o *readOracle) record(key [32]byte, idx uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.indices[key] = append(o.indices[key], idx)
}

func (o *readOracle) getAll(key [32]byte) []uint64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return slices.Clone(o.indices[key])
}

// TestStress_DifferentialLookupAndPagination tests client Lookup and LookupAll against
// an independent oracle across multi-chunk datasets.
func TestStress_DifferentialLookupAndPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const chunkSize = 8 // Tiny chunk size: forces chunks every 8 entries!
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	oracle := newOracle()

	key1 := sha256.Sum256([]byte("key_1"))
	key2 := sha256.Sum256([]byte("key_2"))
	keyExact := sha256.Sum256([]byte("key_chunk_exact"))
	keyPlus1 := sha256.Sum256([]byte("key_chunk_plus_1"))
	keyDouble := sha256.Sum256([]byte("key_chunk_double"))
	keyHeavy := sha256.Sum256([]byte("key_heavy"))
	keySparse := sha256.Sum256([]byte("key_sparse"))
	keyAbsent := sha256.Sum256([]byte("key_absent_never_indexed"))

	type leafSpec struct {
		keyName string
		keyHash [32]byte
	}

	var sequence []leafSpec

	// Interleave entries to create realistic log structure
	sequence = append(sequence, leafSpec{"key_1", key1})

	for i := 0; i < 2; i++ {
		sequence = append(sequence, leafSpec{"key_2", key2})
	}
	for i := 0; i < 8; i++ {
		sequence = append(sequence, leafSpec{"key_chunk_exact", keyExact})
	}
	for i := 0; i < 9; i++ {
		sequence = append(sequence, leafSpec{"key_chunk_plus_1", keyPlus1})
	}
	for i := 0; i < 16; i++ {
		sequence = append(sequence, leafSpec{"key_chunk_double", keyDouble})
	}
	for i := 0; i < 50; i++ {
		sequence = append(sequence, leafSpec{"key_heavy", keyHeavy})
		if i%10 == 0 {
			sequence = append(sequence, leafSpec{"key_sparse", keySparse})
		}
	}

	// Write all leaves to input log and record in oracle
	for i, spec := range sequence {
		leafData := []byte(fmt.Sprintf("%s_leaf_%d", spec.keyName, i))
		idx, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(leafData)))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("failed to append leaf %d: %v", i, err)
		}
		oracle.record(spec.keyHash, idx.Index)
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         8,
		PollInterval:       30 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.outlog",
		OutputLogSignerKey: outSKey,
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		s := string(leaf)
		for _, spec := range []struct {
			prefix string
			hash   [32]byte
		}{
			{"key_1_", key1},
			{"key_2_", key2},
			{"key_chunk_exact_", keyExact},
			{"key_chunk_plus_1_", keyPlus1},
			{"key_chunk_double_", keyDouble},
			{"key_heavy_", keyHeavy},
			{"key_sparse_", keySparse},
		} {
			if len(s) >= len(spec.prefix) && s[:len(spec.prefix)] == spec.prefix {
				return []vindex.MappedEntry{{KeyHash: spec.hash}}, nil
			}
		}
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

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
		OutputLogOrigin:   "test.stress.outlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.stress.inlog",
		InputLogVerifier:  inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// 1. Non-inclusion verification
	t.Run("NonInclusion_AbsentKey", func(t *testing.T) {
		resp, err := cli.Lookup(ctx, keyAbsent, nil, 10)
		if err != nil {
			t.Fatalf("Lookup non-inclusion failed: %v", err)
		}
		if resp.Exists {
			t.Fatalf("expected Exists=false for absent key, got true")
		}
		if len(resp.Indices) != 0 {
			t.Fatalf("expected 0 indices, got %d", len(resp.Indices))
		}
	})

	// 2. Comprehensive differential check on LookupAll across various page sizes
	allKeys := []struct {
		name string
		hash [32]byte
	}{
		{"key_1", key1},
		{"key_2", key2},
		{"key_chunk_exact", keyExact},
		{"key_chunk_plus_1", keyPlus1},
		{"key_chunk_double", keyDouble},
		{"key_heavy", keyHeavy},
		{"key_sparse", keySparse},
	}

	pageSizes := []uint64{1, 2, 3, 5, 8, 9, 16, 25, 50, 100}

	for _, k := range allKeys {
		t.Run("LookupAll_"+k.name, func(t *testing.T) {
			expected := oracle.getAll(k.hash)
			if len(expected) == 0 {
				t.Fatalf("oracle has 0 entries for %s", k.name)
			}

			for _, ps := range pageSizes {
				resp, err := cli.LookupAll(ctx, k.hash, ps)
				if err != nil {
					t.Fatalf("LookupAll(%s, pageSize=%d) failed: %v", k.name, ps, err)
				}
				if !resp.Exists {
					t.Fatalf("LookupAll(%s, pageSize=%d): Exists=false", k.name, ps)
				}
				if !slices.Equal(resp.Indices, expected) {
					t.Fatalf("LookupAll(%s, pageSize=%d) mismatch:\n got:  %v\n want: %v", k.name, ps, resp.Indices, expected)
				}
			}
		})
	}

	// 3. Step-by-step backward pagination state machine verification
	t.Run("BackwardPagination_StateMachine", func(t *testing.T) {
		expected := oracle.getAll(keyHeavy) // 50 items across 7 chunks
		pageSize := uint64(7)

		var collected []uint64
		var before *uint64
		steps := 0

		for {
			steps++
			resp, err := cli.Lookup(ctx, keyHeavy, before, pageSize)
			if err != nil {
				t.Fatalf("step %d failed: %v", steps, err)
			}
			if !resp.Exists {
				t.Fatalf("step %d: key does not exist", steps)
			}
			if len(resp.Indices) == 0 {
				t.Fatalf("step %d: returned 0 indices before NextBefore was nil", steps)
			}

			// Indices within page must be strictly ascending
			for i := 1; i < len(resp.Indices); i++ {
				if resp.Indices[i] <= resp.Indices[i-1] {
					t.Fatalf("step %d: page indices not strictly ascending: %v", steps, resp.Indices)
				}
			}

			// Prepend page to reconstruct chronological order
			collected = append(slices.Clone(resp.Indices), collected...)

			if resp.NextBefore == nil {
				break
			}

			// NextBefore must equal the smallest index of the current page
			if *resp.NextBefore != resp.Indices[0] {
				t.Fatalf("step %d: NextBefore=%d != first index of page=%d", steps, *resp.NextBefore, resp.Indices[0])
			}

			// All indices in the next page must be strictly less than NextBefore
			before = resp.NextBefore
		}

		if !slices.Equal(collected, expected) {
			t.Fatalf("manual pagination collected mismatch:\n got:  %v\n want: %v", collected, expected)
		}

		// A subsequent query with before=0 must return 0 indices and NextBefore=nil
		zero := uint64(0)
		respZero, err := cli.Lookup(ctx, keyHeavy, &zero, 10)
		if err != nil {
			t.Fatalf("Lookup before=0 failed: %v", err)
		}
		if len(respZero.Indices) != 0 {
			t.Fatalf("Lookup before=0 returned %d indices, want 0", len(respZero.Indices))
		}
		if respZero.NextBefore != nil {
			t.Fatalf("Lookup before=0 NextBefore=%v, want nil", respZero.NextBefore)
		}
	})

	// 4. Edge Cases: boundary values, overflows, empty results
	t.Run("EdgeCases", func(t *testing.T) {
		// before = 1
		one := uint64(1)
		resp1, err := cli.Lookup(ctx, keyHeavy, &one, 10)
		if err != nil {
			t.Fatalf("Lookup before=1 failed: %v", err)
		}
		for _, idx := range resp1.Indices {
			if idx >= 1 {
				t.Fatalf("Lookup before=1 returned index %d >= 1", idx)
			}
		}

		// before = math.MaxUint64
		maxU64 := uint64(math.MaxUint64)
		respMax, err := cli.Lookup(ctx, key1, &maxU64, 10)
		if err != nil {
			t.Fatalf("Lookup before=MaxUint64 failed: %v", err)
		}
		if len(respMax.Indices) != 1 {
			t.Fatalf("Lookup before=MaxUint64 len=%d, want 1", len(respMax.Indices))
		}

		// limit = 0 (defaults to server page limit)
		respDefault, err := cli.Lookup(ctx, keyHeavy, nil, 0)
		if err != nil {
			t.Fatalf("Lookup limit=0 failed: %v", err)
		}
		if len(respDefault.Indices) == 0 {
			t.Fatal("Lookup limit=0 returned 0 indices")
		}

		// limit = 10000 (exceeds all data)
		respBigLimit, err := cli.Lookup(ctx, keyHeavy, nil, 10000)
		if err != nil {
			t.Fatalf("Lookup limit=10000 failed: %v", err)
		}
		if len(respBigLimit.Indices) != 50 {
			t.Fatalf("Lookup limit=10000 len=%d, want 50", len(respBigLimit.Indices))
		}
		if respBigLimit.NextBefore != nil {
			t.Fatalf("Lookup limit=10000 NextBefore=%v, want nil", respBigLimit.NextBefore)
		}
	})
}

// TestStress_HighConcurrencyReadPath subjects the pruned engine and client to
// 30 parallel reader goroutines performing simultaneous lookups and backward
// pagination while asserting 0 data races, 0 proof failures, and 0 hangs.
func TestStress_HighConcurrencyReadPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	const chunkSize = 16
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.concurr.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.concurr.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	const numKeys = 10
	keys := make([][32]byte, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = sha256.Sum256([]byte(fmt.Sprintf("concurr_key_%d", i)))
	}

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		var kID int
		if _, err := fmt.Sscanf(string(leaf), "entry_key_%d", &kID); err == nil && kID >= 0 && kID < numKeys {
			return []vindex.MappedEntry{{KeyHash: keys[kID]}}, nil
		}
		return []vindex.MappedEntry{{KeyHash: sha256.Sum256(leaf)}}, nil
	})

	// Seed 100 leaves
	for i := 0; i < 100; i++ {
		kID := i % numKeys
		leafData := []byte(fmt.Sprintf("entry_key_%d_%d", kID, i))
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(leafData)))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("append leaf %d failed: %v", i, err)
		}
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         16,
		PollInterval:       20 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.concurr.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.concurr.outlog",
		OutputLogSignerKey: outSKey,
	}

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
		OutputLogOrigin:   "test.stress.concurr.outlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.stress.concurr.inlog",
		InputLogVerifier:  inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	const numWorkers = 20
	const iterationsPerWorker = 30
	var totalSuccess atomic.Uint64
	var totalFail atomic.Uint64

	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			for it := 0; it < iterationsPerWorker; it++ {
				kID := (workerID + it) % numKeys
				key := keys[kID]

				switch it % 3 {
				case 0:
					// Simple tip lookup
					resp, err := cli.Lookup(ctx, key, nil, 5)
					if err != nil || !resp.Exists || len(resp.Indices) == 0 {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				case 1:
					// LookupAll full pagination
					resp, err := cli.LookupAll(ctx, key, 3)
					if err != nil || !resp.Exists || len(resp.Indices) != 10 {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				case 2:
					// Non-inclusion lookup
					fakeKey := sha256.Sum256([]byte(fmt.Sprintf("non_existent_%d_%d", workerID, it)))
					resp, err := cli.Lookup(ctx, fakeKey, nil, 10)
					if err != nil || resp.Exists || len(resp.Indices) != 0 {
						totalFail.Add(1)
					} else {
						totalSuccess.Add(1)
					}
				}
			}
		}(w)
	}

	close(startBarrier)
	wg.Wait()

	t.Logf("Concurrent read stress results: %d successes, %d failures", totalSuccess.Load(), totalFail.Load())

	if totalFail.Load() > 0 {
		t.Fatalf("encountered %d failures during concurrent read stress", totalFail.Load())
	}
	expectedSuccess := uint64(numWorkers * iterationsPerWorker)
	if totalSuccess.Load() != expectedSuccess {
		t.Fatalf("totalSuccess = %d, want %d", totalSuccess.Load(), expectedSuccess)
	}
}

// TestStress_ConcurrentWriterAndBackwardPaginator stresses backward pagination while
// the engine is actively ingesting and publishing new batches in the background.
func TestStress_ConcurrentWriterAndBackwardPaginator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	const chunkSize = 8
	rootDir := t.TempDir()
	inLogDir := filepath.Join(rootDir, "inlog")
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.stress.writer.inlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.stress.writer.outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)

	dynamicKey := sha256.Sum256([]byte("dynamic_hot_key"))

	mapper := vindex.FuncMapper(func(_ context.Context, leaf []byte) ([]vindex.MappedEntry, error) {
		return []vindex.MappedEntry{{KeyHash: dynamicKey}}, nil
	})

	// Seed 20 initial leaves
	for i := 0; i < 20; i++ {
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte(fmt.Sprintf("initial_%d", i)))))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("seed leaf %d failed: %v", i, err)
		}
	}

	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          chunkSize,
		BundleSize:         8,
		PollInterval:       20 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.stress.writer.inlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.stress.writer.outlog",
		OutputLogSignerKey: outSKey,
	}

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
		OutputLogOrigin:   "test.stress.writer.outlog",
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    "test.stress.writer.inlog",
		InputLogVerifier:  inVerifier,
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	var stopFlag atomic.Bool
	var totalReads atomic.Uint64
	var readErrors atomic.Uint64
	var lastSeenCount atomic.Uint64

	var wg sync.WaitGroup

	// Reader goroutines continuously running LookupAll
	const numReaders = 4
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stopFlag.Load() {
				resp, err := cli.LookupAll(ctx, dynamicKey, 4) // small page size = multiple pages per query
				if err != nil {
					readErrors.Add(1)
				} else if resp.Exists {
					totalReads.Add(1)
					// Assert monotonicity and ascending order
					for i := 1; i < len(resp.Indices); i++ {
						if resp.Indices[i] <= resp.Indices[i-1] {
							t.Errorf("read non-ascending indices: %v", resp.Indices)
							readErrors.Add(1)
							return
						}
					}
					cnt := uint64(len(resp.Indices))
					for {
						curr := lastSeenCount.Load()
						if cnt <= curr || lastSeenCount.CompareAndSwap(curr, cnt) {
							break
						}
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	// Concurrently append 30 more leaves into the log
	for i := 20; i < 50; i++ {
		_, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry([]byte(fmt.Sprintf("dyn_%d", i)))))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("append dyn leaf %d failed: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)
	stopFlag.Store(true)
	wg.Wait()

	t.Logf("Concurrent writer/paginator results: %d verified reads, %d errors, max indices seen: %d",
		totalReads.Load(), readErrors.Load(), lastSeenCount.Load())

	if readErrors.Load() > 0 {
		t.Fatalf("encountered %d read errors during continuous ingestion pagination", readErrors.Load())
	}
	if totalReads.Load() < 10 {
		t.Fatalf("expected >= 10 reads, got %d", totalReads.Load())
	}
	if lastSeenCount.Load() < 30 {
		t.Fatalf("expected lastSeenCount >= 30, got %d", lastSeenCount.Load())
	}
}
