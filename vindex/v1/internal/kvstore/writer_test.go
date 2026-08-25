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

package kvstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func computeExpectedSubRoot(indices []uint64) [sha256.Size]byte {
	var leaves [][]byte
	for _, idx := range indices {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		leaves = append(leaves, b[:])
	}
	return BatchRoot(leaves)
}

func TestKVIndexer_SingleChunk(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, 256)

	key1 := sha256.Sum256([]byte("domain:example.com"))
	key2 := sha256.Sum256([]byte("domain:google.com"))

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key1: {0, 5, 50},
			key2: {0, 10, 50},
		},
	}

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_data_v1"),
		Origin: "example.com/test",
		Size:   100,
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want 100", res.NewKVSize)
	}

	// Verify metadata
	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 100 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 100", kvSize, err)
	}

	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %s, want %s", string(kvCP), string(targetCP.Raw))
	}

	// Check sub-roots
	expectedKey1Root := computeExpectedSubRoot([]uint64{0, 5, 50})
	expectedKey2Root := computeExpectedSubRoot([]uint64{0, 10, 50})

	if res.ModifiedSubRoots[key1] != expectedKey1Root {
		t.Fatalf("key1 subroot mismatch: got %x, want %x", res.ModifiedSubRoots[key1], expectedKey1Root)
	}
	if res.ModifiedSubRoots[key2] != expectedKey2Root {
		t.Fatalf("key2 subroot mismatch: got %x, want %x", res.ModifiedSubRoots[key2], expectedKey2Root)
	}

	// Check GetSubRoot
	subRoot1, err := idx.GetSubRoot(key1, 100)
	if err != nil || subRoot1 != expectedKey1Root {
		t.Fatalf("GetSubRoot(key1) = %x (err: %v), want %x", subRoot1, err, expectedKey1Root)
	}
}

func TestKVIndexer_MultiChunkRollover(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 100
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("hot-key-multi-chunk"))

	// Create 350 occurrences: across chunks 0, 1, 2, 3
	var indices []uint64
	for i := uint64(0); i < 350; i++ {
		leafIdx := i * 3 // 0, 3, 6, ...
		indices = append(indices, leafIdx)
	}

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        1050,
		KeyMap: map[[32]byte][]uint64{
			key: indices,
		},
	}

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("cp"),
		Origin: "test",
		Size:   1050,
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	expectedRoot := computeExpectedSubRoot(indices)
	if res.ModifiedSubRoots[key] != expectedRoot {
		t.Fatalf("SubRoot mismatch: got %x, want %x", res.ModifiedSubRoots[key], expectedRoot)
	}

	subRoot, err := idx.GetSubRoot(key, 1050)
	if err != nil || subRoot != expectedRoot {
		t.Fatalf("GetSubRoot = %x (err: %v), want %x", subRoot, err, expectedRoot)
	}

	// Verify active chunk is sought first via SeekPrefixGE
	prefix := EncodeChunkPrefix(key)
	iter, err := db.NewIter(nil)
	if err != nil {
		t.Fatalf("NewIter failed: %v", err)
	}
	defer func() { _ = iter.Close() }()

	if !iter.SeekPrefixGE(prefix) {
		t.Fatal("SeekPrefixGE failed to find key prefix")
	}

	// Latest leaf index is 349 * 3 = 1047, chunk = 1047 / 100 = 10
	_, activeChunkNum, err := DecodeChunkKey(iter.Key())
	if err != nil {
		t.Fatalf("DecodeChunkKey failed: %v", err)
	}
	expectedActiveChunk := uint64(349 * 3 / chunkSize)
	if activeChunkNum != expectedActiveChunk {
		t.Fatalf("active chunk num = %d, want %d", activeChunkNum, expectedActiveChunk)
	}
}

func TestKVIndexer_SubRootIncrementalMatchesFull(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const chunkSize = 16
	idx := NewKVIndexer(db, chunkSize)

	key := sha256.Sum256([]byte("incremental_test_key"))

	var allIndices []uint64
	for batchNum := 0; batchNum < 10; batchNum++ {
		var batchIndices []uint64
		for i := 0; i < 25; i++ {
			leafIdx := uint64(batchNum*25 + i)
			allIndices = append(allIndices, leafIdx)
			batchIndices = append(batchIndices, leafIdx)
		}
		batch := &ingest.MappedBatch{
			BundleIdx:    uint64(batchNum),
			StartLeafIdx: uint64(batchNum * 25),
			Count:        25,
			KeyMap: map[[32]byte][]uint64{
				key: batchIndices,
			},
		}
		res, err := idx.IndexBatch(ctx, batch, nil)
		if err != nil {
			t.Fatalf("batch %d failed: %v", batchNum, err)
		}

		expectedRoot := computeExpectedSubRoot(allIndices)
		if res.ModifiedSubRoots[key] != expectedRoot {
			t.Fatalf("batch %d subroot mismatch: got %x, want %x", batchNum, res.ModifiedSubRoots[key], expectedRoot)
		}
	}
}

func TestKVIndexer_ResumingBatches(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, 64)

	keyA := sha256.Sum256([]byte("A"))
	keyB := sha256.Sum256([]byte("B"))

	var keyA_1, keyB_1 []uint64
	for i := uint64(0); i < 50; i++ {
		if i%2 == 0 {
			keyA_1 = append(keyA_1, i)
		}
		if i%3 == 0 {
			keyB_1 = append(keyB_1, i)
		}
	}

	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			keyA: keyA_1,
			keyB: keyB_1,
		},
	}

	res1, err := idx.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("batch 1 failed: %v", err)
	}
	if res1.NewKVSize != 50 {
		t.Fatalf("NewKVSize = %d, want 50", res1.NewKVSize)
	}

	var keyA_2, keyB_2 []uint64
	for i := uint64(50); i < 100; i++ {
		if i%2 == 0 {
			keyA_2 = append(keyA_2, i)
		}
		if i%3 == 0 {
			keyB_2 = append(keyB_2, i)
		}
	}

	batch2 := &ingest.MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			keyA: keyA_2,
			keyB: keyB_2,
		},
	}

	res2, err := idx.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("batch 2 failed: %v", err)
	}
	if res2.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want 100", res2.NewKVSize)
	}

	var allKeyA []uint64
	for i := uint64(0); i < 100; i++ {
		if i%2 == 0 {
			allKeyA = append(allKeyA, i)
		}
	}
	expectedRootA := computeExpectedSubRoot(allKeyA)
	if res2.ModifiedSubRoots[keyA] != expectedRootA {
		t.Fatalf("Resumed keyA root mismatch: got %x, want %x", res2.ModifiedSubRoots[keyA], expectedRootA)
	}
}

func TestKVIndexer_GetSubRoot_WatermarkBoundary(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	key := sha256.Sum256([]byte("watermark-subroot-key"))

	// Entries: 10, 30 in committed range (< 50), 60, 80 in in-flight range (>= 50)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			key: {10, 30, 60, 80},
		},
	}
	if _, err := idx.IndexMappedBatch(ctx, batch, nil, 100); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Full root up to 100
	fullRoot, err := idx.GetSubRoot(key, 100)
	if err != nil {
		t.Fatalf("GetSubRoot(100) failed: %v", err)
	}
	expectedFullRoot := computeExpectedSubRoot([]uint64{10, 30, 60, 80})
	if fullRoot != expectedFullRoot {
		t.Fatalf("GetSubRoot(100) = %x, want %x", fullRoot, expectedFullRoot)
	}

	// 2. Filtered root up to 50 (should commit ONLY to [10, 30])
	filteredRoot, err := idx.GetSubRoot(key, 50)
	if err != nil {
		t.Fatalf("GetSubRoot(50) failed: %v", err)
	}
	expectedFilteredRoot := computeExpectedSubRoot([]uint64{10, 30})
	if filteredRoot != expectedFilteredRoot {
		t.Fatalf("GetSubRoot(50) = %x, want %x", filteredRoot, expectedFilteredRoot)
	}

	// 3. Filtered root before any occurrences (up to 5) -> should return EmptyRoot()
	emptyRoot, err := idx.GetSubRoot(key, 5)
	if err != nil {
		t.Fatalf("GetSubRoot(5) failed: %v", err)
	}
	if emptyRoot != EmptyRoot() {
		t.Fatalf("GetSubRoot(5) = %x, want empty root %x", emptyRoot, EmptyRoot())
	}
}

func TestKVIndexer_UnalignedBundleOffset_SyncAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_at_60967846"),
		Origin: "example.com/log",
		Size:   60967846,
	}

	key := sha256.Sum256([]byte("unaligned_key"))

	// Bundle starts at 60,964,864 (238144 * 256), but sync stream was [60,964,972, 60,967,846) with Count = 2,874
	batch := &ingest.MappedBatch{
		BundleIdx:    238144,
		StartLeafIdx: 60964864,
		EndLeafIdx:   60967846,
		Count:        2874,
		KeyMap: map[[32]byte][]uint64{
			key: {60964975, 60967800},
		},
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 60967846 {
		t.Fatalf("NewKVSize = %d, want target size 60967846", res.NewKVSize)
	}

	// Verify durable m_kv_size
	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 60967846 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 60967846", kvSize, err)
	}

	// Verify durable m_kv_checkpoint (asserts final batch synced with pebble.Sync)
	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %q (err: %v), want %q", string(kvCP), err, string(targetCP.Raw))
	}
}

func TestKVIndexer_ZeroEmissionTrailingLeaves_SyncAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_zero_emission"),
		Origin: "example.com/log",
		Size:   100,
	}

	// Trailing batch from 50 to 100 where NO mapper entries are produced (e.g. non-matching leaves)
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 50,
		EndLeafIdx:   100,
		Count:        50,
		KeyMap:       make(map[[32]byte][]uint64),
	}

	res, err := idx.IndexBatch(ctx, batch, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	if res.NewKVSize != 100 {
		t.Fatalf("NewKVSize = %d, want target size 100", res.NewKVSize)
	}

	kvSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || kvSize != 100 {
		t.Fatalf("KeyMetaKVSize = %d (err: %v), want 100", kvSize, err)
	}

	kvCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(kvCP, targetCP.Raw) {
		t.Fatalf("KeyMetaKVCheckpoint = %q (err: %v), want %q", string(kvCP), err, string(targetCP.Raw))
	}
}

func TestKVIndexer_IntermediateVsFinalBatch_SyncBehavior(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	idx := NewKVIndexer(db, ChunkSize)

	targetCP := &ingest.Checkpoint{
		Raw:    []byte("checkpoint_multi_batch"),
		Origin: "example.com/log",
		Size:   100,
	}

	key := sha256.Sum256([]byte("multi_batch_key"))

	// 1. Intermediate batch [0, 50)
	batch1 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20},
		},
	}
	res1, err := idx.IndexBatch(ctx, batch1, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch batch1 failed: %v", err)
	}
	if res1.NewKVSize != 50 {
		t.Fatalf("batch1 NewKVSize = %d, want 50", res1.NewKVSize)
	}
	kvSize1, _ := db.GetUint64(KeyMetaKVSize)
	if kvSize1 != 50 {
		t.Fatalf("KeyMetaKVSize after batch1 = %d, want 50", kvSize1)
	}
	kvCP1, _ := db.GetMetadata(KeyMetaKVCheckpoint)
	if len(kvCP1) != 0 {
		t.Fatalf("Intermediate batch must not write KeyMetaKVCheckpoint, got: %s", string(kvCP1))
	}

	// 2. Final batch [50, 100)
	batch2 := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 50,
		EndLeafIdx:   100,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			key: {60, 70},
		},
	}
	res2, err := idx.IndexBatch(ctx, batch2, targetCP)
	if err != nil {
		t.Fatalf("IndexBatch batch2 failed: %v", err)
	}
	if res2.NewKVSize != 100 {
		t.Fatalf("batch2 NewKVSize = %d, want 100", res2.NewKVSize)
	}
	kvSize2, _ := db.GetUint64(KeyMetaKVSize)
	if kvSize2 != 100 {
		t.Fatalf("KeyMetaKVSize after batch2 = %d, want 100", kvSize2)
	}
	kvCP2, _ := db.GetMetadata(KeyMetaKVCheckpoint)
	if !bytes.Equal(kvCP2, targetCP.Raw) {
		t.Fatalf("Final batch must write KeyMetaKVCheckpoint, got: %q", string(kvCP2))
	}
}
