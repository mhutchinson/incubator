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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
)

func setupTestStore(t *testing.T) (*DB, *KVIndexer) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db_reader_test")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	indexer := NewKVIndexer(db, ChunkSize)
	return db, indexer
}

func TestLookup_KeyNotFound(t *testing.T) {
	db, _ := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("nonexistent_key"))

	res, err := db.Lookup(keyHash, nil, 100, 1000)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if res == nil {
		t.Fatalf("Lookup returned nil result")
	}
	if len(res.MatchedIndices) != 0 {
		t.Fatalf("expected 0 matched indices, got %v", res.MatchedIndices)
	}
	if res.PrefixCoveredSz != 0 {
		t.Fatalf("expected PrefixCoveredSz = 0, got %d", res.PrefixCoveredSz)
	}
}

func TestLookup_SingleChunk_ReversePagination(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("single_chunk_key"))

	// Indices within Chunk 0 (< 65536)
	indices := []uint64{10, 25, 50, 100, 250, 500}
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 1000); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query full range (limit = 10 >= 6) -> returns all 6 entries, nextBefore = nil
	resAll, err := db.Lookup(keyHash, nil, 10, 1000)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=10) failed: %v", err)
	}
	if !slices.Equal(resAll.MatchedIndices, indices) {
		t.Fatalf("Lookup(before=nil) = %v, want %v", resAll.MatchedIndices, indices)
	}
	if resAll.NextBefore != nil {
		t.Fatalf("Lookup(before=nil) NextBefore = %v, want nil", resAll.NextBefore)
	}
	if resAll.PrefixCoveredSz != 0 {
		t.Fatalf("Lookup(before=nil) PrefixCoveredSz = %d, want 0", resAll.PrefixCoveredSz)
	}

	// 2. Query Page 1 (Tip, limit = 3) -> should return latest 3 entries: [100, 250, 500]
	// prefix compact range should cover [10, 25, 50]
	resTip, err := db.Lookup(keyHash, nil, 3, 1000)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=3) failed: %v", err)
	}
	wantTipMatched := []uint64{100, 250, 500}
	if !slices.Equal(resTip.MatchedIndices, wantTipMatched) {
		t.Fatalf("Lookup(before=nil, limit=3) MatchedIndices = %v, want %v", resTip.MatchedIndices, wantTipMatched)
	}
	if resTip.NextBefore == nil || *resTip.NextBefore != 100 {
		t.Fatalf("Lookup(before=nil, limit=3) NextBefore = %v, want 100", resTip.NextBefore)
	}
	if resTip.PrefixCoveredSz != 3 {
		t.Fatalf("Lookup(before=nil, limit=3) PrefixCoveredSz = %d, want 3", resTip.PrefixCoveredSz)
	}

	// Verify prefix compact range matches the hash of [10, 25, 50]
	expectedPrefixRoot := BatchRoot([][]byte{
		binary.BigEndian.AppendUint64(nil, 10),
		binary.BigEndian.AppendUint64(nil, 25),
		binary.BigEndian.AppendUint64(nil, 50),
	})
	cr := &CompactRange{
		CoveredSize: resTip.PrefixCoveredSz,
		Hashes:      resTip.PrefixHashes,
	}
	if cr.Root() != expectedPrefixRoot {
		t.Fatalf("Lookup(before=nil, limit=3) Prefix compact range root mismatch: got %x, want %x", cr.Root(), expectedPrefixRoot)
	}

	// 3. Query Page 2 (before = 100, limit = 3) -> returns [10, 25, 50], NextBefore = nil
	resPage2, err := db.Lookup(keyHash, resTip.NextBefore, 3, 1000)
	if err != nil {
		t.Fatalf("Lookup(before=100, limit=3) failed: %v", err)
	}
	wantPage2Matched := []uint64{10, 25, 50}
	if !slices.Equal(resPage2.MatchedIndices, wantPage2Matched) {
		t.Fatalf("Lookup(before=100, limit=3) MatchedIndices = %v, want %v", resPage2.MatchedIndices, wantPage2Matched)
	}
	if resPage2.NextBefore != nil {
		t.Fatalf("Lookup(before=100, limit=3) NextBefore = %v, want nil", resPage2.NextBefore)
	}
	if resPage2.PrefixCoveredSz != 0 {
		t.Fatalf("Lookup(before=100, limit=3) PrefixCoveredSz = %d, want 0", resPage2.PrefixCoveredSz)
	}
}

func TestLookup_MultiChunkRollover(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("multichunk_key"))

	// Entries across Chunk 0, Chunk 1, Chunk 2
	indices := []uint64{
		10, 20, // Chunk 0
		ChunkSize + 5, ChunkSize + 50, // Chunk 1 (65541, 65586)
		2*ChunkSize + 1, 2*ChunkSize + 99, // Chunk 2 (131073, 131171)
	}

	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 3*ChunkSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query full range
	resAll, err := db.Lookup(keyHash, nil, 100, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil) failed: %v", err)
	}
	if !slices.Equal(resAll.MatchedIndices, indices) {
		t.Fatalf("Lookup(before=nil) MatchedIndices = %v, want %v", resAll.MatchedIndices, indices)
	}
	if resAll.PrefixCoveredSz != 0 {
		t.Fatalf("Lookup(before=nil) PrefixCoveredSz = %d, want 0", resAll.PrefixCoveredSz)
	}

	// 2. Query Tip page (limit = 2) -> returns Chunk 2 entries [131073, 131171]
	resTip, err := db.Lookup(keyHash, nil, 2, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil, limit=2) failed: %v", err)
	}
	wantTipMatches := indices[4:] // Chunk 2
	if !slices.Equal(resTip.MatchedIndices, wantTipMatches) {
		t.Fatalf("Lookup(before=nil, limit=2) MatchedIndices = %v, want %v", resTip.MatchedIndices, wantTipMatches)
	}
	if resTip.PrefixCoveredSz != 4 {
		t.Fatalf("Lookup(before=nil, limit=2) PrefixCoveredSz = %d, want 4", resTip.PrefixCoveredSz)
	}
	if resTip.NextBefore == nil || *resTip.NextBefore != indices[4] {
		t.Fatalf("Lookup(before=nil, limit=2) NextBefore = %v, want %d", resTip.NextBefore, indices[4])
	}

	// 3. Query Page 2 (before = 131073, limit = 2) -> returns Chunk 1 entries
	resPage2, err := db.Lookup(keyHash, resTip.NextBefore, 2, 3*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=131073, limit=2) failed: %v", err)
	}
	wantPage2Matches := indices[2:4] // Chunk 1
	if !slices.Equal(resPage2.MatchedIndices, wantPage2Matches) {
		t.Fatalf("Lookup(before=131073, limit=2) MatchedIndices = %v, want %v", resPage2.MatchedIndices, wantPage2Matches)
	}
	if resPage2.PrefixCoveredSz != 2 {
		t.Fatalf("Lookup(before=131073, limit=2) PrefixCoveredSz = %d, want 2", resPage2.PrefixCoveredSz)
	}
}

func TestLookup_SparseChunks_NoDataDrop(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("sparse_chunk_key"))

	sparseIdx := 5*ChunkSize + 42
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {sparseIdx},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 6*ChunkSize); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	// 1. Query with before = nil
	res0, err := db.Lookup(keyHash, nil, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=nil) failed: %v", err)
	}
	if len(res0.MatchedIndices) != 1 || res0.MatchedIndices[0] != sparseIdx {
		t.Fatalf("Lookup(before=nil) MatchedIndices = %v, want [%d]", res0.MatchedIndices, sparseIdx)
	}

	// 2. Query with before = sparseIdx + 1
	beforeVal := sparseIdx + 1
	resChunk1, err := db.Lookup(keyHash, &beforeVal, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=sparseIdx+1) failed: %v", err)
	}
	if len(resChunk1.MatchedIndices) != 1 || resChunk1.MatchedIndices[0] != sparseIdx {
		t.Fatalf("Lookup(before=sparseIdx+1) MatchedIndices = %v, want [%d]", resChunk1.MatchedIndices, sparseIdx)
	}

	// 3. Query with before = sparseIdx (strictly before sparseIdx -> empty)
	resBefore, err := db.Lookup(keyHash, &sparseIdx, 100, 6*ChunkSize)
	if err != nil {
		t.Fatalf("Lookup(before=sparseIdx) failed: %v", err)
	}
	if len(resBefore.MatchedIndices) != 0 {
		t.Fatalf("Lookup(before=sparseIdx) MatchedIndices = %v, want empty", resBefore.MatchedIndices)
	}
}

func TestLookup_WatermarkFiltering(t *testing.T) {
	ctx := context.Background()
	db, indexer := setupTestStore(t)
	keyHash := sha256.Sum256([]byte("watermark_key"))

	// Index batch with indices 10, 20, 30 at targetSize 50
	batch1 := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {10, 20, 30},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch1, nil, 50); err != nil {
		t.Fatalf("IndexMappedBatch batch1 failed: %v", err)
	}

	// Index in-flight batch with indices 60, 70 at targetSize 100
	batch2 := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: {60, 70},
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch2, nil, 100); err != nil {
		t.Fatalf("IndexMappedBatch batch2 failed: %v", err)
	}

	// Reader has serving size = 50. Indices 60, 70 should be filtered out.
	res, err := db.Lookup(keyHash, nil, 100, 50)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	wantIndices := []uint64{10, 20, 30}
	if !slices.Equal(res.MatchedIndices, wantIndices) {
		t.Fatalf("Lookup with maxInputLogSize=50 = %v, want %v", res.MatchedIndices, wantIndices)
	}
}

func TestLookup_NonDefaultChunkSize(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "db_reader_custom_chunk")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const customChunkSize = 64
	db.SetChunkSize(customChunkSize)
	indexer := NewKVIndexer(db, customChunkSize)

	keyHash := sha256.Sum256([]byte("custom_chunk_key"))
	indices := []uint64{0, 65, 130} // 0 (chunk 0), 65 (chunk 1), 130 (chunk 2)
	batch := &ingest.MappedBatch{
		KeyMap: map[[32]byte][]uint64{
			keyHash: indices,
		},
	}
	if _, err := indexer.IndexMappedBatch(ctx, batch, nil, 200); err != nil {
		t.Fatalf("IndexMappedBatch failed: %v", err)
	}

	res, err := db.Lookup(keyHash, nil, 100, 200)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !slices.Equal(res.MatchedIndices, indices) {
		t.Fatalf("Lookup matched indices = %v, want %v", res.MatchedIndices, indices)
	}
}

