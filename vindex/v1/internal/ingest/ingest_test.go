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

package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/tlog"
)

type mockTileFetcher struct {
	leaves     [][]byte
	origin     string
	bundleSize uint64
}

func (f *mockTileFetcher) Checkpoint(_ context.Context) (*Checkpoint, error) {
	root := sha256.Sum256([]byte(fmt.Sprintf("%d", len(f.leaves))))
	return &Checkpoint{
		Raw:    []byte(fmt.Sprintf("%s\n%d\n%x\n", f.origin, len(f.leaves), root)),
		Origin: f.origin,
		Size:   uint64(len(f.leaves)),
		Hash:   root,
	}, nil
}

func (f *mockTileFetcher) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	if idx >= uint64(len(f.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (len %d)", idx, len(f.leaves))
	}
	return f.leaves[idx], nil
}

func (f *mockTileFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	bsz := f.bundleSize
	if bsz == 0 {
		bsz = uint64(layout.EntryBundleWidth)
	}
	adapter := &LeafAdapter{
		LeafFn:     f.Leaf,
		BundleSize: bsz,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

type testMapper struct {
	failOnLeaf int
}

func (m *testMapper) MapLeaf(_ context.Context, leaf []byte) ([]MappedEntry, error) {
	if m.failOnLeaf > 0 && string(leaf) == fmt.Sprintf("entry_leaf_%d", m.failOnLeaf) {
		return nil, errors.New("simulated mapper failure")
	}
	kh := sha256.Sum256(leaf)
	return []MappedEntry{{KeyHash: kh}}, nil
}

func (m *testMapper) Close(_ context.Context) error { return nil }

func TestManagedTileCache_Operations(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewManagedTileCache(dir, 16)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	b0 := &LeafBundle{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Leaves:       [][]byte{[]byte("leaf0"), []byte("leaf1")},
	}
	b1 := &LeafBundle{
		BundleIdx:    1,
		StartLeafIdx: 16,
		Leaves:       [][]byte{[]byte("leaf16"), []byte("leaf17")},
	}

	if err := cache.PutBundle(b0); err != nil {
		t.Fatalf("PutBundle b0 failed: %v", err)
	}
	if err := cache.PutBundle(b1); err != nil {
		t.Fatalf("PutBundle b1 failed: %v", err)
	}

	// Retrieve b0
	gotB0, err := cache.GetBundle(0)
	if err != nil || len(gotB0.Leaves) != 2 || string(gotB0.Leaves[0]) != "leaf0" {
		t.Fatalf("GetBundle(0) failed: got %v (err: %v)", gotB0, err)
	}

	// Prune before leaf 16 -> should delete b0 (leaves 0..2 <= 16)
	pruned, err := cache.PruneBefore(16)
	if err != nil {
		t.Fatalf("PruneBefore failed: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}

	if _, err := cache.GetBundle(0); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("expected ErrBundleNotFound after prune, got %v", err)
	}
	if _, err := cache.GetBundle(1); err != nil {
		t.Fatalf("expected bundle 1 to still exist, got %v", err)
	}
}

func TestIngestionPipeline_EndToEndResequencing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 4)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	var receivedCount uint64
	var expectedNextStart uint64 = 0

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)

		// Verify key mappings
		for k, idxs := range batch.KeyMap {
			if len(idxs) == 0 {
				t.Fatalf("empty indices for key %x", k)
			}
		}
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	if receivedCount != totalLeaves {
		t.Fatalf("received %d leaves, want %d", receivedCount, totalLeaves)
	}
}

func TestIngestionPipeline_HaltOnMapError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const totalLeaves = 50
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{failOnLeaf: 20}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected mapper failure error, got nil")
	}
}

func TestNewTiledFetcher_DefaultHTTPClient(t *testing.T) {
	u, err := url.Parse("https://example.com/log")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	f, err := NewTiledFetcher(u, nil, "example-origin", nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher failed: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil TiledFetcher")
	}
}

type mockTiledReader struct {
	readEntryBundleFn func(ctx context.Context, i uint64, p uint8) ([]byte, error)
	readTileFn        func(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
}

func (m *mockTiledReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (m *mockTiledReader) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	if m.readTileFn != nil {
		return m.readTileFn(ctx, l, i, p)
	}
	if m.readEntryBundleFn != nil {
		bundleBytes, err := m.readEntryBundleFn(ctx, i, p)
		if err != nil {
			return nil, err
		}
		var eb api.EntryBundle
		if err := eb.UnmarshalText(bundleBytes); err != nil {
			return nil, err
		}
		var tileData []byte
		for _, leaf := range eb.Entries {
			h := tlog.RecordHash(leaf)
			tileData = append(tileData, h[:]...)
		}
		return tileData, nil
	}
	return nil, nil
}

func (m *mockTiledReader) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	if m.readEntryBundleFn != nil {
		return m.readEntryBundleFn(ctx, i, p)
	}
	return nil, nil
}

func TestTiledFetcher_FetchTiles_ParallelOrdering(t *testing.T) {
	ctx := t.Context()

	var activeGoroutines atomic.Int32
	var maxConcurrent atomic.Int32

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, i uint64, _ uint8) ([]byte, error) {
			cur := activeGoroutines.Add(1)
			defer activeGoroutines.Add(-1)

			for {
				max := maxConcurrent.Load()
				if cur <= max || maxConcurrent.CompareAndSwap(max, cur) {
					break
				}
			}

			time.Sleep(10 * time.Millisecond)
			entry := []byte(fmt.Sprintf("entry_for_bundle_%d", i))
			var buf []byte
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(entry)))
			buf = append(buf, entry...)
			return buf, nil
		},
	}

	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 5 * uint64(layout.EntryBundleWidth),
	}

	bundles, err := fetcher.FetchTiles(ctx, 0, 5*uint64(layout.EntryBundleWidth))
	if err != nil {
		t.Fatalf("FetchTiles failed: %v", err)
	}

	if len(bundles) != 5 {
		t.Fatalf("got %d bundles, want 5", len(bundles))
	}

	for i, b := range bundles {
		if b.BundleIdx != uint64(i) {
			t.Fatalf("bundle[%d].BundleIdx = %d, want %d", i, b.BundleIdx, i)
		}
		if b.StartLeafIdx != uint64(i)*uint64(layout.EntryBundleWidth) {
			t.Fatalf("bundle[%d].StartLeafIdx = %d, want %d", i, b.StartLeafIdx, uint64(i)*uint64(layout.EntryBundleWidth))
		}
		if len(b.Leaves) == 0 {
			t.Fatalf("bundle[%d] has 0 leaves", i)
		}
	}

	if maxConcurrent.Load() < 2 {
		t.Fatalf("expected concurrent bundle downloads, maxConcurrent = %d", maxConcurrent.Load())
	}
}

func TestMappedBatch_Merge(t *testing.T) {
	k1 := sha256.Sum256([]byte("key1"))
	k2 := sha256.Sum256([]byte("key2"))
	k3 := sha256.Sum256([]byte("key3"))

	b1 := &MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		EndLeafIdx:   256,
		Count:        256,
		KeyMap: map[[32]byte][]uint64{
			k1: {0, 10},
			k2: {5},
		},
	}

	// Merging nil should be a no-op
	b1.Merge(nil)
	if b1.EndLeafIdx != 256 || b1.Count != 256 {
		t.Fatalf("unexpected state after nil merge: end=%d count=%d", b1.EndLeafIdx, b1.Count)
	}

	b2 := &MappedBatch{
		BundleIdx:    1,
		StartLeafIdx: 256,
		EndLeafIdx:   512,
		Count:        256,
		KeyMap: map[[32]byte][]uint64{
			k1: {260},
			k3: {300, 301},
		},
	}

	b1.Merge(b2)

	if b1.StartLeafIdx != 0 {
		t.Errorf("StartLeafIdx = %d, want 0", b1.StartLeafIdx)
	}
	if b1.EndLeafIdx != 512 {
		t.Errorf("EndLeafIdx = %d, want 512", b1.EndLeafIdx)
	}
	if b1.Count != 512 {
		t.Errorf("Count = %d, want 512", b1.Count)
	}

	wantK1 := []uint64{0, 10, 260}
	if len(b1.KeyMap[k1]) != len(wantK1) {
		t.Fatalf("k1 len = %d, want %d", len(b1.KeyMap[k1]), len(wantK1))
	}
	for i, v := range wantK1 {
		if b1.KeyMap[k1][i] != v {
			t.Errorf("k1[%d] = %d, want %d", i, b1.KeyMap[k1][i], v)
		}
	}

	wantK2 := []uint64{5}
	if len(b1.KeyMap[k2]) != len(wantK2) || b1.KeyMap[k2][0] != 5 {
		t.Errorf("k2 mismatch: %v", b1.KeyMap[k2])
	}

	wantK3 := []uint64{300, 301}
	if len(b1.KeyMap[k3]) != len(wantK3) {
		t.Errorf("k3 mismatch: %v", b1.KeyMap[k3])
	}
}

func TestIngestionPipeline_UnalignedFromLeafIdx(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 4)

	// Stream from unaligned start: [100, 600)
	const fromIdx = 100
	batchChan, errChan := pipeline.StreamBatches(ctx, fromIdx, totalLeaves)

	var receivedCount uint64
	var expectedNextStart uint64 = fromIdx

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	wantCount := uint64(totalLeaves - fromIdx)
	if receivedCount != wantCount {
		t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
	}
}

func TestIngestionPipeline_UnalignedTargetSize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 4)

	// Stream to unaligned target: [0, 350)
	const targetSize = 350
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, targetSize)

	var receivedCount uint64
	var expectedNextStart uint64 = 0

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	if receivedCount != targetSize {
		t.Fatalf("received %d leaves, want %d", receivedCount, targetSize)
	}
	if expectedNextStart != targetSize {
		t.Fatalf("expectedNextStart = %d, want %d", expectedNextStart, targetSize)
	}
}

func TestIngestionPipeline_UnalignedBothEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 4)

	// Stream unaligned at both ends: [123, 456)
	const fromIdx = 123
	const targetSize = 456
	batchChan, errChan := pipeline.StreamBatches(ctx, fromIdx, targetSize)

	var receivedCount uint64
	var expectedNextStart uint64 = fromIdx

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	wantCount := uint64(targetSize - fromIdx)
	if receivedCount != wantCount {
		t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
	}
}

func TestIngestionPipeline_SingleBundleSubSlice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const totalLeaves = 600
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 4)

	// Subslice within a single bundle: [50, 150)
	const fromIdx = 50
	const targetSize = 150
	batchChan, errChan := pipeline.StreamBatches(ctx, fromIdx, targetSize)

	var receivedCount uint64
	var expectedNextStart uint64 = fromIdx

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	wantCount := uint64(targetSize - fromIdx)
	if receivedCount != wantCount {
		t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
	}
}

func TestIngestionPipeline_EmptyAndInvertedRange(t *testing.T) {
	ctx := context.Background()

	fetcher := &mockTileFetcher{leaves: nil, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)

	// from == target
	b1, e1 := pipeline.StreamBatches(ctx, 100, 100)
	for range b1 {
		t.Fatal("expected 0 batches for from == target")
	}
	if err := <-e1; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// from > target
	b2, e2 := pipeline.StreamBatches(ctx, 200, 100)
	for range b2 {
		t.Fatal("expected 0 batches for from > target")
	}
	if err := <-e2; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIngestionPipeline_CachedUnaligned(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cache, err := NewManagedTileCache(t.TempDir(), 256)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// Pre-populate cache with 3 bundles (0..255, 256..511, 512..767)
	for bIdx := uint64(0); bIdx < 3; bIdx++ {
		leaves := make([][]byte, 256)
		for j := 0; j < 256; j++ {
			leaves[j] = []byte(fmt.Sprintf("entry_leaf_%d", bIdx*256+uint64(j)))
		}
		if err := cache.PutBundle(&LeafBundle{
			BundleIdx:    bIdx,
			StartLeafIdx: bIdx * 256,
			Leaves:       leaves,
		}); err != nil {
			t.Fatalf("PutBundle failed: %v", err)
		}
	}

	mapper := &testMapper{}
	pipeline := NewPipeline(nil, cache, mapper, 4)

	// Stream unaligned from cache: [100, 600)
	const fromIdx = 100
	const targetSize = 600
	batchChan, errChan := pipeline.StreamBatches(ctx, fromIdx, targetSize)

	var receivedCount uint64
	var expectedNextStart uint64 = fromIdx

	for batch := range batchChan {
		if batch.StartLeafIdx != expectedNextStart {
			t.Fatalf("out of order batch: got StartLeafIdx=%d, want %d", batch.StartLeafIdx, expectedNextStart)
		}
		expectedNextStart = batch.StartLeafIdx + uint64(batch.Count)
		receivedCount += uint64(batch.Count)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("pipeline returned error: %v", err)
	}

	wantCount := uint64(targetSize - fromIdx)
	if receivedCount != wantCount {
		t.Fatalf("received %d leaves, want %d", receivedCount, wantCount)
	}
}

func TestIngestionPipeline_PartialCacheExpansion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cache, err := NewManagedTileCache(t.TempDir(), 256)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	// 1. Initial state: 3 leaves in bundle 0
	leaves := [][]byte{[]byte("leaf0"), []byte("leaf1"), []byte("leaf2")}
	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, cache, mapper, 2)

	// Stream [0, 3) -> bundle 0 cached with 3 leaves
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 3)
	for range batchChan {
	}
	if err := <-errChan; err != nil {
		t.Fatalf("StreamBatches [0, 3) failed: %v", err)
	}

	// 2. Log expands dynamically: leaf 3 is added (total 4 leaves)
	fetcher.leaves = append(fetcher.leaves, []byte("leaf3"))

	// Stream [3, 4) -> must fetch updated bundle rather than getting stuck on partial cache
	batchChan2, errChan2 := pipeline.StreamBatches(ctx, 3, 4)
	var count uint64
	for batch := range batchChan2 {
		if batch.StartLeafIdx != 3 || batch.EndLeafIdx != 4 {
			t.Fatalf("unexpected batch range: [%d, %d)", batch.StartLeafIdx, batch.EndLeafIdx)
		}
		count += uint64(batch.Count)
	}
	if err := <-errChan2; err != nil {
		t.Fatalf("StreamBatches [3, 4) failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("received %d leaves, want 1", count)
	}
}

func TestTiledFetcher_FetchTiles_TreeSizeClamping(t *testing.T) {
	ctx := context.Background()

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, i uint64, _ uint8) ([]byte, error) {
			entry := []byte(fmt.Sprintf("entry_for_bundle_%d", i))
			var buf []byte
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(entry)))
			buf = append(buf, entry...)
			return buf, nil
		},
	}

	// treeSize = 300 (covers bundle 0 and bundle 1)
	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 300,
	}

	// 1. Requesting beyond treeSize should return nil
	bundles, err := fetcher.FetchTiles(ctx, 300, 100)
	if err != nil {
		t.Fatalf("FetchTiles beyond treeSize failed: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("got %d bundles, want 0", len(bundles))
	}

	// 2. Requesting overlapping range [100, 600) should clamp to treeSize (300) -> bundles 0 and 1
	bundles, err = fetcher.FetchTiles(ctx, 100, 500)
	if err != nil {
		t.Fatalf("FetchTiles overlapping failed: %v", err)
	}
	if len(bundles) != 2 {
		t.Fatalf("got %d bundles, want 2 (clamped to treeSize)", len(bundles))
	}
	if bundles[0].BundleIdx != 0 || bundles[1].BundleIdx != 1 {
		t.Fatalf("unexpected bundles: %v", bundles)
	}
}

type gapTileFetcher struct {
	bundles []*LeafBundle
}

func (f *gapTileFetcher) Checkpoint(_ context.Context) (*Checkpoint, error) {
	return &Checkpoint{Size: 300}, nil
}
func (f *gapTileFetcher) Leaf(_ context.Context, _ uint64) ([]byte, error) {
	return nil, nil
}
func (f *gapTileFetcher) FetchTiles(_ context.Context, _, _ uint64) ([]*LeafBundle, error) {
	return f.bundles, nil
}

func TestIngestionPipeline_ResequencerSilentDataDrop_GapError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Provide bundle 0 [0..100) and bundle 2 [200..300), skipping bundle 1 [100..200)
	b0 := &LeafBundle{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Leaves:       make([][]byte, 100),
	}
	for i := range b0.Leaves {
		b0.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", i))
	}
	b2 := &LeafBundle{
		BundleIdx:    2,
		StartLeafIdx: 200,
		Leaves:       make([][]byte, 100),
	}
	for i := range b2.Leaves {
		b2.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", 200+i))
	}

	fetcher := &gapTileFetcher{bundles: []*LeafBundle{b0, b2}}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)

	// Stream [0, 300)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 300)

	for range batchChan {
		// drain available batches
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error on gap/unpopped items in resequencer, got nil")
	}
}

func TestIngestionPipeline_ResequencerSilentDataDrop_MissingStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Only provide bundle 1 [100..200), missing [0..100)
	b1 := &LeafBundle{
		BundleIdx:    1,
		StartLeafIdx: 100,
		Leaves:       make([][]byte, 100),
	}
	for i := range b1.Leaves {
		b1.Leaves[i] = []byte(fmt.Sprintf("leaf_%d", 100+i))
	}

	fetcher := &gapTileFetcher{bundles: []*LeafBundle{b1}}
	mapper := &testMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)

	// Stream [0, 200)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 200)

	for range batchChan {
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error on missing start batch in resequencer, got nil")
	}
}

func TestTiledFetcher_LeafHashAuthentication_CorruptedLeaf(t *testing.T) {
	ctx := context.Background()

	originalLeaf := []byte("original_valid_leaf_data")
	corruptedLeaf := []byte("tampered_malicious_leaf_data")

	var bundleBuf []byte
	bundleBuf = binary.BigEndian.AppendUint16(bundleBuf, uint16(len(corruptedLeaf)))
	bundleBuf = append(bundleBuf, corruptedLeaf...)

	validHash := tlog.RecordHash(originalLeaf)
	tileBuf := validHash[:]

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, _ uint64, _ uint8) ([]byte, error) {
			return bundleBuf, nil
		},
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return tileBuf, nil
		},
	}

	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 1,
	}

	// 1. FetchTiles must fail authentication
	_, err := fetcher.FetchTiles(ctx, 0, 1)
	if err == nil {
		t.Fatal("FetchTiles expected hash mismatch error for corrupted leaf, got nil")
	}

	// 2. Leaf must fail authentication
	_, err = fetcher.Leaf(ctx, 0)
	if err == nil {
		t.Fatal("Leaf expected hash mismatch error for corrupted leaf, got nil")
	}
}

func TestIngestionPipeline_CorruptedLeafRejectedByPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalLeaf := []byte("original_valid_leaf_data")
	corruptedLeaf := []byte("tampered_malicious_leaf_data")

	var bundleBuf []byte
	bundleBuf = binary.BigEndian.AppendUint16(bundleBuf, uint16(len(corruptedLeaf)))
	bundleBuf = append(bundleBuf, corruptedLeaf...)

	validHash := tlog.RecordHash(originalLeaf)
	tileBuf := validHash[:]

	reader := &mockTiledReader{
		readEntryBundleFn: func(_ context.Context, _ uint64, _ uint8) ([]byte, error) {
			return bundleBuf, nil
		},
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return tileBuf, nil
		},
	}

	fetcher := &TiledFetcher{
		fetcher:  reader,
		origin:   "test-origin",
		treeSize: 1,
	}

	pipeline := NewPipeline(fetcher, nil, &testMapper{}, 2)
	batchChan, errChan := pipeline.StreamBatches(ctx, 0, 1)

	for range batchChan {
	}

	err := <-errChan
	if err == nil {
		t.Fatal("pipeline expected error due to corrupted leaf hash mismatch, got nil")
	}
}

func TestIngestionPipeline_PropagateMapperErrorDirectly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const totalLeaves = 50
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log"}
	errCustomMapFailed := errors.New("custom map failure")
	mapper := &errorMapper{err: errCustomMapFailed}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error from pipeline, got nil")
	}
	if !errors.Is(err, errCustomMapFailed) {
		t.Fatalf("expected error wrapping or matching errCustomMapFailed, got: %v", err)
	}
}

type errorMapper struct {
	err error
}

func (m *errorMapper) MapLeaf(_ context.Context, _ []byte) ([]MappedEntry, error) {
	return nil, m.err
}

func (m *errorMapper) Close(_ context.Context) error { return nil }

func TestIngestionPipeline_WorkerErrorUnblocksWithoutMasking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const totalLeaves = 200
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 1}
	errLeafZeroCorrupted := errors.New("corrupted leaf 0")
	mapper := &leafZeroErrorMapper{err: errLeafZeroCorrupted}
	pipeline := NewPipeline(fetcher, nil, mapper, 16)
	pipeline.bundleSize = 1

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected error from pipeline, got nil")
	}
	if !errors.Is(err, errLeafZeroCorrupted) {
		t.Fatalf("expected error matching errLeafZeroCorrupted, got: %v", err)
	}
}

type leafZeroErrorMapper struct {
	err error
}

func (m *leafZeroErrorMapper) MapLeaf(_ context.Context, leaf []byte) ([]MappedEntry, error) {
	if string(leaf) == "entry_leaf_0" {
		return nil, m.err
	}
	kh := sha256.Sum256(leaf)
	return []MappedEntry{{KeyHash: kh}}, nil
}

func (m *leafZeroErrorMapper) Close(_ context.Context) error { return nil }

func TestIngestionPipeline_BundleTimeout_HaltsPipeline(t *testing.T) {
	ctx := context.Background()

	const totalLeaves = 10
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 5}
	mapper := &hangingMapper{}
	pipeline := NewPipeline(fetcher, nil, mapper, 2)
	pipeline.bundleSize = 5
	pipeline.SetBundleTimeout(50 * time.Millisecond)

	batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)

	for range batchChan {
		// drain
	}

	err := <-errChan
	if err == nil {
		t.Fatal("expected timeout error from pipeline, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected error wrapping context.DeadlineExceeded, got: %v", err)
	}
}

type hangingMapper struct{}

func (m *hangingMapper) MapLeaf(ctx context.Context, _ []byte) ([]MappedEntry, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *hangingMapper) Close(_ context.Context) error { return nil }

func TestIngestionPipeline_ConcurrentWorkerFailures_NoPanic(t *testing.T) {
	const totalLeaves = 200
	var leaves [][]byte
	for i := 0; i < totalLeaves; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("entry_leaf_%d", i)))
	}

	for iter := 0; iter < 10; iter++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		fetcher := &mockTileFetcher{leaves: leaves, origin: "test-log", bundleSize: 1}
		errFail := errors.New("concurrent worker map fail")
		mapper := &errorMapper{err: errFail}
		pipeline := NewPipeline(fetcher, nil, mapper, 16)
		pipeline.bundleSize = 1

		batchChan, errChan := pipeline.StreamBatches(ctx, 0, totalLeaves)
		for range batchChan {
		}

		err := <-errChan
		cancel()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errFail) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}


