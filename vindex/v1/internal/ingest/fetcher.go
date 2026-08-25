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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

// LeafAdapter adapts any leaf-by-leaf fetcher to the TileFetcher interface.
type LeafAdapter struct {
	CheckpointFn func(ctx context.Context) (*Checkpoint, error)
	LeafFn       func(ctx context.Context, idx uint64) ([]byte, error)
	BundleSize   uint64
}

// Checkpoint calls CheckpointFn.
func (a *LeafAdapter) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	return a.CheckpointFn(ctx)
}

// Leaf calls LeafFn.
func (a *LeafAdapter) Leaf(ctx context.Context, idx uint64) ([]byte, error) {
	leaf, err := a.LeafFn(ctx, idx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, err
	}
	return leaf, nil
}

// FetchTiles fetches bundles of leaves by calling LeafFn.
func (a *LeafAdapter) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	bundleSz := a.BundleSize
	if bundleSz == 0 {
		bundleSz = DefaultBundleSize
	}

	var bundles []*LeafBundle
	currIdx := startLeafIdx
	endIdx := startLeafIdx + count

	for currIdx < endIdx {
		bCount := bundleSz
		if currIdx+bCount > endIdx {
			bCount = endIdx - currIdx
		}
		leaves := make([][]byte, 0, bCount)
		for i := uint64(0); i < bCount; i++ {
			leaf, err := a.LeafFn(ctx, currIdx+i)
			if err != nil {
				metrics.InputFetchErrorsTotal.Inc()
				return nil, fmt.Errorf("failed to fetch leaf %d: %w", currIdx+i, err)
			}
			leaves = append(leaves, leaf)
		}
		bundles = append(bundles, &LeafBundle{
			BundleIdx:    currIdx / bundleSz,
			StartLeafIdx: currIdx,
			Leaves:       leaves,
		})
		currIdx += bCount
	}

	var totalLeaves int
	for _, b := range bundles {
		totalLeaves += len(b.Leaves)
	}
	metrics.LeavesDownloadedTotal.Add(float64(totalLeaves))

	return bundles, nil
}

// SetTreeSize sets the tree size for LeafAdapter (no-op).
func (a *LeafAdapter) SetTreeSize(_ uint64) {}

// TiledReader defines the low-level tile and entry bundle retrieval methods.
type TiledReader interface {
	ReadCheckpoint(ctx context.Context) ([]byte, error)
	ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error)
}

type tiledReader = TiledReader

type leafBundleCache struct {
	start  uint64
	leaves [][]byte
}

func (tc leafBundleCache) get(i uint64) []byte {
	end := tc.start + uint64(len(tc.leaves))
	if i >= tc.start && i < end {
		return tc.leaves[i-tc.start]
	}
	return nil
}

// TiledFetcher adapts a tlog-tiles HTTP endpoint to the TileFetcher interface.
type TiledFetcher struct {
	mu       sync.Mutex
	fetcher  tiledReader
	verifier note.Verifier
	origin   string
	cache    leafBundleCache
	treeSize uint64
}

// SetTreeSize sets the current tree size used for partial tile fetching.
func (f *TiledFetcher) SetTreeSize(size uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.treeSize = size
}

// TreeSize returns the current tree size.
func (f *TiledFetcher) TreeSize() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.treeSize
}

// NewTiledFetcherWithReader creates a new TiledFetcher using a custom TiledReader.
func NewTiledFetcherWithReader(reader TiledReader, verifier note.Verifier, origin string) *TiledFetcher {
	return &TiledFetcher{
		fetcher:  reader,
		verifier: verifier,
		origin:   origin,
	}
}

// NewTiledFetcher creates a new TiledFetcher pointing to a baseURL.
func NewTiledFetcher(baseURL *url.URL, verifier note.Verifier, origin string, httpClient *http.Client) (*TiledFetcher, error) {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        200,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}
	if origin == "" && verifier != nil {
		origin = verifier.Name()
	}

	var reader tiledReader
	if baseURL.Scheme == "file" {
		reader = &tclient.FileFetcher{Root: baseURL.Path}
	} else {
		httpReader, err := tclient.NewHTTPFetcher(baseURL, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP fetcher for %s: %w", baseURL.String(), err)
		}
		reader = httpReader
	}

	return &TiledFetcher{
		fetcher:  reader,
		verifier: verifier,
		origin:   origin,
	}, nil
}

// Checkpoint reads and validates the latest checkpoint from the log.
func (f *TiledFetcher) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	rawCP, err := f.fetcher.ReadCheckpoint(ctx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}

	var cp *log.Checkpoint
	if f.verifier != nil {
		parsed, _, _, err := log.ParseCheckpoint(rawCP, f.origin, f.verifier)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to verify checkpoint signature: %w", err)
		}
		cp = parsed
	} else {
		parsed, err := parseCheckpointHeaderOnly(rawCP)
		if err != nil {
			metrics.InputFetchErrorsTotal.Inc()
			return nil, fmt.Errorf("failed to parse checkpoint header: %w", err)
		}
		cp = parsed
	}

	f.mu.Lock()
	f.treeSize = cp.Size
	f.mu.Unlock()

	var h [32]byte
	copy(h[:], cp.Hash)

	return &Checkpoint{
		Raw:    rawCP,
		Origin: cp.Origin,
		Size:   cp.Size,
		Hash:   h,
	}, nil
}

// Leaf retrieves a raw leaf from the log's entry bundles.
func (f *TiledFetcher) Leaf(ctx context.Context, idx uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if entry := f.cache.get(idx); entry != nil {
		return entry, nil
	}

	bIdx := idx / layout.EntryBundleWidth
	bundle, err := tclient.GetEntryBundle(ctx, f.fetcher.ReadEntryBundle, bIdx, f.treeSize)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to fetch entry bundle for leaf %d: %w", idx, err)
	}

	p := layout.PartialTileSize(0, bIdx, f.treeSize)
	tileData, err := f.fetcher.ReadTile(ctx, 0, bIdx, p)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to fetch tree tile for leaf %d: %w", idx, err)
	}

	startLeafIdx := bIdx * layout.EntryBundleWidth
	if err := verifyBundleWithTile(&bundle, tileData, startLeafIdx); err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("failed to authenticate entry bundle for leaf %d against tree tile: %w", idx, err)
	}

	ti := idx % layout.EntryBundleWidth
	if int(ti) >= len(bundle.Entries) {
		metrics.InputFetchErrorsTotal.Inc()
		return nil, fmt.Errorf("leaf %d out of bounds in bundle (size %d)", idx, len(bundle.Entries))
	}

	f.cache = leafBundleCache{
		start:  idx - ti,
		leaves: bundle.Entries,
	}

	return bundle.Entries[ti], nil
}

// FetchTiles retrieves bundles of leaves starting at startLeafIdx up to startLeafIdx+count.
func (f *TiledFetcher) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*LeafBundle, error) {
	if count == 0 {
		return nil, nil
	}
	bundleSz := uint64(layout.EntryBundleWidth)
	if bundleSz == 0 {
		bundleSz = 64
	}
	startBundle := startLeafIdx / bundleSz
	endLeaf := startLeafIdx + count
	endBundle := (endLeaf + bundleSz - 1) / bundleSz
	numBundles := endBundle - startBundle
	if numBundles == 0 {
		return nil, nil
	}

	f.mu.Lock()
	treeSize := f.treeSize
	f.mu.Unlock()

	if treeSize > 0 {
		if startLeafIdx >= treeSize {
			return nil, nil
		}
		if endLeaf > treeSize {
			endLeaf = treeSize
		}
		endBundle = (endLeaf + bundleSz - 1) / bundleSz
		numBundles = endBundle - startBundle
		if numBundles == 0 {
			return nil, nil
		}
	}

	bundles := make([]*LeafBundle, numBundles)
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(50)

	for bIdx := startBundle; bIdx < endBundle; bIdx++ {
		bIdx := bIdx
		g.Go(func() error {
			bundle, err := tclient.GetEntryBundle(gCtx, f.fetcher.ReadEntryBundle, bIdx, treeSize)
			if err != nil {
				metrics.InputFetchErrorsTotal.Inc()
				return fmt.Errorf("failed to fetch entry bundle %d: %w", bIdx, err)
			}
			p := layout.PartialTileSize(0, bIdx, treeSize)
			tileData, err := f.fetcher.ReadTile(gCtx, 0, bIdx, p)
			if err != nil {
				metrics.InputFetchErrorsTotal.Inc()
				return fmt.Errorf("failed to fetch tree tile %d: %w", bIdx, err)
			}
			bundleStartIdx := bIdx * bundleSz
			if err := verifyBundleWithTile(&bundle, tileData, bundleStartIdx); err != nil {
				metrics.InputFetchErrorsTotal.Inc()
				return fmt.Errorf("failed to authenticate entry bundle %d against tree tile: %w", bIdx, err)
			}
			bundles[bIdx-startBundle] = &LeafBundle{
				BundleIdx:    bIdx,
				StartLeafIdx: bundleStartIdx,
				Leaves:       bundle.Entries,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	var totalLeavesInBundles int
	for _, b := range bundles {
		if b != nil {
			totalLeavesInBundles += len(b.Leaves)
		}
	}
	metrics.LeavesDownloadedTotal.Add(float64(totalLeavesInBundles))

	return bundles, nil
}

func verifyBundleWithTile(bundle *api.EntryBundle, tileData []byte, startLeafIdx uint64) error {
	expectedTileLen := len(bundle.Entries) * 32
	if len(tileData) != expectedTileLen {
		return fmt.Errorf("tile data length %d mismatch with entry count %d (expected %d bytes)", len(tileData), len(bundle.Entries), expectedTileLen)
	}
	for j, leaf := range bundle.Entries {
		leafHash := tlog.RecordHash(leaf)
		expectedHash := tileData[j*32 : (j+1)*32]
		if !bytes.Equal(leafHash[:], expectedHash) {
			return fmt.Errorf("leaf %d hash mismatch: got %x, want %x", startLeafIdx+uint64(j), leafHash[:], expectedHash)
		}
	}
	return nil
}

func parseCheckpointHeaderOnly(rawCP []byte) (*log.Checkpoint, error) {
	lines := strings.Split(string(bytes.TrimRight(rawCP, "\n")), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("checkpoint header has %d lines, want at least 3", len(lines))
	}
	origin := lines[0]
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size %q: %w", lines[1], err)
	}
	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 hash %q: %w", lines[2], err)
	}
	return &log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hashBytes,
	}, nil
}
