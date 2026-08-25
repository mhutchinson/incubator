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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ManagedTileCache manages local filesystem and in-memory tile bundle caching.
type ManagedTileCache struct {
	mu       sync.RWMutex
	cacheDir string
	memory   map[uint64]*LeafBundle
	bundleSz uint64
}

// NewManagedTileCache creates a new ManagedTileCache.
func NewManagedTileCache(cacheDir string, bundleSz uint64) (*ManagedTileCache, error) {
	if bundleSz == 0 {
		bundleSz = DefaultBundleSize
	}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create tile cache dir %q: %w", cacheDir, err)
		}
	}
	return &ManagedTileCache{
		cacheDir: cacheDir,
		memory:   make(map[uint64]*LeafBundle),
		bundleSz: bundleSz,
	}, nil
}

// GetBundle retrieves a LeafBundle from memory or disk cache.
func (c *ManagedTileCache) GetBundle(bundleIdx uint64) (*LeafBundle, error) {
	if c.cacheDir == "" {
		c.mu.RLock()
		b, ok := c.memory[bundleIdx]
		c.mu.RUnlock()
		if ok {
			return b, nil
		}
		return nil, ErrBundleNotFound
	}

	bundlePath := filepath.Join(c.cacheDir, fmt.Sprintf("bundle_%016d.dat", bundleIdx))
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBundleNotFound
		}
		return nil, err
	}

	return unmarshalBundle(data, bundleIdx)
}

// PutBundle stores a LeafBundle on disk (or in memory if cacheDir is not configured).
func (c *ManagedTileCache) PutBundle(bundle *LeafBundle) error {
	if bundle == nil {
		return nil
	}

	if c.cacheDir == "" {
		c.mu.Lock()
		c.memory[bundle.BundleIdx] = bundle
		c.mu.Unlock()
		return nil
	}

	data := marshalBundle(bundle)
	bundlePath := filepath.Join(c.cacheDir, fmt.Sprintf("bundle_%016d.dat", bundle.BundleIdx))
	return os.WriteFile(bundlePath, data, 0o644)
}

// DirSize calculates the total size in bytes of files stored in the cacheDir.
func (c *ManagedTileCache) DirSize() (int64, error) {
	if c == nil || c.cacheDir == "" {
		return 0, nil
	}
	var totalSize int64
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		totalSize += info.Size()
	}
	return totalSize, nil
}

// PruneBefore prunes all cached bundles whose leaf range is strictly below the given watermark.
func (c *ManagedTileCache) PruneBefore(watermark uint64) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prunedCount := 0
	for bIdx, b := range c.memory {
		endIdx := b.StartLeafIdx + uint64(len(b.Leaves))
		if endIdx <= watermark {
			delete(c.memory, bIdx)
			prunedCount++
		}
	}

	if c.cacheDir != "" {
		entries, err := os.ReadDir(c.cacheDir)
		if err != nil {
			return prunedCount, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "bundle_") || !strings.HasSuffix(entry.Name(), ".dat") {
				continue
			}
			var bIdx uint64
			if _, err := fmt.Sscanf(entry.Name(), "bundle_%016d.dat", &bIdx); err == nil {
				endIdx := (bIdx + 1) * c.bundleSz
				if endIdx <= watermark {
					if err := os.Remove(filepath.Join(c.cacheDir, entry.Name())); err == nil {
						prunedCount++
					}
				}
			}
		}
	}

	return prunedCount, nil
}

func marshalBundle(b *LeafBundle) []byte {
	var totalLeavesLen int
	for _, l := range b.Leaves {
		totalLeavesLen += 4 + len(l)
	}
	buf := make([]byte, 12+totalLeavesLen)
	binary.BigEndian.PutUint64(buf[0:8], b.StartLeafIdx)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(b.Leaves)))
	offset := 12
	for _, l := range b.Leaves {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(l)))
		offset += 4
		copy(buf[offset:offset+len(l)], l)
		offset += len(l)
	}
	return buf
}

func unmarshalBundle(data []byte, bundleIdx uint64) (*LeafBundle, error) {
	if len(data) < 12 {
		return nil, errors.New("bundle data too short")
	}
	startLeafIdx := binary.BigEndian.Uint64(data[0:8])
	numLeaves := binary.BigEndian.Uint32(data[8:12])
	leaves := make([][]byte, 0, numLeaves)
	offset := 12
	for i := uint32(0); i < numLeaves; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("bundle truncated")
		}
		lLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+lLen > len(data) {
			return nil, errors.New("bundle leaf truncated")
		}
		leaf := make([]byte, lLen)
		copy(leaf, data[offset:offset+lLen])
		leaves = append(leaves, leaf)
		offset += lLen
	}
	return &LeafBundle{
		BundleIdx:    bundleIdx,
		StartLeafIdx: startLeafIdx,
		Leaves:       leaves,
	}, nil
}
