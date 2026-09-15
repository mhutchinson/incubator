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

package tree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"

	torchmpt "filippo.io/torchwood/mpt"
	"golang.org/x/sync/errgroup"
)

// Manager manages a Merkle Patricia Trie with thread-safe read access and lock-free root prediction.
type Manager struct {
	writeMu     sync.RWMutex // Serializes Commit, Persist, and Close operations
	treeMu      sync.RWMutex // Protects in-memory trie operations (Prove, Predict, Snap, root swaps)
	tree        torchmpt.Tree
	mmapDir     string
	currentRoot [sha256.Size]byte
}

// Open opens an existing MPT in the specified directory or creates a new one.
// If mmapDir is empty or ":memory:", an in-memory tree is used.
func Open(mmapDir string) (*Manager, error) {
	var tree torchmpt.Tree
	if mmapDir == "" || mmapDir == ":memory:" {
		tree = torchmpt.NewMemTree()
	} else {
		if err := os.MkdirAll(mmapDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create mmap dir: %w", err)
		}
		file1 := filepath.Join(mmapDir, "mpt.tree1")
		file2 := filepath.Join(mmapDir, "mpt.tree2")
		disk := filepath.Join(mmapDir, "mpt.disk")

		var openErr error
		tree, openErr = torchmpt.Open(file1, file2, disk)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				var createErr error
				tree, createErr = torchmpt.Create(file1, file2, disk)
				if createErr != nil {
					return nil, fmt.Errorf("torchmpt.Create failed: %w", createErr)
				}
			} else {
				return nil, fmt.Errorf("torchmpt.Open failed: %w", openErr)
			}
		}
	}

	snap, err := tree.Snap(-1)
	if err != nil {
		return nil, fmt.Errorf("initial Snap failed: %w", err)
	}

	return &Manager{
		tree:        tree,
		mmapDir:     mmapDir,
		currentRoot: [sha256.Size]byte(snap.Hash),
	}, nil
}

// NewMem creates a new in-memory MPT manager.
func NewMem() *Manager {
	mgr, _ := Open("")
	return mgr
}

// NewManager opens an existing MPT in the specified directory or creates a new one (alias for Open).
func NewManager(mmapDir string) (*Manager, error) {
	return Open(mmapDir)
}


// RLock acquires the read lock.
func (m *Manager) RLock() {
	m.treeMu.RLock()
}

// RUnlock releases the read lock.
func (m *Manager) RUnlock() {
	m.treeMu.RUnlock()
}

// Lock acquires the write lock.
func (m *Manager) Lock() {
	m.writeMu.Lock()
	m.treeMu.Lock()
}

// Unlock releases the write lock.
func (m *Manager) Unlock() {
	m.treeMu.Unlock()
	m.writeMu.Unlock()
}

// Root returns the current MPT root hash.
func (m *Manager) Root() [sha256.Size]byte {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.currentRoot
}

// SortKeyVals sorts changes by Key using parallel bucket sort across CPU cores when size is large.
func SortKeyVals(changes []torchmpt.KeyVal) {
	const parallelThreshold = 8192
	if len(changes) < parallelThreshold {
		slices.SortFunc(changes, func(a, b torchmpt.KeyVal) int {
			return bytes.Compare(a.Key[:], b.Key[:])
		})
		return
	}

	var counts [256]int
	for i := range changes {
		counts[changes[i].Key[0]]++
	}

	var offsets [257]int
	for i := 0; i < 256; i++ {
		offsets[i+1] = offsets[i] + counts[i]
	}

	aux := make([]torchmpt.KeyVal, len(changes))
	cursor := offsets
	for i := range changes {
		b := changes[i].Key[0]
		aux[cursor[b]] = changes[i]
		cursor[b]++
	}

	var g errgroup.Group
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	bucketChunk := (256 + workers - 1) / workers
	for w := 0; w < workers; w++ {
		bStart := w * bucketChunk
		bEnd := bStart + bucketChunk
		if bEnd > 256 {
			bEnd = 256
		}
		if bStart >= 256 {
			break
		}
		g.Go(func() error {
			for b := bStart; b < bEnd; b++ {
				start := offsets[b]
				end := offsets[b+1]
				if end-start > 1 {
					slices.SortFunc(aux[start:end], func(a, b torchmpt.KeyVal) int {
						return bytes.Compare(a.Key[:], b.Key[:])
					})
				}
			}
			return nil
		})
	}
	_ = g.Wait()
	copy(changes, aux)
}

// Predict calculates the MPT root hash that would result from applying mutations without modifying the tree.
func (m *Manager) Predict(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error) {
	if len(mutations) == 0 {
		return m.Root(), nil
	}

	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(v),
		})
	}
	SortKeyVals(changes)

	return m.PredictKeyVals(changes)
}

// PredictKeyVals calculates the MPT root hash that would result from applying sorted changes without modifying the tree.
func (m *Manager) PredictKeyVals(changes []torchmpt.KeyVal) ([sha256.Size]byte, error) {
	if len(changes) == 0 {
		return m.Root(), nil
	}

	m.treeMu.RLock()
	defer m.treeMu.RUnlock()

	hash, err := m.tree.Predict(changes)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Predict failed: %w", err)
	}
	return [sha256.Size]byte(hash), nil
}

// Update inserts or updates a single key-value pair in the MPT.
func (m *Manager) Update(keyHash [sha256.Size]byte, valHash [sha256.Size]byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if err := m.tree.Set(torchmpt.Key(keyHash), torchmpt.Val(valHash)); err != nil {
		return fmt.Errorf("tree.Set failed: %w", err)
	}
	snap, err := m.tree.Snap(-1)
	if err != nil {
		return fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	return nil
}

// SetBatch applies mutations directly to the working tree under writeMu without creating a snapshot.
func (m *Manager) SetBatch(mutations map[[sha256.Size]byte][sha256.Size]byte) error {
	if len(mutations) == 0 {
		return nil
	}
	keys := make([][sha256.Size]byte, 0, len(mutations))
	for k := range mutations {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [sha256.Size]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	for _, k := range keys {
		v := mutations[k]
		if err := m.tree.Set(torchmpt.Key(k), torchmpt.Val(v)); err != nil {
			return fmt.Errorf("tree.Set failed for key %x: %w", k, err)
		}
	}
	return nil
}

// Snap creates a snapshot at the specified version, updates currentRoot, and returns the root hash.
func (m *Manager) Snap(version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	return m.currentRoot, nil
}

// Commit applies mutations to the MPT under the write lock and returns the new root hash.
func (m *Manager) Commit(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error) {
	return m.CommitWithVersion(mutations, -1)
}

// CommitWithVersion applies mutations, records the version watermark, and returns the new root hash.
func (m *Manager) CommitWithVersion(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	return m.commitLocked(mutations, version)
}

// CommitWithVersionLocked applies mutations without acquiring the lock (caller must hold m.Lock()).
func (m *Manager) CommitWithVersionLocked(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	return m.commitLocked(mutations, version)
}

// CommitKeyValsLocked applies sorted changes directly without acquiring the lock (caller must hold m.Lock()).
func (m *Manager) CommitKeyValsLocked(changes []torchmpt.KeyVal, version int64) ([sha256.Size]byte, error) {
	for _, kv := range changes {
		if err := m.tree.Set(kv.Key, kv.Val); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("tree.Set failed for key %x: %w", kv.Key, err)
		}
	}

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	return m.currentRoot, nil
}

func (m *Manager) commitLocked(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	if len(mutations) > 0 {
		keys := make([][sha256.Size]byte, 0, len(mutations))
		for k := range mutations {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b [sha256.Size]byte) int {
			return bytes.Compare(a[:], b[:])
		})

		for _, k := range keys {
			v := mutations[k]
			if err := m.tree.Set(torchmpt.Key(k), torchmpt.Val(v)); err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("tree.Set failed for key %x: %w", k, err)
			}
		}
	}

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	return m.currentRoot, nil
}

// Prove generates an inclusion or non-inclusion proof for the given keyHash.
func (m *Manager) Prove(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error) {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.ProveLocked(keyHash)
}

// ProveLocked generates an inclusion or non-inclusion proof without acquiring the lock (caller must hold m.RLock()).
func (m *Manager) ProveLocked(keyHash [sha256.Size]byte) (proof []byte, subRoot [sha256.Size]byte, exists bool, err error) {
	val, ok, p, err := m.tree.Prove(torchmpt.Key(keyHash))
	if err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	return []byte(p), [sha256.Size]byte(val), ok, nil
}

// Version returns the version number of the MPT's last complete snapshot and whether it is exact.
func (m *Manager) Version() (int64, bool) {
	m.writeMu.RLock()
	defer m.writeMu.RUnlock()
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.tree.Version()
}

// PersistedVersion returns the version number of the MPT's last complete snapshot.
func (m *Manager) PersistedVersion() int64 {
	v, _ := m.Version()
	return v
}

// PersistedSize returns the tree size corresponding to the persisted version.
func (m *Manager) PersistedSize() uint64 {
	v := m.PersistedVersion()
	if v > 0 {
		return uint64(v)
	}
	return 0
}

// Persist flushes changes to disk under writeMu without holding treeMu,
// ensuring background disk sync operations never block concurrent Prove/ProveLocked lookups.
func (m *Manager) Persist() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.tree.Sync()
}

// Sync flushes changes to disk under writeMu (alias for Persist).
func (m *Manager) Sync() error {
	return m.Persist()
}

// Close closes the underlying MPT files.
func (m *Manager) Close() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	_ = m.tree.Sync()
	return m.tree.Close()
}

// Verify verifies an inclusion or non-inclusion proof against an MPT root hash.
func Verify(root [sha256.Size]byte, keyHash [sha256.Size]byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	snap := torchmpt.Snapshot{
		Hash:    torchmpt.Hash(root),
		Version: -1,
	}
	var val []byte
	if exists {
		val = valHash[:]
	}
	return torchmpt.Verify(snap, keyHash[:], val, exists, torchmpt.Proof(proof))
}
