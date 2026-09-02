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

package coordinator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

// TestStress_ConsecutiveCheckpoints_BatchCatchup verifies that SyncOnce properly
// ratchets through a series of consecutive checkpoints, correctly accumulating
// KV chunks, MPT roots, and Output Log entries without state drift.
func TestStress_ConsecutiveCheckpoints_BatchCatchup(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, pub, indexer, outLog, fetcher := setupRecoveryEnvironment(t)

	// Step sizes for consecutive checkpoints
	stepSizes := []int{10, 25, 40, 75, 120, 160, 200}

	for stepIdx, targetSize := range stepSizes {
		fetcher.mu.Lock()
		fetcher.leaves = make([][]byte, targetSize)
		for i := 0; i < targetSize; i++ {
			fetcher.leaves[i] = []byte(fmt.Sprintf("key_consec_%04d", i%30))
		}
		fetcher.mu.Unlock()

		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("step %d (size %d): SyncOnce failed: %v", stepIdx, targetSize, err)
		}

		// Verify m_kv_size matches targetSize
		kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
		if err != nil {
			t.Fatalf("step %d: failed to read m_kv_size: %v", stepIdx, err)
		}
		if kvSize != uint64(targetSize) {
			t.Fatalf("step %d: m_kv_size = %d, want %d", stepIdx, kvSize, targetSize)
		}

		// Verify MPT size
		if mptMgr.PersistedSize() != uint64(targetSize) {
			t.Fatalf("step %d: MPT size = %d, want %d", stepIdx, mptMgr.PersistedSize(), targetSize)
		}

		// Verify Output Log size
		outSize, err := outLog.Size(ctx)
		if err != nil {
			t.Fatalf("step %d: outLog.Size failed: %v", stepIdx, err)
		}
		if outSize != uint64(stepIdx+1) {
			t.Fatalf("step %d: outSize = %d, want %d", stepIdx, outSize, stepIdx+1)
		}

		// Verify serving state matches
		state := pub.GetServingState()
		if state == nil {
			t.Fatalf("step %d: serving state is nil", stepIdx)
		}
		if state.InputLogSize != uint64(targetSize) {
			t.Fatalf("step %d: state.InputLogSize = %d, want %d", stepIdx, state.InputLogSize, targetSize)
		}
		if state.MapRoot != mptMgr.Root() {
			t.Fatalf("step %d: state.MapRoot != mptMgr.Root()", stepIdx)
		}

		// Verify subroot retrieval for an existing key
		testKey := sha256.Sum256([]byte("key_consec_0000"))
		subRoot, err := indexer.GetSubRoot(testKey, uint64(targetSize))
		if err != nil {
			t.Fatalf("step %d: GetSubRoot failed: %v", stepIdx, err)
		}
		if subRoot == [32]byte{} {
			t.Fatalf("step %d: empty subroot for existing key", stepIdx)
		}
	}
}

// TestStress_CatchupSkippedCheckpoints verifies that when the input log has advanced
// through several intermediate checkpoints while the coordinator was idle, a single
// SyncOnce correctly catches up across the entire delta in one go.
func TestStress_CatchupSkippedCheckpoints(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, pub, _, outLog, fetcher := setupRecoveryEnvironment(t)

	// Ingest first 20 leaves
	fetcher.mu.Lock()
	fetcher.leaves = make([][]byte, 20)
	for i := 0; i < 20; i++ {
		fetcher.leaves[i] = []byte(fmt.Sprintf("skip_leaf_%d", i))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce failed: %v", err)
	}

	// Now advance fetcher directly to 180 leaves (simulating skipping intermediate checkpoints)
	fetcher.mu.Lock()
	fetcher.leaves = make([][]byte, 180)
	for i := 0; i < 180; i++ {
		fetcher.leaves[i] = []byte(fmt.Sprintf("skip_leaf_%d", i))
	}
	fetcher.mu.Unlock()

	// Single SyncOnce catches up from 20 to 180
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("catch-up SyncOnce failed: %v", err)
	}

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		t.Fatalf("GetUint64 failed: %v", err)
	}
	if kvSize != 180 {
		t.Fatalf("m_kv_size = %d, want 180", kvSize)
	}

	if mptMgr.PersistedSize() != 180 {
		t.Fatalf("MPT persisted size = %d, want 180", mptMgr.PersistedSize())
	}

	outSize, err := outLog.Size(ctx)
	if err != nil || outSize != 2 {
		t.Fatalf("outLog size = %d, want 2", outSize)
	}

	state := pub.GetServingState()
	if state == nil || state.InputLogSize != 180 {
		t.Fatalf("state.InputLogSize = %v, want 180", state)
	}
}

// TestStress_IdempotentSync verifies that calling SyncOnce repeatedly when no new
// input leaves are available is a no-op that does not write spurious output log entries.
func TestStress_IdempotentSync(t *testing.T) {
	ctx := context.Background()
	coord, _, _, _, _, outLog, fetcher := setupRecoveryEnvironment(t)

	fetcher.mu.Lock()
	fetcher.leaves = make([][]byte, 50)
	for i := 0; i < 50; i++ {
		fetcher.leaves[i] = []byte(fmt.Sprintf("idem_leaf_%d", i))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce failed: %v", err)
	}

	outSize1, _ := outLog.Size(ctx)
	if outSize1 != 1 {
		t.Fatalf("outLog size after first sync = %d, want 1", outSize1)
	}

	// Repeat 5 times without new leaves
	for i := 0; i < 5; i++ {
		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("idempotent SyncOnce %d failed: %v", i, err)
		}
		outSizeN, _ := outLog.Size(ctx)
		if outSizeN != 1 {
			t.Fatalf("outLog size changed on idempotent sync %d: got %d, want 1", i, outSizeN)
		}
	}
}

// TestStress_UnalignedCheckpoints tests checkpoints with sizes that do not align
// with standard tile boundaries (e.g. 1, 7, 15, 17, 31, 33, 63, 65, 127, 129, 199).
func TestStress_UnalignedCheckpoints(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, pub, _, outLog, fetcher := setupRecoveryEnvironment(t)

	unalignedSizes := []int{1, 7, 15, 17, 31, 33, 63, 65, 127, 129, 199}

	for _, sz := range unalignedSizes {
		fetcher.mu.Lock()
		fetcher.leaves = make([][]byte, sz)
		for i := 0; i < sz; i++ {
			fetcher.leaves[i] = []byte(fmt.Sprintf("unaligned_%04d", i))
		}
		fetcher.mu.Unlock()

		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce at unaligned size %d failed: %v", sz, err)
		}

		kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
		if err != nil {
			t.Fatalf("size %d: GetUint64 failed: %v", sz, err)
		}
		if kvSize != uint64(sz) {
			t.Fatalf("size %d: m_kv_size = %d, want %d", sz, kvSize, sz)
		}

		if mptMgr.PersistedSize() != uint64(sz) {
			t.Fatalf("size %d: MPT persisted size = %d, want %d", sz, mptMgr.PersistedSize(), sz)
		}

		state := pub.GetServingState()
		if state == nil || state.InputLogSize != uint64(sz) {
			t.Fatalf("size %d: state.InputLogSize = %v, want %d", sz, state, sz)
		}
	}

	totalOutLog, _ := outLog.Size(ctx)
	if totalOutLog != uint64(len(unalignedSizes)) {
		t.Fatalf("outLog size = %d, want %d", totalOutLog, len(unalignedSizes))
	}
}

// TestStress_RapidRestarts simulates repeated crash/restart cycles during active ingestion,
// verifying Phase 1 instant recovery and state consistency after each reboot.
func TestStress_RapidRestarts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	const cycles = 6
	leafCount := 0

	for cycle := 0; cycle < cycles; cycle++ {
		// Open DB and MPT on the persistent directory
		db, err := kvstore.Open(dir, &pebble.Options{})
		if err != nil {
			t.Fatalf("cycle %d: kvstore.Open failed: %v", cycle, err)
		}
		mptMgr := tree.NewMem()
		outLog := newMemoryOutputLog("example.com/outputlog")
		pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
		indexer := kvstore.NewKVIndexer(db, 64)

		// Generate additional leaves
		leafCount += 25
		leaves := make([][]byte, leafCount)
		for i := 0; i < leafCount; i++ {
			leaves[i] = []byte(fmt.Sprintf("rapid_restart_leaf_%d", i))
		}
		fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
		mapper := &simpleIdentityMapper{}

		coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)

		// Perform recovery
		if err := coord.Recover(ctx); err != nil {
			t.Fatalf("cycle %d: Recover failed: %v", cycle, err)
		}

		// Perform sync
		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("cycle %d: SyncOnce failed: %v", cycle, err)
		}

		// Verify state
		kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
		if err != nil || kvSize != uint64(leafCount) {
			t.Fatalf("cycle %d: m_kv_size = %d, want %d", cycle, kvSize, leafCount)
		}

		// Simulate abrupt shutdown by closing DB
		if err := db.Close(); err != nil {
			t.Fatalf("cycle %d: db.Close failed: %v", cycle, err)
		}
	}
}

// TestStress_Phase2_LaggingMPTRecovery simulates a crash where the Output Log and KV store
// advanced, but the MPT was not flushed to disk before crash (Phase 2 replay required).
func TestStress_Phase2_LaggingMPTRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	mptMgr := tree.NewMem()
	outLog := newMemoryOutputLog("example.com/outputlog")
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	indexer := kvstore.NewKVIndexer(db, 64)

	leaves := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		leaves[i] = []byte(fmt.Sprintf("lagging_mpt_leaf_%d", i%15))
	}
	fetcher := &memoryTileFetcher{leaves: leaves, origin: "example.com/inputlog"}
	mapper := &simpleIdentityMapper{}

	coord := NewCoordinator(db, mptMgr, outLog, pub, indexer, fetcher, nil, mapper)

	// Step 1: Ingest all 80 leaves normally
	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce failed: %v", err)
	}

	state := pub.GetServingState()
	expectedRoot := state.MapRoot

	// Step 2: Simulate crash where MPT was reset to size 0 (or lagged behind)
	freshMPTMgr := tree.NewMem()
	freshPub := tree.NewOutputPublisher(db, freshMPTMgr, outLog, nil)

	// Coordinator with fresh (empty) MPT
	recCoord := NewCoordinator(db, freshMPTMgr, outLog, freshPub, indexer, fetcher, nil, mapper)

	// Recover should trigger Phase 2 replay from tile cache/fetcher and update MPT to size 80
	if err := recCoord.Recover(ctx); err != nil {
		t.Fatalf("Recover with lagging MPT failed: %v", err)
	}

	// Verify MPT root matches expected root from Output Log
	if freshMPTMgr.Root() != expectedRoot {
		t.Fatalf("replayed MPT root %x != expected root %x", freshMPTMgr.Root(), expectedRoot)
	}
	if freshMPTMgr.PersistedSize() != 80 {
		t.Fatalf("replayed MPT persisted size = %d, want 80", freshMPTMgr.PersistedSize())
	}

	recState := freshPub.GetServingState()
	if recState == nil || recState.MapRoot != expectedRoot {
		t.Fatalf("replayed serving state root mismatch: got %x, want %x", recState.MapRoot, expectedRoot)
	}

	_ = db.Close()
}

// TestStress_Phase3_CatchupRecovery simulates a crash where m_target_checkpoint was set
// but KV indexing crashed before finishing (m_kv_size < targetCP.Size).
func TestStress_Phase3_CatchupRecovery(t *testing.T) {
	ctx := context.Background()
	coord, db, _, _, _, _, fetcher := setupRecoveryEnvironment(t)

	t.Log("Starting Phase 3 test: ingesting 40 leaves")
	// Ingest 40 leaves
	fetcher.mu.Lock()
	fetcher.leaves = make([][]byte, 40)
	for i := 0; i < 40; i++ {
		fetcher.leaves[i] = []byte(fmt.Sprintf("phase3_leaf_%d", i))
	}
	fetcher.mu.Unlock()

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce failed: %v", err)
	}
	t.Log("SyncOnce for 40 leaves completed")

	// Simulate crash: advance target checkpoint in DB to size 75 without indexing
	fetcher.mu.Lock()
	fetcher.leaves = make([][]byte, 75)
	for i := 0; i < 75; i++ {
		fetcher.leaves[i] = []byte(fmt.Sprintf("phase3_leaf_%d", i))
	}
	fetcher.mu.Unlock()

	cp, _ := fetcher.Checkpoint(ctx)

	if err := db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, cp.Raw); err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
	t.Log("Target checkpoint set in DB to 75. Calling coord.Recover(ctx)")

	// Run Recover: Phase 3 should detect m_kv_size (40) < targetCP.Size (75) and catch up
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("Recover phase 3 catchup failed: %v", err)
	}
	t.Log("coord.Recover(ctx) completed")

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil || kvSize != 75 {
		t.Fatalf("m_kv_size after Phase 3 = %d, want 75", kvSize)
	}
	t.Log("Phase 3 test complete!")
}

// TestStress_MultipleSequentialAndInterleavedSyncs tests rapid sequential SyncOnce invocations
// with randomized increments of leaves to stress boundary conditions and active chunk caching.
func TestStress_MultipleSequentialAndInterleavedSyncs(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, _, _, _, fetcher := setupRecoveryEnvironment(t)

	rng := rand.New(rand.NewSource(999))
	currentLeaves := 0

	for i := 0; i < 20; i++ {
		delta := rng.Intn(15) // 0 to 14 leaves added
		currentLeaves += delta

		fetcher.mu.Lock()
		fetcher.leaves = make([][]byte, currentLeaves)
		for j := 0; j < currentLeaves; j++ {
			fetcher.leaves[j] = []byte(fmt.Sprintf("interleaved_leaf_%d", j%10))
		}
		fetcher.mu.Unlock()

		if err := coord.SyncOnce(ctx); err != nil {
			t.Fatalf("iteration %d (leaves %d): SyncOnce failed: %v", i, currentLeaves, err)
		}

		kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
		if err != nil {
			t.Fatalf("iteration %d: GetUint64 failed: %v", i, err)
		}
		if kvSize != uint64(currentLeaves) {
			t.Fatalf("iteration %d: m_kv_size = %d, want %d", i, kvSize, currentLeaves)
		}
		if mptMgr.PersistedSize() != uint64(currentLeaves) {
			t.Fatalf("iteration %d: MPT size = %d, want %d", i, mptMgr.PersistedSize(), currentLeaves)
		}
	}
}

// TestStress_MultipleCallersSyncOnce tests multiple callers requesting synchronization
// through a serialized coordinator sync loop, confirming that all syncs complete cleanly
// without data races or state corruption.
func TestStress_MultipleCallersSyncOnce(t *testing.T) {
	ctx := context.Background()
	coord, db, mptMgr, pub, _, outLog, fetcher := setupRecoveryEnvironment(t)

	const numCallers = 6
	var wg sync.WaitGroup
	var callerMu sync.Mutex
	var successCount int64

	wg.Add(numCallers)
	for i := 0; i < numCallers; i++ {
		callerID := i
		go func() {
			defer wg.Done()
			// Each caller generates additional leaves and triggers a sync under serialized execution
			callerMu.Lock()
			defer callerMu.Unlock()

			fetcher.mu.Lock()
			newSize := len(fetcher.leaves) + 15
			for len(fetcher.leaves) < newSize {
				fetcher.leaves = append(fetcher.leaves, []byte(fmt.Sprintf("caller_%d_leaf_%d", callerID, len(fetcher.leaves))))
			}
			fetcher.mu.Unlock()

			if err := coord.SyncOnce(ctx); err != nil {
				t.Errorf("caller %d: SyncOnce failed: %v", callerID, err)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != int64(numCallers) {
		t.Fatalf("successCount = %d, want %d", successCount, numCallers)
	}

	fetcher.mu.Lock()
	expectedLeaves := uint64(len(fetcher.leaves))
	fetcher.mu.Unlock()

	kvSize, _ := db.GetUint64(kvstore.KeyMetaKVSize)
	if kvSize != expectedLeaves {
		t.Fatalf("m_kv_size = %d, want %d", kvSize, expectedLeaves)
	}
	if mptMgr.PersistedSize() != expectedLeaves {
		t.Fatalf("MPT size = %d, want %d", mptMgr.PersistedSize(), expectedLeaves)
	}
	outSize, _ := outLog.Size(ctx)
	if outSize != uint64(numCallers) {
		t.Fatalf("outLog size = %d, want %d", outSize, numCallers)
	}
	state := pub.GetServingState()
	if state == nil || state.InputLogSize != expectedLeaves {
		t.Fatalf("state.InputLogSize = %v, want %d", state, expectedLeaves)
	}
}
