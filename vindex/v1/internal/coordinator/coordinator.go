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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

const (
	// DefaultCommitBatchSize is the default number of leaves aggregated before committing to the KV store (16 tiles).
	DefaultCommitBatchSize uint64 = 4096 // 16 tiles (256 * 16)

	// DefaultCoarseCheckpointInterval is the default leaf interval between coarse checkpoints during Genesis Backfill.
	DefaultCoarseCheckpointInterval uint64 = 50000000

	// DefaultBackfillMaxPendingKeys is the default maximum number of deduplicated modified keys
	// buffered in memory before flushing to the MPT during Genesis Backfill (~5.5 GB RAM).
	DefaultBackfillMaxPendingKeys uint64 = 50000000
)

// Coordinator manages the 3-phase startup and crash recovery workflow.
type Coordinator struct {
	db                        *kvstore.DB
	mptMgr                    *tree.Manager
	outputLog                 OutputLogReader
	pub                       *tree.OutputPublisher
	indexer                   *kvstore.KVIndexer
	fetcher                   ingest.TileFetcher
	cache                     ingest.TileCache
	mapper                    ingest.LeafMapper
	pipeline                  *ingest.IngestionPipeline
	commitBatchSize           uint64
	coarseCheckpointInterval  uint64
	backfillMaxPendingKeys    uint64
	fetchWorkers              int
	fetchBatchBundles         int
}

// NewCoordinator creates a new recovery Coordinator.
func NewCoordinator(
	db *kvstore.DB,
	mptMgr *tree.Manager,
	outputLog OutputLogReader,
	pub *tree.OutputPublisher,
	indexer *kvstore.KVIndexer,
	fetcher ingest.TileFetcher,
	cache ingest.TileCache,
	mapper ingest.LeafMapper,
) *Coordinator {
	var pipeline *ingest.IngestionPipeline
	if fetcher != nil && mapper != nil {
		pipeline = ingest.NewPipeline(fetcher, cache, mapper, 0)
	}
	return &Coordinator{
		db:                       db,
		mptMgr:                   mptMgr,
		outputLog:                outputLog,
		pub:                      pub,
		indexer:                  indexer,
		fetcher:                  fetcher,
		cache:                    cache,
		mapper:                   mapper,
		pipeline:                 pipeline,
		commitBatchSize:          DefaultCommitBatchSize,
		coarseCheckpointInterval: DefaultCoarseCheckpointInterval,
	}
}

// SetCommitBatchSize sets the commit batch size for leaf aggregation.
func (c *Coordinator) SetCommitBatchSize(size uint64) {
	if size == 0 {
		size = DefaultCommitBatchSize
	}
	c.commitBatchSize = size
}

// CommitBatchSize returns the configured commit batch size.
func (c *Coordinator) CommitBatchSize() uint64 {
	if c.commitBatchSize == 0 {
		return DefaultCommitBatchSize
	}
	return c.commitBatchSize
}

// SetCoarseCheckpointInterval sets the coarse checkpoint interval for Genesis Backfill.
func (c *Coordinator) SetCoarseCheckpointInterval(interval uint64) {
	if interval == 0 {
		interval = DefaultCoarseCheckpointInterval
	}
	c.coarseCheckpointInterval = interval
}

// CoarseCheckpointInterval returns the configured coarse checkpoint interval.
func (c *Coordinator) CoarseCheckpointInterval() uint64 {
	if c.coarseCheckpointInterval == 0 {
		return DefaultCoarseCheckpointInterval
	}
	return c.coarseCheckpointInterval
}

// SetBackfillMaxPendingKeys sets the maximum number of deduplicated keys buffered during Genesis Backfill.
func (c *Coordinator) SetBackfillMaxPendingKeys(maxKeys uint64) {
	if maxKeys == 0 {
		maxKeys = DefaultBackfillMaxPendingKeys
	}
	c.backfillMaxPendingKeys = maxKeys
}

// BackfillMaxPendingKeys returns the configured maximum number of deduplicated keys buffered during Genesis Backfill.
func (c *Coordinator) BackfillMaxPendingKeys() uint64 {
	if c.backfillMaxPendingKeys == 0 {
		return DefaultBackfillMaxPendingKeys
	}
	return c.backfillMaxPendingKeys
}

// SafeWatermark returns min(m_kv_size, MPT.PersistedSize()).
func (c *Coordinator) SafeWatermark(_ context.Context) (uint64, error) {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()
	return min(kvSize, mptPersistedSize), nil
}

// SetFetchWorkers sets the number of concurrent tile fetch workers for the pipeline.
func (c *Coordinator) SetFetchWorkers(n int) {
	if n < 1 {
		n = 1
	}
	c.fetchWorkers = n
	if c.pipeline != nil {
		c.pipeline.SetFetchWorkers(n)
	}
}

// FetchWorkers returns the configured number of tile fetch workers.
func (c *Coordinator) FetchWorkers() int {
	if c.fetchWorkers <= 0 {
		return ingest.DefaultFetchWorkers()
	}
	return c.fetchWorkers
}

// SetFetchBatchBundles sets the number of bundles fetched per worker batch in Stage 1.
func (c *Coordinator) SetFetchBatchBundles(n int) {
	if n < 1 {
		n = 1
	}
	c.fetchBatchBundles = n
	if c.pipeline != nil {
		c.pipeline.SetFetchBatchBundles(n)
	}
}

// FetchBatchBundles returns the configured number of bundles fetched per worker batch.
func (c *Coordinator) FetchBatchBundles() int {
	if c.fetchBatchBundles <= 0 {
		return ingest.DefaultFetchBatchBundles()
	}
	return c.fetchBatchBundles
}

// Recover runs the recovery sequence:
// 1. If output log has size 0, executes Genesis Backfill dirty crash recovery if needed.
// 2. Phase 1: Tip match check (< 5ms fast serve on clean shutdown).
// 3. Phase 2: If tip did not match, replay missing tiles up to Output Log tip, verify, and promote serving state.
// 4. Phase 3: Resume background pipeline.
func (c *Coordinator) Recover(ctx context.Context) error {
	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}

	if outSize == 0 {
		return c.recoverGenesisBackfill(ctx)
	}

	matched, err := c.Phase1(ctx)
	if err != nil {
		return fmt.Errorf("phase 1 recovery failed: %w", err)
	}

	if !matched {
		if err := c.Phase2(ctx, outSize); err != nil {
			return fmt.Errorf("phase 2 recovery failed: %w", err)
		}
	}

	if err := c.Phase3(ctx); err != nil {
		return fmt.Errorf("phase 3 recovery failed: %w", err)
	}

	return nil
}

// recoverGenesisBackfill handles crash recovery when outputLog.Size() == 0.
// If mptPersistedSize < kvSize, leaves in [mptPersistedSize .. kvSize) are replayed
// with zero storage writes and sub-roots extracted via indexer.GetSubRoot, then coarse-checkpointed.
func (c *Coordinator) recoverGenesisBackfill(ctx context.Context) error {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()

	if mptPersistedSize > kvSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > m_kv_size (%d)", mptPersistedSize, kvSize)
		return fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", ErrInvariantViolation, mptPersistedSize, kvSize)
	}

	if mptPersistedSize < kvSize {
		klog.Infof("Genesis dirty crash detected: MPT size (%d) < KV size (%d). Replaying leaves [%d..%d) from WASM with zero Pebble writes...",
			mptPersistedSize, kvSize, mptPersistedSize, kvSize)

		if c.fetcher != nil {
			if sizer, ok := c.fetcher.(interface{ SetTreeSize(uint64) }); ok {
				sizer.SetTreeSize(kvSize)
			}
		}
		if c.pipeline == nil && c.fetcher != nil && c.mapper != nil {
			c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
			if c.fetchWorkers > 0 {
				c.pipeline.SetFetchWorkers(c.fetchWorkers)
			}
			if c.fetchBatchBundles > 0 {
				c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
			}
		}
		if c.pipeline == nil {
			return errors.New("cannot replay genesis backfill: pipeline not initialized")
		}

		batchChan, errChan := c.pipeline.StreamBatches(ctx, mptPersistedSize, kvSize)
		modifiedKeys := make(map[[sha256.Size]byte]struct{})
		var replayedLeaves uint64 = mptPersistedSize
		lastReplayLog := mptPersistedSize
		for batch := range batchChan {
			for k := range batch.KeyMap {
				modifiedKeys[k] = struct{}{}
			}
			replayedLeaves += uint64(batch.Count)
			if replayedLeaves-lastReplayLog >= 500000 || replayedLeaves == kvSize {
				klog.Infof("Genesis replay progress: %d / %d leaves replayed (%d unique keys)",
					replayedLeaves, kvSize, len(modifiedKeys))
				lastReplayLog = replayedLeaves
			}
		}
		if err := <-errChan; err != nil {
			return fmt.Errorf("stream batches failed during genesis recovery: %w", err)
		}

		klog.Infof("Genesis replay extracting sub-roots for %d unique modified keys from Pebble (zero storage writes)...", len(modifiedKeys))
		uniqueKeys := make([][sha256.Size]byte, 0, len(modifiedKeys))
		for k := range modifiedKeys {
			uniqueKeys = append(uniqueKeys, k)
		}

		mutations, err := c.indexer.GetSubRoots(ctx, uniqueKeys, kvSize)
		if err != nil {
			return fmt.Errorf("failed to extract sub-roots during genesis replay: %w", err)
		}

		klog.Infof("Genesis replay applying %d sub-root mutations to MPT...", len(mutations))
		if err := c.mptMgr.SetBatch(mutations); err != nil {
			return fmt.Errorf("failed to set batch in MPT during genesis replay: %w", err)
		}

		if _, err := c.mptMgr.Snap(int64(kvSize)); err != nil {
			return fmt.Errorf("genesis recovery mpt.Snap error: %w", err)
		}
		if err := c.mptMgr.Sync(); err != nil {
			return fmt.Errorf("genesis recovery mpt.Sync error: %w", err)
		}
		klog.Infof("Genesis dirty crash recovery completed: MPT snapped at %d", kvSize)
	}
	return nil
}

// Phase1 inspects the Output Log tip (leaf N-1) for a clean shutdown match where
// tip.InputLogSize == MPT_Persisted_Size and tip.MapRoot == MPT.Root().
//
// Performance fast-path (NOT a functional correctness requirement):
// On a clean shutdown, the tip Output Log commitment matches the persisted MPT state.
// Phase1 verifies this in O(1) time (< 5ms) and promotes serving state immediately, completely
// bypassing Phase 2 replay. If this check fails or is omitted, Phase 2 executes full replay
// and arrives at the exact same state.
func (c *Coordinator) Phase1(ctx context.Context) (matched bool, err error) {
	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return false, fmt.Errorf("outputLog.Size failed: %w", err)
	}
	if outSize == 0 {
		return false, nil
	}

	tipIdx := outSize - 1
	leafData, err := c.outputLog.GetLeaf(ctx, tipIdx)
	if err != nil {
		return false, fmt.Errorf("failed to get tip leaf %d: %w", tipIdx, err)
	}

	mapRoot, inCP, rawInCP, err := parseOutputLogLeaf(leafData)
	if err != nil {
		return false, fmt.Errorf("failed to parse tip leaf %d: %w", tipIdx, err)
	}

	mptPersistedSize := c.mptMgr.PersistedSize()
	if inCP.Size == mptPersistedSize && c.mptMgr.Root() == mapRoot {
		// Clean match at tip! Generate inclusion proof and promote serving state
		proof, err := c.outputLog.InclusionProof(ctx, tipIdx, outSize)
		if err != nil {
			return false, fmt.Errorf("failed to generate inclusion proof for tip leaf %d: %w", tipIdx, err)
		}

		rawOutCP, err := c.outputLog.Checkpoint(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to fetch output log checkpoint: %w", err)
		}
		outCP, err := tree.ParseCheckpointHeader(rawOutCP)
		if err != nil {
			return false, fmt.Errorf("failed to parse output log checkpoint: %w", err)
		}

		state := &tree.ServingState{
			OutputLogIndex: tipIdx,
			OutputLogSize:  outSize,
			OutputLogCP:    outCP,
			RawCheckpoint:  rawOutCP,
			OutputLogProof: proof,
			InputLogCP:     inCP,
			RawInputLogCP:  rawInCP,
			InputLogSize:   inCP.Size,
			MapRoot:        mapRoot,
		}
		c.pub.SetServingState(state)
		return true, nil
	}

	return false, nil
}

// Phase2 replays missing leaf delta up to OutputLog[N-1].InputLogSize from tile cache / fetcher into MPT and ratchets serving state.
func (c *Coordinator) Phase2(ctx context.Context, outSize uint64) error {
	if outSize == 0 {
		return nil
	}
	tipIdx := outSize - 1
	tipLeafData, err := c.outputLog.GetLeaf(ctx, tipIdx)
	if err != nil {
		return fmt.Errorf("failed to get tip leaf %d: %w", tipIdx, err)
	}

	tipMapRoot, tipInCP, tipRawInCP, err := parseOutputLogLeaf(tipLeafData)
	if err != nil {
		return fmt.Errorf("failed to parse tip leaf: %w", err)
	}

	mptPersistedSize := c.mptMgr.PersistedSize()
	targetInputSize := tipInCP.Size

	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to get m_kv_size: %w", err)
	}

	// Grouped Invariant Checks: Target CP >= Cached Tiles >= m_kv_size >= Output Size >= MPT_Durable_Size
	if kvSize < targetInputSize {
		klog.Errorf("Invariant violation: m_kv_size (%d) < OutputLog tip size (%d)", kvSize, targetInputSize)
		return fmt.Errorf("%w: m_kv_size (%d) < OutputLog tip size (%d)", ErrInvariantViolation, kvSize, targetInputSize)
	}
	if kvSize < mptPersistedSize {
		klog.Errorf("Invariant violation: m_kv_size (%d) < MPT durable size (%d)", kvSize, mptPersistedSize)
		return fmt.Errorf("%w: m_kv_size (%d) < MPT durable size (%d)", ErrInvariantViolation, kvSize, mptPersistedSize)
	}
	if mptPersistedSize > targetInputSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > OutputLog tip size (%d)", mptPersistedSize, targetInputSize)
		return fmt.Errorf("%w: MPT durable size (%d) > OutputLog tip size (%d)", ErrInvariantViolation, mptPersistedSize, targetInputSize)
	}
	if mptPersistedSize == targetInputSize && c.mptMgr.Root() != tipMapRoot {
		klog.Errorf("Invariant violation: MPT root mismatch at equal size %d (MPT root %x != tip root %x)", targetInputSize, c.mptMgr.Root(), tipMapRoot)
		return fmt.Errorf("%w: MPT root mismatch at size %d: MPT %x, want tip %x", ErrRootMismatch, targetInputSize, c.mptMgr.Root(), tipMapRoot)
	}

	if mptPersistedSize < targetInputSize {
		if c.fetcher != nil {
			if sizer, ok := c.fetcher.(interface{ SetTreeSize(uint64) }); ok {
				sizer.SetTreeSize(targetInputSize)
			}
		}
		if c.pipeline == nil && c.fetcher != nil && c.mapper != nil {
			c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
			if c.fetchWorkers > 0 {
				c.pipeline.SetFetchWorkers(c.fetchWorkers)
			}
			if c.fetchBatchBundles > 0 {
				c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
			}
		}

		modifiedKeys := make(map[[sha256.Size]byte]struct{})

		if c.pipeline != nil {
			batchChan, errChan := c.pipeline.StreamBatches(ctx, mptPersistedSize, targetInputSize)
			for batch := range batchChan {
				for k := range batch.KeyMap {
					modifiedKeys[k] = struct{}{}
				}
			}
			if err := <-errChan; err != nil {
				return fmt.Errorf("stream batches failed during recovery: %w", err)
			}
		}

		uniqueKeys := make([][sha256.Size]byte, 0, len(modifiedKeys))
		for k := range modifiedKeys {
			uniqueKeys = append(uniqueKeys, k)
		}
		mutations, err := c.indexer.GetSubRoots(ctx, uniqueKeys, targetInputSize)
		if err != nil {
			return fmt.Errorf("failed to get sub-roots during Phase 2 replay: %w", err)
		}

		// Commit mutations to MPT
		actualRoot, err := c.mptMgr.CommitWithVersion(mutations, int64(targetInputSize))
		if err != nil {
			return fmt.Errorf("mptMgr.CommitWithVersion failed during replay: %w", err)
		}
		if actualRoot != tipMapRoot {
			klog.Errorf("Invariant violation: replayed MPT root %x != tip root %x at size %d", actualRoot, tipMapRoot, targetInputSize)
			return fmt.Errorf("%w: replay reached root %x, want tip leaf root %x", ErrRootMismatch, actualRoot, tipMapRoot)
		}
	}

	// Generate proof for tip leaf
	proof, err := c.outputLog.InclusionProof(ctx, tipIdx, outSize)
	if err != nil {
		return fmt.Errorf("failed to generate inclusion proof for tip leaf %d: %w", tipIdx, err)
	}

	rawOutCP, err := c.outputLog.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch output log checkpoint: %w", err)
	}
	outCP, err := tree.ParseCheckpointHeader(rawOutCP)
	if err != nil {
		return fmt.Errorf("failed to parse output log checkpoint: %w", err)
	}

	state := &tree.ServingState{
		OutputLogIndex: tipIdx,
		OutputLogSize:  outSize,
		OutputLogCP:    outCP,
		RawCheckpoint:  rawOutCP,
		OutputLogProof: proof,
		InputLogCP:     tipInCP,
		RawInputLogCP:  tipRawInCP,
		InputLogSize:   tipInCP.Size,
		MapRoot:        tipMapRoot,
	}
	c.pub.SetServingState(state)
	return nil
}

// Phase3 resumes steady-state ingestion from m_kv_size.
func (c *Coordinator) Phase3(ctx context.Context) error {
	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}
	if outSize == 0 {
		return nil
	}

	rawTargetCP, err := c.db.GetMetadata(kvstore.KeyMetaTargetCheckpoint)
	if err != nil {
		return fmt.Errorf("failed to read m_target_checkpoint: %w", err)
	}
	if len(rawTargetCP) == 0 {
		return nil
	}

	targetCP, err := tree.ParseCheckpointHeader(rawTargetCP)
	if err != nil {
		return fmt.Errorf("failed to parse m_target_checkpoint: %w", err)
	}
	metrics.InputTreeSize.Set(float64(targetCP.Size))

	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}

	if kvSize < targetCP.Size && c.pipeline != nil {
		if c.fetcher != nil {
			if sizer, ok := c.fetcher.(interface{ SetTreeSize(uint64) }); ok {
				sizer.SetTreeSize(targetCP.Size)
			}
		}
		startTime := time.Now()
		startProgressSize := kvSize
		lastLogSize := kvSize
		logInterval := uint64(102400)

		batchSize := c.commitBatchSize
		if batchSize == 0 {
			batchSize = DefaultCommitBatchSize
		}

		err := c.streamAndIndex(ctx, kvSize, targetCP.Size, batchSize, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
			res, err := c.indexer.IndexMappedBatch(drainCtx, batch, rawTargetCP, targetCP.Size)
			if err != nil {
				return fmt.Errorf("phase 3 indexing catch-up failed: %w", err)
			}
			metrics.KVCommittedSize.Set(float64(res.NewKVSize))
			metrics.LeavesIndexedTotal.Add(float64(batch.Count))
			if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
				elapsed := time.Since(startTime).Seconds()
				rate := 0.0
				if elapsed > 0 {
					rate = float64(res.NewKVSize-startProgressSize) / elapsed
				}
				klog.Infof("Catch-up indexing progress: %d / %d leaves (%.1f leaves/sec)", res.NewKVSize, targetCP.Size, rate)
				lastLogSize = res.NewKVSize
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// SyncOnce fetches the latest checkpoint from the input log, streams and indexes missing batches.
// When outputLog.Size == 0 (unserved bootstrap), it executes Genesis Backfill.
// Once Leaf 0 is committed, it operates in Normal Serving Mode.
func (c *Coordinator) SyncOnce(ctx context.Context) error {
	if c.fetcher == nil {
		return nil
	}

	targetCP, err := c.fetcher.Checkpoint(ctx)
	if err != nil {
		metrics.InputFetchErrorsTotal.Inc()
		return fmt.Errorf("ingestion fetch checkpoint error: %w", err)
	}
	if targetCP == nil {
		return nil
	}
	metrics.InputTreeSize.Set(float64(targetCP.Size))

	if err := c.db.SetMetadata(kvstore.KeyMetaTargetCheckpoint, targetCP.Raw); err != nil {
		return fmt.Errorf("failed to persist target checkpoint: %w", err)
	}

	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}

	if outSize == 0 {
		return c.syncGenesisBackfill(ctx, targetCP)
	}

	var startLogSize uint64
	if state := c.pub.GetServingState(); state != nil {
		startLogSize = state.InputLogSize
	}

	if startLogSize >= targetCP.Size {
		return nil
	}

	if c.pipeline == nil {
		if c.mapper == nil {
			return errors.New("cannot initialize pipeline without leaf mapper")
		}
		c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
		if c.fetchWorkers > 0 {
			c.pipeline.SetFetchWorkers(c.fetchWorkers)
		}
		if c.fetchBatchBundles > 0 {
			c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
		}
	}

	allModifiedSubRoots := make(map[[sha256.Size]byte][sha256.Size]byte)
	startTime := time.Now()
	startProgressSize := startLogSize
	lastLogSize := startLogSize
	const logInterval = uint64(100000)

	batchSize := c.commitBatchSize
	if batchSize == 0 {
		batchSize = DefaultCommitBatchSize
	}

	err = c.streamAndIndex(ctx, startLogSize, targetCP.Size, batchSize, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := c.indexer.IndexBatch(drainCtx, batch, targetCP)
		if err != nil {
			return fmt.Errorf("indexing error: %w", err)
		}
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(batch.Count))
		for k, v := range res.ModifiedSubRoots {
			allModifiedSubRoots[k] = v
		}
		metrics.IndexingLag.Set(float64(targetCP.Size - res.NewKVSize))
		if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
			elapsed := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(res.NewKVSize-startProgressSize) / elapsed
			}
			klog.Infof("Indexing progress: %d / %d leaves (%.1f leaves/sec)", res.NewKVSize, targetCP.Size, rate)
			lastLogSize = res.NewKVSize
		}
		return nil
	})
	if err != nil {
		return err
	}
	klog.Infof("Milestone M2: Ingestion and KV store 100%% synced: %d leaves in %v", targetCP.Size, time.Since(startTime))

	logCP := &log.Checkpoint{
		Origin: targetCP.Origin,
		Size:   targetCP.Size,
		Hash:   targetCP.Hash[:],
	}
	if _, err := c.pub.PublishBatch(ctx, allModifiedSubRoots, logCP, targetCP.Raw); err != nil {
		return fmt.Errorf("publish error: %w", err)
	}
	metrics.IndexingLag.Set(0)
	return nil
}

// syncGenesisBackfill executes the Genesis Backfill lifecycle for unserved bootstrap indexing (outputLog.Size() == 0).
func (c *Coordinator) syncGenesisBackfill(ctx context.Context, targetCP *ingest.Checkpoint) error {
	kvSize, err := c.db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		return fmt.Errorf("failed to read m_kv_size: %w", err)
	}
	mptPersistedSize := c.mptMgr.PersistedSize()

	if mptPersistedSize > kvSize {
		klog.Errorf("Invariant violation: MPT durable size (%d) > m_kv_size (%d) during genesis backfill", mptPersistedSize, kvSize)
		return fmt.Errorf("%w: MPT durable size (%d) > m_kv_size (%d)", ErrInvariantViolation, mptPersistedSize, kvSize)
	}

	if mptPersistedSize < kvSize {
		if err := c.recoverGenesisBackfill(ctx); err != nil {
			return fmt.Errorf("genesis dirty crash recovery failed: %w", err)
		}
		mptPersistedSize = c.mptMgr.PersistedSize()
	}

	startLogSize := min(kvSize, mptPersistedSize)
	if startLogSize >= targetCP.Size {
		return c.finalizeGenesisBackfill(ctx, targetCP, nil)
	}

	if c.pipeline == nil {
		if c.mapper == nil {
			return errors.New("cannot initialize pipeline without leaf mapper")
		}
		c.pipeline = ingest.NewPipeline(c.fetcher, c.cache, c.mapper, 0)
		if c.fetchWorkers > 0 {
			c.pipeline.SetFetchWorkers(c.fetchWorkers)
		}
		if c.fetchBatchBundles > 0 {
			c.pipeline.SetFetchBatchBundles(c.fetchBatchBundles)
		}
	}
	if c.fetcher != nil {
		if sizer, ok := c.fetcher.(interface{ SetTreeSize(uint64) }); ok {
			sizer.SetTreeSize(targetCP.Size)
		}
	}

type backfillFlushJob struct {
	keys      map[[sha256.Size]byte][sha256.Size]byte
	watermark uint64
	doneChan  chan error
}

	batchSize := c.CommitBatchSize()
	coarseInterval := c.CoarseCheckpointInterval()
	maxPendingKeys := c.BackfillMaxPendingKeys()
	lastCheckpointLeaf := mptPersistedSize
	var lastIndexedSize uint64 = startLogSize

	startTime := time.Now()
	startProgressSize := startLogSize
	lastLogSize := startLogSize
	const logInterval = uint64(100000)

	flushChan := make(chan *backfillFlushJob, 1)
	var backgroundWorkerErr error
	var workerWg sync.WaitGroup
	workerWg.Add(1)

	go func() {
		defer workerWg.Done()
		for job := range flushChan {
			flushStart := time.Now()
			klog.Infof("Genesis backfill background worker: flushing %d deduplicated keys to MPT at leaf %d...", len(job.keys), job.watermark)
			if err := c.db.Sync(); err != nil {
				job.doneChan <- fmt.Errorf("genesis background db.Sync error: %w", err)
				backgroundWorkerErr = err
				return
			}
			if len(job.keys) > 0 {
				if err := c.mptMgr.SetBatch(job.keys); err != nil {
					job.doneChan <- fmt.Errorf("genesis background mpt.SetBatch error: %w", err)
					backgroundWorkerErr = err
					return
				}
			}
			job.keys = nil // Free memory immediately for GC

			if _, err := c.mptMgr.Snap(int64(job.watermark)); err != nil {
				job.doneChan <- fmt.Errorf("genesis background mpt.Snap error: %w", err)
				backgroundWorkerErr = err
				return
			}
			if err := c.mptMgr.Sync(); err != nil {
				job.doneChan <- fmt.Errorf("genesis background mpt.Sync error: %w", err)
				backgroundWorkerErr = err
				return
			}
			klog.Infof("Genesis backfill background coarse checkpoint completed at leaf %d in %v", job.watermark, time.Since(flushStart))
			close(job.doneChan)
		}
	}()

	activeBuffer := make(map[[sha256.Size]byte][sha256.Size]byte)
	var currentJob *backfillFlushJob
	currentThreshold := min(uint64(5000000), maxPendingKeys)

	waitForCurrentJob := func() error {
		if currentJob == nil {
			return nil
		}
		select {
		case err, ok := <-currentJob.doneChan:
			if ok && err != nil {
				return err
			}
			lastCheckpointLeaf = currentJob.watermark
			currentJob = nil
			return nil
		default:
			// Apply backpressure if current job is still flushing
			klog.Infof("Genesis backfill: waiting for background MPT flush at leaf %d to complete (backpressure)...", currentJob.watermark)
			err, ok := <-currentJob.doneChan
			if ok && err != nil {
				return err
			}
			lastCheckpointLeaf = currentJob.watermark
			currentJob = nil
			return nil
		}
	}

	dispatchFlush := func(newKVSize uint64) error {
		if err := waitForCurrentJob(); err != nil {
			return err
		}
		if backgroundWorkerErr != nil {
			return backgroundWorkerErr
		}
		job := &backfillFlushJob{
			keys:      activeBuffer,
			watermark: newKVSize,
			doneChan:  make(chan error, 1),
		}
		currentJob = job
		activeBuffer = make(map[[sha256.Size]byte][sha256.Size]byte) // Swap to fresh active buffer (A/B double buffer)
		flushChan <- job

		if currentThreshold < maxPendingKeys {
			currentThreshold = min(currentThreshold*2, maxPendingKeys)
			klog.Infof("Genesis backfill: ramping pending key threshold to %d keys", currentThreshold)
		}
		return nil
	}

	streamErr := c.streamAndIndex(ctx, startLogSize, targetCP.Size, batchSize, func(drainCtx context.Context, batch *ingest.MappedBatch) error {
		res, err := c.indexer.IndexBatch(drainCtx, batch, targetCP)
		if err != nil {
			return fmt.Errorf("genesis indexing error: %w", err)
		}
		lastIndexedSize = res.NewKVSize
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(batch.Count))
		metrics.IndexingLag.Set(float64(targetCP.Size - res.NewKVSize))

		for k, v := range res.ModifiedSubRoots {
			activeBuffer[k] = v
		}
		res.ModifiedSubRoots = nil // Discard batch slice

		flushNeeded := uint64(len(activeBuffer)) >= currentThreshold ||
			(coarseInterval > 0 && res.NewKVSize < targetCP.Size && (res.NewKVSize-lastCheckpointLeaf) >= coarseInterval)

		if res.NewKVSize < targetCP.Size && flushNeeded {
			if err := dispatchFlush(res.NewKVSize); err != nil {
				return err
			}
		}

		if res.NewKVSize-lastLogSize >= logInterval || res.NewKVSize == targetCP.Size {
			elapsed := time.Since(startTime).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(res.NewKVSize-startProgressSize) / elapsed
			}
			klog.Infof("Genesis backfill progress: %d / %d leaves (%.1f leaves/sec, %d pending keys in active buffer)", res.NewKVSize, targetCP.Size, rate, len(activeBuffer))
			lastLogSize = res.NewKVSize
		}
		return nil
	})

	close(flushChan)
	workerWg.Wait()
	if backgroundWorkerErr != nil {
		return backgroundWorkerErr
	}

	if streamErr != nil {
		// On graceful context shutdown / cancellation, execute coarse checkpoint if progress was made
		if lastIndexedSize > lastCheckpointLeaf {
			if err := c.db.Sync(); err == nil {
				if len(activeBuffer) > 0 {
					_ = c.mptMgr.SetBatch(activeBuffer)
				}
				if _, err := c.mptMgr.Snap(int64(lastIndexedSize)); err == nil {
					if err := c.mptMgr.Sync(); err == nil {
						klog.Infof("Genesis backfill shutdown checkpoint saved at leaf %d", lastIndexedSize)
					}
				}
			}
		}
		return streamErr
	}

	return c.finalizeGenesisBackfill(ctx, targetCP, activeBuffer)
}

func (c *Coordinator) finalizeGenesisBackfill(ctx context.Context, targetCP *ingest.Checkpoint, pendingSubRoots map[[sha256.Size]byte][sha256.Size]byte) error {
	if err := c.db.Sync(); err != nil {
		return fmt.Errorf("genesis final db.Sync error: %w", err)
	}
	if len(pendingSubRoots) > 0 {
		klog.Infof("Genesis backfill: applying final %d deduplicated keys to MPT at leaf %d...", len(pendingSubRoots), targetCP.Size)
		if err := c.mptMgr.SetBatch(pendingSubRoots); err != nil {
			return fmt.Errorf("genesis final mpt.SetBatch error: %w", err)
		}
	}
	finalRoot, err := c.mptMgr.Snap(int64(targetCP.Size))
	if err != nil {
		return fmt.Errorf("genesis final mpt.Snap error: %w", err)
	}
	if err := c.mptMgr.Sync(); err != nil {
		return fmt.Errorf("genesis final mpt.Sync error: %w", err)
	}

	var logCP *log.Checkpoint
	var rawCP []byte
	if targetCP != nil {
		logCP = &log.Checkpoint{
			Origin: targetCP.Origin,
			Size:   targetCP.Size,
			Hash:   targetCP.Hash[:],
		}
		rawCP = targetCP.Raw
	}
	if _, err := c.pub.PublishBatch(ctx, nil, logCP, rawCP); err != nil {
		return fmt.Errorf("genesis Leaf 0 publish error: %w", err)
	}
	metrics.IndexingLag.Set(0)
	klog.Infof("STATE TRANSITION: Genesis Backfill -> Normal Serving Mode. Leaf 0 committed to Output Log (root: %x, input size: %d). HTTP read endpoints (/lookup, /checkpoint) are now ACTIVE.", finalRoot, targetCP.Size)
	return nil
}

// streamAndIndex coordinates pipelined double-buffered batch consumption and indexing.
// The reader goroutine streams and aggregates bundles into MappedBatch slabs of batchSize.
// Slabs are dispatched via a bounded channel (capacity 32) to a dedicated committer goroutine,
// overlapping WASM mapping and fetch I/O with Pebble KV indexing and disk commits.
func (c *Coordinator) streamAndIndex(
	ctx context.Context,
	fromLeaf, toLeaf uint64,
	batchSize uint64,
	indexFn func(ctx context.Context, batch *ingest.MappedBatch) error,
) error {
	if fromLeaf >= toLeaf {
		return nil
	}
	if c.pipeline == nil {
		return errors.New("cannot stream and index: pipeline not initialized")
	}
	if batchSize == 0 {
		batchSize = DefaultCommitBatchSize
	}

	g, gCtx := errgroup.WithContext(ctx)
	// Multi-slab buffering: up to 32 slabs draining/pending in committer while reader actively accumulates.
	slabChan := make(chan *ingest.MappedBatch, 32)

	// Committer goroutine: drains slabs sequentially in strict monotonic order.
	g.Go(func() error {
		for slab := range slabChan {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}
			if err := indexFn(gCtx, slab); err != nil {
				return err
			}
		}
		return nil
	})

	// Reader goroutine: streams bundles and aggregates into slabs.
	g.Go(func() error {
		defer close(slabChan)
		batchChan, errChan := c.pipeline.StreamBatches(gCtx, fromLeaf, toLeaf)
		var pendingBatch *ingest.MappedBatch

		for batch := range batchChan {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			if batch.EndLeafIdx == 0 && batch.Count > 0 {
				batch.EndLeafIdx = batch.StartLeafIdx + uint64(batch.Count)
			}
			if pendingBatch == nil {
				pendingBatch = batch
			} else {
				pendingBatch.Merge(batch)
			}

			if pendingBatch.EndLeafIdx-pendingBatch.StartLeafIdx >= batchSize {
				select {
				case slabChan <- pendingBatch:
					pendingBatch = nil
				case <-gCtx.Done():
					return gCtx.Err()
				}
			}
		}

		if err, ok := <-errChan; ok && err != nil {
			return fmt.Errorf("stream batches failed: %w", err)
		}

		if pendingBatch != nil && pendingBatch.EndLeafIdx > pendingBatch.StartLeafIdx {
			select {
			case slabChan <- pendingBatch:
			case <-gCtx.Done():
				return gCtx.Err()
			}
		}
		return nil
	})

	return g.Wait()
}

// Run executes startup recovery and enters the periodic ingestion polling loop until ctx is canceled.
func (c *Coordinator) Run(ctx context.Context, pollInterval time.Duration) error {
	if err := c.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	if err := c.SyncOnce(ctx); err != nil {
		klog.Warningf("Initial sync error: %v", err)
	}

	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.SyncOnce(ctx); err != nil {
				klog.Warningf("Sync error: %v", err)
			}
		}
	}
}
