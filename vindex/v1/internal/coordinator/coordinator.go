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
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"k8s.io/klog/v2"
)

const (
	// DefaultCommitBatchSize is the default number of leaves aggregated before committing to the KV store (16 tiles).
	DefaultCommitBatchSize uint64 = 4096 // 16 tiles (256 * 16)
)

// Coordinator manages the 3-phase startup and crash recovery workflow.
type Coordinator struct {
	db              *kvstore.DB
	mptMgr          *tree.Manager
	outputLog       OutputLogReader
	pub             *tree.OutputPublisher
	indexer         *kvstore.KVIndexer
	fetcher         ingest.TileFetcher
	cache           ingest.TileCache
	mapper          ingest.LeafMapper
	pipeline        *ingest.IngestionPipeline
	commitBatchSize uint64
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
		db:              db,
		mptMgr:          mptMgr,
		outputLog:       outputLog,
		pub:             pub,
		indexer:         indexer,
		fetcher:         fetcher,
		cache:           cache,
		mapper:          mapper,
		pipeline:        pipeline,
		commitBatchSize: DefaultCommitBatchSize,
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

// Recover runs the recovery sequence:
// 1. Phase 1: Tip match check (< 5ms fast serve on clean shutdown).
// 2. Phase 2: If tip did not match, replay missing tiles up to Output Log tip, verify, and promote serving state.
// 3. Phase 3: Resume background pipeline.
func (c *Coordinator) Recover(ctx context.Context) error {
	matched, err := c.Phase1(ctx)
	if err != nil {
		return fmt.Errorf("phase 1 recovery failed: %w", err)
	}

	outSize, err := c.outputLog.Size(ctx)
	if err != nil {
		return fmt.Errorf("failed to get output log size: %w", err)
	}

	if outSize > 0 && !matched {
		if err := c.Phase2(ctx, outSize); err != nil {
			return fmt.Errorf("phase 2 recovery failed: %w", err)
		}
	}

	if err := c.Phase3(ctx); err != nil {
		return fmt.Errorf("phase 3 recovery failed: %w", err)
	}

	return nil
}

// Phase1 inspects the Output Log tip (leaf N-1) for a clean shutdown match where
// tip.InputLogSize == MPT_Persisted_Size and tip.MapRoot == MPT.Root().
// If matched, it validates the root, generates an inclusion proof, and promotes serving state immediately (< 5ms).
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

		// Calculate updated sub-roots for all modified keys from the chunk store
		mutations := make(map[[sha256.Size]byte][sha256.Size]byte, len(modifiedKeys))
		for k := range modifiedKeys {
			subRoot, err := c.indexer.GetSubRoot(k, targetInputSize)
			if err != nil {
				return fmt.Errorf("failed to get sub-root for key %x: %w", k, err)
			}
			mutations[k] = subRoot
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
		batchChan, errChan := c.pipeline.StreamBatches(ctx, kvSize, targetCP.Size)
		for batch := range batchChan {
			res, err := c.indexer.IndexMappedBatch(ctx, batch, rawTargetCP, targetCP.Size)
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
		}
		if err := <-errChan; err != nil {
			return fmt.Errorf("phase 3 streaming catch-up failed: %w", err)
		}
	}

	return nil
}

// SyncOnce fetches the latest checkpoint from the input log, streams and indexes missing batches,
// and publishes the updated sub-roots to the Output Log once fully indexed.
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

	var pendingBatch *ingest.MappedBatch

	flush := func() error {
		if pendingBatch == nil || pendingBatch.EndLeafIdx <= pendingBatch.StartLeafIdx {
			return nil
		}
		res, err := c.indexer.IndexBatch(ctx, pendingBatch, targetCP)
		if err != nil {
			return fmt.Errorf("indexing error: %w", err)
		}
		metrics.KVCommittedSize.Set(float64(res.NewKVSize))
		metrics.LeavesIndexedTotal.Add(float64(pendingBatch.Count))
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
		pendingBatch = nil
		return nil
	}

	batchChan, errChan := c.pipeline.StreamBatches(ctx, startLogSize, targetCP.Size)
	for batch := range batchChan {
		if batch.EndLeafIdx == 0 && batch.Count > 0 {
			batch.EndLeafIdx = batch.StartLeafIdx + uint64(batch.Count)
		}
		if pendingBatch == nil {
			pendingBatch = &ingest.MappedBatch{
				BundleIdx:    batch.BundleIdx,
				StartLeafIdx: batch.StartLeafIdx,
				EndLeafIdx:   batch.EndLeafIdx,
				Count:        batch.Count,
				KeyMap:       make(map[[32]byte][]uint64),
			}
			for k, v := range batch.KeyMap {
				pendingBatch.KeyMap[k] = append([]uint64(nil), v...)
			}
		} else {
			pendingBatch.Merge(batch)
		}

		if pendingBatch.EndLeafIdx-pendingBatch.StartLeafIdx >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := <-errChan; err != nil {
		return fmt.Errorf("stream batches error: %w", err)
	}

	if err := flush(); err != nil {
		return err
	}

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
