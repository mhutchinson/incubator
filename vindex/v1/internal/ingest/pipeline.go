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
	"container/heap"
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/tessera/api/layout"
)

// IngestionPipeline manages the 3-stage asynchronous leaf fetch, parallel mapping, and resequencing pipeline.
type IngestionPipeline struct {
	fetcher       TileFetcher
	cache         TileCache
	mapper        LeafMapper
	numWorkers    int
	bundleSize    uint64
	bundleTimeout time.Duration
}

// NewPipeline creates a new IngestionPipeline instance.
func NewPipeline(fetcher TileFetcher, cache TileCache, mapper LeafMapper, numWorkers int) *IngestionPipeline {
	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0) - 1
		if numWorkers < 1 {
			numWorkers = 1
		}
	}
	return &IngestionPipeline{
		fetcher:       fetcher,
		cache:         cache,
		mapper:        mapper,
		numWorkers:    numWorkers,
		bundleSize:    uint64(layout.EntryBundleWidth),
		bundleTimeout: 30 * time.Second,
	}
}

// SetBundleTimeout sets the execution timeout per bundle for mapping workers.
func (p *IngestionPipeline) SetBundleTimeout(d time.Duration) {
	p.bundleTimeout = d
}

// NewIngestionPipeline creates a new IngestionPipeline instance (alias for NewPipeline).
func NewIngestionPipeline(fetcher TileFetcher, cache TileCache, mapper LeafMapper, numWorkers int) *IngestionPipeline {
	return NewPipeline(fetcher, cache, mapper, numWorkers)
}


// BundleSize returns the configured bundle capacity.
func (p *IngestionPipeline) BundleSize() uint64 {
	return p.bundleSize
}

// StreamBatches streams ordered MappedBatch items in range [fromLeafIdx, targetSize) with zero Pebble WAL writes.
func (p *IngestionPipeline) StreamBatches(ctx context.Context, fromLeafIdx, targetSize uint64) (<-chan *MappedBatch, <-chan error) {
	outBatches := make(chan *MappedBatch, 64)
	errChan := make(chan error, 1)

	if fromLeafIdx >= targetSize {
		close(outBatches)
		close(errChan)
		return outBatches, errChan
	}

	pipeCtx, cancelPipe := context.WithCancel(ctx)

	var (
		errMu    sync.Mutex
		firstErr error
	)
	recordError := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancelPipe()
	}

	leafBundleChan := make(chan *LeafBundle, 64)
	unorderedBatchChan := make(chan *MappedBatch, 64)

	var (
		fetchWg sync.WaitGroup
		mapWg   sync.WaitGroup
		reseqWg sync.WaitGroup
	)

	// Stage 1: TileFetcher & Cache
	fetchWg.Add(1)
	go func() {
		defer fetchWg.Done()
		defer close(leafBundleChan)
		currIdx := fromLeafIdx
		for currIdx < targetSize {
			select {
			case <-pipeCtx.Done():
				return
			default:
			}

			bundleIdx := currIdx / p.bundleSize
			var bundle *LeafBundle
			if p.cache != nil {
				if b, err := p.cache.GetBundle(bundleIdx); err == nil && b != nil {
					bEnd := b.StartLeafIdx + uint64(len(b.Leaves))
					if currIdx < bEnd && (uint64(len(b.Leaves)) == p.bundleSize || bEnd >= targetSize) {
						bundle = b
					}
				}
			}

			if bundle == nil {
				count := p.bundleSize * 50
				if currIdx+count > targetSize {
					count = targetSize - currIdx
				}
				bundles, err := p.fetcher.FetchTiles(pipeCtx, currIdx, count)
				if err != nil {
					recordError(fmt.Errorf("fetch tiles [%d, %d) failed: %w", currIdx, currIdx+count, err))
					return
				}
				if len(bundles) == 0 {
					recordError(fmt.Errorf("fetch tiles [%d, %d) returned 0 bundles", currIdx, currIdx+count))
					return
				}
				for _, b := range bundles {
					if p.cache != nil {
						_ = p.cache.PutBundle(b)
					}
					select {
					case <-pipeCtx.Done():
						return
					case leafBundleChan <- b:
					}
					nextIdx := b.StartLeafIdx + uint64(len(b.Leaves))
					if nextIdx <= currIdx {
						nextIdx = (b.BundleIdx + 1) * p.bundleSize
					}
					currIdx = nextIdx
				}
			} else {
				select {
				case <-pipeCtx.Done():
					return
				case leafBundleChan <- bundle:
				}
				nextIdx := bundle.StartLeafIdx + uint64(len(bundle.Leaves))
				if nextIdx <= currIdx {
					nextIdx = (bundle.BundleIdx + 1) * p.bundleSize
				}
				currIdx = nextIdx
			}
		}
	}()

	// Stage 2: MapWorkerPool
	for i := 0; i < p.numWorkers; i++ {
		mapWg.Add(1)
		go func() {
			defer mapWg.Done()
			for bundle := range leafBundleChan {
				select {
				case <-pipeCtx.Done():
					return
				default:
				}

				startIdx := bundle.StartLeafIdx
				if fromLeafIdx > startIdx {
					startIdx = fromLeafIdx
				}
				endIdx := bundle.StartLeafIdx + uint64(len(bundle.Leaves))
				if targetSize < endIdx {
					endIdx = targetSize
				}
				if startIdx >= endIdx {
					continue
				}

				bTimeout := p.bundleTimeout
				if bTimeout <= 0 {
					bTimeout = 30 * time.Second
				}
				bundleCtx, bundleCancel := context.WithTimeout(pipeCtx, bTimeout)

				keyMap := make(map[[32]byte][]uint64)
				var mapErr error
				var numLeavesMapped int
				var totalKeysGenerated int
				startMapBundle := time.Now()

				subLeaves := bundle.Leaves[startIdx-bundle.StartLeafIdx : endIdx-bundle.StartLeafIdx]

				if bm, ok := p.mapper.(BundleMapper); ok {
					bundleResults, err := bm.MapBundle(bundleCtx, subLeaves)
					if err != nil {
						metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
						if bundleCtx.Err() == context.DeadlineExceeded && pipeCtx.Err() == nil {
							mapErr = fmt.Errorf("mapper timed out on bundle %d: %w", bundle.BundleIdx, context.DeadlineExceeded)
						} else {
							mapErr = fmt.Errorf("mapper failed on bundle %d: %w", bundle.BundleIdx, err)
						}
					} else {
						for offset, entries := range bundleResults {
							leafIdx := startIdx + uint64(offset)
							numLeavesMapped++
							totalKeysGenerated += len(entries)

							var keys [][32]byte
							for _, e := range entries {
								keys = append(keys, e.KeyHash)
							}
							slices.SortFunc(keys, func(a, b [32]byte) int {
								return bytes.Compare(a[:], b[:])
							})
							keys = slices.Compact(keys)

							for _, k := range keys {
								keyMap[k] = append(keyMap[k], leafIdx)
							}
						}
					}
				} else {
					for j, leaf := range bundle.Leaves {
						leafIdx := bundle.StartLeafIdx + uint64(j)
						if leafIdx < startIdx || leafIdx >= endIdx {
							continue
						}
						entries, err := p.mapper.MapLeaf(bundleCtx, leaf)
						if err != nil {
							metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
							if bundleCtx.Err() == context.DeadlineExceeded && pipeCtx.Err() == nil {
								mapErr = fmt.Errorf("mapper timed out on bundle %d (leaf %d): %w", bundle.BundleIdx, leafIdx, context.DeadlineExceeded)
							} else {
								mapErr = fmt.Errorf("mapper failed on leaf %d: %w", leafIdx, err)
							}
							break
						}
						numLeavesMapped++
						totalKeysGenerated += len(entries)

						var keys [][32]byte
						for _, e := range entries {
							keys = append(keys, e.KeyHash)
						}
						slices.SortFunc(keys, func(a, b [32]byte) int {
							return bytes.Compare(a[:], b[:])
						})
						keys = slices.Compact(keys)

						for _, k := range keys {
							keyMap[k] = append(keyMap[k], leafIdx)
						}
					}
				}
				bundleCancel()
				metrics.MapDurationSeconds.Observe(time.Since(startMapBundle).Seconds())

				if mapErr != nil {
					recordError(mapErr)
					return
				}

				metrics.LeavesMappedTotal.Add(float64(numLeavesMapped))
				metrics.KeysMappedTotal.Add(float64(totalKeysGenerated))

				batch := &MappedBatch{
					BundleIdx:    bundle.BundleIdx,
					StartLeafIdx: startIdx,
					EndLeafIdx:   endIdx,
					Count:        uint32(endIdx - startIdx),
					KeyMap:       keyMap,
				}

				select {
				case <-pipeCtx.Done():
					return
				case unorderedBatchChan <- batch:
				}
			}
		}()
	}

	go func() {
		mapWg.Wait()
		close(unorderedBatchChan)
	}()

	// Stage 3: Resequencer
	reseqWg.Add(1)
	go func() {
		defer reseqWg.Done()
		defer close(outBatches)

		expectedStartLeafIdx := fromLeafIdx
		pq := &batchPriorityQueue{}
		heap.Init(pq)

		for {
			select {
			case <-pipeCtx.Done():
				return
			case batch, ok := <-unorderedBatchChan:
				if !ok {
					for pq.Len() > 0 && (*pq)[0].StartLeafIdx == expectedStartLeafIdx {
						nextBatch := heap.Pop(pq).(*MappedBatch)
						select {
						case <-pipeCtx.Done():
							return
						case outBatches <- nextBatch:
						}
						expectedStartLeafIdx = nextBatch.EndLeafIdx
					}
					goto finishedDrain
				}

				heap.Push(pq, batch)
				for pq.Len() > 0 && (*pq)[0].StartLeafIdx == expectedStartLeafIdx {
					nextBatch := heap.Pop(pq).(*MappedBatch)
					select {
					case <-pipeCtx.Done():
						return
					case outBatches <- nextBatch:
					}
					expectedStartLeafIdx = nextBatch.EndLeafIdx
				}
			}
		}

	finishedDrain:
		if expectedStartLeafIdx != targetSize || pq.Len() > 0 {
			if ctx.Err() != nil {
				recordError(ctx.Err())
			} else if pipeCtx.Err() != nil {
				// Handled by recordError from upstream worker
			} else {
				recordError(fmt.Errorf("resequencer incomplete: processed up to leaf %d, want target size %d (%d batches unconsumed)", expectedStartLeafIdx, targetSize, pq.Len()))
			}
		}
	}()

	// Stage 4: Completion barrier
	go func() {
		fetchWg.Wait()
		mapWg.Wait()
		reseqWg.Wait()
		cancelPipe()

		errMu.Lock()
		if firstErr != nil {
			errChan <- firstErr
		} else if ctx.Err() != nil {
			errChan <- ctx.Err()
		}
		errMu.Unlock()
		close(errChan)
	}()

	return outBatches, errChan
}

type batchPriorityQueue []*MappedBatch

func (pq batchPriorityQueue) Len() int           { return len(pq) }
func (pq batchPriorityQueue) Less(i, j int) bool { return pq[i].StartLeafIdx < pq[j].StartLeafIdx }
func (pq batchPriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }
func (pq *batchPriorityQueue) Push(x any)        { *pq = append(*pq, x.(*MappedBatch)) }
func (pq *batchPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}
