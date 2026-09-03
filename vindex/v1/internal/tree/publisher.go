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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	torchmpt "filippo.io/torchwood/mpt"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"k8s.io/klog/v2"
)

// OutputPublisher orchestrates root prediction, Output Log append, witness collection, and atomic state ratcheting.
type OutputPublisher struct {
	db           *kvstore.DB
	mptMgr       *Manager
	outputLog    OutputLogClient
	witness      WitnessClient
	servingState atomic.Pointer[ServingState]
}

// NewOutputPublisher creates a new OutputPublisher.
func NewOutputPublisher(db *kvstore.DB, mptMgr *Manager, outputLog OutputLogClient, witness WitnessClient) *OutputPublisher {
	return &OutputPublisher{
		db:        db,
		mptMgr:    mptMgr,
		outputLog: outputLog,
		witness:   witness,
	}
}

// GetServingState returns the currently active ServingState.
func (p *OutputPublisher) GetServingState() *ServingState {
	return p.servingState.Load()
}

// SetServingState explicitly sets the active serving state (e.g. during recovery/startup).
func (p *OutputPublisher) SetServingState(state *ServingState) {
	p.servingState.Store(state)
	if state != nil {
		metrics.ServingTreeSize.Set(float64(state.InputLogSize))
		metrics.WitnessSignaturesCount.Set(float64(countWitnessSignatures(state.RawCheckpoint)))
	}
}

// PublishBatch publishes a batch of sub-root modifications to the Output Log and promotes the serving state.
func (p *OutputPublisher) PublishBatch(ctx context.Context, modifiedSubRoots map[[sha256.Size]byte][sha256.Size]byte, inputLogCP *log.Checkpoint, rawInputLogCP []byte) (*ServingState, error) {
	if inputLogCP == nil && len(rawInputLogCP) > 0 {
		parsed, err := ParseCheckpointHeader(rawInputLogCP)
		if err == nil {
			inputLogCP = parsed
		}
	}
	var inputLogSize uint64
	if inputLogCP != nil {
		inputLogSize = inputLogCP.Size
	}

	changes := make([]torchmpt.KeyVal, 0, len(modifiedSubRoots))
	for k, v := range modifiedSubRoots {
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(v),
		})
	}
	SortKeyVals(changes)

	// 1. Lock-Free Phase: Predict MPT root
	predictStart := time.Now()
	predictedMapRoot, err := p.mptMgr.PredictKeyVals(changes)
	metrics.MPTPredictDurationSeconds.Observe(time.Since(predictStart).Seconds())
	if err != nil {
		return nil, fmt.Errorf("mptMgr.Predict failed: %w", err)
	}
	klog.V(2).Infof("Milestone M3: MPT root predicted: %x for %d keys in %v", predictedMapRoot, len(changes), time.Since(predictStart))

	// 2. Format StateCommitment: hex(MapRoot) + "\n" + rawInputLogCP + "\n"
	leafData := FormatOutputLogLeaf(predictedMapRoot, rawInputLogCP)

	// 3. Append to Output Log
	appendStart := time.Now()
	leafIdx, rawCP, err := p.outputLog.Append(ctx, leafData)
	if err != nil {
		return nil, fmt.Errorf("outputLog.Append failed: %w", err)
	}
	metrics.OutputTreeSize.Set(float64(leafIdx + 1))

	// 4. Submit to remote witnesses if configured
	if p.witness != nil {
		witStart := time.Now()
		witnessedCP, err := p.witness.Witness(ctx, rawCP)
		metrics.WitnessWaitSeconds.Observe(time.Since(witStart).Seconds())
		if err != nil {
			metrics.WitnessErrorsTotal.Inc()
			return nil, fmt.Errorf("witness failed: %w", err)
		}
		if len(witnessedCP) > 0 {
			rawCP = witnessedCP
		}
	}

	// 5. Parse Output Log checkpoint
	outCP, err := ParseCheckpointHeader(rawCP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse output log checkpoint: %w", err)
	}

	// 6. Fetch inclusion proof for Output Log leaf
	proof, err := p.outputLog.InclusionProof(ctx, leafIdx, outCP.Size)
	if err != nil {
		return nil, fmt.Errorf("outputLog.InclusionProof failed: %w", err)
	}
	metrics.OutputLogAppendDurationSeconds.Observe(time.Since(appendStart).Seconds())
	klog.V(2).Infof("Milestone M4: Output Log updated: index %d size %d in %v", leafIdx, outCP.Size, time.Since(appendStart))

	// 7. Critical Section: Commit to MPT under lock, assert root matches prediction, and ratchet serving state
	lockWaitStart := time.Now()
	p.mptMgr.Lock()
	metrics.MPTLockWaitSeconds.Observe(time.Since(lockWaitStart).Seconds())
	writeStart := time.Now()
	actualRoot, err := p.mptMgr.CommitKeyValsLocked(changes, int64(inputLogSize))
	metrics.MPTWriteDurationSeconds.Observe(time.Since(writeStart).Seconds())
	if err != nil {
		p.mptMgr.Unlock()
		return nil, fmt.Errorf("mptMgr.CommitKeyValsLocked failed: %w", err)
	}
	if actualRoot != predictedMapRoot {
		p.mptMgr.Unlock()
		panic(fmt.Sprintf("FATAL: MPT root prediction mismatch after output log append: actual root %x != predicted root %x", actualRoot, predictedMapRoot))
	}
	klog.Infof("Milestone M5: Committed MPT MapRoot: %x for InputLog size %d in %v (time-to-serve reached)", actualRoot, inputLogSize, time.Since(writeStart))

	// 8. Construct and store new ServingState
	newState := &ServingState{
		OutputLogIndex: leafIdx,
		OutputLogSize:  outCP.Size,
		OutputLogCP:    outCP,
		RawCheckpoint:  rawCP,
		OutputLogProof: proof,
		InputLogCP:     inputLogCP,
		RawInputLogCP:  rawInputLogCP,
		InputLogSize:   inputLogSize,
		MapRoot:        actualRoot,
	}
	p.SetServingState(newState)
	p.mptMgr.Unlock()
	return newState, nil
}

func countWitnessSignatures(rawCP []byte) int {
	if len(rawCP) == 0 {
		return 0
	}
	lines := bytes.Split(rawCP, []byte("\n"))
	count := 0
	for _, l := range lines {
		trimmed := bytes.TrimSpace(l)
		if bytes.HasPrefix(trimmed, []byte("— ")) || bytes.HasPrefix(trimmed, []byte("-- ")) || bytes.HasPrefix(trimmed, []byte("\xe2\x80\x94 ")) {
			count++
		}
	}
	return count
}

// Publish provides a simplified signature taking raw checkpoint bytes and input log size.
func (p *OutputPublisher) Publish(ctx context.Context, rawInputLogCP []byte, inputLogSize uint64, subRoots map[[sha256.Size]byte][sha256.Size]byte) (*ServingState, error) {
	cp := &log.Checkpoint{
		Size: inputLogSize,
	}
	return p.PublishBatch(ctx, subRoots, cp, rawInputLogCP)
}

// ParseCheckpointHeader parses a raw signed-note / tlog-checkpoint header extracting Origin, Size, and Hash.
func ParseCheckpointHeader(rawCP []byte) (*log.Checkpoint, error) {
	lines := bytes.Split(rawCP, []byte("\n"))
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid checkpoint format: expected at least 3 lines, got %d", len(lines))
	}
	origin := string(lines[0])
	size, err := strconv.ParseUint(string(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint size %q: %w", string(lines[1]), err)
	}
	hashStr := string(lines[2])
	hashBytes, err := base64.StdEncoding.DecodeString(hashStr)
	if err != nil {
		if h, hErr := hex.DecodeString(hashStr); hErr == nil && len(h) == 32 {
			hashBytes = h
		} else {
			return nil, fmt.Errorf("failed to decode checkpoint root hash %q: %w", hashStr, err)
		}
	}
	return &log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hashBytes,
	}, nil
}
