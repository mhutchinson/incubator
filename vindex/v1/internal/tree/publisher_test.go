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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
)

type mockOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
}

func newMockOutputLog(origin string) *mockOutputLog {
	return &mockOutputLog{origin: origin}
}

func (m *mockOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n\n— test_sig\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (m *mockOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if leafIdx >= uint64(len(m.leaves)) || treeSize > uint64(len(m.leaves)) {
		return nil, fmt.Errorf("invalid leafIdx %d or treeSize %d", leafIdx, treeSize)
	}
	// For testing, return mock sibling hashes
	var proof [][sha256.Size]byte
	if treeSize > 1 {
		proof = append(proof, sha256.Sum256([]byte("sibling_hash")))
	}
	return proof, nil
}

type mockWitness struct {
	witnessName string
}

func (w *mockWitness) Witness(_ context.Context, checkpoint []byte) ([]byte, error) {
	cosig := fmt.Sprintf("— %s cosig_valid\n", w.witnessName)
	return append(checkpoint, []byte(cosig)...), nil
}

func TestPublisher_PublishBatch(t *testing.T) {
	ctx := context.Background()
	mptMgr := NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.alpha"}

	pub := NewOutputPublisher(nil, mptMgr, outLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	subRoots := map[[32]byte][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	state, err := pub.PublishBatch(ctx, subRoots, inputCP, rawInputCP)
	if err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	if state.OutputLogIndex != 0 {
		t.Fatalf("OutputLogIndex = %d, want 0", state.OutputLogIndex)
	}
	if state.OutputLogSize != 1 {
		t.Fatalf("OutputLogSize = %d, want 1", state.OutputLogSize)
	}
	if state.InputLogSize != 1000 {
		t.Fatalf("InputLogSize = %d, want 1000", state.InputLogSize)
	}

	// Verify MPT has the updated key
	proof, val, exists, err := mptMgr.Prove(key1)
	if err != nil || !exists || val != val1 {
		t.Fatalf("Prove(key1) failed: exists=%v, val=%x (want %x), err=%v", exists, val, val1, err)
	}
	if err := Verify(state.MapRoot, key1, val, true, proof); err != nil {
		t.Fatalf("Verify(key1) against MapRoot failed: %v", err)
	}
}

type divergingOutputLog struct {
	*mockOutputLog
	mptMgr *Manager
}

func (d *divergingOutputLog) Append(ctx context.Context, leafData []byte) (uint64, []byte, error) {
	sneakKey := sha256.Sum256([]byte("sneaky_interfering_key"))
	sneakVal := sha256.Sum256([]byte("sneaky_interfering_val"))
	if _, err := d.mptMgr.Commit(map[[32]byte][32]byte{sneakKey: sneakVal}); err != nil {
		return 0, nil, err
	}
	return d.mockOutputLog.Append(ctx, leafData)
}

func TestPublishBatch_RootPredictionMismatch_Panics(t *testing.T) {
	ctx := context.Background()
	mptMgr := NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.alpha"}

	divergeLog := &divergingOutputLog{
		mockOutputLog: outLog,
		mptMgr:        mptMgr,
	}

	pub := NewOutputPublisher(nil, mptMgr, divergeLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	subRoots := map[[32]byte][32]byte{key1: val1}

	rawInputCP := []byte("example.com/inputlog\n1000\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   1000,
		Hash:   make([]byte, 32),
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected PublishBatch to panic on root prediction mismatch, but it did not panic")
		}
		panicMsg := fmt.Sprintf("%v", r)
		if !strings.Contains(panicMsg, "prediction mismatch") && !strings.Contains(panicMsg, "invariant violation") {
			t.Errorf("unexpected panic message: %s", panicMsg)
		}
	}()

	_, _ = pub.PublishBatch(ctx, subRoots, inputCP, rawInputCP)
}

func TestPublisher_PublishDirect(t *testing.T) {
	ctx := context.Background()
	mptMgr := NewMem()
	outLog := newMockOutputLog("example.com/outputlog")
	wit := &mockWitness{witnessName: "witness.example.com"}

	pub := NewOutputPublisher(nil, mptMgr, outLog, wit)

	key1 := sha256.Sum256([]byte("key1"))
	val1 := sha256.Sum256([]byte("val1"))
	subRoots := map[[32]byte][32]byte{key1: val1}

	// Apply mutations directly via SetBatch and Snap
	if err := mptMgr.SetBatch(subRoots); err != nil {
		t.Fatalf("SetBatch failed: %v", err)
	}
	mapRoot, err := mptMgr.Snap(500)
	if err != nil {
		t.Fatalf("Snap failed: %v", err)
	}

	rawInputCP := []byte("example.com/inputlog\n500\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	inputCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   500,
		Hash:   make([]byte, 32),
	}

	state, err := pub.PublishDirect(ctx, mapRoot, inputCP, rawInputCP)
	if err != nil {
		t.Fatalf("PublishDirect failed: %v", err)
	}

	if state.InputLogSize != 500 {
		t.Errorf("state.InputLogSize = %d, want 500", state.InputLogSize)
	}
	if state.MapRoot != mapRoot {
		t.Errorf("state.MapRoot = %x, want %x", state.MapRoot, mapRoot)
	}
	if state.OutputLogSize != 1 {
		t.Errorf("state.OutputLogSize = %d, want 1", state.OutputLogSize)
	}

	// Verify serving state was promoted
	activeState := pub.GetServingState()
	if activeState == nil {
		t.Fatal("GetServingState() returned nil, want promoted state")
		return
	}
	if activeState.MapRoot != mapRoot {
		t.Errorf("activeState.MapRoot = %x, want %x", activeState.MapRoot, mapRoot)
	}
}


