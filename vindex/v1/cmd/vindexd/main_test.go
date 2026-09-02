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

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/hammer"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"golang.org/x/mod/sumdb/note"
)

func TestVindexdRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	posixInLogDir := filepath.Join(tmpDir, "posix_inlog")
	dbPathVal := filepath.Join(tmpDir, "db")
	mptPathVal := filepath.Join(tmpDir, "mpt")
	outDirVal := filepath.Join(tmpDir, "outputlog")
	tileDirVal := filepath.Join(tmpDir, "tiles")

	signerKey, _, err := note.GenerateKey(rand.Reader, "test.output.log")
	if err != nil {
		t.Fatalf("failed to generate output signer key: %v", err)
	}

	// 1. Setup Hammer Generator & Sequencer
	genCfg := hammer.GeneratorConfig{
		Distribution: hammer.DistUniform,
		NumKeys:      10,
		Seed:         42,
		LeafFormat:   hammer.FormatRaw,
	}
	generator := hammer.NewGenerator(genCfg)
	queue := hammer.NewCheckpointQueue()

	seqCfg := hammer.DefaultSequencerConfig(posixInLogDir)
	seqCfg.BatchSize = 4
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 50 * time.Millisecond

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = sequencer.Close(ctx) }()

	// Write 10 leaves
	var targetLeafData []byte
	for i := 0; i < 10; i++ {
		leaf := generator.NextLeaf()
		if i == 0 {
			targetLeafData = leaf.LeafData
		}
		if _, _, err := sequencer.WriteLeaf(ctx, leaf.LeafData); err != nil {
			t.Fatalf("WriteLeaf %d failed: %v", i, err)
		}
	}

	// 2. Setup Drip Server
	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixInLogDir,
		DripRate:   100.0,
		BurstSize:  1,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() { _ = dripServer.Close(ctx) }()

	// Configure flags for run()
	*dbPath = dbPathVal
	*mptDir = mptPathVal
	*outputLogDir = outDirVal
	*tileCacheDir = tileDirVal
	*outputLogOrigin = "test.output.log"
	*outputLogSignerKey = signerKey
	*inputLogURL = dripServer.URL()
	*inputLogOrigin = sequencer.Origin()
	*inputLogPubKey = sequencer.VerifierKey()
	*mapper = "identity"
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*pollInterval = 50 * time.Millisecond

	// Cancel context after vindexd has had time to ingest the 10 leaves
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	if err := run(ctx); err != nil {
		t.Fatalf("run(ctx) failed: %v", err)
	}

	// Verify that DB metadata was populated and can be opened
	db, err := kvstore.Open(dbPathVal, nil)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		t.Fatalf("failed to read KV size: %v", err)
	}
	if kvSize != 10 {
		t.Errorf("kvSize = %d, want 10", kvSize)
	}

	// Verify that key chunks exist in storage
	_, rec, exists, err := db.ActiveChunk(sha256.Sum256(targetLeafData))
	if err != nil {
		t.Fatalf("ActiveChunk failed: %v", err)
	}
	if !exists || rec == nil {
		t.Fatalf("expected key chunk to exist in indexed storage")
	}
	if len(rec.RelativeIndices) == 0 {
		t.Errorf("len(rec.RelativeIndices) = 0, want >= 1")
	}
}
