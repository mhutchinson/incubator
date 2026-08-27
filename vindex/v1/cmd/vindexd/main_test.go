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
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/hammer"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"golang.org/x/mod/sumdb/note"
)

func TestParseCheckpointHeaderOnly(t *testing.T) {
	hash := sha256.Sum256([]byte("root-hash"))
	raw := fmt.Sprintf("test.origin.org\n12345\n%s\n", base64.StdEncoding.EncodeToString(hash[:]))

	cp, err := parseCheckpointHeaderOnly([]byte(raw))
	if err != nil {
		t.Fatalf("parseCheckpointHeaderOnly failed: %v", err)
	}
	if cp.Origin != "test.origin.org" {
		t.Errorf("Origin = %q, want %q", cp.Origin, "test.origin.org")
	}
	if cp.Size != 12345 {
		t.Errorf("Size = %d, want 12345", cp.Size)
	}
	if string(cp.Hash) != string(hash[:]) {
		t.Errorf("Hash mismatch")
	}
}

func TestBackfillExecution(t *testing.T) {
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
	var latestSignedCP []byte
	for i := 0; i < 10; i++ {
		leaf := generator.NextLeaf()
		if i == 0 {
			targetLeafData = leaf.LeafData
		}
		_, rawCP, err := sequencer.WriteLeaf(ctx, leaf.LeafData)
		if err != nil {
			t.Fatalf("WriteLeaf %d failed: %v", i, err)
		}
		latestSignedCP = rawCP
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

	// Write checkpoint file for testing --backfill_checkpoint
	cpFile := filepath.Join(tmpDir, "target.checkpoint")
	if err := os.WriteFile(cpFile, latestSignedCP, 0644); err != nil {
		t.Fatalf("failed to write checkpoint file: %v", err)
	}

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
	*metricsAddr = ""
	*backfill = true
	*backfillCheckpoint = cpFile

	if err := run(ctx); err != nil {
		t.Fatalf("run(ctx) with --backfill failed: %v", err)
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

	// Verify that key chunks exist in the backfilled storage
	_, rec, exists, err := db.ActiveChunk(sha256.Sum256(targetLeafData))
	if err != nil {
		t.Fatalf("ActiveChunk failed: %v", err)
	}
	if !exists || rec == nil {
		t.Fatalf("expected key chunk to exist in backfilled index")
	}
	if len(rec.RelativeIndices) == 0 {
		t.Errorf("len(rec.RelativeIndices) = 0, want >= 1")
	}
}
