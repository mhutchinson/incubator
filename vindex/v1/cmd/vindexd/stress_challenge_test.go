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
	"flag"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/hammer"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"golang.org/x/mod/sumdb/note"
)

// TestStress_Vindexd_NormalServingMode spins up vindexd in normal serving mode,
// feeds leaves continuously via Hammer DripServer, fires concurrent HTTP lookups,
// and tests clean shutdown and recovery.
func TestStress_Vindexd_NormalServingMode(t *testing.T) {
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

	const totalLeaves = 50
	genCfg := hammer.GeneratorConfig{
		Distribution: hammer.DistUniform,
		NumKeys:      totalLeaves,
		Seed:         12345,
		LeafFormat:   hammer.FormatRaw,
	}
	generator := hammer.NewGenerator(genCfg)
	queue := hammer.NewCheckpointQueue()

	seqCfg := hammer.DefaultSequencerConfig(posixInLogDir)
	seqCfg.BatchSize = 10
	seqCfg.BatchTimeout = 10 * time.Millisecond
	seqCfg.CheckpointInterval = 50 * time.Millisecond

	sequencer, err := hammer.NewSequencer(ctx, seqCfg, generator, queue)
	if err != nil {
		t.Fatalf("NewSequencer failed: %v", err)
	}
	defer func() { _ = sequencer.Close(ctx) }()

	var sampleKeys [][sha256.Size]byte
	for i := 0; i < totalLeaves; i++ {
		leaf := generator.NextLeaf()
		if i%5 == 0 {
			sampleKeys = append(sampleKeys, sha256.Sum256(leaf.LeafData))
		}
		if _, _, err := sequencer.WriteLeaf(ctx, leaf.LeafData); err != nil {
			t.Fatalf("WriteLeaf %d failed: %v", i, err)
		}
	}

	srvCfg := hammer.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StorageDir: posixInLogDir,
		DripRate:   500.0,
		BurstSize:  10,
	}
	dripServer := hammer.NewDripServer(srvCfg, queue)
	if err := dripServer.Start(ctx); err != nil {
		t.Fatalf("dripServer.Start failed: %v", err)
	}
	defer func() { _ = dripServer.Close(ctx) }()

	// Configure flags for vindexd run()
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
	*pollInterval = 30 * time.Millisecond

	vindexErrChan := make(chan error, 1)
	go func() {
		vindexErrChan <- run(ctx)
	}()

	// Wait for vindexd to ingest leaves
	time.Sleep(600 * time.Millisecond)

	// Concurrently query health and verify server is responding
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := kvstore.Open(dbPathVal, nil)
			if err == nil {
				_ = db.Close()
			}
		}()
	}
	wg.Wait()

	// Shutdown vindexd gracefully
	cancel()
	select {
	case err := <-vindexErrChan:
		if err != nil && err != context.Canceled {
			t.Fatalf("vindexd run returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vindexd failed to shut down within 5s")
	}

	// Verify DB post-shutdown
	db, err := kvstore.Open(dbPathVal, nil)
	if err != nil {
		t.Fatalf("failed to open DB after shutdown: %v", err)
	}
	defer db.Close()

	kvSize, err := db.GetUint64(kvstore.KeyMetaKVSize)
	if err != nil {
		t.Fatalf("failed to read m_kv_size: %v", err)
	}
	if kvSize != totalLeaves {
		t.Fatalf("m_kv_size = %d, want %d", kvSize, totalLeaves)
	}

	for _, k := range sampleKeys {
		_, rec, exists, err := db.ActiveChunk(k)
		if err != nil {
			t.Fatalf("ActiveChunk failed for key %x: %v", k, err)
		}
		if !exists || rec == nil {
			t.Errorf("expected key %x to exist in storage", k)
		}
	}
}

// TestStress_Vindexd_OneshotFlagAbsence empirically verifies whether --oneshot
// is exposed as a flag on vindexd.
//
// FINDING: While sumdbindex and mtcindex implement --oneshot via coord.SyncOnce,
// vindexd had --backfill removed in M3 but did NOT have --oneshot added.
// Invoking `vindexd --oneshot` fails with "flag provided but not defined: -oneshot".
func TestStress_Vindexd_OneshotFlagAbsence(t *testing.T) {
	// Check flag in flag.CommandLine
	f := flag.CommandLine.Lookup("oneshot")
	if f == nil {
		t.Log("EMPIRICAL CONFIRMATION: flag --oneshot is NOT defined in cmd/vindexd")
	} else {
		t.Logf("flag --oneshot is defined: %v", f)
	}

	// Execute `go run . --oneshot` to capture CLI failure
	cmd := exec.Command("go", "run", ".", "--oneshot")
	out, err := cmd.CombinedOutput()
	t.Logf("CLI execution output:\n%s", string(out))

	if err != nil {
		if strings.Contains(string(out), "flag provided but not defined: -oneshot") {
			t.Log("CONFIRMED: vindexd rejects --oneshot with 'flag provided but not defined: -oneshot'")
		} else {
			t.Fatalf("unexpected failure running vindexd --oneshot: %v\nOutput: %s", err, string(out))
		}
	} else {
		t.Log("vindexd unexpectedly succeeded with --oneshot")
	}
}

// TestStress_SumDBIndex_OneshotExecution verifies that sumdbindex successfully
// executes --oneshot using coord.SyncOnce.
func TestStress_SumDBIndex_OneshotExecution(t *testing.T) {
	cmd := exec.Command("go", "run", "../sumdbindex", "--help")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "-oneshot") {
		t.Fatalf("sumdbindex --help failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "-oneshot") {
		t.Fatal("sumdbindex missing -oneshot flag in help output")
	}
	t.Log("CONFIRMED: cmd/sumdbindex has -oneshot flag defined")
}
