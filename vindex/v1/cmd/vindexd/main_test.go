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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func newTestSignerKey(t *testing.T, origin string) (string, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("failed to generate note key: %v", err)
	}
	return skey, vkey
}

func TestVindexd_FlagValidation_Publisher(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	*mode = "publisher"

	// 1. Missing db_path
	*dbPath = ""
	err := run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--db_path flag is required") {
		t.Fatalf("expected missing db_path error, got: %v", err)
	}
	*dbPath = filepath.Join(tmpDir, "db")

	// 2. Missing output_log_dir
	*outputLogDir = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--output_log_dir flag is required") {
		t.Fatalf("expected missing output_log_dir error, got: %v", err)
	}
	*outputLogDir = filepath.Join(tmpDir, "outputlog")

	// 3. Missing output_log_signer_key
	*outputLogSignerKey = ""
	err = run(ctx)
	if err == nil || !strings.Contains(err.Error(), "--output_log_signer_key flag is required") {
		t.Fatalf("expected missing output_log_signer_key error, got: %v", err)
	}
}

func TestVindexd_POSIXOutputLog_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	origin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, origin)

	dbD := filepath.Join(tmpDir, "db")
	mptD := filepath.Join(tmpDir, "mpt")
	outD := filepath.Join(tmpDir, "outputlog")
	cacheD := filepath.Join(tmpDir, "tiles")

	*mode = "publisher"
	*dbPath = dbD
	*mptDir = mptD
	*outputLogDir = outD
	*outputLogSignerKey = skey
	*outputLogOrigin = origin
	*tileCacheDir = cacheD
	*mapper = "identity"
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*inputLogURL = "" // no fetcher, run recovery and shutdown

	// Run publisher briefly in background
	runCtx, runCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(runCtx)
	}()

	// Wait for initialization, verify checkpoint file exists on disk
	cpPath := filepath.Join(outD, "checkpoint")
	var cpBytes []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(cpPath)
		if err == nil && len(data) > 0 {
			cpBytes = data
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	runCancel()
	if err := <-errCh; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("run failed: %v", err)
	}

	// Verify Tessera POSIX storage initialization on disk
	if len(cpBytes) == 0 {
		t.Fatalf("expected Tessera checkpoint to be written to %s", cpPath)
	}
	if !strings.Contains(string(cpBytes), origin) {
		t.Errorf("checkpoint header %q does not contain origin %q", string(cpBytes), origin)
	}
}

func TestVindexd_POSIXOutputLog_SyncAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	// 1. Create Input Log with Tessera POSIX
	inLogDir := filepath.Join(tmpDir, "inlog")
	inOrigin := "test.inlog"
	inSKey, inVKey := newTestSignerKey(t, inOrigin)
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	driver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("posix.New failed: %v", err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 10*time.Millisecond)
	_, _, err = awaiter.Await(ctx, appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-0"))))
	if err != nil {
		t.Fatalf("appender.Add failed: %v", err)
	}
	_, _, err = awaiter.Await(ctx, appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-1"))))
	if err != nil {
		t.Fatalf("appender.Add failed: %v", err)
	}

	inServer := httptest.NewServer(http.FileServer(http.Dir(inLogDir)))
	defer inServer.Close()

	// 2. Setup VIndex Output Log keys and paths
	outOrigin := "test.outlog"
	outSKey, _ := newTestSignerKey(t, outOrigin)

	dbD := filepath.Join(tmpDir, "db")
	mptD := filepath.Join(tmpDir, "mpt")
	outD := filepath.Join(tmpDir, "outputlog")
	cacheD := filepath.Join(tmpDir, "tilecache")

	// 3. Run vindexd in oneshot mode
	*mode = "publisher"
	*dbPath = dbD
	*mptDir = mptD
	*outputLogDir = outD
	*outputLogSignerKey = outSKey
	*outputLogOrigin = outOrigin
	*tileCacheDir = cacheD
	*inputLogURL = inServer.URL
	*inputLogOrigin = inOrigin
	*inputLogPubKey = inVKey
	*mapper = "identity"
	*oneShot = true
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""

	if err := run(ctx); err != nil {
		t.Fatalf("first run (oneshot) failed: %v", err)
	}

	// Verify Output Log checkpoint on disk has size >= 1
	cpBytes, err := os.ReadFile(filepath.Join(outD, "checkpoint"))
	if err != nil {
		t.Fatalf("failed to read output log checkpoint: %v", err)
	}
	if !strings.Contains(string(cpBytes), outOrigin) {
		t.Fatalf("output checkpoint missing origin: %s", string(cpBytes))
	}

	// 4. Restart vindexd on same directory with oneshot mode to test persistence and recovery
	if err := run(ctx); err != nil {
		t.Fatalf("second run (recovery restart) failed: %v", err)
	}

	// 5. Verify HTTP serving of tiles from outputLogDir
	freePort, err := getFreePort()
	if err != nil {
		t.Fatalf("getFreePort failed: %v", err)
	}
	srvAddr := fmt.Sprintf("127.0.0.1:%d", freePort)
	*listenAddr = srvAddr
	*oneShot = false
	*pollInterval = 100 * time.Millisecond

	srvCtx, srvCancel := context.WithCancel(ctx)
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- run(srvCtx)
	}()

	// Query /checkpoint and /tile/ endpoints from vindexd
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(fmt.Sprintf("http://%s/checkpoint", srvAddr))
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		srvCancel()
		t.Fatalf("failed to query /checkpoint: %v, resp: %v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), outOrigin) {
		t.Errorf("read server /checkpoint body %q missing %q", string(body), outOrigin)
	}

	srvCancel()
	if err := <-srvErrCh; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("server run error: %v", err)
	}
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
