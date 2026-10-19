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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
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

func getTestWasm(t *testing.T) string {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "test.wasm")
	if err := os.WriteFile(wasmPath, wasmtest.Bytes(), 0o644); err != nil {
		t.Fatalf("failed to write test wasm: %v", err)
	}
	return wasmPath
}

func resetFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		*dbPath = ""
		*mptDir = ""
		*outputLogDir = ""
		*outputLogOrigin = ""
		*outputLogSignerKey = ""
		*tileCacheDir = ""
		*wasmPath = ""
		*wasmWorkers = 0
		*listenAddr = "127.0.0.1:0"
		*metricsAddr = ""
		*inputLogURL = ""
		*inputLogOrigin = ""
		*inputLogPubKey = ""
		*inputLogPolicy = ""
		*oneShot = false
		*cleanDirs = false
		*prefixPolicyFlag = "allow"
		*pathPrefix = ""
		boundListenAddr.Store(nil)
		boundMetricsAddr.Store(nil)
	})
}

func TestVindexd_FlagValidation(t *testing.T) {
	resetFlags(t)
	ctx := context.Background()
	tmpDir := t.TempDir()

	*dbPath = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--db_path flag is required") {
		t.Fatalf("expected missing db_path error, got: %v", err)
	}
	*dbPath = filepath.Join(tmpDir, "db")

	*wasmPath = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--wasm_path flag is required") {
		t.Fatalf("expected missing wasm_path error, got: %v", err)
	}
	*wasmPath = getTestWasm(t)

	*outputLogDir = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--output_log_dir flag is required") {
		t.Fatalf("expected missing output_log_dir error, got: %v", err)
	}
	*outputLogDir = filepath.Join(tmpDir, "outputlog")

	*outputLogSignerKey = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--output_log_signer_key flag is required") {
		t.Fatalf("expected missing output_log_signer_key error, got: %v", err)
	}
}

func TestVindexd_POSIXOutputLog_Lifecycle(t *testing.T) {
	resetFlags(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	origin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, origin)

	outD := filepath.Join(tmpDir, "outputlog")
	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	*outputLogDir = outD
	*outputLogSignerKey = skey
	*outputLogOrigin = origin
	*tileCacheDir = filepath.Join(tmpDir, "tiles")
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 1
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*inputLogURL = ""

	runCtx, runCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(runCtx)
	}()

	cpPath := filepath.Join(outD, "checkpoint")
	var cpBytes []byte
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(cpPath); err == nil && len(data) > 0 {
			cpBytes = data
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	runCancel()
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("run failed: %v", err)
	}
	if len(cpBytes) == 0 {
		t.Fatalf("expected Tessera checkpoint to be written to %s", cpPath)
	}
	if !strings.Contains(string(cpBytes), origin) {
		t.Errorf("checkpoint header %q does not contain origin %q", string(cpBytes), origin)
	}
}

func TestVindexd_POSIXOutputLog_SyncAndRestart(t *testing.T) {
	resetFlags(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

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
		WithBatching(2, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewAppender failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 10*time.Millisecond)
	f0 := appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-0")))
	f1 := appender.Add(ctx, tessera.NewEntry([]byte("hello-leaf-1")))
	if _, _, err := awaiter.Await(ctx, f0); err != nil {
		t.Fatalf("appender.Add(0) failed: %v", err)
	}
	if _, _, err := awaiter.Await(ctx, f1); err != nil {
		t.Fatalf("appender.Add(1) failed: %v", err)
	}

	inServer := httptest.NewServer(http.FileServer(http.Dir(inLogDir)))
	defer inServer.Close()

	outOrigin := "test.outlog"
	outSKey, _ := newTestSignerKey(t, outOrigin)
	outD := filepath.Join(tmpDir, "outputlog")

	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	*outputLogDir = outD
	*outputLogSignerKey = outSKey
	*outputLogOrigin = outOrigin
	*tileCacheDir = filepath.Join(tmpDir, "tilecache")
	*inputLogURL = inServer.URL
	*inputLogOrigin = inOrigin
	*inputLogPubKey = inVKey
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 2
	*oneShot = true
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""

	if err := run(ctx); err != nil {
		t.Fatalf("first run (oneshot) failed: %v", err)
	}

	cpBytes, err := os.ReadFile(filepath.Join(outD, "checkpoint"))
	if err != nil {
		t.Fatalf("failed to read output log checkpoint: %v", err)
	}
	if !strings.Contains(string(cpBytes), outOrigin) {
		t.Fatalf("output checkpoint missing origin: %s", string(cpBytes))
	}

	// Second run on same directory exercises warm startup recovery.
	if err := run(ctx); err != nil {
		t.Fatalf("second run (recovery restart) failed: %v", err)
	}

	// Verify HTTP serving of tiles and operational listener separation.
	boundListenAddr.Store(nil)
	boundMetricsAddr.Store(nil)
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = "127.0.0.1:0"
	*oneShot = false
	*pollInterval = 100 * time.Millisecond

	srvCtx, srvCancel := context.WithCancel(ctx)
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- run(srvCtx)
	}()

	httpCli := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		addrPtr := boundListenAddr.Load()
		mAddrPtr := boundMetricsAddr.Load()
		if addrPtr == nil || *addrPtr == "" || mAddrPtr == nil || *mAddrPtr == "" {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		resp, err = httpCli.Get(fmt.Sprintf("http://%s/checkpoint", *addrPtr))
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}
	if resp == nil || err != nil || resp.StatusCode != http.StatusOK {
		srvCancel()
		t.Fatalf("failed to query /checkpoint: %v, resp: %v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), outOrigin) {
		t.Errorf("read server /checkpoint body %q missing %q", string(body), outOrigin)
	}

	pubAddr := *boundListenAddr.Load()
	admAddr := *boundMetricsAddr.Load()

	for _, opPath := range []string{"/healthz", "/readyz", "/syncz", "/metrics", "/debug/pprof/"} {
		opResp, opErr := httpCli.Get(fmt.Sprintf("http://%s%s", pubAddr, opPath))
		if opErr != nil {
			t.Fatalf("GET public %s failed: %v", opPath, opErr)
		}
		_ = opResp.Body.Close()
		if opResp.StatusCode != http.StatusNotFound {
			t.Errorf("GET public %s status = %d, want 404", opPath, opResp.StatusCode)
		}
	}

	for _, opPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/"} {
		opResp, opErr := httpCli.Get(fmt.Sprintf("http://%s%s", admAddr, opPath))
		if opErr != nil {
			t.Fatalf("GET admin %s failed: %v", opPath, opErr)
		}
		_ = opResp.Body.Close()
		if opResp.StatusCode != http.StatusOK {
			t.Errorf("GET admin %s status = %d, want 200", opPath, opResp.StatusCode)
		}
	}

	srvCancel()
	if err := <-srvErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server run error: %v", err)
	}
}

func TestVindexd_MTCVerifier_FlagAndInit(t *testing.T) {
	resetFlags(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	outOrigin := "vindex.test.output"
	skey, _ := newTestSignerKey(t, outOrigin)

	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	*outputLogDir = filepath.Join(tmpDir, "outputlog")
	*outputLogSignerKey = skey
	*outputLogOrigin = outOrigin
	*wasmPath = getTestWasm(t)
	*wasmWorkers = 1
	*listenAddr = "127.0.0.1:0"
	*metricsAddr = ""
	*inputLogURL = "https://bootstrap-mtca-shard3.cloudflareresearch.com"
	*inputLogOrigin = "bootstrap-mtca.cloudflareresearch.com/logs/shard3"

	*inputLogPubKey = "mtc+invalid+key"
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "invalid MTC verifier") {
		t.Fatalf("expected invalid MTC verifier error, got: %v", err)
	}

	*inputLogPubKey = mtcKey
	cancel()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected clean run/exit on context cancel, got: %v", err)
	}
}

func TestVindexd_CleanDirs(t *testing.T) {
	resetFlags(t)
	tmpDir := t.TempDir()
	d1 := filepath.Join(tmpDir, "db")
	d2 := filepath.Join(tmpDir, "mpt")
	d3 := filepath.Join(tmpDir, "outlog")
	d4 := filepath.Join(tmpDir, "tiles")

	for _, d := range []string{d1, d2, d3, d4} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "canary.txt"), []byte("canary"), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	*dbPath = d1
	*mptDir = d2
	*outputLogDir = d3
	*tileCacheDir = d4
	*cleanDirs = true
	*wasmPath = "" // Missing required flag must abort before wiping directories.

	if err := run(context.Background()); err == nil {
		t.Fatalf("expected error due to missing wasm_path, got nil")
	}
	for _, d := range []string{d1, d2, d3, d4} {
		canary := filepath.Join(d, "canary.txt")
		if _, err := os.Stat(canary); errors.Is(err, os.ErrNotExist) {
			t.Fatalf("destructive clean executed despite invalid flags: %q was deleted", canary)
		}
	}

	if err := cleanDirectories(); err != nil {
		t.Fatalf("cleanDirectories failed: %v", err)
	}
	for _, d := range []string{d1, d2, d3, d4} {
		canary := filepath.Join(d, "canary.txt")
		if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected %q to be deleted by cleanDirectories", canary)
		}
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Errorf("expected %q to exist as an empty directory after cleanDirectories", d)
		}
	}
}
