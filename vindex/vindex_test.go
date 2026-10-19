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

package vindex_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func newTestWASMHost(t *testing.T) *vindex.WASMHost {
	t.Helper()
	h, err := vindex.NewWASMHost(context.Background(), wasmtest.Bytes(), 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	return h
}

func newBaseEngineConfig(t *testing.T) vindex.Config {
	t.Helper()
	rootDir := t.TempDir()
	outSKey, _, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	return vindex.Config{
		DBPath:             filepath.Join(rootDir, "db"),
		MPTDir:             filepath.Join(rootDir, "mpt"),
		TileCacheDir:       filepath.Join(rootDir, "cache"),
		OutputLogDir:       filepath.Join(rootDir, "outlog"),
		OutputLogSignerKey: outSKey,
		PollInterval:       10 * time.Millisecond,
	}
}

func TestVIndex_PublicAPIAndSharedWASMHostSurvivesClose(t *testing.T) {
	cfg := vindex.DefaultConfig()
	if cfg.ChunkSize == 0 {
		t.Fatalf("invalid default config: %+v", cfg)
	}

	sharedHost := newTestWASMHost(t)

	// Bug #8 verification: closing an Engine constructed with a caller-supplied *WASMHost
	// must NOT close sharedHost!
	engCfg := newBaseEngineConfig(t)
	eng, err := vindex.New(engCfg, sharedHost)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("eng.Close failed: %v", err)
	}

	batch, err := sharedHost.MapBundle(context.Background(), [][]byte{[]byte("hello")})
	if err != nil {
		t.Fatalf("sharedHost.MapBundle after Engine.Close() failed: %v", err)
	}
	if len(batch) != 1 || len(batch[0]) != 1 || batch[0][0].Key != "hello" || batch[0][0].KeyHash != sha256.Sum256([]byte("hello")) {
		t.Fatalf("unexpected canonical entries: %+v", batch)
	}
}

func TestEngine_Lifecycle_EndToEndIngestionAndLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.inputlog")
	if err != nil {
		t.Fatalf("failed to generate input log key: %v", err)
	}
	inSigner, _ := note.NewSigner(inSKey)
	inVerifier, _ := note.NewVerifier(inVKey)

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "test.outputlog")
	if err != nil {
		t.Fatalf("failed to generate output log key: %v", err)
	}
	outVerifier, _ := note.NewVerifier(outVKey)

	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	mptDir := filepath.Join(rootDir, "mpt")
	cacheDir := filepath.Join(rootDir, "cache")
	outLogDir := filepath.Join(rootDir, "outlog")
	inLogDir := filepath.Join(rootDir, "inlog")

	inDriver, err := posix.New(ctx, posix.Config{Path: inLogDir})
	if err != nil {
		t.Fatalf("failed to initialize input log storage: %v", err)
	}
	inAppender, inShutdown, inReader, err := tessera.NewAppender(ctx, inDriver, tessera.NewAppendOptions().
		WithCheckpointSigner(inSigner).
		WithBatching(1, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create input log appender: %v", err)
	}
	t.Cleanup(func() { _ = inShutdown(context.Background()) })

	inAwaiter := tessera.NewPublicationAwaiter(ctx, inReader.ReadCheckpoint, 5*time.Millisecond)
	appendLeaf := func(payload []byte) uint64 {
		idx, rawCP, err := inAwaiter.Await(ctx, inAppender.Add(ctx, tessera.NewEntry(payload)))
		if err != nil || len(rawCP) == 0 {
			t.Fatalf("failed to append leaf %q: %v", string(payload), err)
		}
		return idx.Index
	}

	if idx0, idx1, idx2 := appendLeaf([]byte("apple alpha")), appendLeaf([]byte("banana beta")), appendLeaf([]byte("apple gamma")); idx0 != 0 || idx1 != 1 || idx2 != 2 {
		t.Fatalf("unexpected indices: %d, %d, %d", idx0, idx1, idx2)
	}

	sharedHost := newTestWASMHost(t)
	cfg := vindex.Config{
		DBPath:             dbDir,
		MPTDir:             mptDir,
		TileCacheDir:       cacheDir,
		ChunkSize:          64,
		PollInterval:       50 * time.Millisecond,
		InputLogURL:        fmt.Sprintf("file://%s", inLogDir),
		InputLogOrigin:     "test.inputlog",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       outLogDir,
		OutputLogOrigin:    "test.outputlog",
		OutputLogSignerKey: outSKey,
		PrefixPolicy:       "allow",
	}

	engine, err := vindex.New(cfg, sharedHost)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if engine.OutputLogVerifier() == nil {
		t.Fatal("expected OutputLogVerifier() to be derived from standard Ed25519 note signer key")
	}

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	adminTS := httptest.NewServer(engine.AdminHandler())
	defer adminTS.Close()

	for _, removedURL := range []string{
		ts.URL + "/vindex/v1/lookup",
		ts.URL + "/inputlog_checkpoint",
		adminTS.URL + "/syncz",
	} {
		resp, err := ts.Client().Get(removedURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", removedURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", removedURL, resp.StatusCode)
		}
	}
	for _, liveURL := range []string{
		ts.URL + "/checkpoint",
		adminTS.URL + "/healthz",
		adminTS.URL + "/readyz",
		adminTS.URL + "/metrics",
	} {
		resp, err := ts.Client().Get(liveURL)
		if err != nil {
			t.Fatalf("GET %s failed: %v", liveURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", liveURL, resp.StatusCode)
		}
	}

	outPolicy, err := client.SingleKeyPolicy("test.outputlog", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(out) failed: %v", err)
	}
	verifierCfg := client.Config{
		ExpectedOutputLogOrigin: "test.outputlog",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "test.inputlog",
	}
	cli, err := client.New(ts.URL, verifierCfg, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	collectAscending := func(c *client.Client, key string) ([]uint64, error) {
		res, err := c.LookupKey(ctx, key)
		if err != nil {
			return nil, err
		}
		if len(res.Keys) == 0 {
			return nil, nil
		}
		var out []uint64
		for idx, err := range res.Keys[0].Values(ctx) {
			if err != nil {
				return nil, err
			}
			out = append(out, idx)
		}
		slices.Reverse(out)
		return out, nil
	}

	if indicesApple, err := collectAscending(cli, "apple"); err != nil || !slices.Equal(indicesApple, []uint64{0, 2}) {
		t.Fatalf("LookupKey/Values(apple) = %v, err=%v, want [0 2]", indicesApple, err)
	}
	if prefResp, err := cli.LookupPrefix(ctx, "a"); err != nil || len(prefResp.Keys) != 1 || prefResp.Keys[0].Key != "apple" {
		t.Fatalf("LookupPrefix(a) = %+v, err=%v", prefResp, err)
	}
	if indicesBanana, err := collectAscending(cli, "banana"); err != nil || !slices.Equal(indicesBanana, []uint64{1}) {
		t.Fatalf("LookupKey/Values(banana) = %v, err=%v, want [1]", indicesBanana, err)
	}
	if krCherry, err := cli.LookupKey(ctx, "cherry"); err != nil || len(krCherry.Keys) != 0 {
		t.Fatalf("LookupKey(cherry) = %+v, err=%v", krCherry, err)
	}

	if idx3 := appendLeaf([]byte("apple delta")); idx3 != 3 {
		t.Fatalf("unexpected idx3 = %d, want 3", idx3)
	}

	deadline := time.Now().Add(5 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		if indices, err := collectAscending(cli, "apple"); err == nil && slices.Equal(indices, []uint64{0, 2, 3}) {
			updated = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !updated {
		t.Fatal("timed out waiting for background synchronization of dynamic leaf 3")
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close failed: %v", err)
	}

	// Restart using the SAME sharedHost (proving Close did not destroy sharedHost)
	engine2, err := vindex.New(cfg, sharedHost)
	if err != nil {
		t.Fatalf("vindex.New (restart) failed: %v", err)
	}
	if err := engine2.Start(ctx); err != nil {
		t.Fatalf("engine2.Start failed: %v", err)
	}
	defer func() { _ = engine2.Close() }()

	ts2 := httptest.NewServer(engine2.Handler())
	defer ts2.Close()

	cli2, err := client.New(ts2.URL, verifierCfg, client.WithHTTPClient(ts2.Client()))
	if err != nil {
		t.Fatalf("client.New (restart) failed: %v", err)
	}
	if indicesRestart, err := collectAscending(cli2, "apple"); err != nil || !slices.Equal(indicesRestart, []uint64{0, 2, 3}) {
		t.Fatalf("after restart: indices=%v, err=%v, want [0 2 3]", indicesRestart, err)
	}
}

func TestEngine_ListenersLifecycleAndValidation(t *testing.T) {
	t.Run("early_listeners_and_lifecycle_guards", func(t *testing.T) {
		cfg := newBaseEngineConfig(t)
		cfg.ListenAddr = "127.0.0.1:0"
		cfg.MetricsAddr = "127.0.0.1:0"
		cfg.ServeOutputTiles = true

		engine, err := vindex.New(cfg, newTestWASMHost(t))
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}
		if engine.ListenAddr() == "" || engine.MetricsAddr() == "" {
			t.Fatalf("expected bound addresses, got listen=%q metrics=%q", engine.ListenAddr(), engine.MetricsAddr())
		}

		resp, err := http.Get("http://" + engine.MetricsAddr() + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
		}

		ctx := context.Background()
		if err := engine.Start(ctx); err != nil {
			t.Fatalf("engine.Start failed: %v", err)
		}
		if err := engine.Start(ctx); err == nil {
			t.Error("expected error calling Start() when already running")
		}
		if err := engine.Run(ctx); err == nil {
			t.Error("expected error calling Run() when already running")
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("engine.Close failed: %v", err)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}
		if err := engine.Start(ctx); err == nil {
			t.Error("expected error calling Start() after Close")
		}
		if err := engine.Run(ctx); err == nil {
			t.Error("expected error calling Run() after Close")
		}
	})

	t.Run("run_and_context_cancel", func(t *testing.T) {
		cfg := newBaseEngineConfig(t)
		engine, err := vindex.New(cfg, newTestWASMHost(t))
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}
		defer func() { _ = engine.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		runErrCh := make(chan error, 1)
		go func() {
			runErrCh <- engine.Run(ctx)
		}()
		time.Sleep(25 * time.Millisecond)
		cancel()

		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run returned unexpected error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for engine.Run to exit after cancel()")
		}
	})

	t.Run("config_validation_errors", func(t *testing.T) {
		rootDir := t.TempDir()
		outSKey, _, _ := note.GenerateKey(rand.Reader, "test.out")

		for _, tc := range []struct {
			name string
			cfg  vindex.Config
		}{
			{
				name: "missing_output_log_dir",
				cfg: vindex.Config{
					DBPath:             filepath.Join(rootDir, "db0"),
					MPTDir:             filepath.Join(rootDir, "mpt0"),
					OutputLogSignerKey: outSKey,
				},
			},
			{
				name: "missing_output_log_signer_key",
				cfg: vindex.Config{
					DBPath:       filepath.Join(rootDir, "db1"),
					MPTDir:       filepath.Join(rootDir, "mpt1"),
					OutputLogDir: filepath.Join(rootDir, "out1"),
				},
			},
			{
				name: "invalid_signer_key",
				cfg: vindex.Config{
					DBPath:             filepath.Join(rootDir, "db2"),
					MPTDir:             filepath.Join(rootDir, "mpt2"),
					OutputLogDir:       filepath.Join(rootDir, "out2"),
					OutputLogSignerKey: "not_a_valid_key",
				},
			},
			{
				name: "missing_wasm_with_input_log_url",
				cfg: vindex.Config{
					DBPath:             filepath.Join(rootDir, "db3"),
					MPTDir:             filepath.Join(rootDir, "mpt3"),
					OutputLogDir:       filepath.Join(rootDir, "out3"),
					OutputLogSignerKey: outSKey,
					InputLogURL:        "file:///tmp/some-log",
				},
			},
			{
				name: "unknown_prefix_policy",
				cfg: vindex.Config{
					DBPath:             filepath.Join(rootDir, "db4"),
					MPTDir:             filepath.Join(rootDir, "mpt4"),
					OutputLogDir:       filepath.Join(rootDir, "out4"),
					OutputLogSignerKey: outSKey,
					PrefixPolicy:       "invalid_policy",
				},
			},
		} {
			if _, err := vindex.New(tc.cfg, nil); err == nil {
				t.Errorf("%s: expected error from vindex.New, got nil", tc.name)
			}
		}
	})

	t.Run("fatal_background_halt_flips_readyz_to_503", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		inSKey, inVKey, err := note.GenerateKey(rand.Reader, "test.halt.in")
		if err != nil {
			t.Fatal(err)
		}
		inSigner, _ := note.NewSigner(inSKey)
		inVerifier, _ := note.NewVerifier(inVKey)

		rootDir := t.TempDir()
		inLogDir1 := filepath.Join(rootDir, "in1")
		inLogDir2 := filepath.Join(rootDir, "in2")

		// Log 1: honest leaf 0 -> Engine starts and reaches /readyz 200 OK.
		inDrv1, err := posix.New(ctx, posix.Config{Path: inLogDir1})
		if err != nil {
			t.Fatal(err)
		}
		app1, shut1, rdr1, err := tessera.NewAppender(ctx, inDrv1, tessera.NewAppendOptions().
			WithCheckpointSigner(inSigner).WithBatching(1, time.Millisecond).WithCheckpointInterval(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = shut1(context.Background()) }()
		aw1 := tessera.NewPublicationAwaiter(ctx, rdr1.ReadCheckpoint, 5*time.Millisecond)
		if _, _, err := aw1.Await(ctx, app1.Add(ctx, tessera.NewEntry([]byte("honest")))); err != nil {
			t.Fatal(err)
		}

		// Log 2: split-view leaf 0 at same size 1 signed by same key -> triggers fatal split-view halt on next poll.
		inDrv2, err := posix.New(ctx, posix.Config{Path: inLogDir2})
		if err != nil {
			t.Fatal(err)
		}
		app2, shut2, rdr2, err := tessera.NewAppender(ctx, inDrv2, tessera.NewAppendOptions().
			WithCheckpointSigner(inSigner).WithBatching(1, time.Millisecond).WithCheckpointInterval(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = shut2(context.Background()) }()
		aw2 := tessera.NewPublicationAwaiter(ctx, rdr2.ReadCheckpoint, 5*time.Millisecond)
		if _, _, err := aw2.Await(ctx, app2.Add(ctx, tessera.NewEntry([]byte("split_view_forged")))); err != nil {
			t.Fatal(err)
		}

		var serveSplit atomic.Bool
		fs1 := http.FileServer(http.Dir(inLogDir1))
		fs2 := http.FileServer(http.Dir(inLogDir2))
		inTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if serveSplit.Load() {
				fs2.ServeHTTP(w, r)
				return
			}
			fs1.ServeHTTP(w, r)
		}))
		defer inTS.Close()

		cfg := newBaseEngineConfig(t)
		cfg.MetricsAddr = "127.0.0.1:0"
		cfg.PollInterval = 25 * time.Millisecond
		cfg.InputLogURL = inTS.URL
		cfg.InputLogOrigin = "test.halt.in"
		cfg.InputLogVerifier = inVerifier

		engine, err := vindex.New(cfg, newTestWASMHost(t))
		if err != nil {
			t.Fatalf("vindex.New failed: %v", err)
		}
		defer func() { _ = engine.Close() }()

		if err := engine.Start(ctx); err != nil {
			t.Fatalf("engine.Start failed: %v", err)
		}
		readyURL := "http://" + engine.MetricsAddr() + "/readyz"
		resp, err := http.Get(readyURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("initial /readyz status=%v err=%v, want 200", resp, err)
		}
		_ = resp.Body.Close()

		// Flip upstream to split-view checkpoint; background poll must fatally halt and flip /readyz to 503.
		serveSplit.Store(true)
		deadline := time.Now().Add(3 * time.Second)
		halted := false
		for time.Now().Before(deadline) {
			r503, rErr := http.Get(readyURL)
			if rErr == nil {
				_ = r503.Body.Close()
				if r503.StatusCode == http.StatusServiceUnavailable {
					halted = true
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !halted {
			t.Fatal("expected /readyz to transition to 503 after fatal background sync error")
		}
	})
}
