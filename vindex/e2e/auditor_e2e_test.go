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

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmtest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type verifierTestCluster struct {
	*testCluster
	inLogServer       *httptest.Server
	outLogServer      *httptest.Server
	inCheckpointCalls atomic.Int64
	outHandler        atomic.Pointer[http.Handler]
}

func newVerifierTestCluster(t *testing.T, ctx context.Context, chunkSize, bundleSize uint64) *verifierTestCluster {
	t.Helper()
	baseCluster := newTestCluster(t, ctx, chunkSize, bundleSize)
	vtc := &verifierTestCluster{testCluster: baseCluster}

	inFs := http.FileServer(http.Dir(baseCluster.inLogDir))
	inMux := http.NewServeMux()
	inMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkpoint" || strings.HasSuffix(r.URL.Path, "/checkpoint") {
			vtc.inCheckpointCalls.Add(1)
		}
		inFs.ServeHTTP(w, r)
	})
	vtc.inLogServer = httptest.NewServer(inMux)
	t.Cleanup(vtc.inLogServer.Close)

	defaultOutHandler := http.FileServer(http.Dir(baseCluster.outLogDir))
	vtc.outHandler.Store(&defaultOutHandler)
	vtc.outLogServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*vtc.outHandler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(vtc.outLogServer.Close)

	return vtc
}

func (c *verifierTestCluster) newVerifierConfig(t *testing.T, wasmHost *vindex.WASMHost) auditor.Config {
	t.Helper()
	tmpDir := t.TempDir()
	inPolicy, err := wire.BuildPolicy(c.config.InputLogOrigin, c.inVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(input) failed: %v", err)
	}
	outPolicy, err := wire.BuildPolicy(c.config.OutputLogOrigin, c.outVerifier, nil, 0)
	if err != nil {
		t.Fatalf("wire.BuildPolicy(output) failed: %v", err)
	}
	return auditor.Config{
		InputLogURL:     c.inLogServer.URL,
		InputLogOrigin:  c.config.InputLogOrigin,
		InputLogPolicy:  inPolicy,
		OutputLogURL:    c.outLogServer.URL,
		OutputLogOrigin: c.config.OutputLogOrigin,
		OutputLogPolicy: outPolicy,
		WASMHost:        wasmHost,
		DBPath:          filepath.Join(tmpDir, "verifier_db"),
		MPTDir:          filepath.Join(tmpDir, "verifier_mpt"),
		PollInterval:    50 * time.Millisecond,
	}
}

func waitForOutputLogCheckpoint(t *testing.T, url string, minSize uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/checkpoint")
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if cp, err := wire.ParseCheckpointHeader(body); err == nil && cp.Size >= minSize {
				return
			}
		} else if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for OutputLog checkpoint size >= %d", minSize)
}

func TestE2E_HonestSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	var batch1 [][]byte
	for i := range 10 {
		batch1 = append(batch1, []byte(fmt.Sprintf("entry_%02d", i)))
	}
	vtc.appendLeaves(batch1...)

	mapper := newTestWASMHost(t)
	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	st := v.Status()
	if st.IsHalted {
		_ = v.Close()
		t.Fatalf("verifier unexpectedly halted: %v", st.HaltError)
	}
	if st.VerifiedOutputSize != 1 || st.VerifiedInputSize != 10 {
		t.Errorf("unexpected status: %+v", st)
	}

	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 0", m)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c != 0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want 0", c)
	}
	if st.HaltError != nil {
		t.Errorf("Status().HaltError = %v, want nil", st.HaltError)
	}

	adminTS := httptest.NewServer(v.AdminHandler())
	for _, opPath := range []string{"/healthz", "/readyz", "/metrics", "/debug/pprof/"} {
		res, reqErr := http.Get(adminTS.URL + opPath)
		if reqErr != nil {
			adminTS.Close()
			_ = v.Close()
			t.Fatalf("GET %s failed: %v", opPath, reqErr)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", opPath, res.StatusCode)
		}
	}
	adminTS.Close()

	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	v2, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New restart failed: %v", err)
	}
	defer func() { _ = v2.Close() }()

	if v2.Status().VerifiedOutputSize != 1 || v2.Status().VerifiedInputSize != 10 {
		t.Fatalf("reopened verifier recovered status mismatch: %+v", v2.Status())
	}

	daemonCtx, daemonCancel := context.WithCancel(ctx)
	defer daemonCancel()
	go func() { _ = v2.Run(daemonCtx) }()

	var batch2 [][]byte
	for i := 10; i < 20; i++ {
		batch2 = append(batch2, []byte(fmt.Sprintf("entry_%02d", i)))
	}
	vtc.appendLeaves(batch2...)

	catchupDeadline := time.Now().Add(10 * time.Second)
	caughtUp := false
	for time.Now().Before(catchupDeadline) {
		s := v2.Status()
		if s.VerifiedOutputSize >= 2 && s.VerifiedInputSize >= 20 {
			caughtUp = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !caughtUp {
		t.Fatalf("verifier daemon failed to catch up to leaf 1; status: %+v", v2.Status())
	}
	if v2.Status().IsHalted {
		t.Fatalf("verifier halted during daemon mode: %v", v2.Status().HaltError)
	}
}

func TestE2E_TamperedRootDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)
	baseMismatches := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal)

	var batch1 [][]byte
	for i := range 5 {
		batch1 = append(batch1, []byte(fmt.Sprintf("record_%d", i)))
	}
	vtc.appendLeaves(batch1...)

	mapper := newTestWASMHost(t)
	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	vCfg := vtc.newVerifierConfig(t, mapper)
	v, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}

	if err := v.VerifyOnce(ctx); err != nil {
		_ = v.Close()
		t.Fatalf("initial VerifyOnce failed: %v", err)
	}
	authenticRoot0 := v.Status().LastVerifiedRoot
	rawInCP5, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		_ = v.Close()
		t.Fatalf("failed to read initial input checkpoint: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("failed to close verifier: %v", err)
	}

	var batch2 [][]byte
	for i := 5; i < 10; i++ {
		batch2 = append(batch2, []byte(fmt.Sprintf("record_%d", i)))
	}
	vtc.appendLeaves(batch2...)
	rawInCP10, err := vtc.inReader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("failed to read input checkpoint at size 10: %v", err)
	}

	advOutDir := t.TempDir()
	outSigner, err := note.NewSigner(vtc.outSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	advLog, err := tree.NewPOSIXOutputLog(ctx, advOutDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
	if err != nil {
		t.Fatalf("failed to create adversarial OutputLog: %v", err)
	}
	defer func() { _ = advLog.Close() }()

	inCP5, _, _, err := log.ParseCheckpoint(rawInCP5, vtc.config.InputLogOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP5: %v", err)
	}
	if _, _, err := advLog.Append(ctx, wire.FormatOutputLogLeafFull(authenticRoot0, 0, inCP5)); err != nil {
		t.Fatalf("failed to append honest leaf 0: %v", err)
	}

	inCP10, _, _, err := log.ParseCheckpoint(rawInCP10, vtc.config.InputLogOrigin, vtc.inVerifier)
	if err != nil {
		t.Fatalf("failed to parse rawInCP10: %v", err)
	}
	tamperedRoot := sha256.Sum256([]byte("forged_mpt_root_hash"))
	if _, _, err := advLog.Append(ctx, wire.FormatOutputLogLeafFull(tamperedRoot, 0, inCP10)); err != nil {
		t.Fatalf("failed to append tampered leaf 1: %v", err)
	}

	advServer := httptest.NewServer(http.FileServer(http.Dir(advOutDir)))
	defer advServer.Close()

	vCfg.OutputLogURL = advServer.URL
	advVerifier, err := auditor.New(vCfg)
	if err != nil {
		t.Fatalf("failed to create advVerifier: %v", err)
	}
	defer func() { _ = advVerifier.Close() }()

	err = advVerifier.VerifyOnce(ctx)
	if !errors.Is(err, auditor.ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got: %v", err)
	}

	var mismatchErr *auditor.RootMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected *auditor.RootMismatchError, got %T", err)
	}
	if mismatchErr.CommittedMPTRoot != tamperedRoot || mismatchErr.OutputIndex != 1 || mismatchErr.InputSize != 10 {
		t.Errorf("unexpected mismatch details: %+v", mismatchErr)
	}

	if m := testutil.ToFloat64(metrics.AuditorRootMismatch); m != 1.0 {
		t.Errorf("vindex_auditor_root_mismatch = %v, want 1.0", m)
	}
	if h := testutil.ToFloat64(metrics.AuditorHalted); h != 1.0 {
		t.Errorf("vindex_auditor_halted = %v, want 1.0", h)
	}
	if c := testutil.ToFloat64(metrics.AuditorRootMismatchesTotal) - baseMismatches; c < 1.0 {
		t.Errorf("vindex_auditor_root_mismatches_total delta = %v, want >= 1.0", c)
	}

	advAdminTS := httptest.NewServer(advVerifier.AdminHandler())
	defer advAdminTS.Close()

	if resH, reqErr := http.Get(advAdminTS.URL + "/healthz"); reqErr != nil {
		t.Fatalf("GET halted /healthz failed: %v", reqErr)
	} else {
		_ = resH.Body.Close()
		if resH.StatusCode != http.StatusOK {
			t.Errorf("halted /healthz status = %d, want 200", resH.StatusCode)
		}
	}
	if resR, reqErr := http.Get(advAdminTS.URL + "/readyz"); reqErr != nil {
		t.Fatalf("GET halted /readyz failed: %v", reqErr)
	} else {
		_ = resR.Body.Close()
		if resR.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("halted /readyz status = %d, want 503", resR.StatusCode)
		}
	}

	status := advVerifier.Status()
	if !status.IsHalted || status.VerifiedOutputSize != 1 || status.VerifiedInputSize != 5 {
		t.Errorf("unexpected halted status: %+v", status)
	}
	if err := advVerifier.VerifyOnce(ctx); !errors.Is(err, auditor.ErrRootMismatch) {
		t.Errorf("subsequent VerifyOnce = %v, want ErrRootMismatch", err)
	}
}

func TestE2E_InputLogCheckpointVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	metrics.AuditorRootMismatch.Set(0)

	var batch [][]byte
	for i := range 20 {
		batch = append(batch, []byte(fmt.Sprintf("entry_%d", i)))
	}
	vtc.appendLeaves(batch...)

	mapper := newTestWASMHost(t)
	engine, err := vindex.New(vtc.config, mapper)
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	v, err := auditor.New(vtc.newVerifierConfig(t, mapper))
	if err != nil {
		t.Fatalf("auditor.New failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("VerifyOnce failed: %v", err)
	}

	if vtc.inCheckpointCalls.Load() == 0 {
		t.Fatal("expected InputLog /checkpoint to be fetched and verified during auditor sync, got 0 requests")
	}
	if v.Status().VerifiedInputSize != 20 {
		t.Errorf("VerifiedInputSize = %d, want 20", v.Status().VerifiedInputSize)
	}
}

var (
	buildAuditorOnce sync.Once
	vindexAuditorBin string
	testWasmBin      string
	auditorBuildErr  error
)

func getAuditorBinaryAndWASM(t *testing.T) (string, string) {
	t.Helper()
	buildAuditorOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "vindex-e2e-bins-*")
		if err != nil {
			auditorBuildErr = err
			return
		}
		vBin := filepath.Join(tmpDir, "vindex-auditor")
		cmdV := exec.Command("go", "build", "-o", vBin, "github.com/transparency-dev/incubator/vindex/cmd/vindex-auditor")
		if out, err := cmdV.CombinedOutput(); err != nil {
			auditorBuildErr = fmt.Errorf("failed to build vindex-auditor: %w\n%s", err, string(out))
			return
		}
		wBin := filepath.Join(tmpDir, "test.wasm")
		if err := os.WriteFile(wBin, wasmtest.Bytes(), 0o644); err != nil {
			auditorBuildErr = fmt.Errorf("failed to write test.wasm: %w", err)
			return
		}
		vindexAuditorBin = vBin
		testWasmBin = wBin
	})
	if auditorBuildErr != nil {
		t.Fatalf("getAuditorBinaryAndWASM failed: %v", auditorBuildErr)
	}
	return vindexAuditorBin, testWasmBin
}

type syncLogBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestE2E_CLI_EntryPoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vBin, wBin := getAuditorBinaryAndWASM(t)
	vtc := newVerifierTestCluster(t, ctx, 64, 16)

	var cliBatch [][]byte
	for i := range 10 {
		cliBatch = append(cliBatch, []byte(fmt.Sprintf("cli_entry_%d", i)))
	}
	vtc.appendLeaves(cliBatch...)

	engine, err := vindex.New(vtc.config, newTestWASMHost(t))
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	t.Run("vindex-auditor_Honest", func(t *testing.T) {
		cliDir := t.TempDir()
		// Omit --output_log_origin and --input_log_origin to verify origin auto-derivation from pubkey/policy.
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--wasm_path="+wBin,
			"--metrics_addr=",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vindex-auditor honest run failed: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Oneshot verification succeeded.") {
			t.Errorf("missing success log in vindex-auditor output: %s", string(out))
		}

		vCheckCfg := vtc.newVerifierConfig(t, newTestWASMHost(t))
		vCheckCfg.DBPath = filepath.Join(cliDir, "db")
		vCheckCfg.MPTDir = filepath.Join(cliDir, "mpt")
		vCheck, err := auditor.New(vCheckCfg)
		if err != nil {
			t.Fatalf("failed to reopen CLI auditor state: %v", err)
		}
		defer func() { _ = vCheck.Close() }()
		if st := vCheck.Status(); st.VerifiedOutputSize != 1 {
			t.Fatalf("persisted output watermark = %d, want 1", st.VerifiedOutputSize)
		}
	})

	t.Run("vindex-auditor_TamperedRoot", func(t *testing.T) {
		advDir := t.TempDir()
		outSigner, err := note.NewSigner(vtc.outSKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		advLog, err := tree.NewPOSIXOutputLog(ctx, advDir, outSigner, tree.WithOrigin(vtc.config.OutputLogOrigin))
		if err != nil {
			t.Fatalf("failed to create advLog: %v", err)
		}
		rawInCP, _ := vtc.inReader.ReadCheckpoint(ctx)
		inCP, _, _, _ := log.ParseCheckpoint(rawInCP, vtc.config.InputLogOrigin, vtc.inVerifier)
		_, _, _ = advLog.Append(ctx, wire.FormatOutputLogLeafFull(sha256.Sum256([]byte("fake")), 0, inCP))
		_ = advLog.Close()

		advSrv := httptest.NewServer(http.FileServer(http.Dir(advDir)))
		defer advSrv.Close()

		cliDir := t.TempDir()
		cmd := exec.CommandContext(ctx, vBin,
			"--output_log_url="+advSrv.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--wasm_path="+wBin,
			"--metrics_addr=",
			"--oneshot",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected vindex-auditor against tampered root to exit with error, got 0")
		}
		if !strings.Contains(string(out), "root hash mismatch") && !strings.Contains(string(out), "oneshot verification failed") {
			t.Errorf("output missing root mismatch error: %s", string(out))
		}
	})

	t.Run("vindex-auditor_RejectsSignerKeyFlag", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, vBin, "--output_log_signer_key=FORBIDDEN_KEY")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected vindex-auditor to reject --output_log_signer_key, got exit 0\n%s", string(out))
		}
	})

	t.Run("vindex-auditor_DaemonAdminListener", func(t *testing.T) {
		cliDir := t.TempDir()
		dCtx, dCancel := context.WithCancel(ctx)
		defer dCancel()

		cmd := exec.CommandContext(dCtx, vBin,
			"--output_log_url="+vtc.outLogServer.URL,
			"--output_log_pubkey="+vtc.outVKey,
			"--output_log_origin="+vtc.config.OutputLogOrigin,
			"--input_log_url="+vtc.inLogServer.URL,
			"--input_log_pubkey="+vtc.inVKey,
			"--input_log_origin="+vtc.config.InputLogOrigin,
			"--db_path="+filepath.Join(cliDir, "db"),
			"--mpt_dir="+filepath.Join(cliDir, "mpt"),
			"--wasm_path="+wBin,
			"--metrics_addr=127.0.0.1:0",
			"--poll_interval=50ms",
		)
		var logBuf syncLogBuffer
		cmd.Stdout = &logBuf
		cmd.Stderr = &logBuf
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start vindex-auditor daemon: %v", err)
		}
		defer func() {
			dCancel()
			_ = cmd.Wait()
		}()

		var adminAddr string
		addrDeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(addrDeadline) {
			logs := logBuf.String()
			const marker = "Serving auditor metrics at http://"
			if idx := strings.Index(logs, marker); idx >= 0 {
				rest := logs[idx+len(marker):]
				if slash := strings.IndexByte(rest, '/'); slash > 0 {
					adminAddr = rest[:slash]
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
		}
		if adminAddr == "" {
			t.Fatalf("timed out waiting for vindex-auditor to log bound --metrics_addr\nLogs:\n%s", logBuf.String())
		}

		httpCli := &http.Client{Timeout: 1 * time.Second}
		readyDeadline := time.Now().Add(10 * time.Second)
		readyOK := false
		for time.Now().Before(readyDeadline) {
			if res, reqErr := httpCli.Get(fmt.Sprintf("http://%s/readyz", adminAddr)); reqErr == nil {
				_ = res.Body.Close()
				if res.StatusCode == http.StatusOK {
					readyOK = true
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !readyOK {
			t.Fatalf("timed out waiting for vindex-auditor http://%s/readyz to return 200 OK\nLogs:\n%s", adminAddr, logBuf.String())
		}

		for _, opPath := range []string{"/healthz", "/metrics"} {
			res, reqErr := httpCli.Get(fmt.Sprintf("http://%s%s", adminAddr, opPath))
			if reqErr != nil {
				t.Fatalf("GET http://%s%s failed: %v", adminAddr, opPath, reqErr)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("GET http://%s%s status = %d, want 200", adminAddr, opPath, res.StatusCode)
			}
		}
	})
}

func TestE2E_MTCPersonality_GoldenLeavesAndAuditor(t *testing.T) {
	wasmPath := filepath.Join(t.TempDir(), "mtc.wasm")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", wasmPath, "github.com/transparency-dev/incubator/vindex/mapfn/examples/mtc")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mtc.wasm: %v\n%s", err, string(out))
	}
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read mtc.wasm: %v", err)
	}
	mtcMapper, err := vindex.NewWASMHost(context.Background(), wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost(mtc) failed: %v", err)
	}
	t.Cleanup(func() { _ = mtcMapper.Close(context.Background()) })

	goldenJSON, err := os.ReadFile(filepath.Join("..", "mapfn", "examples", "mtc", "testdata", "golden_leaves.json"))
	if err != nil {
		t.Fatalf("failed to read mtc golden_leaves.json: %v", err)
	}
	var golden []struct {
		LeafHex         string   `json:"leaf_hex"`
		ExpectedDomains []string `json:"expected_domains"`
	}
	if err := json.Unmarshal(goldenJSON, &golden); err != nil || len(golden) == 0 {
		t.Fatalf("failed to parse mtc golden_leaves.json: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vtc := newVerifierTestCluster(t, ctx, 64, 16)
	var firstExpectedKey string
	for _, g := range golden {
		leafBytes, decErr := hex.DecodeString(g.LeafHex)
		if decErr != nil {
			t.Fatalf("hex.DecodeString failed: %v", decErr)
		}
		vtc.appendLeaf(leafBytes)
		if firstExpectedKey == "" && len(g.ExpectedDomains) > 0 {
			firstExpectedKey = g.ExpectedDomains[0]
		}
	}

	engine, err := vindex.New(vtc.config, mtcMapper)
	if err != nil {
		t.Fatalf("vindex.New(mtc) failed: %v", err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start(mtc) failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	waitForOutputLogCheckpoint(t, vtc.outLogServer.URL, 1, 5*time.Second)

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()
	cli := vtc.newClient(ts.URL)
	if firstExpectedKey != "" {
		idxs, lErr := getAllAscending(ctx, cli, firstExpectedKey)
		if lErr != nil || !slices.Contains(idxs, 0) {
			t.Fatalf("expected MTC golden domain %q at leaf 0, got %v (err=%v)", firstExpectedKey, idxs, lErr)
		}
	}

	// Verify independent auditor running identical mtc.wasm agrees on MPT root.
	v, err := auditor.New(vtc.newVerifierConfig(t, mtcMapper))
	if err != nil {
		t.Fatalf("auditor.New(mtc) failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	if err := v.VerifyOnce(ctx); err != nil {
		t.Fatalf("auditor.VerifyOnce(mtc) failed: %v", err)
	}
}
