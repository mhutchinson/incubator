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
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost/wasmhosttest"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/zip"
)

var testExampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var testExampleLeaf2 = []byte(`golang.org/x/text v0.3.1 h1:anotherhash1234567890=
golang.org/x/text v0.3.1/go.mod h1:anothermodhash123456=
`)

func TestParseLeaf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		idx         uint64
		data        []byte
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "valid leaf",
			idx:         42,
			data:        testExampleLeaf,
			wantVersion: "v0.3.0",
			wantErr:     false,
		},
		{
			name:    "single line",
			idx:     1,
			data:    []byte("golang.org/x/text v0.3.0 h1:hash="),
			wantErr: true,
		},
		{
			name:    "mismatched module names",
			idx:     2,
			data:    []byte("mod1 v0.1.0 h1:hash=\nmod2 v0.1.0/go.mod h1:hash=\n"),
			wantErr: true,
		},
		{
			name:    "mismatched versions",
			idx:     3,
			data:    []byte("mod1 v0.1.0 h1:hash=\nmod1 v0.2.0/go.mod h1:hash=\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ver, md, err := parseLeaf(tt.idx, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLeaf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ver != tt.wantVersion {
					t.Errorf("parseLeaf() version = %q, want %q", ver, tt.wantVersion)
				}
				if md.index != tt.idx {
					t.Errorf("parseLeaf() index = %d, want %d", md.index, tt.idx)
				}
				if md.zipHash != "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=" {
					t.Errorf("parseLeaf() zipHash = %q, want expected", md.zipHash)
				}
				if md.modHash != "h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=" {
					t.Errorf("parseLeaf() modHash = %q, want expected", md.modHash)
				}
			}
		})
	}

	if _, _, err := parseLeaf(42, testExampleLeaf, "other.org/mod"); err == nil {
		t.Fatal("expected parseLeaf to reject leaf with wrong expectedMod")
	}
	if _, _, err := parseLeaf(42, testExampleLeaf, "golang.org/x/text"); err != nil {
		t.Fatalf("expected parseLeaf to accept matching expectedMod, got: %v", err)
	}
}

func TestGetReport_LocalGitRepo(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	repoDir := t.TempDir()

	gitExec := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	gitExec("init")
	// Pre-module release v0.0.1 (no go.mod yet)
	if err := os.WriteFile(filepath.Join(repoDir, "hello.go"), []byte("package hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "hello.go")
	gitExec("commit", "-m", "pre-module")
	gitExec("tag", "v0.0.1")

	// Lightweight tag v0.1.0 with go.mod
	goModContent := []byte("module example.com/hello\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), goModContent, 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "go.mod")
	gitExec("commit", "-m", "add go.mod")
	gitExec("tag", "v0.1.0")
	commitV1 := gitExec("rev-parse", "v0.1.0^{commit}")

	// Annotated tag v0.2.0
	if err := os.WriteFile(filepath.Join(repoDir, "hello.go"), []byte("package hello\n\nconst V = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec("add", "hello.go")
	gitExec("commit", "-m", "v0.2.0")
	gitExec("tag", "-a", "v0.2.0", "-m", "annotated release")
	commitV2 := gitExec("rev-parse", "v0.2.0^{commit}")

	wantModHash, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(goModContent)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	calcZipHash := func(ver, commit string) string {
		f, zErr := os.CreateTemp(t.TempDir(), "zip-*")
		if zErr != nil {
			t.Fatal(zErr)
		}
		if zErr := zip.CreateFromVCS(f, module.Version{Path: "example.com/hello", Version: ver}, repoDir, commit, ""); zErr != nil {
			t.Fatal(zErr)
		}
		_ = f.Close()
		h, zErr := dirhash.HashZip(f.Name(), dirhash.Hash1)
		if zErr != nil {
			t.Fatal(zErr)
		}
		return h
	}
	wantZipV1 := calcZipHash("v0.1.0", commitV1)
	wantZipV2 := calcZipHash("v0.2.0", commitV2)

	report, err := getReport(ctx, repoDir, func(_ context.Context, modName string) (map[string]modData, error) {
		if modName != "example.com/hello" {
			t.Fatalf("unexpected modName %q", modName)
		}
		return map[string]modData{
			"v0.0.1": {index: 1, modHash: "h1:unused=", zipHash: "h1:unused="},
			"v0.1.0": {index: 10, modHash: wantModHash, zipHash: wantZipV1},
			"v0.2.0": {index: 20, modHash: wantModHash, zipHash: wantZipV2},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport failed: %v", err)
	}
	if len(report.versions) != 3 {
		t.Fatalf("len(report.versions) = %d, want 3", len(report.versions))
	}
	if report.versions[0].version != "v0.0.1" || report.versions[0].gitCommit == "" || report.versions[0].gitModHash != "" {
		t.Fatalf("unexpected pre-module report: %+v", report.versions[0])
	}
	if report.versions[1].gitModHash != wantModHash || report.versions[1].gitZipHash != wantZipV1 {
		t.Fatalf("v0.1.0 hash mismatch: %+v", report.versions[1])
	}
	if report.versions[2].gitModHash != wantModHash || report.versions[2].gitZipHash != wantZipV2 {
		t.Fatalf("v0.2.0 annotated tag hash mismatch: %+v", report.versions[2])
	}

	// Local git tag missing from SumDB must be surfaced with sumFound == false.
	gitExec("tag", "v0.3.0")
	reportMissing, err := getReport(ctx, repoDir, func(_ context.Context, _ string) (map[string]modData, error) {
		return map[string]modData{
			"v0.0.1": {index: 1, modHash: "h1:unused=", zipHash: "h1:unused="},
			"v0.1.0": {index: 10, modHash: wantModHash, zipHash: wantZipV1},
			"v0.2.0": {index: 20, modHash: wantModHash, zipHash: wantZipV2},
		}, nil
	})
	if err != nil {
		t.Fatalf("getReport with missing SumDB tag failed: %v", err)
	}
	if len(reportMissing.versions) != 4 || reportMissing.versions[3].version != "v0.3.0" || reportMissing.versions[3].sumFound {
		t.Fatalf("expected v0.3.0 with sumFound=false, got: %+v", reportMissing.versions)
	}
}

func TestQueryIndex_Integration(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "sum.golang.org")
	if err != nil {
		t.Fatalf("note.GenerateKey(input) failed: %v", err)
	}
	inSigner, err := note.NewSigner(inSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(input) failed: %v", err)
	}
	inVerifier, err := note.NewVerifier(inVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(input) failed: %v", err)
	}

	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "sumdb.vindex.local")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(output) failed: %v", err)
	}

	inLogDir := filepath.Join(tempDir, "inputlog")
	inLog, err := tree.NewPOSIXOutputLog(ctx, inLogDir, inSigner, tree.WithOrigin("sum.golang.org"))
	if err != nil {
		t.Fatalf("NewPOSIXOutputLog(input) failed: %v", err)
	}
	defer func() { _ = inLog.Close() }()

	for i, leaf := range [][]byte{testExampleLeaf, testExampleLeaf2} {
		if _, _, err := inLog.Append(ctx, leaf); err != nil {
			t.Fatalf("inLog.Append(%d) failed: %v", i, err)
		}
	}

	engine, err := vindex.New(vindex.Config{
		DBPath:             filepath.Join(tempDir, "pebble"),
		MPTDir:             filepath.Join(tempDir, "mpt"),
		TileCacheDir:       filepath.Join(tempDir, "tilecache"),
		ChunkSize:          16,
		InputLogURL:        "file://" + inLogDir,
		InputLogOrigin:     "sum.golang.org",
		InputLogVerifier:   inVerifier,
		OutputLogDir:       filepath.Join(tempDir, "outputlog"),
		OutputLogOrigin:    "sumdb.vindex.local",
		OutputLogSignerKey: outSKey,
	}, wasmhosttest.Host())
	if err != nil {
		t.Fatalf("vindex.New failed: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if err := engine.SyncOnce(ctx); err != nil {
		t.Fatalf("engine.SyncOnce failed: %v", err)
	}

	ts := httptest.NewServer(engine.Handler())
	defer ts.Close()

	outPolicy, err := client.SingleKeyPolicy("sumdb.vindex.local", outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	cli, err := client.New(ts.URL, client.Config{
		ExpectedOutputLogOrigin: "sumdb.vindex.local",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "sum.golang.org",
	}, client.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	versions, err := queryIndex(ctx, cli, "file://"+inLogDir, "golang.org/x/text", 0)
	if err != nil {
		t.Fatalf("queryIndex failed: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d (%v)", len(versions), versions)
	}
}
