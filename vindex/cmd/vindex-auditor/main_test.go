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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func TestVindexAuditor_NoSignerKeyFlag(t *testing.T) {
	if f := flag.CommandLine.Lookup("output_log_signer_key"); f != nil {
		t.Fatalf("security invariant violation: --output_log_signer_key must not exist in vindex-auditor, found: %v", f)
	}
	if fDir := flag.CommandLine.Lookup("output_log_dir"); fDir != nil {
		t.Fatalf("output_log_dir must not exist in vindex-auditor, found: %v", fDir)
	}
	if fMode := flag.CommandLine.Lookup("mode"); fMode != nil {
		t.Fatalf("mode flag should not exist in dedicated vindex-auditor, found: %v", fMode)
	}
}

func TestVindexAuditor_FlagValidation(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	*outputLogURL = ""
	*inputLogURL = "http://localhost:8080/in"
	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = filepath.Join(tmpDir, "mpt")
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--output_log_url is required") {
		t.Fatalf("expected missing output_log_url error, got: %v", err)
	}

	*outputLogURL = "http://localhost:8080/out"
	*inputLogURL = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--input_log_url is required") {
		t.Fatalf("expected missing input_log_url error, got: %v", err)
	}

	*inputLogURL = "http://localhost:8080/in"
	*dbPath = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--db_path flag is required") {
		t.Fatalf("expected missing db_path error, got: %v", err)
	}

	*dbPath = filepath.Join(tmpDir, "db")
	*mptDir = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--mpt_dir flag is required") {
		t.Fatalf("expected missing mpt_dir error, got: %v", err)
	}
	*mptDir = filepath.Join(tmpDir, "mpt")

	*wasmPath = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--wasm_path flag is required") {
		t.Fatalf("expected missing wasm_path error, got: %v", err)
	}

	*wasmPath = filepath.Join(tmpDir, "dummy.wasm")
	*inputLogPolicy = ""
	*inputLogPubKey = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--input_log_policy or --input_log_pubkey is required") {
		t.Fatalf("expected missing input_log_policy/pubkey error, got: %v", err)
	}
}

func TestVindexAuditor_CLIHelp(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "-output_log_url") {
		t.Fatalf("vindex-auditor --help failed: %v\nOutput: %s", err, string(out))
	}
	helpText := string(out)
	for _, want := range []string{"-output_log_url", "-oneshot"} {
		if !strings.Contains(helpText, want) {
			t.Errorf("expected %s in help output, got: %s", want, helpText)
		}
	}
	for _, forbidden := range []string{"-output_log_signer_key", "/syncz"} {
		if strings.Contains(helpText, forbidden) {
			t.Errorf("found forbidden %s in help output: %s", forbidden, helpText)
		}
	}
}

func TestVindexAuditor_PolicyFlagsExist(t *testing.T) {
	for _, name := range []string{
		"output_log_policy",
		"input_log_policy",
		"input_log_type",
		"witness_pubkeys",
		"witness_threshold",
		"wasm_workers",
		"fetch_workers",
		"db_cache_size_mb",
		"db_max_open_files",
	} {
		if flag.CommandLine.Lookup(name) == nil {
			t.Errorf("expected --%s flag to be registered", name)
		}
	}
	if f := flag.CommandLine.Lookup("output_log_origin"); f == nil || f.DefValue != "" {
		t.Fatalf("expected --output_log_origin default to be empty string, got %+v", f)
	}

	_, vkey1, err := note.GenerateKey(rand.Reader, "custom.log/one")
	if err != nil {
		t.Fatal(err)
	}
	_, vkey2, err := note.GenerateKey(rand.Reader, "custom.log/two")
	if err != nil {
		t.Fatal(err)
	}
	singleFile := filepath.Join(t.TempDir(), "single.policy")
	if err := os.WriteFile(singleFile, fmt.Appendf(nil, "log %s\nquorum none\n", vkey1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, gotOrigin, err := buildLogPolicy(singleFile, "", "", nil, 0, "input_log"); err != nil || gotOrigin != "custom.log/one" {
		t.Fatalf("buildLogPolicy(single) = (%q, %v), want (custom.log/one, nil)", gotOrigin, err)
	}

	multiFile := filepath.Join(t.TempDir(), "multi.policy")
	if err := os.WriteFile(multiFile, fmt.Appendf(nil, "log %s\nlog %s\nquorum none\n", vkey1, vkey2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildLogPolicy(multiFile, "", "", nil, 0, "input_log"); err == nil {
		t.Fatal("expected buildLogPolicy(multi without --input_log_origin) to fail closed")
	}
}
