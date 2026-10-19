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
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func TestRemovedLegacyFlags(t *testing.T) {
	for _, removed := range []string{
		"key_hash",
		"sub_root",
		"expected_map_fn",
		"before",
		"value_root",
		"limit",
		"in_log_policy",
		"in_log_pubkey",
		"in_log_origin",
		"in_log_url",
		"out_log_policy",
		"out_log_pubkey",
		"out_log_origin",
	} {
		if f := flag.CommandLine.Lookup(removed); f != nil {
			t.Errorf("removed legacy flag --%s must not be registered", removed)
		}
	}
}

func TestPrefixFlagModes(t *testing.T) {
	var pf prefixFlag
	if err := pf.Set("true"); err != nil || !pf.enabled || pf.value != "" {
		t.Fatalf("Set(true) failed: %+v, err=%v", pf, err)
	}
	if err := pf.Set("com.example."); err != nil || !pf.enabled || pf.value != "com.example." {
		t.Fatalf("Set(com.example.) failed: %+v, err=%v", pf, err)
	}
	if err := pf.Set("false"); err != nil || pf.enabled || pf.value != "" {
		t.Fatalf("Set(false) failed: %+v, err=%v", pf, err)
	}
}

func TestResolveTargetAndDomainFlag(t *testing.T) {
	t.Cleanup(func() {
		*key = ""
		*domain = ""
		prefix = prefixFlag{}
	})

	*key = ""
	*domain = "Example.COM"
	prefix = prefixFlag{}
	target, isPrefix, err := resolveTarget()
	if err != nil || isPrefix || target != "com.example." {
		t.Fatalf("resolveTarget(Example.COM) = (%q, %v, %v), want (com.example., false, nil)", target, isPrefix, err)
	}

	*domain = "*.sub.example.com"
	prefix = prefixFlag{enabled: true}
	target, isPrefix, err = resolveTarget()
	if err != nil || !isPrefix || target != "com.example.sub.*." {
		t.Fatalf("resolveTarget(--prefix *.sub.example.com) = (%q, %v, %v), want (com.example.sub.*., true, nil)", target, isPrefix, err)
	}

	*key = "manual.key"
	*domain = "example.com"
	if _, _, err := resolveTarget(); err == nil {
		t.Fatal("expected error when combining --domain and --key")
	}
}

func TestRunFlagValidation(t *testing.T) {
	t.Cleanup(func() {
		*key = ""
		*domain = ""
		prefix = prefixFlag{}
		*outputLogPolicy = ""
		*outputLogPubKey = ""
		*outputLogOrigin = ""
		*inputLogOrigin = ""
		*inputLogURL = ""
		*dereference = false
	})

	ctx := context.Background()
	*key = ""
	*domain = ""
	prefix = prefixFlag{}
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "must specify --key") {
		t.Fatalf("expected missing --key error, got: %v", err)
	}

	*key = "example"
	*dereference = true
	*inputLogURL = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--dereference requires --input_log_url") {
		t.Fatalf("expected missing --input_log_url error with --dereference, got: %v", err)
	}
	*dereference = false

	*outputLogPolicy = ""
	*outputLogPubKey = ""
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "--output_log_policy or --output_log_pubkey") {
		t.Fatalf("expected missing output policy/pubkey error, got: %v", err)
	}

	// Verify --output_log_policy infers single-log origin when --output_log_origin is omitted.
	_, vkey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(t.TempDir(), "out.policy")
	if err := os.WriteFile(polPath, fmt.Appendf(nil, "log %s\nquorum none\n", vkey), 0o644); err != nil {
		t.Fatal(err)
	}
	*outputLogPolicy = polPath
	*outputLogOrigin = ""
	*inputLogOrigin = "example.com/input"
	*vindexURL = "http://127.0.0.1:1" // unreachable port, proving client.New succeeded past origin check
	if err := run(ctx); err == nil || strings.Contains(err.Error(), "failed to create client") {
		t.Fatalf("expected client.New to succeed with inferred origin from --output_log_policy, got: %v", err)
	}
}
