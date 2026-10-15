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
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/mtc/mtctest"
)

func TestMapMTCLeaf_Golden(t *testing.T) {
	cases := mtctest.GoldenLeaves()
	if len(cases) == 0 {
		t.Fatal("no golden test cases loaded")
	}

	for _, tc := range cases {
		t.Run(tc.Category, func(t *testing.T) {
			raw := tc.MustLeafBytes()
			var got []string
			MapMTCLeaf(raw, func(key []byte) {
				got = append(got, string(key))
			})
			want := slices.Clone(tc.ExpectedDomains)
			slices.Sort(got)
			slices.Sort(want)

			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("MapMTCLeaf() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapMTCLeaf_WASMHost_Golden(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "mtc.wasm")

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-buildid=", "-buildmode=c-shared", "-o", wasmPath, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mtc.wasm: %v\n%s", err, string(out))
	}

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read compiled wasm: %v", err)
	}

	host, err := ingest.NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("failed to create WASM host: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	less := func(a, b ingest.MappedEntry) bool {
		for i := 0; i < 32; i++ {
			if a.KeyHash[i] < b.KeyHash[i] {
				return true
			}
			if a.KeyHash[i] > b.KeyHash[i] {
				return false
			}
		}
		return false
	}

	cases := mtctest.GoldenLeaves()
	for _, tc := range cases {
		t.Run(tc.Category, func(t *testing.T) {
			raw := tc.MustLeafBytes()
			entries, err := host.MapLeaf(ctx, raw)
			if err != nil {
				t.Fatalf("host.MapLeaf failed: %v", err)
			}

			var want []ingest.MappedEntry
			for _, d := range tc.ExpectedDomains {
				want = append(want, ingest.MappedEntry{
					Key:     d,
					KeyHash: sha256.Sum256([]byte(d)),
				})
			}

			if diff := cmp.Diff(want, entries, cmpopts.SortSlices(less), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("host.MapLeaf() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkMapMTCLeaf(b *testing.B) {
	cases := mtctest.GoldenLeaves()
	if len(cases) == 0 {
		b.Fatal("no golden leaves found")
	}
	// Use authentic leaf with apex and wildcard (tile 000 entry 0)
	leaf := cases[0].MustLeafBytes()

	b.ReportAllocs()
	emitSink := func(key []byte) {}
	for b.Loop() {
		MapMTCLeaf(leaf, emitSink)
	}
}

func BenchmarkMapMTCLeaf_WASM(b *testing.B) {
	ctx := context.Background()
	tmpDir := b.TempDir()
	wasmPath := filepath.Join(tmpDir, "mtc.wasm")

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-buildid=", "-buildmode=c-shared", "-o", wasmPath, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("failed to build mtc.wasm: %v\n%s", err, string(out))
	}

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		b.Fatalf("failed to read compiled wasm: %v", err)
	}

	host, err := ingest.NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("failed to create WASM host: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	cases := mtctest.GoldenLeaves()
	leaf := cases[0].MustLeafBytes()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := host.MapLeaf(ctx, leaf); err != nil {
			b.Fatalf("host.MapLeaf failed: %v", err)
		}
	}
}

func buildCustomMTCLeaf(t *testing.T, cn string, sans []string) []byte {
	t.Helper()
	var subj pkix.RDNSequence
	if cn != "" {
		subj = pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
					Value: cn,
				},
			},
		}
	}

	var exts []asn1.RawValue
	if len(sans) > 0 {
		var rawNames []asn1.RawValue
		for _, s := range sans {
			rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(s)})
		}
		sanVal, err := asn1.Marshal(rawNames)
		if err != nil {
			t.Fatalf("failed to marshal SANs: %v", err)
		}
		ext := struct {
			Id       asn1.ObjectIdentifier
			Critical bool `asn1:"optional,default:false"`
			Value    []byte
		}{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanVal,
		}
		extBytes, err := asn1.Marshal(ext)
		if err != nil {
			t.Fatalf("failed to marshal extension: %v", err)
		}
		exts = append(exts, asn1.RawValue{FullBytes: extBytes})
	}

	entry := mtc.TBSCertificateLogEntry{
		Subject:    subj,
		Extensions: exts,
	}
	der, err := asn1.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal TBSCertificateLogEntry: %v", err)
	}
	return append([]byte{0, 1}, der...)
}

func TestMapMTCLeaf_SubjectCN_IDNA_TrailingDot_And_Overflow(t *testing.T) {
	// 1. Subject CN only + IDNA Punycode + trailing dot
	leaf1 := buildCustomMTCLeaf(t, "cn-only.example.com.", []string{"münchen.de.", "*.münchen.de"})
	var got1 []string
	MapMTCLeaf(leaf1, func(key []byte) {
		got1 = append(got1, string(key))
	})
	want1 := []string{
		"com.example.cn-only.",
		"de.xn--mnchen-3ya.",
		"de.xn--mnchen-3ya.*.",
	}
	if diff := cmp.Diff(want1, got1); diff != "" {
		t.Errorf("MapMTCLeaf(CN/IDNA/TrailingDot) mismatch (-want +got):\n%s", diff)
	}

	// 2. Overflow >64 unique SANs and >2048 bytes
	var sans []string
	var want2 []string
	for i := 0; i < 100; i++ {
		sans = append(sans, fmt.Sprintf("host-%03d.long-subdomain-segment.example.com", i))
		want2 = append(want2, fmt.Sprintf("com.example.long-subdomain-segment.host-%03d.", i))
	}
	leaf2 := buildCustomMTCLeaf(t, "", sans)
	var got2 []string
	MapMTCLeaf(leaf2, func(key []byte) {
		got2 = append(got2, string(key))
	})
	if diff := cmp.Diff(want2, got2); diff != "" {
		t.Errorf("MapMTCLeaf(100 SANs overflow) mismatch (-want +got):\n%s", diff)
	}
}

