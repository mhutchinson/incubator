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

package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/torchwood"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

func TestOutputLogLeafRoundTrip(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("mpt-root"))
	mapFn := sha256.Sum256([]byte("map-fn"))
	inRoot := sha256.Sum256([]byte("in-root"))
	rawInCP := []byte("example.com/inputlog\n42\n" + base64.StdEncoding.EncodeToString(inRoot[:]) + "\n\n— example.com/inputlog sig==\n")

	leaf := FormatOutputLogLeafFull(mptRoot, mapFn, 10, rawInCP)
	parsed, err := ParseOutputLogLeafFull(leaf)
	if err != nil {
		t.Fatalf("ParseOutputLogLeafFull failed: %v", err)
	}
	if parsed.MPTRoot != mptRoot {
		t.Errorf("mptRoot = %x, want %x", parsed.MPTRoot, mptRoot)
	}
	if parsed.MapFn != mapFn {
		t.Errorf("mapFn = %x, want %x", parsed.MapFn, mapFn)
	}
	if parsed.From != 10 {
		t.Errorf("from = %d, want 10", parsed.From)
	}
	if parsed.InCP.Origin != "example.com/inputlog" || parsed.InCP.Size != 42 || !bytes.Equal(parsed.InCP.Hash, inRoot[:]) {
		t.Errorf("gotCP = %+v", parsed.InCP)
	}
	if !bytes.Equal(parsed.RawInCP, rawInCP) {
		t.Errorf("gotRaw = %q, want %q", parsed.RawInCP, rawInCP)
	}

	// Simple leaf round-trip
	simpleLeaf := FormatOutputLogLeaf(mptRoot, rawInCP)
	gotRoot, gotCP, gotRaw, err := ParseOutputLogLeaf(simpleLeaf)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}
	if gotRoot != mptRoot || gotCP.Size != 42 || !bytes.Equal(gotRaw, rawInCP) {
		t.Errorf("simple leaf round-trip mismatch")
	}

	// Reject hex-encoded checkpoint root hash (must be strict 44-char base64)
	hexCP := []byte("example.com/inputlog\n42\n0101010101010101010101010101010101010101010101010101010101010101\n")
	if _, err := ParseCheckpointHeader(hexCP); err == nil {
		t.Errorf("expected ParseCheckpointHeader to reject 64-char hex hash, got nil")
	}
}

func TestFormatAndParseSections(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("mpt-root"))
	mapFn := sha256.Sum256([]byte("map-fn"))
	valueRoot := sha256.Sum256([]byte("value-root"))
	rawOutCP := []byte("example.com/vindex\n1\n" + base64.StdEncoding.EncodeToString(mptRoot[:]) + "\n\n— example.com/vindex sig==\n")
	rawInCP := []byte("example.com/inputlog\n10\n" + base64.StdEncoding.EncodeToString(mptRoot[:]) + "\n\n— example.com/inputlog sig==\n")

	keysBody := FormatKeysResponseFull(
		rawOutCP,
		0,
		mptRoot,
		mapFn,
		2,
		rawInCP,
		[][32]byte{valueRoot},
		"inclusion",
		[]byte("proof-bytes"),
		[]KeyValueRoot{{Key: "com.google.mail.", ValueRoot: valueRoot}},
	)

	stanzas := bytes.SplitN(keysBody, []byte("\n\n"), 2)
	if len(stanzas) != 2 {
		t.Fatalf("expected 2 top-level sections, got %d", len(stanzas))
	}
	keysSec, err := ParseKeysSection(stanzas[0])
	if err != nil {
		t.Fatalf("ParseKeysSection failed: %v", err)
	}
	if !bytes.Equal(keysSec.MPTProof, []byte("proof-bytes")) {
		t.Errorf("keysSec.MPTProof = %q, want proof-bytes", keysSec.MPTProof)
	}
	if len(keysSec.Matches) != 1 || keysSec.Matches[0].Key != "com.google.mail." || keysSec.Matches[0].ValueRoot != valueRoot {
		t.Errorf("keysSec.Matches = %+v", keysSec.Matches)
	}

	bindSec, err := ParseBindingSection(stanzas[1])
	if err != nil {
		t.Fatalf("ParseBindingSection failed: %v", err)
	}
	if bindSec.MPTRoot != mptRoot || bindSec.MapFn != mapFn || bindSec.From != 2 || bindSec.OutLeafIdx != 0 {
		t.Errorf("bindSec = %+v", bindSec)
	}
	if len(bindSec.InclusionProof) != 1 || !bytes.Equal(bindSec.InclusionProof[0], valueRoot[:]) {
		t.Errorf("bindSec.InclusionProof = %+v", bindSec.InclusionProof)
	}
	if !bytes.Equal(bindSec.RawProofAndCP, stanzas[1]) {
		t.Errorf("bindSec.RawProofAndCP = %q, want %q", bindSec.RawProofAndCP, stanzas[1])
	}

	// Test bare 'proof' line when mptProof is empty
	emptyProofSec := FormatKeysSection(nil, "inclusion", []KeyValueRoot{{Key: "com.google.mail.", ValueRoot: valueRoot}})
	if bytes.Contains(emptyProofSec, []byte("proof ")) || !bytes.Contains(emptyProofSec, []byte("proof\n")) {
		t.Errorf("expected bare 'proof' line without trailing space when mptProof is empty, got:\n%s", string(emptyProofSec))
	}
	if _, err := ParseKeysSection(emptyProofSec); err != nil {
		t.Fatalf("ParseKeysSection(emptyProofSec) failed: %v", err)
	}
	if _, err := ParseKeysSection([]byte("c2sp.org/tlog-vindex-keys@v1\nproof \n")); err == nil {
		t.Errorf("expected error for 'proof ' with trailing space and empty base64")
	}

	valuesBody := FormatValuesResponse(1, [][32]byte{valueRoot}, []uint64{5, 8})
	valSec, err := ParseValuesResponse(valuesBody)
	if err != nil {
		t.Fatalf("ParseValuesResponse failed: %v", err)
	}
	if valSec.Preceding != 1 || len(valSec.CompactRange) != 1 || valSec.CompactRange[0] != valueRoot {
		t.Errorf("valSec header = %+v", valSec)
	}
	if len(valSec.Indices) != 2 || valSec.Indices[0] != 5 || valSec.Indices[1] != 8 {
		t.Errorf("valSec.Indices = %v, want [5 8]", valSec.Indices)
	}
}

func TestLeafAndInteriorHashMatchRFC6962(t *testing.T) {
	for _, sz := range []int{0, 8, 64, 511, 512, 1024} {
		data := bytes.Repeat([]byte{0xAB}, sz)
		got := LeafHash(data)
		want := rfc6962.DefaultHasher.HashLeaf(data)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("LeafHash(len=%d) = %x, want %x", sz, got, want)
		}
	}

	l := sha256.Sum256([]byte("left"))
	r := sha256.Sum256([]byte("right"))
	gotInt := InteriorHash(l, r)
	wantInt := rfc6962.DefaultHasher.HashChildren(l[:], r[:])
	if !bytes.Equal(gotInt[:], wantInt) {
		t.Fatalf("InteriorHash = %x, want %x", gotInt, wantInt)
	}

	var b0, b1 [8]byte
	binary.BigEndian.PutUint64(b0[:], 10)
	binary.BigEndian.PutUint64(b1[:], 20)
	h0 := LeafHash(b0[:])
	root2, err := ComputeValueLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		t.Fatalf("ComputeValueLogRoot(2) failed: %v", err)
	}
	rootFromCompactRange, err := ComputeValueLogRoot([][32]byte{h0}, 1, []uint64{20})
	if err != nil {
		t.Fatalf("ComputeValueLogRoot(compactRange+1) failed: %v", err)
	}
	if root2 != rootFromCompactRange {
		t.Fatalf("root2 %x != rootFromCompactRange %x", root2, rootFromCompactRange)
	}
}

func TestPackageDependencyBoundaries(t *testing.T) {
	cases := []struct {
		pkg       string
		forbidden []string
	}{
		{
			pkg: "github.com/transparency-dev/incubator/vindex/client",
			forbidden: []string{
				"github.com/cockroachdb/pebble",
				"github.com/tetratelabs/wazero",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/internal/mtc",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/cmd/vindex-wasm",
			forbidden: []string{
				"net/http",
				"github.com/transparency-dev/tessera",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/internal/mtc",
			forbidden: []string{
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
			},
		},
	}

	for _, tc := range cases {
		relDir := strings.TrimPrefix(tc.pkg, "github.com/transparency-dev/incubator/vindex/")
		goFiles, err := filepath.Glob(filepath.Join("..", "..", relDir, "*.go"))
		if err != nil || len(goFiles) == 0 {
			continue
		}
		out, err := exec.Command("go", "list", "-deps", tc.pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s failed: %v\n%s", tc.pkg, err, string(out))
		}
		deps := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, dep := range deps {
			for _, bad := range tc.forbidden {
				if dep == bad || strings.HasPrefix(dep, bad+"/") {
					t.Errorf("package %s transitively depends on forbidden package %s (via %s)", tc.pkg, bad, dep)
				}
			}
		}
	}
}

func TestMTCVerifier(t *testing.T) {
	name := "oid/1.3.6.1.4.1.44363.47.1.44363.48.8"
	pubKeyB64 := "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	cosignerID := "44363.48.9"
	logID := "44363.48.8"

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode pubKey: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	v, err := NewMTCVerifier(name, pubKey, cosignerID, logID)
	if err != nil {
		t.Fatalf("NewMTCVerifier failed: %v", err)
	}

	if v.Name() != name {
		t.Errorf("Name() = %q, want %q", v.Name(), name)
	}

	wantKeyHash := uint32(0x8e6a3b1a)
	if v.KeyHash() != wantKeyHash {
		t.Errorf("KeyHash() = 0x%x, want 0x%x", v.KeyHash(), wantKeyHash)
	}

	checkpointText := `bootstrap-mtca.cloudflareresearch.com/logs/shard3
197762974
7NWRnNW49lCjHOLMyMLBYRkRTGxDhVEmQhTw2gD/Pig=`

	sigB64 := "jmo7GsZLYkXSa+C4eXII6rUTN8BECzdUogRIlzML8wqeWnFuTjOjAOGrHu79pnjuZBx1syo5FYNs5sKpj2D93QEkLws="
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}
	rawSig := sigBytes[4:]

	if !v.Verify([]byte(checkpointText), rawSig) {
		t.Error("Verification failed")
	}

	parsed, err := ParseVerifier("mtc+" + name + "+" + cosignerID + "+" + logID + "+" + pubKeyB64)
	if err != nil {
		t.Fatalf("ParseVerifier(mtc+...) failed: %v", err)
	}
	if !parsed.Verify([]byte(checkpointText), rawSig) {
		t.Error("ParseVerifier MTC verification failed")
	}
}

func TestParseVerifierAndWitnessVerifier(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}

	v, err := ParseVerifier(vkey)
	if err != nil {
		t.Fatalf("ParseVerifier(inline) failed: %v", err)
	}
	if v.Name() != "example.com/log" {
		t.Fatalf("v.Name() = %q, want example.com/log", v.Name())
	}

	keyPath := filepath.Join(t.TempDir(), "log.pub")
	if err := os.WriteFile(keyPath, []byte(vkey+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	vFromFile, err := ParseVerifier(keyPath)
	if err != nil {
		t.Fatalf("ParseVerifier(file) failed: %v", err)
	}
	if vFromFile.KeyHash() != v.KeyHash() {
		t.Fatalf("KeyHash mismatch: %x != %x", vFromFile.KeyHash(), v.KeyHash())
	}

	// Cosignature v1 witness key
	_, cosigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	cosigSigner, err := torchwood.NewCosignatureSigner("witness.example/w1", cosigPriv)
	if err != nil {
		t.Fatalf("NewCosignatureSigner failed: %v", err)
	}
	cosigVKey := cosigSigner.Verifier().String()
	wv, err := ParseWitnessVerifier(cosigVKey)
	if err != nil {
		t.Fatalf("ParseWitnessVerifier(cosig) failed: %v", err)
	}

	root := sha256.Sum256([]byte("tree-root"))
	cpText := fmt.Sprintf("example.com/log\n5\n%s\n", base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: cpText}, signer, cosigSigner)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}

	pol, err := BuildPolicy("example.com/log", v, []note.Verifier{wv}, 1)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}
	cp, _, err := torchwood.VerifyCheckpoint(signed, pol)
	if err != nil {
		t.Fatalf("VerifyCheckpoint with cosignature witness failed: %v", err)
	}
	if cp.N != 5 || cp.Origin != "example.com/log" {
		t.Fatalf("unexpected verified checkpoint: %+v", cp)
	}

	// Fallback witness verifier via standard note key file
	witSKey, witVKey, err := note.GenerateKey(rand.Reader, "witness.example/note")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	witSigner, err := note.NewSigner(witSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	witPath := filepath.Join(t.TempDir(), "wit.pub")
	if err := os.WriteFile(witPath, []byte(witVKey+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	wvNote, err := ParseWitnessVerifier(witPath)
	if err != nil {
		t.Fatalf("ParseWitnessVerifier(file) failed: %v", err)
	}
	signed2, err := note.Sign(&note.Note{Text: cpText}, signer, witSigner)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}
	pol2, err := ParsePolicyOrVerifier("", keyPath, "", []note.Verifier{wvNote}, 1)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier failed: %v", err)
	}
	if _, _, err := torchwood.VerifyCheckpoint(signed2, pol2); err != nil {
		t.Fatalf("VerifyCheckpoint(pol2) failed: %v", err)
	}
}

func TestBuildPolicyErrorsAndPolicyFile(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	signer, _ := note.NewSigner(skey)
	v, _ := ParseVerifier(vkey)
	_, wvkey, _ := note.GenerateKey(rand.Reader, "witness.example/w1")
	wv, _ := ParseVerifier(wvkey)

	if _, err := BuildPolicy("", nil, nil, 0); err == nil {
		t.Fatal("expected error for nil primary verifier")
	}
	if _, err := BuildPolicy("", v, []note.Verifier{v}, 1); err == nil {
		t.Fatal("expected error when witness collides with primary verifier")
	}
	if _, err := BuildPolicy("", v, []note.Verifier{wv, wv}, 2); err == nil {
		t.Fatal("expected error when duplicate witnesses fall short of threshold")
	}

	// Valid tlog-policy file via ParsePolicyOrVerifier
	policyContent := fmt.Sprintf("log %s\nquorum none\n", vkey)
	policyPath := filepath.Join(t.TempDir(), "log.policy")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	pol, err := ParsePolicyOrVerifier(policyPath, "", "", nil, 0)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier(policyFile) failed: %v", err)
	}
	root := sha256.Sum256([]byte("policy-file-root"))
	cpText := fmt.Sprintf("example.com/log\n7\n%s\n", base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: cpText}, signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, _, err := torchwood.VerifyCheckpoint(signed, pol); err != nil {
		t.Fatalf("VerifyCheckpoint with policy file failed: %v", err)
	}
}
