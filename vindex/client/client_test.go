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

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"filippo.io/torchwood"
	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/tree"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

type testOutputLog struct {
	mu     sync.Mutex
	leaves [][]byte
	origin string
	signer note.Signer
}

func (m *testOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafData)
	size := uint64(len(m.leaves))

	root := kvstore.BatchRoot(m.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", m.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signedCP, err := note.Sign(&note.Note{Text: rawCP}, m.signer)
	if err != nil {
		return 0, nil, err
	}
	return idx, signedCP, nil
}

func (m *testOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var leafHashes [][sha256.Size]byte
	for _, l := range m.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(l))
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		k := uint64(1)
		for k*2 < uint64(n) {
			k *= 2
		}
		if idx < k {
			rightSubRoot := kvstore.BatchRootHashes(leaves[k:])
			buildProof(leaves[:k], idx)
			proof = append(proof, rightSubRoot)
		} else {
			leftSubRoot := kvstore.BatchRootHashes(leaves[:k])
			buildProof(leaves[k:], idx-k)
			proof = append(proof, leftSubRoot)
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}

type testKeys struct {
	outSigner   note.Signer
	outVerifier note.Verifier
	outVKey     string
	inSigner    note.Signer
	inVerifier  note.Verifier
	inVKey      string
}

func newTestKeys(t testing.TB) testKeys {
	t.Helper()
	outSKey, outVKey, err := note.GenerateKey(rand.Reader, "example.com/output")
	if err != nil {
		t.Fatalf("note.GenerateKey(output) failed: %v", err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		t.Fatalf("note.NewSigner(output) failed: %v", err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		t.Fatalf("note.NewVerifier(output) failed: %v", err)
	}

	inSKey, inVKey, err := note.GenerateKey(rand.Reader, "example.com/input")
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

	return testKeys{
		outSigner:   outSigner,
		outVerifier: outVerifier,
		outVKey:     outVKey,
		inSigner:    inSigner,
		inVerifier:  inVerifier,
		inVKey:      inVKey,
	}
}

func (k testKeys) verifierConfig(t testing.TB) VerifierConfig {
	t.Helper()
	outPol, err := SingleKeyPolicy("example.com/output", k.outVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(output) failed: %v", err)
	}
	inPol, err := SingleKeyPolicy("example.com/input", k.inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(input) failed: %v", err)
	}
	return VerifierConfig{
		OutputLogPolicy: outPol,
		InputLogPolicy:  inPol,
	}
}

func (k testKeys) signInputCP(t testing.TB, size uint64) (*log.Checkpoint, []byte) {
	t.Helper()
	hash := sha256.Sum256(fmt.Appendf(nil, "input-root-%d", size))
	text := fmt.Sprintf("example.com/input\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(hash[:]))
	signed, err := note.Sign(&note.Note{Text: text}, k.inSigner)
	if err != nil {
		t.Fatalf("note.Sign(input) failed: %v", err)
	}
	return &log.Checkpoint{
		Origin: "example.com/input",
		Size:   size,
		Hash:   hash[:],
	}, signed
}

func setupTestEnvironment(t testing.TB, chunkSize uint64) (*server.ReadServer, *kvstore.DB, *mpt.Manager, *tree.OutputPublisher, *kvstore.KVIndexer, testKeys) {
	t.Helper()
	dir := t.TempDir()
	db, err := kvstore.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys := newTestKeys(t)
	mptMgr := mpt.NewMem()
	outLog := &testOutputLog{
		origin: "example.com/output",
		signer: keys.outSigner,
	}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	idxer := kvstore.NewKVIndexer(db, chunkSize)
	srv := server.NewReadServer(db, mptMgr, pub, chunkSize)

	return srv, db, mptMgr, pub, idxer, keys
}

func TestClient_PositiveInclusionAndNonInclusion(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	k1 := "target_key_1"
	k2 := "target_key_2"
	unmapped := "unmapped_key"
	kh1 := sha256.Sum256([]byte(k1))
	kh2 := sha256.Sum256([]byte(k2))

	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			kh1: {5, 20, 35},
			kh2: {10},
		},
		CanonicalKeys: map[[32]byte]string{
			kh1: k1,
			kh2: k2,
		},
	}

	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, keys.verifierConfig(t), ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	// 1. Inclusion test for k1
	kr1, err := cli.LookupKey(ctx, k1)
	if err != nil {
		t.Fatalf("LookupKey(k1) failed: %v", err)
	}
	if kr1.Mode != "inclusion" || len(kr1.Keys) != 1 || kr1.Keys[0].Key != k1 {
		t.Fatalf("unexpected KeysResponse for k1: %+v", kr1)
	}
	if kr1.InputSize != 100 || kr1.OutputSize != 1 {
		t.Fatalf("unexpected sizes: in=%d out=%d", kr1.InputSize, kr1.OutputSize)
	}
	if kr1.MPTRoot == ([32]byte{}) || kr1.Keys[0].ValueRoot == ([32]byte{}) {
		t.Fatalf("expected non-zero MPTRoot and ValueRoot")
	}

	indices1, err := cli.LookupAllValues(ctx, k1, 100)
	if err != nil {
		t.Fatalf("LookupAllValues(k1) failed: %v", err)
	}
	if !slices.Equal(indices1, []uint64{5, 20, 35}) {
		t.Fatalf("LookupAllValues(k1) = %v, want [5 20 35]", indices1)
	}

	// 2. Inclusion test for k2
	indices2, err := cli.LookupAllValues(ctx, k2, 100)
	if err != nil {
		t.Fatalf("LookupAllValues(k2) failed: %v", err)
	}
	if !slices.Equal(indices2, []uint64{10}) {
		t.Fatalf("LookupAllValues(k2) = %v, want [10]", indices2)
	}

	// 3. Non-inclusion test for unmapped
	krNon, err := cli.LookupKey(ctx, unmapped)
	if err != nil {
		t.Fatalf("LookupKey(unmapped) failed: %v", err)
	}
	if krNon.Mode != "non-inclusion" || len(krNon.Keys) != 0 {
		t.Fatalf("LookupKey(unmapped) unexpected response: %+v", krNon)
	}
	indicesNon, err := cli.LookupAllValues(ctx, unmapped, 100)
	if err != nil {
		t.Fatalf("LookupAllValues(unmapped) failed: %v", err)
	}
	if len(indicesNon) != 0 {
		t.Fatalf("LookupAllValues(unmapped) returned non-empty indices: %v", indicesNon)
	}
}

func TestClient_PaginationContinuation(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 100
	srv, db, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

	keyStr := "paginated_key"
	kh := sha256.Sum256([]byte(keyStr))

	var indices []uint64
	for i := uint64(0); i < 50; i++ {
		indices = append(indices, i*10)
	}
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        500,
		KeyMap: map[[32]byte][]uint64{
			kh: indices,
		},
		CanonicalKeys: map[[32]byte]string{
			kh: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 500)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := New(ts.URL, keys.verifierConfig(t), ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	kr, err := cli.LookupKey(ctx, keyStr)
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}

	// Page 1: before=500, limit=20 -> returns [300..490], NextPage -> before=300
	page1, err := cli.LookupValues(ctx, keyStr, kr.Keys[0].ValueRoot, kr.From, kr.InputSize, 20)
	if err != nil {
		t.Fatalf("Page 1 LookupValues failed: %v", err)
	}
	if len(page1.Indices) != 20 {
		t.Fatalf("Page 1 indices len = %d, want 20", len(page1.Indices))
	}
	nextBefore1, nextRoot1, ok1 := page1.NextPage()
	if !ok1 || nextBefore1 != 300 {
		t.Fatalf("Page 1 NextPage = (%d, %x, %v), want before=300, ok=true", nextBefore1, nextRoot1, ok1)
	}

	// Calling LookupValues with zero expectedValueRoot must fail
	if _, err := cli.LookupValues(ctx, keyStr, [32]byte{}, kr.From, nextBefore1, 20); err == nil {
		t.Fatal("expected error when calling LookupValues with zero expectedValueRoot, got nil")
	}

	// Page 2: before=300, limit=20 -> returns [100..290], NextPage -> before=100
	page2, err := cli.LookupValues(ctx, keyStr, nextRoot1, kr.From, nextBefore1, 20)
	if err != nil {
		t.Fatalf("Page 2 LookupValues failed: %v", err)
	}
	if len(page2.Indices) != 20 {
		t.Fatalf("Page 2 indices len = %d, want 20", len(page2.Indices))
	}
	nextBefore2, nextRoot2, ok2 := page2.NextPage()
	if !ok2 || nextBefore2 != 100 {
		t.Fatalf("Page 2 NextPage = (%d, %x, %v), want before=100, ok=true", nextBefore2, nextRoot2, ok2)
	}

	// Page 3: before=100, limit=20 -> returns remaining 10 items [0..90], NextPage -> ok=false
	page3, err := cli.LookupValues(ctx, keyStr, nextRoot2, kr.From, nextBefore2, 20)
	if err != nil {
		t.Fatalf("Page 3 LookupValues failed: %v", err)
	}
	if len(page3.Indices) != 10 {
		t.Fatalf("Page 3 indices len = %d, want 10", len(page3.Indices))
	}
	if _, _, ok3 := page3.NextPage(); ok3 {
		t.Fatal("Page 3 NextPage ok = true, want false")
	}

	// Test LookupAllValues -> fetches all pages backwards and returns sorted ascending indices [0..490]
	allIndices, err := cli.LookupAllValues(ctx, keyStr, 20)
	if err != nil {
		t.Fatalf("LookupAllValues failed: %v", err)
	}
	if !slices.Equal(allIndices, indices) {
		t.Fatalf("LookupAllValues = %v, want %v", allIndices, indices)
	}
}

func TestClient_NegativeTamperCases(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	keyStr := "tamper_key"
	key := sha256.Sum256([]byte(keyStr))
	batch := &ingest.MappedBatch{
		BundleIdx:    0,
		StartLeafIdx: 0,
		Count:        100,
		KeyMap: map[[32]byte][]uint64{
			key: {10, 20, 30},
		},
		CanonicalKeys: map[[32]byte]string{
			key: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}

	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	reqKeys := httptest.NewRequest(http.MethodGet, "/keys?key="+keyStr, nil)
	wKeys := httptest.NewRecorder()
	srv.HandleKeys(wKeys, reqKeys)
	if wKeys.Code != http.StatusOK {
		t.Fatalf("HandleKeys failed: %d", wKeys.Code)
	}
	validKeysBody := wKeys.Body.String()

	reqValues := httptest.NewRequest(http.MethodGet, "/values?key="+keyStr+"&before=100&limit=100", nil)
	wValues := httptest.NewRecorder()
	srv.HandleValues(wValues, reqValues)
	if wValues.Code != http.StatusOK {
		t.Fatalf("HandleValues failed: %d", wValues.Code)
	}
	validValuesBody := wValues.Body.String()

	cfg := keys.verifierConfig(t)

	// Baseline check
	keysResp, err := VerifyKeysResponse([]byte(validKeysBody), keyStr, false, cfg)
	if err != nil {
		t.Fatalf("Baseline valid keys body failed verification: %v", err)
	}
	expectedValueRoot := keysResp.Keys[0].ValueRoot
	if _, err := VerifyValuesResponse([]byte(validValuesBody), expectedValueRoot, 0, 100); err != nil {
		t.Fatalf("Baseline valid values body failed verification: %v", err)
	}

	// Tamper 1: Corrupted Output Log Root in checkpoint
	tamperedCP := strings.Replace(validKeysBody, "example.com/output\n1\n", "example.com/output\n2\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedCP), keyStr, false, cfg); err == nil {
		t.Error("Tampered checkpoint size should fail verification")
	}

	// Tamper 2: Corrupted Output Log inclusion proof
	tamperedProof := strings.Replace(validKeysBody, "index 0\n", "index 0\nbm9uc2Vuc2VoYXNoCg==\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedProof), keyStr, false, cfg); err == nil {
		t.Error("Tampered output log proof should fail verification")
	}

	// Tamper 3: Tampered Index in values response
	tamperedIndices := strings.Replace(validValuesBody, "20\n", "21\n", 1)
	if _, err := VerifyValuesResponse([]byte(tamperedIndices), expectedValueRoot, 0, 100); err == nil {
		t.Error("Tampered index value should fail value log root verification")
	}

	// Tamper 4: Unordered Indices
	unorderedIndices := strings.Replace(validValuesBody, "20\n30\n", "30\n20\n", 1)
	if _, err := VerifyValuesResponse([]byte(unorderedIndices), expectedValueRoot, 0, 100); err == nil {
		t.Error("Unordered indices should fail verification")
	}

	// Tamper 5: Index >= before
	outOfBoundsIndices := strings.Replace(validValuesBody, "30\n", "150\n", 1)
	if _, err := VerifyValuesResponse([]byte(outOfBoundsIndices), expectedValueRoot, 0, 100); err == nil {
		t.Error("Out of bounds index >= before should fail verification")
	}

	// Tamper 6: Corrupted MPT proof
	tamperedMPT := strings.Replace(validKeysBody, "c2sp.org/tlog-vindex-keys@v1\nproof\n", "c2sp.org/tlog-vindex-keys@v1\nproof AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n", 1)
	if _, err := VerifyKeysResponse([]byte(tamperedMPT), keyStr, false, cfg); err == nil {
		t.Error("Tampered MPT proof should fail verification")
	}

	// Tamper 7: Missing mandatory section
	stanzas := strings.SplitN(validKeysBody, "\n\n", 2)
	if _, err := VerifyKeysResponse([]byte(stanzas[0]), keyStr, false, cfg); err == nil {
		t.Error("Missing binding proof section should fail verification")
	}

	// Tamper 8: Empty indexed range (input_size == from) returning non-empty matches must be rejected with ErrCryptographicFault
	srvEmpty, _, _, pubEmpty, _, keysEmpty := setupTestEnvironment(t, chunkSize)
	pubEmpty.SetFrom(100)
	inCPEmpty, rawInCPEmpty := keysEmpty.signInputCP(t, 100)
	fakeVR := sha256.Sum256([]byte("forged-vr"))
	// Server publishes a forged key even though input_size == from == 100
	if _, err := pubEmpty.PublishKeyBatch(ctx, map[string][32]byte{keyStr: fakeVR}, inCPEmpty, rawInCPEmpty); err != nil {
		t.Fatalf("PublishKeyBatch empty range failed: %v", err)
	}
	wEmpty := httptest.NewRecorder()
	srvEmpty.HandleKeys(wEmpty, httptest.NewRequest(http.MethodGet, "/keys?key="+keyStr, nil))
	if _, err := VerifyKeysResponse(wEmpty.Body.Bytes(), keyStr, false, keysEmpty.verifierConfig(t)); !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault when input_size == from has non-empty matches, got: %v", err)
	}
}

func TestClient_LookupAllValues_ContinuationFaults(t *testing.T) {
	ctx := context.Background()
	const chunkSize = 100
	srv, db, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)
	db.SetChunkSize(chunkSize)

	keyStr := "mismatch_key"
	kh := sha256.Sum256([]byte(keyStr))
	var indices []uint64
	for i := uint64(0); i < 50; i++ {
		indices = append(indices, i*10)
	}
	batch := &ingest.MappedBatch{
		Count: 500,
		KeyMap: map[[32]byte][]uint64{
			kh: indices,
		},
		CanonicalKeys: map[[32]byte]string{
			kh: keyStr,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 500)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	var return404OnValues bool
	tamperedMux := http.NewServeMux()
	tamperedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if return404OnValues && strings.HasPrefix(r.URL.Path, "/values") {
			http.Error(w, "missing values", http.StatusNotFound)
			return
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		body := rec.Body.String()
		if r.URL.Query().Get("before") == "300" {
			body = strings.Replace(body, "200\n", "201\n", 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body))
	})

	ts := httptest.NewServer(tamperedMux)
	defer ts.Close()

	cli, err := New(ts.URL, keys.verifierConfig(t), ts.Client())
	if err != nil {
		t.Fatalf("New Client failed: %v", err)
	}

	_, err = cli.LookupAllValues(ctx, keyStr, 20)
	if err == nil || !strings.Contains(err.Error(), "value log root mismatch") {
		t.Fatalf("expected value log root mismatch error, got: %v", err)
	}

	// Unexpected HTTP 404 on promised /values page must surface as ErrCryptographicFault
	return404OnValues = true
	_, err = cli.LookupAllValues(ctx, keyStr, 20)
	if !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault on unexpected HTTP 404 for promised /values page, got: %v", err)
	}
}

func TestClient_PrefixLookupAndTwoSidedSoundness(t *testing.T) {
	ctx := context.Background()
	const chunkSize = kvstore.ChunkSize
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, chunkSize)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."
	kSibling := "com.googleapis.www."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))
	khSibling := sha256.Sum256([]byte(kSibling))

	batch := &ingest.MappedBatch{
		Count: 100,
		KeyMap: map[[32]byte][]uint64{
			khApex:    {1, 10},
			khMail:    {2, 20, 30},
			khDocs:    {3},
			khWild:    {4, 40},
			khSibling: {99},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex:    kApex,
			khMail:    kMail,
			khDocs:    kDocs,
			khWild:    kWild,
			khSibling: kSibling,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := keys.verifierConfig(t)
	cli, err := New(ts.URL, cfg, ts.Client())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// 1. LookupPrefixAll("com.google.") -> must return 4 keys in ascending order and exclude "com.googleapis.www."
	prefixResp, err := cli.LookupPrefixAll(ctx, "com.google.", 10)
	if err != nil {
		t.Fatalf("LookupPrefixAll failed: %v", err)
	}
	if len(prefixResp.Results) != 4 {
		t.Fatalf("expected 4 matched keys, got %d: %+v", len(prefixResp.Results), prefixResp.Results)
	}
	wantOrder := []string{kApex, kWild, kDocs, kMail}
	for i, wantKey := range wantOrder {
		if prefixResp.Results[i].Key != wantKey {
			t.Errorf("Result[%d].Key = %q, want %q", i, prefixResp.Results[i].Key, wantKey)
		}
		if prefixResp.Results[i].ValueRoot == ([32]byte{}) {
			t.Errorf("Result[%d].ValueRoot is zero", i)
		}
	}
	if !slices.Equal(prefixResp.Results[3].Indices, []uint64{2, 20, 30}) {
		t.Errorf("unexpected indices for %s: %v", kMail, prefixResp.Results[3].Indices)
	}

	// 2. Non-existent prefix ("com.nonexistent.") -> verified empty subtree
	emptyPrefixResp, err := cli.LookupPrefixAll(ctx, "com.nonexistent.", 10)
	if err != nil {
		t.Fatalf("LookupPrefixAll(com.nonexistent.) failed: %v", err)
	}
	if len(emptyPrefixResp.Results) != 0 {
		t.Fatalf("expected 0 results for nonexistent prefix, got %d", len(emptyPrefixResp.Results))
	}

	// 3. Adversarial two-sided soundness check: broader prefix proof rejected
	req := httptest.NewRequest(http.MethodGet, "/keys?prefix=com.", nil)
	w := httptest.NewRecorder()
	srv.SetPrefixPolicy(nil)
	srv.HandleKeys(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HandleKeys(com.) failed: %d", w.Code)
	}
	if _, err := VerifyKeysResponse(w.Body.Bytes(), "com.google.", true, cfg); err == nil {
		t.Fatal("VerifyKeysResponse must reject broader subtree containing keys outside query prefix")
	}
	if _, err := VerifyKeysResponse(w.Body.Bytes(), "com.google.", false, cfg); err == nil {
		t.Fatal("VerifyKeysResponse point lookup must reject response with multiple keys")
	}

	// 4. HTTP 413 maps to ErrTooManyKeys
	srv.SetMaxPrefixKeys(2)
	if _, err := cli.LookupPrefix(ctx, "com.google."); !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("expected ErrTooManyKeys on HTTP 413, got: %v", err)
	}
}

func TestClient_ValuesTruncationAndCompactRangeValidation(t *testing.T) {
	indices := []uint64{10, 20}
	valueRoot, err := wire.ComputeValueLogRoot(nil, 0, indices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot failed: %v", err)
	}

	// 1. Valid single-page values response (preceding 0)
	validBody := "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n10\n20\n"
	if _, err := VerifyValuesResponse([]byte(validBody), valueRoot, 0, 100); err != nil {
		t.Fatalf("expected valid values response to pass, got: %v", err)
	}

	// 1b. Zero expectedValueRoot must be rejected by VerifyValuesResponse
	if _, err := VerifyValuesResponse([]byte(validBody), [32]byte{}, 0, 100); err == nil {
		t.Fatal("expected VerifyValuesResponse to reject zero expectedValueRoot")
	}

	// 2. Preceding 0 with non-empty hash lines -> rejected
	dummyHash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	extraHashBody := fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 0\n%s\n\n10\n20\n", dummyHash)
	if _, err := VerifyValuesResponse([]byte(extraHashBody), valueRoot, 0, 100); err == nil {
		t.Fatalf("expected error when preceding 0 has hash lines, got nil")
	}

	// 3. Mismatched preceding > 0 with 0 hashes
	mismatchedBody := "c2sp.org/tlog-vindex-values@v1\npreceding 5\n\n10\n20\n"
	if _, err := VerifyValuesResponse([]byte(mismatchedBody), valueRoot, 0, 100); err == nil {
		t.Fatalf("expected mismatched popcount error, got: %v", err)
	}

	// 4. Empty indices block -> rejected
	emptyIndicesBody := "c2sp.org/tlog-vindex-values@v1\npreceding 0\n\n"
	if _, err := VerifyValuesResponse([]byte(emptyIndicesBody), valueRoot, 0, 100); err == nil {
		t.Fatalf("expected error for empty indices block, got nil")
	}

	// 5. Preceding size > indices[0] - from (exceeds available range / upperBound)
	overflowBody := fmt.Sprintf("c2sp.org/tlog-vindex-values@v1\npreceding 64\n%s\n\n10\n20\n", dummyHash)
	if _, err := VerifyValuesResponse([]byte(overflowBody), valueRoot, 0, 100); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("expected exceed upperBound error, got: %v", err)
	}
}

func TestStateless_VerifyKeysAndValuesResponse(t *testing.T) {
	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, 64)
	pub.SetFrom(50)

	kTest := "com.example.stateless"
	khTest := sha256.Sum256([]byte(kTest))
	batch1 := &ingest.MappedBatch{
		StartLeafIdx: 50,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			khTest: {55, 60, 75},
		},
		CanonicalKeys: map[[32]byte]string{
			khTest: kTest,
		},
	}
	res1, err := idxer.IndexBatch(ctx, batch1, nil)
	if err != nil {
		t.Fatalf("IndexBatch 1 failed: %v", err)
	}
	inCP1, rawInCP1 := keys.signInputCP(t, 100)
	if _, err := pub.PublishKeyBatch(ctx, res1.ModifiedKeyValueRoots, inCP1, rawInCP1); err != nil {
		t.Fatalf("PublishKeyBatch 1 failed: %v", err)
	}

	wKeys1 := httptest.NewRecorder()
	srv.HandleKeys(wKeys1, httptest.NewRequest(http.MethodGet, "/keys?key="+kTest, nil))
	if wKeys1.Code != http.StatusOK {
		t.Fatalf("HandleKeys 1 failed: %d", wKeys1.Code)
	}
	body1 := wKeys1.Body.Bytes()

	batch2 := &ingest.MappedBatch{
		StartLeafIdx: 100,
		Count:        50,
		KeyMap: map[[32]byte][]uint64{
			khTest: {110},
		},
		CanonicalKeys: map[[32]byte]string{
			khTest: kTest,
		},
	}
	res2, err := idxer.IndexBatch(ctx, batch2, nil)
	if err != nil {
		t.Fatalf("IndexBatch 2 failed: %v", err)
	}
	inCP2, rawInCP2 := keys.signInputCP(t, 150)
	if _, err := pub.PublishKeyBatch(ctx, res2.ModifiedKeyValueRoots, inCP2, rawInCP2); err != nil {
		t.Fatalf("PublishKeyBatch 2 failed: %v", err)
	}

	wKeys2 := httptest.NewRecorder()
	srv.HandleKeys(wKeys2, httptest.NewRequest(http.MethodGet, "/keys?key="+kTest, nil))
	if wKeys2.Code != http.StatusOK {
		t.Fatalf("HandleKeys 2 failed: %d", wKeys2.Code)
	}
	body2 := wKeys2.Body.Bytes()

	cfg := keys.verifierConfig(t)

	// Pure VerifyKeysResponse has zero state: verifying body2 (size 150) then body1 (size 100) both succeed!
	kr2, err := VerifyKeysResponse(body2, kTest, false, cfg)
	if err != nil {
		t.Fatalf("VerifyKeysResponse(body2) failed: %v", err)
	}
	if kr2.Mode != "inclusion" || kr2.From != 50 || kr2.InputSize != 150 || kr2.OutputSize != 2 {
		t.Fatalf("unexpected kr2: %+v", kr2)
	}
	if kr2.OutputRoot == ([32]byte{}) || kr2.InputRoot == ([32]byte{}) {
		t.Fatalf("expected non-zero OutputRoot and InputRoot on kr2")
	}

	kr1, err := VerifyKeysResponse(body1, kTest, false, cfg)
	if err != nil {
		t.Fatalf("stateless VerifyKeysResponse(body1) after body2 failed: %v", err)
	}
	if kr1.Mode != "inclusion" || kr1.From != 50 || kr1.InputSize != 100 || kr1.OutputSize != 1 {
		t.Fatalf("unexpected kr1: %+v", kr1)
	}

	// VerifyValuesResponse with from > 0 bounds:
	compHash := sha256.Sum256([]byte("compact-prefix-4"))
	pageIndices := []uint64{55, 58, 59}
	valRoot, err := wire.ComputeValueLogRoot([][32]byte{compHash}, 4, pageIndices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot failed: %v", err)
	}
	rawVals := wire.FormatValuesResponse(4, [][32]byte{compHash}, pageIndices)
	vr, err := VerifyValuesResponse(rawVals, valRoot, 50, 60)
	if err != nil {
		t.Fatalf("VerifyValuesResponse valid from=50 failed: %v", err)
	}
	nextBefore, nextRoot, ok := vr.NextPage()
	if !ok || nextBefore != 55 || vr.Preceding != 4 || nextRoot == ([32]byte{}) {
		t.Fatalf("unexpected ValuesResponse NextPage: before=%d root=%x ok=%v", nextBefore, nextRoot, ok)
	}

	// before <= from -> rejected with ErrCryptographicFault
	if _, err := VerifyValuesResponse(rawVals, valRoot, 50, 50); !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault when before == from, got: %v", err)
	}
	if _, err := VerifyValuesResponse(rawVals, valRoot, 60, 50); !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault when before < from, got: %v", err)
	}
	if _, err := VerifyValuesResponse(rawVals, valRoot, 0, 0); !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault when before == 0, got: %v", err)
	}

	// Indices[0] < from
	if _, err := VerifyValuesResponse(rawVals, valRoot, 56, 60); !errors.Is(err, ErrIndexRange) {
		t.Fatalf("expected ErrIndexRange when Indices[0] < from, got: %v", err)
	}

	// Preceding > Indices[0] - from
	if _, err := VerifyValuesResponse(rawVals, valRoot, 52, 60); !errors.Is(err, ErrIndexRange) {
		t.Fatalf("expected ErrIndexRange when Preceding > Indices[0]-from, got: %v", err)
	}

	// Tight bound len(Indices) == before - from - Preceding
	tightIndices := []uint64{54, 55, 56}
	tightRoot, err := wire.ComputeValueLogRoot([][32]byte{compHash}, 4, tightIndices)
	if err != nil {
		t.Fatalf("ComputeValueLogRoot tight failed: %v", err)
	}
	tightRaw := wire.FormatValuesResponse(4, [][32]byte{compHash}, tightIndices)
	if _, err := VerifyValuesResponse(tightRaw, tightRoot, 50, 57); err != nil {
		t.Fatalf("expected tight bound len(Indices) == before - from - Preceding to succeed, got: %v", err)
	}
}

func TestStateTracker_InvariantsAndAtomicity(t *testing.T) {
	st := NewStateTracker()

	outH1 := sha256.Sum256([]byte("out-1"))
	outH2 := sha256.Sum256([]byte("out-2"))
	outH2Alt := sha256.Sum256([]byte("out-2-split"))
	inH1 := sha256.Sum256([]byte("in-100"))
	inH2 := sha256.Sum256([]byte("in-200"))
	inH2Alt := sha256.Sum256([]byte("in-200-split"))
	mapFn1 := sha256.Sum256([]byte("map-fn-1"))
	mapFn2 := sha256.Sum256([]byte("map-fn-2"))

	// 1. Initial ObserveKeysResponse records watermarks and (from, mapFn)
	resp1 := &KeysResponse{
		OutputSize: 1,
		OutputRoot: outH1,
		InputSize:  100,
		InputRoot:  inH1,
		From:       10,
		MapFn:      mapFn1,
	}
	if err := st.ObserveKeysResponse(resp1); err != nil {
		t.Fatalf("ObserveKeysResponse(resp1) failed: %v", err)
	}

	// 2. Advancing both checkpoints with identical (from, mapFn) succeeds
	resp2 := &KeysResponse{
		OutputSize: 2,
		OutputRoot: outH2,
		InputSize:  200,
		InputRoot:  inH2,
		From:       10,
		MapFn:      mapFn1,
	}
	if err := st.ObserveKeysResponse(resp2); err != nil {
		t.Fatalf("ObserveKeysResponse(resp2) failed: %v", err)
	}

	// 3. Output Log size regression rejected with ErrCheckpointRegressed
	if err := st.Observe(1, outH1, 200, inH2, mapFn1, 10); !errors.Is(err, ErrCheckpointRegressed) {
		t.Fatalf("expected ErrCheckpointRegressed on output log regression, got: %v", err)
	}

	// 4. Input Log size regression rejected with ErrCheckpointRegressed
	if err := st.Observe(2, outH2, 100, inH1, mapFn1, 10); !errors.Is(err, ErrCheckpointRegressed) {
		t.Fatalf("expected ErrCheckpointRegressed on input log regression, got: %v", err)
	}

	// 5. Output Log equal-size hash mismatch (split-view) rejected with ErrConsistencyFault
	if err := st.Observe(2, outH2Alt, 200, inH2, mapFn1, 10); !errors.Is(err, ErrConsistencyFault) {
		t.Fatalf("expected ErrConsistencyFault on output log split-view, got: %v", err)
	}

	// 6. Input Log equal-size hash mismatch (split-view) rejected with ErrConsistencyFault
	if err := st.Observe(2, outH2, 200, inH2Alt, mapFn1, 10); !errors.Is(err, ErrConsistencyFault) {
		t.Fatalf("expected ErrConsistencyFault on input log split-view, got: %v", err)
	}

	// 7. `from` mutation rejected AND must NOT advance outSize/inSize!
	outH3 := sha256.Sum256([]byte("out-3"))
	inH3 := sha256.Sum256([]byte("in-300"))
	if err := st.Observe(3, outH3, 300, inH3, mapFn1, 25); !errors.Is(err, ErrConsistencyFault) {
		t.Fatalf("expected ErrConsistencyFault on from mutation, got: %v", err)
	}
	if st.outSize != 2 || st.inSize != 200 || st.from != 10 {
		t.Fatalf("failed Observe mutated tracker state: outSize=%d inSize=%d from=%d", st.outSize, st.inSize, st.from)
	}

	// 8. `map-fn` mutation rejected AND must NOT advance outSize/inSize!
	if err := st.Observe(3, outH3, 300, inH3, mapFn2, 10); !errors.Is(err, ErrConsistencyFault) {
		t.Fatalf("expected ErrConsistencyFault on map-fn mutation, got: %v", err)
	}
	if st.outSize != 2 || st.inSize != 200 || st.mapFn != mapFn1 {
		t.Fatalf("failed Observe mutated tracker state: outSize=%d inSize=%d mapFn=%x", st.outSize, st.inSize, st.mapFn)
	}
}

func TestEncodeRFC3986Unreserved(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	if got := encodeRFC3986Unreserved(unreserved); got != unreserved {
		t.Fatalf("unreserved characters were modified:\n got:  %q\n want: %q", got, unreserved)
	}

	cases := []struct {
		in   string
		want string
	}{
		{"a+b", "a%2Bb"},
		{"~tilde~", "~tilde~"},
		{"pkg+v1~rc1/sub*key?x=1&y=2%z", "pkg%2Bv1~rc1%2Fsub%2Akey%3Fx%3D1%26y%3D2%25z"},
		{"space here", "space%20here"},
	}
	for _, tc := range cases {
		if got := encodeRFC3986Unreserved(tc.in); got != tc.want {
			t.Errorf("encodeRFC3986Unreserved(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(t, 64)
	specialKey := "pkg+v1.2_3-rc~final/mod"
	kh := sha256.Sum256([]byte(specialKey))
	res, err := idxer.IndexBatch(ctx, &ingest.MappedBatch{
		Count:         50,
		KeyMap:        map[[32]byte][]uint64{kh: {7, 42}},
		CanonicalKeys: map[[32]byte]string{kh: specialKey},
	}, nil)
	if err != nil {
		t.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(t, 50)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		t.Fatalf("PublishKeyBatch failed: %v", err)
	}

	var capturedRawQueries []string
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawQueries = append(capturedRawQueries, r.URL.RawQuery)
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, keys.verifierConfig(t), ts.Client())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if cli.StateTracker() != nil {
		t.Fatalf("expected Client.StateTracker() to be nil by default")
	}
	cli.SetStateTracker(NewStateTracker())

	indices, err := cli.LookupAllValues(ctx, specialKey, 10)
	if err != nil {
		t.Fatalf("LookupAllValues(%q) failed: %v", specialKey, err)
	}
	if !slices.Equal(indices, []uint64{7, 42}) {
		t.Fatalf("unexpected LookupAllValues(%q) result: %v", specialKey, indices)
	}
	if len(capturedRawQueries) != 2 {
		t.Fatalf("expected 2 HTTP queries (/keys and /values), got %d", len(capturedRawQueries))
	}
	for _, rq := range capturedRawQueries {
		if !strings.Contains(rq, "pkg%2Bv1.2_3-rc~final%2Fmod") {
			t.Errorf("expected RFC 3986 unreserved encoding in RawQuery, got %q", rq)
		}
	}
}

func TestClient_TorchwoodPolicyWitnessQuorumAndRedirects(t *testing.T) {
	ctx := context.Background()

	genKey := func(name string) (note.Signer, note.Verifier, string) {
		sKey, vKey, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatalf("note.GenerateKey(%s) failed: %v", name, err)
		}
		s, err := note.NewSigner(sKey)
		if err != nil {
			t.Fatalf("note.NewSigner(%s) failed: %v", name, err)
		}
		v, err := note.NewVerifier(vKey)
		if err != nil {
			t.Fatalf("note.NewVerifier(%s) failed: %v", name, err)
		}
		return s, v, vKey
	}

	genWitness := func(name string) (note.Signer, note.Verifier, string) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey(%s) failed: %v", name, err)
		}
		cs, err := torchwood.NewCosignatureSigner(name, priv)
		if err != nil {
			t.Fatalf("torchwood.NewCosignatureSigner(%s) failed: %v", name, err)
		}
		cv := cs.Verifier()
		return cs, cv, cv.String()
	}

	outSigner, outVerifier, outVKey := genKey("example.com/output")
	inSigner, inVerifier, _ := genKey("example.com/input")
	w1Signer, w1Verifier, w1VKey := genWitness("witness1.example.com")
	w2Signer, w2Verifier, w2VKey := genWitness("witness2.example.com")
	_, w3Verifier, w3VKey := genWitness("witness3.example.com")

	inPol, err := SingleKeyPolicy("example.com/input", inVerifier)
	if err != nil {
		t.Fatalf("SingleKeyPolicy(input) failed: %v", err)
	}

	// Build 2-of-3 witness policy both via WitnessPolicy helper and torchwood.ParsePolicy
	outWitnessPol, err := WitnessPolicy("example.com/output", outVerifier, []note.Verifier{w1Verifier, w2Verifier, w3Verifier}, 2)
	if err != nil {
		t.Fatalf("WitnessPolicy failed: %v", err)
	}

	policyText := fmt.Sprintf("log %s\nwitness w1 %s\nwitness w2 %s\nwitness w3 %s\ngroup g 2 w1 w2 w3\nquorum g\n",
		outVKey, w1VKey, w2VKey, w3VKey)
	parsedPol, err := torchwood.ParsePolicy([]byte(policyText))
	if err != nil {
		t.Fatalf("torchwood.ParsePolicy failed: %v", err)
	}

	// Build a valid /keys response signed by outSigner + witness cosigners
	mptMgr := mpt.NewMem()
	kTest := "com.google."
	vr := sha256.Sum256([]byte("vr-1"))
	mptRoot, err := mptMgr.CommitKeysWithVersion(map[string][32]byte{kTest: vr}, 50)
	if err != nil {
		t.Fatalf("CommitKeysWithVersion failed: %v", err)
	}
	mptProof, _, _, err := mptMgr.ProveKey([]byte(kTest))
	if err != nil {
		t.Fatalf("ProveKey failed: %v", err)
	}

	inHash := sha256.Sum256([]byte("in-root-50"))
	inSignedCP, err := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/input\n50\n%s\n", base64.StdEncoding.EncodeToString(inHash[:])),
	}, inSigner)
	if err != nil {
		t.Fatalf("note.Sign(input) failed: %v", err)
	}

	rawOutLeaf := wire.FormatOutputLogLeafFull(mptRoot, [32]byte{}, 0, inSignedCP)
	outRoot := wire.LeafHash(rawOutLeaf)
	outText := fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))

	buildKeysBody := func(signers ...note.Signer) []byte {
		outSigned, sErr := note.Sign(&note.Note{Text: outText}, signers...)
		if sErr != nil {
			t.Fatalf("note.Sign(output) failed: %v", sErr)
		}
		return wire.FormatKeysResponseFull(outSigned, 0, mptRoot, [32]byte{}, 0, inSignedCP, nil, "inclusion", mptProof, []KeyValueRoot{{Key: kTest, ValueRoot: vr}})
	}

	// 1. Only 1 witness signed -> fails 2-of-3 quorum with ErrCheckpointFailed
	body1Witness := buildKeysBody(outSigner, w1Signer)
	if _, err := VerifyKeysResponse(body1Witness, kTest, false, VerifierConfig{
		OutputLogPolicy: outWitnessPol,
		InputLogPolicy:  inPol,
	}); !errors.Is(err, ErrCheckpointFailed) {
		t.Fatalf("expected ErrCheckpointFailed when 1-of-3 witnesses signed, got: %v", err)
	}

	// 2. 2 distinct witnesses signed -> passes both WitnessPolicy and torchwood.ParsePolicy
	body2Witnesses := buildKeysBody(outSigner, w1Signer, w2Signer)
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, VerifierConfig{
		OutputLogPolicy: outWitnessPol,
		InputLogPolicy:  inPol,
	}); err != nil {
		t.Fatalf("expected 2-of-3 WitnessPolicy to pass, got: %v", err)
	}
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, VerifierConfig{
		OutputLogPolicy: parsedPol,
		InputLogPolicy:  inPol,
	}); err != nil {
		t.Fatalf("expected 2-of-3 torchwood.ParsePolicy to pass, got: %v", err)
	}

	// 3. Nil OutputLogPolicy or InputLogPolicy rejected with ErrCheckpointFailed
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, VerifierConfig{InputLogPolicy: inPol}); !errors.Is(err, ErrCheckpointFailed) {
		t.Fatalf("expected ErrCheckpointFailed when OutputLogPolicy is nil, got: %v", err)
	}
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, VerifierConfig{OutputLogPolicy: outWitnessPol}); !errors.Is(err, ErrCheckpointFailed) {
		t.Fatalf("expected ErrCheckpointFailed when InputLogPolicy is nil, got: %v", err)
	}

	// 4. ExpectedMapFn mismatch rejected with ErrCryptographicFault
	wrongMapFn := sha256.Sum256([]byte("wrong-map-fn"))
	if _, err := VerifyKeysResponse(body2Witnesses, kTest, false, VerifierConfig{
		OutputLogPolicy: outWitnessPol,
		InputLogPolicy:  inPol,
		ExpectedMapFn:   &wrongMapFn,
	}); !errors.Is(err, ErrCryptographicFault) {
		t.Fatalf("expected ErrCryptographicFault on ExpectedMapFn mismatch, got: %v", err)
	}

	// 5. Invalid canonical query target rejected with ErrInvalidRequest
	if _, err := VerifyKeysResponse(body2Witnesses, "bad key with spaces", false, VerifierConfig{
		OutputLogPolicy: outWitnessPol,
		InputLogPolicy:  inPol,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest on invalid target key, got: %v", err)
	}

	// 6. Client rejects 3xx HTTP redirects per tlog-vindex spec
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/keys?key=com.google.", http.StatusFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	redirectCli, err := New(ts.URL+"/redirect", VerifierConfig{
		OutputLogPolicy: outWitnessPol,
		InputLogPolicy:  inPol,
	}, ts.Client())
	if err != nil {
		t.Fatalf("New redirectCli failed: %v", err)
	}
	if _, err := redirectCli.LookupKey(ctx, kTest); err == nil || !strings.Contains(err.Error(), "redirects (3xx) are forbidden") {
		t.Fatalf("expected LookupKey to reject 3xx redirect, got: %v", err)
	}
}

func TestClient_DependencyBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{range .Imports}}{{.}}\n{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, string(out))
	}
	allowedExternal := map[string]bool{
		"filippo.io/torchwood":                                true,
		"golang.org/x/mod/sumdb/note":                         true,
		"golang.org/x/mod/sumdb/tlog":                         true,
		"github.com/transparency-dev/incubator/vindex/internal/mpt":  true,
		"github.com/transparency-dev/incubator/vindex/internal/wire": true,
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if imp == "" || !strings.Contains(imp, ".") {
			continue // stdlib package
		}
		if !allowedExternal[imp] {
			t.Errorf("forbidden direct import in vindex/client: %q", imp)
		}
	}
}

func BenchmarkClient_VerifyKeysAndValues(b *testing.B) {
	ctx := context.Background()
	srv, _, _, pub, idxer, keys := setupTestEnvironment(b, 64)

	kApex := "com.google."
	kMail := "com.google.mail."
	kDocs := "com.google.docs."
	kWild := "com.google.*."

	khApex := sha256.Sum256([]byte(kApex))
	khMail := sha256.Sum256([]byte(kMail))
	khDocs := sha256.Sum256([]byte(kDocs))
	khWild := sha256.Sum256([]byte(kWild))

	var mailIndices []uint64
	for i := uint64(0); i < 128; i++ {
		mailIndices = append(mailIndices, i*10+1)
	}

	batch := &ingest.MappedBatch{
		Count: 2000,
		KeyMap: map[[32]byte][]uint64{
			khApex: {1, 10},
			khMail: mailIndices,
			khDocs: {3},
			khWild: {4, 40},
		},
		CanonicalKeys: map[[32]byte]string{
			khApex: kApex,
			khMail: kMail,
			khDocs: kDocs,
			khWild: kWild,
		},
	}
	res, err := idxer.IndexBatch(ctx, batch, nil)
	if err != nil {
		b.Fatalf("IndexBatch failed: %v", err)
	}
	inCP, rawInCP := keys.signInputCP(b, 2000)
	if _, err := pub.PublishKeyBatch(ctx, res.ModifiedKeyValueRoots, inCP, rawInCP); err != nil {
		b.Fatalf("PublishKeyBatch failed: %v", err)
	}

	wPoint := httptest.NewRecorder()
	srv.HandleKeys(wPoint, httptest.NewRequest(http.MethodGet, "/keys?key=com.google.mail.", nil))
	pointBytes := wPoint.Body.Bytes()

	wPrefix := httptest.NewRecorder()
	srv.HandleKeys(wPrefix, httptest.NewRequest(http.MethodGet, "/keys?prefix=com.google.", nil))
	prefixBytes := wPrefix.Body.Bytes()

	wValues := httptest.NewRecorder()
	srv.HandleValues(wValues, httptest.NewRequest(http.MethodGet, "/values?key=com.google.mail.&before=2000&limit=64", nil))
	valuesBytes := wValues.Body.Bytes()

	cfg := keys.verifierConfig(b)
	keysResp, err := VerifyKeysResponse(pointBytes, kMail, false, cfg)
	if err != nil {
		b.Fatalf("VerifyKeysResponse failed: %v", err)
	}
	mailValueRoot := keysResp.Keys[0].ValueRoot

	b.Run("VerifyKeysResponse_Point", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(pointBytes, kMail, false, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyKeysResponse_Prefix4Keys", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyKeysResponse(prefixBytes, kApex, true, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("VerifyValuesResponse_ZeroMPTContinuation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := VerifyValuesResponse(valuesBytes, mailValueRoot, keysResp.From, 2000); err != nil {
				b.Fatal(err)
			}
		}
	})
}
