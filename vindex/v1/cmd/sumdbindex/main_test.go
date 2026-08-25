package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/incubator/vindex/v1/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

var exampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var pseudoVersionLeaf = []byte(`github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356 h1:4jV/qA6RzP7Z6s+/vQ0W2RjM3FjC6B2M3r8=
github.com/transparency-dev/tessera v0.0.0-20240222160914-411202e8d356/go.mod h1:T/Ym+5H1e28Qv6iMzT3w=
`)

var releaseCandidateLeaf = []byte(`github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1 h1:f1nwnVa7t5Ftd+BPef/V/Y8XxT1Sdiif0cdIo/8R9i0=
github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s v1.7.0-rc1/go.mod h1:CuxOEw4CmUSK44owsXWkZ6Njh0G/gfboQoLl9hn1Voo=`)

func TestMapFn(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf []byte
		want [][32]byte
	}{
		{
			name: "valid",
			leaf: exampleLeaf,
			want: [][32]byte{sha256.Sum256([]byte("golang.org/x/text"))},
		},
		{
			name: "pseudo_version",
			leaf: pseudoVersionLeaf,
			want: nil,
		},
		{
			name: "release_candidate",
			leaf: releaseCandidateLeaf,
			want: [][32]byte{sha256.Sum256([]byte("github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"))},
		},
		{
			name: "empty_leaf",
			leaf: []byte{},
			want: nil,
		},
		{
			name: "no_spaces",
			leaf: []byte("invalidleafwithnospaces"),
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapFn(tc.leaf)
			if len(got) != len(tc.want) {
				t.Fatalf("mapFn() returned %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !bytes.Equal(got[i][:], tc.want[i][:]) {
					t.Errorf("mapFn()[%d] = %x, want %x", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSumDBLeafMapper(t *testing.T) {
	ctx := context.Background()
	mapper := &SumDBLeafMapper{}
	defer func() {
		if err := mapper.Close(ctx); err != nil {
			t.Errorf("mapper.Close failed: %v", err)
		}
	}()

	// 1. Valid leaf
	entries, err := mapper.MapLeaf(ctx, exampleLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(exampleLeaf) unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("MapLeaf(exampleLeaf) got %d entries, want 1", len(entries))
	}
	wantHash := sha256.Sum256([]byte("golang.org/x/text"))
	if entries[0].KeyHash != wantHash {
		t.Errorf("MapLeaf(exampleLeaf) key hash = %x, want %x", entries[0].KeyHash, wantHash)
	}

	// 2. Pseudo version (should be dropped)
	pseudoEntries, err := mapper.MapLeaf(ctx, pseudoVersionLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(pseudoVersionLeaf) unexpected error: %v", err)
	}
	if len(pseudoEntries) != 0 {
		t.Errorf("MapLeaf(pseudoVersionLeaf) got %d entries, want 0", len(pseudoEntries))
	}

	// 3. Release candidate
	rcEntries, err := mapper.MapLeaf(ctx, releaseCandidateLeaf)
	if err != nil {
		t.Fatalf("MapLeaf(releaseCandidateLeaf) unexpected error: %v", err)
	}
	if len(rcEntries) != 1 {
		t.Fatalf("MapLeaf(releaseCandidateLeaf) got %d entries, want 1", len(rcEntries))
	}
	wantRCHash := sha256.Sum256([]byte("github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"))
	if rcEntries[0].KeyHash != wantRCHash {
		t.Errorf("MapLeaf(releaseCandidateLeaf) key hash = %x, want %x", rcEntries[0].KeyHash, wantRCHash)
	}
}

type testInputLog struct {
	mu     sync.Mutex
	origin string
	leaves [][]byte
}

func (l *testInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return &ingest.Checkpoint{
		Raw:    []byte(rawCP),
		Origin: l.origin,
		Size:   size,
		Hash:   root,
	}, nil
}

func (l *testInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     l.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *testInputLog) InclusionProof(_ context.Context, idx, treeSize uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

func TestSumDBIndex_Integration(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	db, err := kvstore.Open(tempDir+"/pebble", &pebble.Options{})
	if err != nil {
		t.Fatalf("kvstore.Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	mptMgr, err := tree.Open(tempDir + "/mpt")
	if err != nil {
		t.Fatalf("tree.Open failed: %v", err)
	}
	defer func() { _ = mptMgr.Close() }()

	mockInputLog := &testInputLog{
		origin: "go.sum database tree",
		leaves: [][]byte{
			exampleLeaf,          // idx 0 -> golang.org/x/text
			pseudoVersionLeaf,    // idx 1 -> dropped (pseudo version)
			releaseCandidateLeaf, // idx 2 -> github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s
		},
	}

	outLog, err := newLocalOutputLog("SumDBIndex", tempDir+"/outputlog", nil)
	if err != nil {
		t.Fatalf("newLocalOutputLog failed: %v", err)
	}

	const chunkSize = 16
	leafMapper := &SumDBLeafMapper{}
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	idxer := kvstore.NewKVIndexer(db, chunkSize)

	tileCache, err := ingest.NewManagedTileCache(tempDir+"/tilecache", 0)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	coord := coordinator.NewCoordinator(db, mptMgr, outLog, pub, idxer, mockInputLog, tileCache, leafMapper)
	if err := coord.Recover(ctx); err != nil {
		t.Fatalf("coord.Recover failed: %v", err)
	}

	if err := coord.SyncOnce(ctx); err != nil {
		t.Fatalf("coord.SyncOnce failed: %v", err)
	}

	readSrv := server.NewReadServer(db, mptMgr, pub, chunkSize)
	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.New(ts.URL, client.VerifierConfig{
		OutputLogOrigin: "SumDBIndex",
		InputLogOrigin:  "go.sum database tree",
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// 1. Lookup "golang.org/x/text"
	respText, err := cli.LookupAllKey(ctx, "golang.org/x/text", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(golang.org/x/text) failed: %v", err)
	}
	if !respText.Exists {
		t.Fatal("golang.org/x/text should exist in index")
	}
	if len(respText.Indices) != 1 || respText.Indices[0] != 0 {
		t.Fatalf("golang.org/x/text indices = %v, want [0]", respText.Indices)
	}

	// 2. Lookup "github.com/transparency-dev/tessera" (pseudo-version should not be in index)
	respTessera, err := cli.LookupAllKey(ctx, "github.com/transparency-dev/tessera", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(github.com/transparency-dev/tessera) failed: %v", err)
	}
	if respTessera.Exists {
		t.Fatalf("github.com/transparency-dev/tessera pseudo-version should not exist in index: got %v", respTessera.Indices)
	}

	// 3. Lookup "github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s"
	respRC, err := cli.LookupAllKey(ctx, "github.1485827954.workers.dev/aws/amazon-vpc-cni-k8s", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(rc) failed: %v", err)
	}
	if !respRC.Exists {
		t.Fatal("release candidate module should exist in index")
	}
	if len(respRC.Indices) != 1 || respRC.Indices[0] != 2 {
		t.Fatalf("release candidate indices = %v, want [2]", respRC.Indices)
	}

	// 4. Lookup unknown key (verified non-inclusion)
	respUnknown, err := cli.LookupAllKey(ctx, "nonexistent/module", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(nonexistent/module) failed: %v", err)
	}
	if respUnknown.Exists {
		t.Fatal("nonexistent/module should not exist")
	}
}

func BenchmarkMapFn(b *testing.B) {
	for b.Loop() {
		mapFn(exampleLeaf)
		mapFn(pseudoVersionLeaf)
		mapFn(releaseCandidateLeaf)
	}
}
