package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/bits"
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

var testExampleLeaf = []byte(`golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`)

var testExampleLeaf2 = []byte(`golang.org/x/text v0.3.1 h1:anotherhash1234567890=
golang.org/x/text v0.3.1/go.mod h1:anothermodhash123456=
`)

func TestParseLeaf(t *testing.T) {
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
}

type testLocalOutputLog struct {
	mu     sync.Mutex
	origin string
	leaves [][]byte
}

func (l *testLocalOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	idx := uint64(len(l.leaves))
	l.leaves = append(l.leaves, leafData)
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	rawCP := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return idx, []byte(rawCP), nil
}

func (l *testLocalOutputLog) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves)), nil
}

func (l *testLocalOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("out of bounds: %d >= %d", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testLocalOutputLog) Checkpoint(_ context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (l *testLocalOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var leafHashes [][sha256.Size]byte
	for _, leaf := range l.leaves[:treeSize] {
		leafHashes = append(leafHashes, kvstore.LeafHash(leaf))
	}

	var proof [][sha256.Size]byte
	var buildProof func(leaves [][sha256.Size]byte, idx uint64)
	buildProof = func(leaves [][sha256.Size]byte, idx uint64) {
		n := len(leaves)
		if n <= 1 {
			return
		}
		k := uint64(1) << (bits.Len(uint(n-1)) - 1)
		if idx < k {
			buildProof(leaves[:k], idx)
			proof = append(proof, kvstore.BatchRootHashes(leaves[k:]))
		} else {
			buildProof(leaves[k:], idx-k)
			proof = append(proof, kvstore.BatchRootHashes(leaves[:k]))
		}
	}

	buildProof(leafHashes, leafIdx)
	return proof, nil
}

type testSumDBInputLog struct {
	mu     sync.Mutex
	origin string
	leaves [][]byte
}

func (l *testSumDBInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
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

func (l *testSumDBInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testSumDBInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     l.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *testSumDBInputLog) InclusionProof(_ context.Context, idx, treeSize uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

type sumdbMapper struct{}

func (m *sumdbMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	kh := sha256.Sum256([]byte("golang.org/x/text"))
	return []ingest.MappedEntry{{KeyHash: kh}}, nil
}

func (m *sumdbMapper) Close(_ context.Context) error { return nil }

func TestQueryIndex_Integration(t *testing.T) {
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

	inLog := &testSumDBInputLog{
		origin: "go.sum database tree",
		leaves: [][]byte{testExampleLeaf, testExampleLeaf2},
	}
	outLog := &testLocalOutputLog{
		origin: "SumDBIndex",
	}

	const chunkSize = 16
	mapper := &sumdbMapper{}
	idxer := kvstore.NewKVIndexer(db, chunkSize)
	pub := tree.NewOutputPublisher(db, mptMgr, outLog, nil)
	tileCache, err := ingest.NewManagedTileCache(tempDir+"/tilecache", 0)
	if err != nil {
		t.Fatalf("NewManagedTileCache failed: %v", err)
	}

	coord := coordinator.NewCoordinator(db, mptMgr, outLog, pub, idxer, inLog, tileCache, mapper)
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

	resp, err := cli.LookupAllKey(ctx, "golang.org/x/text", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey failed: %v", err)
	}
	if !resp.Exists {
		t.Fatal("expected key to exist")
	}
	if len(resp.Indices) != 2 {
		t.Fatalf("expected 2 indices, got %d (%v)", len(resp.Indices), resp.Indices)
	}
}
