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
	"encoding/asn1"
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
	"github.com/transparency-dev/incubator/vindex/v1/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

// helper to marshal TBSCertificateLogEntry
func marshalMTCEntry(dnsNames []string) ([]byte, error) {
	rawNames := []asn1.RawValue{}
	for _, name := range dnsNames {
		rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	sanValue, err := asn1.Marshal(rawNames)
	if err != nil {
		return nil, err
	}

	ext := struct {
		Id       asn1.ObjectIdentifier
		Critical bool `asn1:"optional,default:false"`
		Value    []byte
	}{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: sanValue,
	}
	extBytes, err := asn1.Marshal(ext)
	if err != nil {
		return nil, err
	}

	entry := mtc.TBSCertificateLogEntry{
		Extensions: []asn1.RawValue{{FullBytes: extBytes}},
	}

	entryBytes, err := asn1.Marshal(entry)
	if err != nil {
		return nil, err
	}

	return append([]byte{0, 1}, entryBytes...), nil
}

type testMTCInputLog struct {
	mu     sync.Mutex
	origin string
	leaves [][]byte
}

func (l *testMTCInputLog) Checkpoint(_ context.Context) (*ingest.Checkpoint, error) {
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

func (l *testMTCInputLog) Leaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *testMTCInputLog) FetchTiles(ctx context.Context, startLeafIdx, count uint64) ([]*ingest.LeafBundle, error) {
	adapter := &ingest.LeafAdapter{
		LeafFn:     l.Leaf,
		BundleSize: 16,
	}
	return adapter.FetchTiles(ctx, startLeafIdx, count)
}

func (l *testMTCInputLog) InclusionProof(_ context.Context, _, _ uint64) ([][sha256.Size]byte, error) {
	return nil, nil
}

func TestMTCIndex_Integration(t *testing.T) {
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

	leaf0, err := marshalMTCEntry([]string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatalf("failed to create leaf0: %v", err)
	}
	leaf1, err := marshalMTCEntry([]string{"deep.maps.google.co.uk"})
	if err != nil {
		t.Fatalf("failed to create leaf1: %v", err)
	}
	leaf2, err := marshalMTCEntry([]string{"MAPS.GOOGLE.COM"})
	if err != nil {
		t.Fatalf("failed to create leaf2: %v", err)
	}

	mockInputLog := &testMTCInputLog{
		origin: "bootstrap-mtca.cloudflareresearch.com/logs/shard3",
		leaves: [][]byte{
			leaf0, // idx 0 -> example.com
			leaf1, // idx 1 -> deep.maps.google.co.uk, maps.google.co.uk, google.co.uk
			leaf2, // idx 2 -> maps.google.com, google.com
		},
	}

	outLog, err := newLocalOutputLog("MTCIndex", tempDir+"/outputlog", nil)
	if err != nil {
		t.Fatalf("newLocalOutputLog failed: %v", err)
	}

	const chunkSize = 16
	leafMapper := &mtcLeafMapper{}
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
		OutputLogOrigin: "MTCIndex",
		InputLogOrigin:  "bootstrap-mtca.cloudflareresearch.com/logs/shard3",
	}, ts.Client())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}

	// 1. Lookup "com.example."
	respExample, err := cli.LookupAllKey(ctx, "com.example.", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(com.example.) failed: %v", err)
	}
	if !respExample.Exists {
		t.Fatal("com.example. should exist in index")
	}
	if len(respExample.Indices) != 1 || respExample.Indices[0] != 0 {
		t.Fatalf("com.example. indices = %v, want [0]", respExample.Indices)
	}

	// 2. Lookup "com.example.*." (wildcard preserved separately from apex)
	respWildcard, err := cli.LookupAllKey(ctx, "com.example.*.", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(com.example.*.) failed: %v", err)
	}
	if !respWildcard.Exists {
		t.Fatal("com.example.*. should exist in index")
	}
	if len(respWildcard.Indices) != 1 || respWildcard.Indices[0] != 0 {
		t.Fatalf("com.example.*. indices = %v, want [0]", respWildcard.Indices)
	}

	// 3. Lookup "uk.co.google.maps.deep."
	respDeepUK, err := cli.LookupAllKey(ctx, "uk.co.google.maps.deep.", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(uk.co.google.maps.deep.) failed: %v", err)
	}
	if !respDeepUK.Exists {
		t.Fatal("uk.co.google.maps.deep. should exist in index")
	}
	if len(respDeepUK.Indices) != 1 || respDeepUK.Indices[0] != 1 {
		t.Fatalf("uk.co.google.maps.deep. indices = %v, want [1]", respDeepUK.Indices)
	}

	// 4. Lookup "com.google.maps." (from MAPS.GOOGLE.COM)
	respGoogleMaps, err := cli.LookupAllKey(ctx, "com.google.maps.", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(com.google.maps.) failed: %v", err)
	}
	if !respGoogleMaps.Exists {
		t.Fatal("com.google.maps. should exist in index")
	}
	if len(respGoogleMaps.Indices) != 1 || respGoogleMaps.Indices[0] != 2 {
		t.Fatalf("com.google.maps. indices = %v, want [2]", respGoogleMaps.Indices)
	}

	// 5. Lookup unknown key (verified non-inclusion)
	respUnknown, err := cli.LookupAllKey(ctx, "org.example.nonexistent.", 10)
	if err != nil {
		t.Fatalf("cli.LookupAllKey(org.example.nonexistent.) failed: %v", err)
	}
	if respUnknown.Exists {
		t.Fatal("org.example.nonexistent. should not exist")
	}
}
