// Copyright 2025 Google LLC. All Rights Reserved.
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

// sumdbindex brings up a verifiable index for the Go SumDB.
// This requires a proxy to be running to bridge to a tlog-tiles API.
// See the README for usage details.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/sumdb"
	"github.com/transparency-dev/incubator/vindex/v1/internal/coordinator"
	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/server"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	outputLogPrivKeyFile = flag.String("output_log_private_key_path", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	outputLogOrigin      = flag.String("output_log_origin", "SumDBIndex", "Origin string for the Output Log.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the index and output log.")
	witnessSigs          = flag.Uint("witnesses", 0, "Number of witness signatures required on the SumDB checkpoint. Setting this will pull checkpoints from the transparency-dev prod distributor.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on.")

	oneShot          = flag.Bool("oneshot", false, "Set to true to build the map once and then exit.")
	inputOverrideUrl = flag.String("input_override_url", "", "Set this to read from a different URL than the local proxy. Supports file paths. Intended for performance testing. Note this log MUST be presented as tlog-tiles format.")
	chunkSize        = flag.Uint64("chunk_size", 65536, "Logical chunk size for inverted index.")
	pollInterval     = flag.Duration("poll_interval", 10*time.Second, "Polling interval for input log updates.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("Run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}

	pebbleDir := filepath.Join(*storageDir, "pebble")
	mptDir := filepath.Join(*storageDir, "mpt")
	outputLogDir := filepath.Join(*storageDir, "outputlog")
	tileCacheDir := filepath.Join(*storageDir, "tilecache")

	for _, d := range []string{pebbleDir, mptDir, outputLogDir, tileCacheDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", d, err)
		}
	}

	// 1. Storage DB
	db, err := kvstore.Open(pebbleDir, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("failed to open Pebble DB at %q: %w", pebbleDir, err)
	}
	defer func() { _ = db.Close() }()

	// 2. MPT Manager
	mptMgr, err := tree.Open(mptDir)
	if err != nil {
		return fmt.Errorf("failed to open MPT at %q: %w", mptDir, err)
	}
	defer func() { _ = mptMgr.Close() }()

	// 3. Leaf Mapper
	leafMapper := &SumDBLeafMapper{}

	// 4. Output Log
	signer := getOutputLogSigner()
	outputLog, err := newLocalOutputLog(*outputLogOrigin, outputLogDir, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize output log: %w", err)
	}

	pub := tree.NewOutputPublisher(db, mptMgr, outputLog, nil)
	idxer := kvstore.NewKVIndexer(db, *chunkSize)

	// Setup Tile Cache
	tileCache, err := ingest.NewManagedTileCache(tileCacheDir, 0)
	if err != nil {
		return fmt.Errorf("failed to create tile cache: %w", err)
	}

	// 5. Proxy & HTTP Server
	sumProxy := sumdb.NewProxy(sumdb.ProxyOpts{
		PathPrefix:  "/inputlog/",
		WitnessSigs: *witnessSigs,
	})

	readSrv := server.NewReadServer(db, mptMgr, pub, *chunkSize)
	mux := http.NewServeMux()
	readSrv.RegisterRoutes(mux)
	mux.Handle("/inputlog/", sumProxy)

	olfs := http.FileServer(http.Dir(outputLogDir))
	mux.Handle("/outputlog/", http.StripPrefix("/outputlog/", olfs))
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", *listen, err)
	}

	httpServer := &http.Server{
		Handler: mux,
	}
	go func() {
		klog.Infof("Started HTTP server listening on %s", listener.Addr().String())
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("HTTP server error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	// 6. Setup Input Log Fetcher
	sumV, err := note.NewVerifier("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8")
	if err != nil {
		return fmt.Errorf("failed to construct SumDB verifier: %w", err)
	}

	inPath := fmt.Sprintf("http://127.0.0.1:%d/inputlog/", listener.Addr().(*net.TCPAddr).Port)
	if *inputOverrideUrl != "" {
		inPath = *inputOverrideUrl
	}
	sumUrl, err := url.Parse(inPath)
	if err != nil {
		return fmt.Errorf("invalid input log URL %q: %w", inPath, err)
	}

	fetcher, err := ingest.NewTiledFetcher(sumUrl, sumV, "go.sum database tree", http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create input log fetcher: %w", err)
	}

	// 7. Crash Recovery & Coordinator
	coord := coordinator.NewCoordinator(db, mptMgr, outputLog, pub, idxer, fetcher, tileCache, leafMapper)
	klog.Info("Running startup recovery...")
	if err := coord.Recover(ctx); err != nil {
		return fmt.Errorf("startup recovery failed: %w", err)
	}
	klog.Info("Startup recovery completed.")

	// 8. Background Tile Reaper
	tileReaper := ingest.NewTileReaper(db, mptMgr, tileCache)
	go func() {
		_ = tileReaper.Run(ctx, 60*time.Second)
	}()

	// 9. Ingestion & Polling Loop
	if *oneShot {
		if err := coord.SyncOnce(ctx); err != nil {
			return fmt.Errorf("failed to update index: %w", err)
		}
		klog.Info("Oneshot index build complete.")
		return nil
	}

	if err := coord.Run(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("coordinator run failed: %w", err)
	}

	klog.Info("Shutting down sumdbindex gracefully...")
	return nil
}

// SumDBLeafMapper implements ingest.LeafMapper for SumDB module parsing.
type SumDBLeafMapper struct{}

func (m *SumDBLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	keys := mapFn(leaf)
	if len(keys) == 0 {
		return nil, nil
	}
	entries := make([]ingest.MappedEntry, len(keys))
	for i, k := range keys {
		entries[i] = ingest.MappedEntry{KeyHash: k}
	}
	return entries, nil
}

func (m *SumDBLeafMapper) Close(_ context.Context) error {
	return nil
}

func mapFn(data []byte) [][32]byte {
	modEnd := bytes.IndexByte(data, ' ')
	if modEnd == -1 {
		return nil
	}

	verStart := modEnd + 1
	verLen := bytes.IndexByte(data[verStart:], ' ')
	if verLen == -1 {
		return nil
	}
	verBytes := data[verStart : verStart+verLen]

	// Fast path: pseudo-versions always contain a dash.
	if bytes.IndexByte(verBytes, '-') != -1 {
		// Only allocate a string and call IsPseudoVersion if a dash is present.
		if module.IsPseudoVersion(string(verBytes)) {
			// Drop any ephemeral builds
			return nil
		}
	}

	return [][32]byte{sha256.Sum256(data[:modEnd])}
}

type localOutputLog struct {
	mu     sync.Mutex
	origin string
	dir    string
	signer note.Signer
	leaves [][]byte
}

func newLocalOutputLog(origin, dir string, signer note.Signer) (*localOutputLog, error) {
	l := &localOutputLog{
		origin: origin,
		dir:    dir,
		signer: signer,
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create output log directory: %w", err)
		}
		leavesPath := filepath.Join(dir, "leaves.dat")
		if data, err := os.ReadFile(leavesPath); err == nil {
			offset := 0
			for offset < len(data) {
				if offset+4 > len(data) {
					break
				}
				leafLen := binary.BigEndian.Uint32(data[offset : offset+4])
				offset += 4
				if offset+int(leafLen) > len(data) {
					break
				}
				leaf := make([]byte, leafLen)
				copy(leaf, data[offset:offset+int(leafLen)])
				offset += int(leafLen)
				l.leaves = append(l.leaves, leaf)
			}
		}
	}
	return l, nil
}

func (l *localOutputLog) Append(_ context.Context, leafData []byte) (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := uint64(len(l.leaves))
	leafCopy := append([]byte(nil), leafData...)
	l.leaves = append(l.leaves, leafCopy)
	size := uint64(len(l.leaves))

	root := kvstore.BatchRoot(l.leaves)
	var rawCP []byte
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, l.signer)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to sign checkpoint note: %w", err)
		}
		rawCP = signed
	} else {
		rawCP = []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:])))
	}

	if l.dir != "" {
		leavesPath := filepath.Join(l.dir, "leaves.dat")
		f, err := os.OpenFile(leavesPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(leafData)))
			_, _ = f.Write(lenBuf[:])
			_, _ = f.Write(leafData)
			_ = f.Close()
		}
		_ = os.WriteFile(filepath.Join(l.dir, "checkpoint"), rawCP, 0o644)
	}

	return idx, rawCP, nil
}

func (l *localOutputLog) Size(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves)), nil
}

func (l *localOutputLog) GetLeaf(_ context.Context, idx uint64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("leaf index %d out of bounds (size %d)", idx, len(l.leaves))
	}
	return l.leaves[idx], nil
}

func (l *localOutputLog) Checkpoint(ctx context.Context) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := uint64(len(l.leaves))
	root := kvstore.BatchRoot(l.leaves)
	if l.signer != nil {
		text := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))
		return note.Sign(&note.Note{Text: text}, l.signer)
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))), nil
}

func (l *localOutputLog) InclusionProof(_ context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if treeSize > uint64(len(l.leaves)) {
		return nil, fmt.Errorf("treeSize %d > current size %d", treeSize, len(l.leaves))
	}
	if leafIdx >= treeSize {
		return nil, fmt.Errorf("leafIdx %d >= treeSize %d", leafIdx, treeSize)
	}

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

func getOutputLogSigner() note.Signer {
	var privKey string
	var err error
	if len(*outputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*outputLogPrivKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
		}
	} else {
		privKey = os.Getenv("OUTPUT_LOG_PRIVATE_KEY")
	}
	if len(privKey) == 0 {
		return nil
	}
	s, _, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		s2, err2 := note.NewSigner(privKey)
		if err2 != nil {
			klog.Exitf("Failed to construct note signer: %v", err2)
		}
		return s2
	}
	return s
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}
