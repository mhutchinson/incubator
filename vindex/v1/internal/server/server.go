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

// Package server provides HTTP read endpoints for the Verifiable Index wire protocol.
package server

import (
	_ "embed"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

//go:embed index.html
var defaultIndexHTML []byte

const (
	defaultLookupLimit uint64 = 100
	maxLookupLimit     uint64 = 1000
)

// ReadServer serves HTTP lookup and checkpoint queries.
type ReadServer struct {
	store     kvstore.IndexStore
	mptMgr    *tree.Manager
	publisher *tree.OutputPublisher
	chunkSize uint64
	enableUI  bool
}

// NewReadServer creates a new ReadServer instance.
func NewReadServer(store kvstore.IndexStore, mptMgr *tree.Manager, pub *tree.OutputPublisher, chunkSize uint64) *ReadServer {
	if chunkSize == 0 {
		chunkSize = kvstore.ChunkSize
	}
	if store != nil {
		store.SetChunkSize(chunkSize)
	}
	return &ReadServer{
		store:     store,
		mptMgr:    mptMgr,
		publisher: pub,
		chunkSize: chunkSize,
		enableUI:  true,
	}
}

// ChunkSize returns the configured chunk capacity.
func (s *ReadServer) ChunkSize() uint64 {
	if s.chunkSize == 0 {
		return kvstore.ChunkSize
	}
	return s.chunkSize
}

// SetEnableUI configures whether the single-page HTML UI is served.
func (s *ReadServer) SetEnableUI(enable bool) {
	s.enableUI = enable
}

// RegisterRoutes registers HTTP endpoints on the provided ServeMux.
func (s *ReadServer) RegisterRoutes(mux *http.ServeMux) {
	if s.enableUI {
		mux.HandleFunc("/", s.HandleUI)
		mux.HandleFunc("/index.html", s.HandleUI)
	}

	mux.HandleFunc("/vindex/v1/checkpoint", s.HandleCheckpoint)
	mux.HandleFunc("/checkpoint", s.HandleCheckpoint)

	mux.HandleFunc("/vindex/v1/inputlog_checkpoint", s.HandleInputLogCheckpoint)
	mux.HandleFunc("/inputlog_checkpoint", s.HandleInputLogCheckpoint)

	mux.HandleFunc("/vindex/v1/lookup/", s.HandleLookup)
	mux.HandleFunc("/vindex/lookup/", s.HandleLookup)
	mux.HandleFunc("/lookup/", s.HandleLookup)

	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/readyz", s.HandleReadyz)
	mux.Handle("/metrics", promhttp.Handler())
}

// HandleUI handles GET / and /index.html requests serving the single-page HTML UI.
func (s *ReadServer) HandleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(defaultIndexHTML)
	}
}

// HandleCheckpoint handles GET /vindex/v1/checkpoint.
func (s *ReadServer) HandleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := s.publisher.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(state.RawCheckpoint)
}

// HandleInputLogCheckpoint handles GET /vindex/v1/inputlog_checkpoint.
func (s *ReadServer) HandleInputLogCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := s.publisher.GetServingState()
	if state == nil || len(state.RawInputLogCP) == 0 {
		http.Error(w, "input log checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(state.RawInputLogCP)
}

// HandleHealthz handles GET /healthz (liveness probe).
func (s *ReadServer) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleReadyz handles GET /readyz (readiness probe).
func (s *ReadServer) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := s.publisher.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		http.Error(w, "serving state not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleLookup handles GET /vindex/v1/lookup queries.
func (s *ReadServer) HandleLookup(w http.ResponseWriter, r *http.Request) {
	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyHash, err := parseKeyHash(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}

	var before *uint64
	if beforeStr := r.URL.Query().Get("before"); beforeStr != "" {
		parsedBefore, err := strconv.ParseUint(beforeStr, 10, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid before parameter %q: %v", beforeStr, err), http.StatusBadRequest)
			return
		}
		before = &parsedBefore
	}

	limit := defaultLookupLimit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsedLimit, err := strconv.ParseUint(limitStr, 10, 64)
		if err != nil || parsedLimit == 0 {
			http.Error(w, fmt.Sprintf("invalid limit parameter %q: must be a positive integer", limitStr), http.StatusBadRequest)
			return
		}
		limit = parsedLimit
	}
	if limit > maxLookupLimit {
		limit = maxLookupLimit
	}

	// 1. Snapshot Serving State & MPT proof under unified lock
	s.mptMgr.RLock()
	state := s.publisher.GetServingState()
	if state == nil {
		s.mptMgr.RUnlock()
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}
	proof, _, exists, err := s.mptMgr.ProveLocked(keyHash)
	s.mptMgr.RUnlock()

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate MPT proof: %v", err), http.StatusInternalServerError)
		return
	}

	if !exists {
		respBytes := FormatResponse(state, proof, false, nil, nil, nil)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
		return
	}

	// Inclusion response: query storage
	lookupRes, err := s.store.Lookup(keyHash, before, limit, state.InputLogSize)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to lookup key in storage: %v", err), http.StatusInternalServerError)
		return
	}

	var matchedIndices []uint64
	var nextBefore *uint64
	var prefixCompactRange *kvstore.CompactRange
	if lookupRes != nil {
		matchedIndices = lookupRes.MatchedIndices
		nextBefore = lookupRes.NextBefore
		if lookupRes.PrefixCoveredSz > 0 || len(lookupRes.PrefixHashes) > 0 {
			prefixCompactRange = &kvstore.CompactRange{
				CoveredSize: lookupRes.PrefixCoveredSz,
				Hashes:      slices.Clone(lookupRes.PrefixHashes),
			}
		}
	}

	metrics.LookupResultsReturned.Observe(float64(len(matchedIndices)))

	respBytes := FormatResponse(state, proof, true, matchedIndices, prefixCompactRange, nextBefore)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
