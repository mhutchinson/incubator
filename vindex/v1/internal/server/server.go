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
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/metrics"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

//go:embed index.html
var defaultIndexHTML []byte

const (
	defaultLookupLimit   uint64 = 100
	maxLookupLimit       uint64 = 1000
	DefaultMaxPrefixKeys int    = 10000
)

// HealthChecker determines whether the server or underlying subsystems are healthy.
// It returns nil if healthy, or an error detailing the health failure.
type HealthChecker func() error

// CleanPathPrefix cleans and normalizes a URL path prefix.
// It ensures a leading slash and strips any trailing slashes.
// An empty or "/" prefix is returned as "".
func CleanPathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}
	return "/" + prefix
}

// ReadServer serves HTTP lookup and checkpoint queries.
type ReadServer struct {
	backendMu     sync.RWMutex
	store         kvstore.IndexStore
	mptMgr        *tree.Manager
	publisher     *tree.OutputPublisher
	chunkSize     uint64
	enableUI      bool
	pathPrefix    string
	prefixPolicy  PrefixPolicy
	maxPrefixKeys int
	healthMu      sync.RWMutex
	healthChecker HealthChecker
	readyChecker  HealthChecker
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
		store:         store,
		mptMgr:        mptMgr,
		publisher:     pub,
		chunkSize:     chunkSize,
		enableUI:      true,
		prefixPolicy:  AllowAllPrefixPolicy,
		maxPrefixKeys: DefaultMaxPrefixKeys,
	}
}

// SetPrefixPolicy configures the policy function invoked before executing ?prefix=true queries on /keys/.
func (s *ReadServer) SetPrefixPolicy(policy PrefixPolicy) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	s.prefixPolicy = policy
}

// SetMaxPrefixKeys configures the maximum number of keys a ?prefix=true query on /keys/ may return before failing with HTTP 413.
func (s *ReadServer) SetMaxPrefixKeys(maxKeys int) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	if maxKeys <= 0 {
		maxKeys = DefaultMaxPrefixKeys
	}
	s.maxPrefixKeys = maxKeys
}

// SetBackend attaches or updates the MPT Manager and OutputPublisher after asynchronous initialization.
func (s *ReadServer) SetBackend(mptMgr *tree.Manager, pub *tree.OutputPublisher) {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	s.mptMgr = mptMgr
	s.publisher = pub
}

func (s *ReadServer) getBackend() (*tree.Manager, *tree.OutputPublisher) {
	s.backendMu.RLock()
	defer s.backendMu.RUnlock()
	return s.mptMgr, s.publisher
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

// SetPathPrefix configures the URL path prefix under which endpoints are served.
func (s *ReadServer) SetPathPrefix(prefix string) {
	s.pathPrefix = CleanPathPrefix(prefix)
}

// PathPrefix returns the normalized path prefix.
func (s *ReadServer) PathPrefix() string {
	return s.pathPrefix
}

// Publisher returns the underlying OutputPublisher.
func (s *ReadServer) Publisher() *tree.OutputPublisher {
	_, pub := s.getBackend()
	return pub
}

// SetHealthChecker registers a dynamic health check callback for /healthz. If hc is nil,
// the server defaults to returning healthy (HTTP 200 "ok\n").
func (s *ReadServer) SetHealthChecker(hc HealthChecker) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.healthChecker = hc
}

// SetReadyChecker registers a dynamic readiness check callback for /readyz and /syncz.
func (s *ReadServer) SetReadyChecker(rc HealthChecker) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.readyChecker = rc
}

// RegisterRoutes registers HTTP endpoints on the provided ServeMux.
// If s.PathPrefix() is non-empty, routes are mounted under the prefix.
// In addition, /healthz and /readyz are also registered at the root level for orchestrators.
func (s *ReadServer) RegisterRoutes(mux *http.ServeMux) {
	s.RegisterRoutesWithOutputLog(mux, "")
}

// RegisterRoutesWithOutputLog registers HTTP endpoints and optionally mounts output log tile and file servers.
// If outputLogDir is non-empty, /tile/ and /outputlog/ are served from that directory.
// If s.PathPrefix() is non-empty, all routes (including tile servers) are mounted under the prefix.
func (s *ReadServer) RegisterRoutesWithOutputLog(mux *http.ServeMux, outputLogDir string) {
	prefix := s.pathPrefix
	if prefix == "" {
		s.registerEndpoints(mux, outputLogDir)
		return
	}

	// Internal sub-mux with clean un-prefixed routes
	subMux := http.NewServeMux()
	s.registerEndpoints(subMux, outputLogDir)

	// Mount under prefix (strip prefix so handlers match root paths)
	mux.Handle(prefix+"/", http.StripPrefix(prefix, subMux))

	// Redirect /prefix -> /prefix/
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
	})

	// Also expose health/readiness probes at the root level for container orchestrators
	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/readyz", s.HandleReadyz)
	mux.HandleFunc("/syncz", s.HandleReadyz)
}

func (s *ReadServer) registerEndpoints(mux *http.ServeMux, outputLogDir string) {
	if s.enableUI {
		mux.HandleFunc("/", s.HandleUI)
		mux.HandleFunc("/index.html", s.HandleUI)
	}

	mux.HandleFunc("/vindex/v1/checkpoint", s.HandleCheckpoint)
	mux.HandleFunc("/checkpoint", s.HandleCheckpoint)

	mux.HandleFunc("/vindex/v1/inputlog_checkpoint", s.HandleInputLogCheckpoint)
	mux.HandleFunc("/inputlog_checkpoint", s.HandleInputLogCheckpoint)

	mux.HandleFunc("/vindex/v1/keys/", s.HandleKeys)
	mux.HandleFunc("/vindex/keys/", s.HandleKeys)
	mux.HandleFunc("/keys/", s.HandleKeys)

	mux.HandleFunc("/vindex/v1/entries/", s.HandleEntries)
	mux.HandleFunc("/vindex/entries/", s.HandleEntries)
	mux.HandleFunc("/entries/", s.HandleEntries)

	mux.HandleFunc("/vindex/v1/lookup/", s.HandleLookup)
	mux.HandleFunc("/vindex/lookup/", s.HandleLookup)
	mux.HandleFunc("/lookup/", s.HandleLookup)

	if outputLogDir != "" {
		mux.Handle("/tile/", http.FileServer(http.Dir(outputLogDir)))
		mux.Handle("/outputlog/", http.StripPrefix("/outputlog/", http.FileServer(http.Dir(outputLogDir))))
	}

	mux.HandleFunc("/healthz", s.HandleHealthz)
	mux.HandleFunc("/readyz", s.HandleReadyz)
	mux.HandleFunc("/syncz", s.HandleReadyz)
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
	_, pub := s.getBackend()
	if pub == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	state := pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		w.Header().Set("Retry-After", "30")
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
	_, pub := s.getBackend()
	if pub == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "input log checkpoint not ready", http.StatusServiceUnavailable)
		return
	}
	state := pub.GetServingState()
	if state == nil || len(state.RawInputLogCP) == 0 {
		w.Header().Set("Retry-After", "30")
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

	s.healthMu.RLock()
	hc := s.healthChecker
	s.healthMu.RUnlock()

	if hc != nil {
		if err := hc(); err != nil {
			http.Error(w, fmt.Sprintf("unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// HandleReadyz handles GET /readyz and /syncz (readiness and sync probe).
func (s *ReadServer) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.healthMu.RLock()
	rc := s.readyChecker
	if rc == nil {
		rc = s.healthChecker
	}
	s.healthMu.RUnlock()
	if rc != nil {
		if err := rc(); err != nil {
			w.Header().Set("Retry-After", "30")
			type jsonDiagnosticsProvider interface {
				JSONDiagnostics() []byte
			}
			if diag, ok := err.(jsonDiagnosticsProvider); ok {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write(diag.JSONDiagnostics())
				return
			}
			http.Error(w, fmt.Sprintf("unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	mptMgr, pub := s.getBackend()
	if mptMgr == nil || pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	state := pub.GetServingState()
	if state == nil || len(state.RawCheckpoint) == 0 {
		w.Header().Set("Retry-After", "30")
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
	mptMgr, pub := s.getBackend()
	if mptMgr == nil || pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	if pub.GetServingState() == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}
	mptMgr.RLock()
	state := pub.GetServingState()
	if state == nil {
		mptMgr.RUnlock()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}
	proof, _, exists, err := mptMgr.ProveLocked(keyHash)
	mptMgr.RUnlock()

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

var (
	keysRoutePrefixes    = []string{"/vindex/v1/keys/", "/vindex/keys/", "/keys/"}
	entriesRoutePrefixes = []string{"/vindex/v1/entries/", "/vindex/entries/", "/entries/"}
)

// HandleKeys handles GET /vindex/v1/keys/{key...}[?prefix=true] queries.
// Point mode (prefix=false or omitted) proves exact inclusion or non-inclusion in the MPT.
// Prefix mode (prefix=true) validates the prefix against the configured PrefixPolicy, proves
// the prefix path, and scans up to maxPrefixKeys matching (key, subRoot) pairs from the MPT.
func (s *ReadServer) HandleKeys(w http.ResponseWriter, r *http.Request) {
	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyStr, err := parseCanonicalKey(r, keysRoutePrefixes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}

	isPrefix := false
	if prefixParam := r.URL.Query().Get("prefix"); prefixParam != "" {
		parsedPrefix, err := strconv.ParseBool(prefixParam)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid prefix parameter %q: %v", prefixParam, err), http.StatusBadRequest)
			return
		}
		isPrefix = parsedPrefix
	}

	s.backendMu.RLock()
	mptMgr := s.mptMgr
	pub := s.publisher
	policy := s.prefixPolicy
	maxKeys := s.maxPrefixKeys
	s.backendMu.RUnlock()

	if isPrefix && policy != nil {
		if err := policy(keyStr); err != nil {
			http.Error(w, fmt.Sprintf("prefix rejected by policy: %v", err), http.StatusBadRequest)
			return
		}
	}

	if mptMgr == nil || pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	if pub.GetServingState() == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}

	if !isPrefix {
		mptMgr.RLock()
		state := pub.GetServingState()
		if state == nil {
			mptMgr.RUnlock()
			w.Header().Set("Retry-After", "30")
			http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
			return
		}
		proof, val, exists, err := mptMgr.ProveKeyLocked([]byte(keyStr))
		mptMgr.RUnlock()

		if err != nil {
			http.Error(w, fmt.Sprintf("failed to generate MPT key proof: %v", err), http.StatusInternalServerError)
			return
		}

		var respBytes []byte
		if !exists {
			respBytes = FormatKeysResponse(state, "non-inclusion", proof, nil)
		} else {
			respBytes = FormatKeysResponse(state, "inclusion", proof, []tree.PrefixKeyVal{{Key: keyStr, SubRoot: val}})
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
		return
	}

	if maxKeys <= 0 {
		maxKeys = DefaultMaxPrefixKeys
	}

	mptMgr.RLock()
	state := pub.GetServingState()
	if state == nil {
		mptMgr.RUnlock()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}
	proof, matches, err := mptMgr.ProvePrefixLocked([]byte(keyStr), maxKeys)
	mptMgr.RUnlock()

	if errors.Is(err, tree.ErrPrefixTooManyKeys) {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate MPT prefix proof: %v", err), http.StatusInternalServerError)
		return
	}

	respBytes := FormatKeysResponse(state, "prefix", proof, matches)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// HandleEntries handles GET /vindex/v1/entries/{key...}?before=X[&limit=Y] queries.
// It hashes {key...} with SHA-256 and queries Pebble directly without acquiring any MPT read lock.
func (s *ReadServer) HandleEntries(w http.ResponseWriter, r *http.Request) {
	startLookup := time.Now()
	defer func() {
		metrics.LookupLatencySeconds.Observe(time.Since(startLookup).Seconds())
	}()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyStr, err := parseCanonicalKey(r, entriesRoutePrefixes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
		return
	}

	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		http.Error(w, "missing required before parameter", http.StatusBadRequest)
		return
	}
	parsedBefore, err := strconv.ParseUint(beforeStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid before parameter %q: must be an unsigned integer", beforeStr), http.StatusBadRequest)
		return
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

	if s.store == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "storage not initialized", http.StatusServiceUnavailable)
		return
	}

	// Lock-free atomic pointer check on OutputPublisher serving state (zero MPT lock acquisitions).
	_, pub := s.getBackend()
	if pub == nil {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"mpt_initializing","genesis_backfill":false}` + "\n"))
		return
	}
	state := pub.GetServingState()
	if state == nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "serving state not initialized", http.StatusServiceUnavailable)
		return
	}

	keyHash := sha256.Sum256([]byte(keyStr))
	lookupRes, err := s.store.Lookup(keyHash, &parsedBefore, limit, state.InputLogSize)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to lookup key in storage: %v", err), http.StatusInternalServerError)
		return
	}
	if (lookupRes == nil || len(lookupRes.MatchedIndices) == 0) && len(keyStr) == 64 {
		if rawBytes, decErr := hex.DecodeString(keyStr); decErr == nil && len(rawBytes) == sha256.Size {
			var rawKeyHash [sha256.Size]byte
			copy(rawKeyHash[:], rawBytes)
			if altRes, altErr := s.store.Lookup(rawKeyHash, &parsedBefore, limit, state.InputLogSize); altErr == nil && altRes != nil && len(altRes.MatchedIndices) > 0 {
				lookupRes = altRes
			}
		}
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

	respBytes := FormatEntriesResponse(matchedIndices, prefixCompactRange, nextBefore)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
