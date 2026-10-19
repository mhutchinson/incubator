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

package hammer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/klog/v2"
)

// ServerConfig configures the drip-feed HTTP server.
type ServerConfig struct {
	ListenAddr    string
	StorageDir    string
	DripRate      float64       // Checkpoints per second released to clients (0 = immediate)
	BurstInterval time.Duration // Interval between burst checkpoint releases (0 = steady drip)
	InitialPause  time.Duration // Initial pause duration before drip-feeding begins
}

// DefaultServerConfig returns default server settings.
func DefaultServerConfig(storageDir string) ServerConfig {
	return ServerConfig{
		ListenAddr: ":8085",
		StorageDir: storageDir,
		DripRate:   2.0,
	}
}

// DripServer hosts local POSIX log tiles and publishes checkpoints to vindexd on a configurable schedule.
type DripServer struct {
	cfg         ServerConfig
	readCP      func(context.Context) ([]byte, error)
	publishedCP atomic.Pointer[[]byte]

	mu         sync.RWMutex
	httpServer *http.Server
	listener   net.Listener
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewDripServer creates a new DripServer backed by readCP (typically sequencer.ReadCheckpoint).
func NewDripServer(cfg ServerConfig, readCP func(context.Context) ([]byte, error)) *DripServer {
	return &DripServer{
		cfg:    cfg,
		readCP: readCP,
	}
}

// RegisterRoutes sets up HTTP handlers on the given ServeMux.
func (s *DripServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/checkpoint", s.HandleCheckpoint)
	mux.HandleFunc("/checkpoint_direct", s.HandleDirectCheckpoint)
	mux.Handle("/", http.FileServer(http.Dir(s.cfg.StorageDir)))
}

// HandleCheckpoint serves the currently published drip-fed checkpoint.
func (s *DripServer) HandleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cpPtr := s.publishedCP.Load()
	if cpPtr == nil || len(*cpPtr) == 0 {
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(*cpPtr)
}

// HandleDirectCheckpoint serves the latest checkpoint directly from readCP without waiting for the drip schedule.
func (s *DripServer) HandleDirectCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cp []byte
	if s.readCP != nil {
		cp, _ = s.readCP(r.Context())
	}
	if len(cp) == 0 {
		if cpPtr := s.publishedCP.Load(); cpPtr != nil {
			cp = *cpPtr
		}
	}
	if len(cp) == 0 {
		http.Error(w, "no checkpoint available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cp)
}

// SetPublishedCheckpoint manually sets the active drip-fed checkpoint.
func (s *DripServer) SetPublishedCheckpoint(rawCP []byte) {
	cloned := slices.Clone(rawCP)
	s.publishedCP.Store(&cloned)
}

// GetPublishedCheckpoint returns the currently published checkpoint bytes.
func (s *DripServer) GetPublishedCheckpoint() []byte {
	cpPtr := s.publishedCP.Load()
	if cpPtr == nil {
		return nil
	}
	return slices.Clone(*cpPtr)
}

// URL returns the base URL of the running server.
func (s *DripServer) URL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return fmt.Sprintf("http://%s", s.cfg.ListenAddr)
	}
	return fmt.Sprintf("http://%s", s.listener.Addr().String())
}

// Start binds to the listening port and starts background drip scheduling.
func (s *DripServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)

	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}

	schedCtx, cancel := context.WithCancel(ctx)
	srv := &http.Server{Handler: mux}

	s.mu.Lock()
	s.listener = listener
	s.httpServer = srv
	s.cancel = cancel
	s.mu.Unlock()

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("DripServer HTTP error: %v", err)
		}
	}()
	go func() {
		defer s.wg.Done()
		s.runDripScheduler(schedCtx)
	}()

	klog.Infof("DripServer listening on %s (storage: %s)", listener.Addr().String(), s.cfg.StorageDir)
	return nil
}

func (s *DripServer) runDripScheduler(ctx context.Context) {
	if s.cfg.InitialPause > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.InitialPause):
		}
	}

	s.refreshCheckpoint(ctx)

	var interval time.Duration
	switch {
	case s.cfg.BurstInterval > 0:
		interval = s.cfg.BurstInterval
	case s.cfg.DripRate > 0:
		interval = max(time.Duration(float64(time.Second)/s.cfg.DripRate), time.Millisecond)
	default:
		interval = 10 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshCheckpoint(ctx)
		}
	}
}

func (s *DripServer) refreshCheckpoint(ctx context.Context) {
	if s.readCP == nil {
		return
	}
	cp, err := s.readCP(ctx)
	if err != nil || len(cp) == 0 {
		return
	}
	if cur := s.publishedCP.Load(); cur != nil && bytes.Equal(*cur, cp) {
		return
	}
	cloned := slices.Clone(cp)
	s.publishedCP.Store(&cloned)
}

// Close gracefully stops the scheduler and HTTP server.
func (s *DripServer) Close(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	srv := s.httpServer
	s.cancel = nil
	s.httpServer = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
	}
	s.wg.Wait()
	return err
}
