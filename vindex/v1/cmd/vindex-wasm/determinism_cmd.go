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
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
)

func runDeterminismCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify-determinism", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")
	inputStr := fs.String("input", "vindex_determinism_test_leaf_payload", "Input leaf payload string.")
	inputFile := fs.String("input_file", "", "Path to file containing input leaf payload.")
	bundleSize := fs.Int("bundle_size", 256, "Number of leaves per bundle (defaults to 256).")
	iterations := fs.Int("iterations", 100, "Number of map executions.")
	concurrency := fs.Int("concurrency", 4, "Number of concurrent worker threads.")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *wasmPath == "" {
		return errors.New("--wasm flag is required")
	}
	if *iterations <= 0 {
		return errors.New("--iterations must be greater than 0")
	}
	if *bundleSize <= 0 {
		*bundleSize = 256
	}
	if *concurrency <= 0 {
		*concurrency = 1
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	var inputBytes []byte
	if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file %q: %w", *inputFile, err)
		}
		inputBytes = b
	} else {
		inputBytes = []byte(*inputStr)
	}

	bundle := make([][]byte, *bundleSize)
	for i := range bundle {
		bundle[i] = inputBytes
	}

	host, err := ingest.NewWASMHost(ctx, wasmBytes, *concurrency)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// Baseline run
	baseline, err := host.MapBundle(ctx, bundle)
	if err != nil {
		return fmt.Errorf("baseline MapBundle failed: %w", err)
	}
	if len(baseline) != *bundleSize {
		return fmt.Errorf("baseline MapBundle returned %d leaves, want %d", len(baseline), *bundleSize)
	}

	var wg sync.WaitGroup
	var mismatchCount int64
	var errCount int64
	var firstMismatchErr error
	var mismatchMu sync.Mutex

	taskChan := make(chan int, *iterations)
	for i := 0; i < *iterations; i++ {
		taskChan <- i
	}
	close(taskChan)

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner, err := host.NewRunner(ctx)
			if err != nil {
				atomic.AddInt64(&errCount, 1)
				mismatchMu.Lock()
				if firstMismatchErr == nil {
					firstMismatchErr = fmt.Errorf("failed to create runner: %w", err)
				}
				mismatchMu.Unlock()
				return
			}
			defer func() { _ = runner.Close(context.Background()) }()

			for range taskChan {
				res, err := runner.MapBundle(ctx, bundle)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					mismatchMu.Lock()
					if firstMismatchErr == nil {
						firstMismatchErr = fmt.Errorf("execution failed: %w", err)
					}
					mismatchMu.Unlock()
					return
				}
				if len(res) != len(baseline) {
					atomic.AddInt64(&mismatchCount, 1)
					mismatchMu.Lock()
					if firstMismatchErr == nil {
						firstMismatchErr = fmt.Errorf("determinism bundle len mismatch: baseline %d != result %d", len(baseline), len(res))
					}
					mismatchMu.Unlock()
					return
				}
				for i := range baseline {
					if !equalEntries(baseline[i], res[i]) {
						atomic.AddInt64(&mismatchCount, 1)
						mismatchMu.Lock()
						if firstMismatchErr == nil {
							firstMismatchErr = fmt.Errorf("determinism mismatch at leaf %d: baseline len %d != result len %d", i, len(baseline[i]), len(res[i]))
						}
						mismatchMu.Unlock()
						return
					}
				}
			}
		}()
	}

	wg.Wait()

	if errCount > 0 || mismatchCount > 0 {
		return fmt.Errorf("FAIL: Determinism check failed with %d errors and %d mismatches: %v", errCount, mismatchCount, firstMismatchErr)
	}

	fmt.Printf("PASS: Verified determinism across %d bundle executions (%d leaves/bundle, concurrency=%d, %d mapped entries/leaf) with bit-for-bit identical outputs.\n",
		*iterations, *bundleSize, *concurrency, len(baseline[0]))
	return nil
}

func equalEntries(a, b []ingest.MappedEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].KeyHash != b[i].KeyHash {
			return false
		}
		if !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}
