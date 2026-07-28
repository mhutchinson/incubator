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

package vindex_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

func runBenchmarkWithParallelLookups(b *testing.B, opts vindex.Options) {
	ctx := context.Background()
	s, v, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		b.Fatal(err)
	}

	inputLog := &inMemoryTreeSource{
		t:      testonly.New(rfc6962.DefaultHasher),
		leaves: make([][]byte, 0),
		s:      s,
		v:      v,
	}

	rng := rand.New(rand.NewSource(12345))

	var uniqueKeys []string
	for i := range benchNumEntries {
		var key string
		if len(uniqueKeys) > 0 && rng.Float64() < benchDuplicationRatio {
			key = uniqueKeys[rng.Intn(len(uniqueKeys))]
		} else {
			key = fmt.Sprintf("key-%d", len(uniqueKeys))
			uniqueKeys = append(uniqueKeys, key)
		}
		inputLog.Append(fmt.Sprintf("%s: %d", key, i))
	}

	mapFn := func(leaf []byte) [][sha256.Size]byte {
		k, _, found := bytes.Cut(leaf, []byte(":"))
		if !found {
			panic("colon not found")
		}
		return [][sha256.Size]byte{sha256.Sum256(k)}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		dir, err := os.MkdirTemp("", "vindex-bench-lookup")
		if err != nil {
			b.Fatal(err)
		}

		iterCtx, iterCancel := context.WithCancel(ctx)

		outputLog, closer, err := vindex.NewOutputLog(iterCtx, path.Join(dir, "outputlog"), s, v, vindex.OutputLogOpts{})
		b.Cleanup(func() {
			iterCancel()
			_ = os.RemoveAll(dir)
			if closer != nil {
				closer(context.Background())
			}
		})
		if err != nil {
			b.Fatal(err)
		}

		vi, err := vindex.NewVerifiableIndex(iterCtx, inputLog, mapFn, outputLog, dir, opts)
		if err != nil {
			b.Fatal(err)
		}

		lookupCtx, lookupCancel := context.WithCancel(iterCtx)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			localRng := rand.New(rand.NewSource(54321))
			for {
				select {
				case <-lookupCtx.Done():
					return
				default:
				}
				if len(uniqueKeys) == 0 {
					continue
				}
				keyStr := uniqueKeys[localRng.Intn(len(uniqueKeys))]
				kh := sha256.Sum256([]byte(keyStr))
				_, _ = vi.Lookup(lookupCtx, kh)
				time.Sleep(10 * time.Microsecond)
			}
		}()

		b.StartTimer()
		if err := vi.Update(iterCtx); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()

		lookupCancel()
		wg.Wait()

		if err := vi.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func BenchmarkBuildWithLookups_InMemory(b *testing.B) {
	runBenchmarkWithParallelLookups(b, vindex.Options{PersistIndex: false})
}

func BenchmarkBuildWithLookups_OnDisk(b *testing.B) {
	runBenchmarkWithParallelLookups(b, vindex.Options{PersistIndex: true})
}
