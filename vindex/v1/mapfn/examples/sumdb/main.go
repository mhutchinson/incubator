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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o sumdb.wasm ."

// Package main implements the SumDB WASM MapFn plugin.
package main

import (
	"bytes"
	"crypto/sha256"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
	"golang.org/x/mod/module"
)

func main() {}

func init() {
	sdk.RegisterRaw(MapSumDBLeaf)
}

// MapSumDBLeaf parses a Go SumDB log leaf, filtering pseudo-versions and returning canonical module path hashes.
func MapSumDBLeaf(data []byte) [][sha256.Size]byte {
	var results [8][sha256.Size]byte
	n := 0

	for len(data) > 0 {
		var line []byte
		idx := bytes.IndexByte(data, '\n')
		if idx >= 0 {
			line = data[:idx]
			data = data[idx+1:]
		} else {
			line = data
			data = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		modEnd := bytes.IndexByte(line, ' ')
		if modEnd == -1 {
			continue
		}
		modPath := line[:modEnd]

		verStart := modEnd + 1
		if verStart >= len(line) {
			continue
		}
		verLen := bytes.IndexByte(line[verStart:], ' ')
		var verBytes []byte
		if verLen == -1 {
			verBytes = line[verStart:]
		} else {
			verBytes = line[verStart : verStart+verLen]
		}
		verBytes = bytes.TrimSuffix(verBytes, []byte("/go.mod"))

		// Filter out ephemeral pseudo-versions
		if bytes.IndexByte(verBytes, '-') != -1 {
			if module.IsPseudoVersion(string(verBytes)) {
				continue
			}
		}

		h := sha256.Sum256(modPath)
		duplicate := false
		for i := 0; i < n; i++ {
			if results[i] == h {
				duplicate = true
				break
			}
		}
		if !duplicate && n < len(results) {
			results[n] = h
			n++
		}
	}

	return results[:n]
}
