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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o starter.wasm ."

// Package main demonstrates a minimal starter template for authoring a VIndex WASM MapFn.
package main

import (
	"bytes"
	"crypto/sha256"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
)

func main() {}

func init() {
	// Register the leaf mapping function.
	// Use sdk.RegisterRaw for raw 32-byte key hashes, or sdk.Register for key+value entries.
	sdk.RegisterRaw(MapLeaf)
}

// MapLeaf inspects a single log leaf and extracts one or more 32-byte search keys.
func MapLeaf(leaf []byte) [][sha256.Size]byte {
	leaf = bytes.TrimSpace(leaf)
	if len(leaf) == 0 {
		return nil
	}

	// Example: hash the leaf payload directly as the search key.
	// Replace this logic with your custom leaf parsing / key extraction.
	keyHash := sha256.Sum256(leaf)
	return [][sha256.Size]byte{keyHash}
}
