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

// Package sdk provides the guest SDK for authoring VIndex WASM MapFn plugins.
package sdk

var (
	registeredMapFunc    MapFunc
	registeredRawMapFunc RawMapFunc
)

// Register registers a structured MapFunc plugin.
func Register(fn MapFunc) {
	registeredMapFunc = fn
}

// RegisterRaw registers a raw RawMapFunc plugin.
func RegisterRaw(fn RawMapFunc) {
	registeredRawMapFunc = fn
}

// ExecuteMap invokes the registered MapFunc or RawMapFunc with the input slice.
func ExecuteMap(leaf []byte) (ptr uint32, length uint32) {
	if registeredMapFunc != nil {
		entries := registeredMapFunc(leaf)
		return EncodeStructured(entries)
	}
	if registeredRawMapFunc != nil {
		hashes := registeredRawMapFunc(leaf)
		return EncodeRaw(hashes)
	}
	return 0, 0
}

//go:wasmexport allocate
func allocate(size uint32) uint32 {
	return Allocate(size)
}

//go:wasmexport map_leaf
func mapLeaf(inPtr, inLen uint32) uint64 {
	var in []byte
	if inLen > 0 {
		in = GetInputSlice(inPtr, inLen)
	}

	outPtr, outLen := ExecuteMap(in)
	return (uint64(outPtr) << 32) | uint64(outLen)
}

//go:wasmexport reset
func reset() {
	Reset()
}
