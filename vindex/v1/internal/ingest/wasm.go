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

package ingest

import (
	"context"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/host"
)

var (
	ErrWasmHalt        = host.ErrWasmHalt
	ErrInvalidMemory   = host.ErrInvalidMemory
	ErrUnalignedOutput = host.ErrUnalignedOutput
	ErrMalformedOutput = host.ErrMalformedOutput
	ErrHostClosed      = host.ErrHostClosed
)

// MappedEntry represents a single search key and optional value produced by a LeafMapper.
type MappedEntry = host.MappedEntry

// ValidatePreimageKey validates that a WASM-emitted preimage key satisfies the canonical
// key invariants: 1 <= len <= 1024 and printable ASCII (0x21..0x7E, no NUL or whitespace).
func ValidatePreimageKey(keyBytes []byte) error {
	return host.ValidatePreimageKey(keyBytes)
}

// LeafMapper maps a raw Input Log leaf payload to a set of searchable MappedEntry records.
type LeafMapper = host.LeafMapper

// WASMHost manages the lifecycle and execution of a compiled Wazero WebAssembly module.
type WASMHost = host.WASMHost

// WASMRunner is a dedicated, unshared WASM execution environment bound to a single worker.
type WASMRunner = host.WASMRunner

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	return host.NewWASMHost(ctx, wasmBytes, poolSize)
}
