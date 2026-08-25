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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

var (
	ErrWasmHalt        = errors.New("wasm execution halted due to violation or trap")
	ErrInvalidMemory   = errors.New("wasm returned memory pointer out of bounds")
	ErrUnalignedOutput = errors.New("wasm output length not a multiple of 32 bytes")
	ErrMalformedOutput = errors.New("wasm output format is malformed")
	ErrHostClosed      = errors.New("wasm host is closed")
)

// MappedEntry represents a single search key and optional value produced by a LeafMapper.
type MappedEntry struct {
	KeyHash [sha256.Size]byte
	Value   []byte
}

// LeafMapper maps a raw Input Log leaf payload to a set of searchable MappedEntry records.
type LeafMapper interface {
	MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error)
	Close(ctx context.Context) error
}

// WASMHost manages the lifecycle and execution of a compiled Wazero WebAssembly module.
type WASMHost struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	pool     chan *wasmInstance
	mu       sync.Mutex
	closed   bool
	haltErr  error
	poolSize int
}

type wasmInstance struct {
	mod       api.Module
	mapLeafFn api.Function
	allocFn   api.Function
	resetFn   api.Function
	mem       api.Memory
}

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	if poolSize <= 0 {
		poolSize = 1
	}

	r := wazero.NewRuntime(ctx)
	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	h := &WASMHost{
		runtime:  r,
		compiled: compiled,
		pool:     make(chan *wasmInstance, poolSize),
		poolSize: poolSize,
	}

	for i := 0; i < poolSize; i++ {
		inst, err := h.instantiateInstance(ctx)
		if err != nil {
			_ = h.Close(ctx)
			return nil, fmt.Errorf("failed to instantiate initial wasm module %d: %w", i, err)
		}
		h.pool <- inst
	}

	return h, nil
}

func (h *WASMHost) instantiateInstance(ctx context.Context) (*wasmInstance, error) {
	var id [8]byte
	_, _ = rand.Read(id[:])
	modName := fmt.Sprintf("vindex_mod_%x", id)

	wasiConfig := wazero.NewModuleConfig().
		WithName(modName).
		WithStartFunctions("_initialize").
		WithStdout(io.Discard).
		WithStderr(io.Discard).
		WithStdin(bytes.NewReader(nil)).
		WithArgs().
		WithWalltime(func() (sec int64, nsec int32) { return 1, 0 }, sys.ClockResolution(1)).
		WithNanotime(func() int64 { return 1_000_000 }, sys.ClockResolution(1)).
		WithNanosleep(func(int64) {}).
		WithRandSource(bytes.NewReader(make([]byte, 1024)))

	mod, err := h.runtime.InstantiateModule(ctx, h.compiled, wasiConfig)
	if err != nil {
		return nil, err
	}

	mapLeafFn := mod.ExportedFunction("map_leaf")
	if mapLeafFn == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: exported function 'map_leaf' not found", ErrWasmHalt)
	}

	mem := mod.Memory()
	if mem == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: module memory not found", ErrWasmHalt)
	}

	allocFn := mod.ExportedFunction("allocate")
	if allocFn == nil {
		allocFn = mod.ExportedFunction("malloc")
	}

	resetFn := mod.ExportedFunction("reset")

	return &wasmInstance{
		mod:       mod,
		mapLeafFn: mapLeafFn,
		allocFn:   allocFn,
		resetFn:   resetFn,
		mem:       mem,
	}, nil
}

func (inst *wasmInstance) executeLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	var inputPtr uint32
	leafLen := uint32(len(leaf))
	if leafLen > 0 {
		if inst.allocFn == nil {
			return nil, fmt.Errorf("%w: guest module must export 'allocate' or 'malloc'", ErrWasmHalt)
		}
		res, err := inst.allocFn.Call(ctx, uint64(leafLen))
		if err != nil {
			return nil, fmt.Errorf("%w: allocate failed: %v", ErrWasmHalt, err)
		}
		inputPtr = uint32(res[0])
		if inputPtr == 0 {
			return nil, fmt.Errorf("%w: guest allocator returned null pointer (0)", ErrInvalidMemory)
		}
		if !inst.mem.Write(inputPtr, leaf) {
			return nil, fmt.Errorf("%w: failed to write leaf to guest memory at ptr %d len %d (mem size %d)",
				ErrInvalidMemory, inputPtr, leafLen, inst.mem.Size())
		}
	}

	results, err := inst.mapLeafFn.Call(ctx, uint64(inputPtr), uint64(leafLen))
	if err != nil {
		return nil, fmt.Errorf("%w: map_leaf execution failed: %v", ErrWasmHalt, err)
	}
	if len(results) == 0 {
		return nil, nil
	}

	packed := results[0]
	outPtr := uint32(packed >> 32)
	outLen := uint32(packed & 0xFFFFFFFF)
	if outLen == 0 {
		return nil, nil
	}

	outBuf, ok := inst.mem.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("%w: out_ptr=%d out_len=%d exceeds guest memory %d",
			ErrInvalidMemory, outPtr, outLen, inst.mem.Size())
	}

	entries, err := decodeMappedEntries(outBuf)
	if err != nil {
		return nil, err
	}

	// Post-processing: Sort by KeyHash and deduplicate
	slices.SortFunc(entries, func(a, b MappedEntry) int {
		if cmp := bytes.Compare(a.KeyHash[:], b.KeyHash[:]); cmp != 0 {
			return cmp
		}
		return bytes.Compare(a.Value, b.Value)
	})

	entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
		return a.KeyHash == b.KeyHash && bytes.Equal(a.Value, b.Value)
	})

	return entries, nil
}

// MapLeaf executes the WASM map_leaf export against leaf payload and returns sorted, deduplicated entries.
func (h *WASMHost) MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	h.mu.Lock()
	if h.closed {
		err := h.haltErr
		if err == nil {
			err = ErrHostClosed
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	var inst *wasmInstance
	var ok bool
	select {
	case inst, ok = <-h.pool:
		if !ok || inst == nil {
			return nil, ErrHostClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	callCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	var modErr error
	defer func() {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			_ = inst.mod.Close(context.Background())
			return
		}

		if modErr != nil {
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				if !h.closed {
					h.closed = true
					h.haltErr = fmt.Errorf("%w: failed to replenish worker instance: %v", ErrWasmHalt, instErr)
				}
				h.mu.Unlock()
				return
			}
			h.pool <- newInst
			h.mu.Unlock()
			return
		}

		if inst.resetFn != nil {
			if _, err := inst.resetFn.Call(context.Background()); err != nil {
				_ = inst.mod.Close(context.Background())
				newInst, instErr := h.instantiateInstance(context.Background())
				if instErr != nil {
					if !h.closed {
						h.closed = true
						h.haltErr = fmt.Errorf("%w: failed to replenish worker instance after reset failure: %v", ErrWasmHalt, instErr)
					}
					h.mu.Unlock()
					return
				}
				h.pool <- newInst
				h.mu.Unlock()
				return
			}
		}

		h.pool <- inst
		h.mu.Unlock()
	}()

	entries, err := inst.executeLeaf(callCtx, leaf)
	if err != nil {
		modErr = err
		return nil, modErr
	}
	return entries, nil
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves using a single checked-out instance.
func (h *WASMHost) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	h.mu.Lock()
	if h.closed {
		err := h.haltErr
		if err == nil {
			err = ErrHostClosed
		}
		h.mu.Unlock()
		return nil, err
	}
	h.mu.Unlock()

	var inst *wasmInstance
	var ok bool
	select {
	case inst, ok = <-h.pool:
		if !ok || inst == nil {
			return nil, ErrHostClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	callCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	var modErr error
	defer func() {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			_ = inst.mod.Close(context.Background())
			return
		}

		if modErr != nil {
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				if !h.closed {
					h.closed = true
					h.haltErr = fmt.Errorf("%w: failed to replenish worker instance: %v", ErrWasmHalt, instErr)
				}
				h.mu.Unlock()
				return
			}
			h.pool <- newInst
			h.mu.Unlock()
			return
		}

		if inst.resetFn != nil {
			if _, err := inst.resetFn.Call(context.Background()); err != nil {
				_ = inst.mod.Close(context.Background())
				newInst, instErr := h.instantiateInstance(context.Background())
				if instErr != nil {
					if !h.closed {
						h.closed = true
						h.haltErr = fmt.Errorf("%w: failed to replenish worker instance after reset failure: %v", ErrWasmHalt, instErr)
					}
					h.mu.Unlock()
					return
				}
				h.pool <- newInst
				h.mu.Unlock()
				return
			}
		}

		h.pool <- inst
		h.mu.Unlock()
	}()

	results := make([][]MappedEntry, len(leaves))
	for i, leaf := range leaves {
		entries, err := inst.executeLeaf(callCtx, leaf)
		if err != nil {
			modErr = fmt.Errorf("leaf %d in bundle: %w", i, err)
			return nil, modErr
		}
		results[i] = entries

		if inst.resetFn != nil && i+1 < len(leaves) {
			if _, err := inst.resetFn.Call(callCtx); err != nil {
				modErr = fmt.Errorf("%w: reset failed on leaf %d: %v", ErrWasmHalt, i, err)
				return nil, modErr
			}
		}
	}

	return results, nil
}

func decodeMappedEntries(data []byte) ([]MappedEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Schema 1: Structured entries: [Count(4B)][Entry: KeyHash(32B) + ValLen(2B) + Val]...
	if len(data) >= 4 {
		count := binary.BigEndian.Uint32(data[0:4])
		maxPossible := uint32(len(data)-4) / 34
		if count <= maxPossible {
			offset := 4
			entries := make([]MappedEntry, 0, count)
			valid := true
			for i := uint32(0); i < count; i++ {
				if offset+34 > len(data) {
					valid = false
					break
				}
				var entry MappedEntry
				copy(entry.KeyHash[:], data[offset:offset+32])
				offset += 32
				valLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
				offset += 2
				if offset+valLen > len(data) {
					valid = false
					break
				}
				if valLen > 0 {
					entry.Value = make([]byte, valLen)
					copy(entry.Value, data[offset:offset+valLen])
					offset += valLen
				}
				entries = append(entries, entry)
			}
			if valid && offset == len(data) {
				return entries, nil
			}
		}
	}

	// Schema 2: Raw concatenated 32-byte hashes: [Hash(32B)]...
	if len(data)%sha256.Size == 0 {
		count := len(data) / sha256.Size
		entries := make([]MappedEntry, count)
		for i := 0; i < count; i++ {
			copy(entries[i].KeyHash[:], data[i*sha256.Size:(i+1)*sha256.Size])
		}
		return entries, nil
	}

	return nil, fmt.Errorf("%w: length %d is neither structured nor a multiple of 32", ErrMalformedOutput, len(data))
}

// Close closes all module instances and releases the Wazero runtime.
func (h *WASMHost) Close(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true

	close(h.pool)
	for inst := range h.pool {
		_ = inst.mod.Close(ctx)
	}
	if h.compiled != nil {
		_ = h.compiled.Close(ctx)
	}
	if h.runtime != nil {
		return h.runtime.Close(ctx)
	}
	return nil
}

