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
	"io"
	"runtime"
	"slices"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
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
	mod         api.Module
	mapBundleFn api.Function
	mapLeafFn   api.Function
	allocFn     api.Function
	resetFn     api.Function
	mem         api.Memory
	packedBuf   []byte
	staticInPtr uint32
}

// NewWASMHost compiles the guest bytecode and initializes a pool of instantiated WASM modules.
// If poolSize <= 0, it defaults to runtime.GOMAXPROCS(0) - 1 (minimum 1).
func NewWASMHost(ctx context.Context, wasmBytes []byte, poolSize int) (*WASMHost, error) {
	if poolSize <= 0 {
		poolSize = runtime.GOMAXPROCS(0) - 1
		if poolSize < 1 {
			poolSize = 1
		}
	}

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(1024).WithCloseOnContextDone(true))
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

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

	mapBundleFn := mod.ExportedFunction("map_bundle")
	mapLeafFn := mod.ExportedFunction("map_leaf")
	if mapBundleFn == nil && mapLeafFn == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("%w: neither 'map_bundle' nor 'map_leaf' exported", ErrWasmHalt)
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

	var staticInPtr uint32
	if inBufFn := mod.ExportedFunction("input_buffer"); inBufFn != nil {
		if res, err := inBufFn.Call(ctx); err == nil && len(res) > 0 && res[0] != 0 {
			staticInPtr = uint32(res[0])
		}
	} else if allocFn != nil && resetFn != nil {
		// Probe if the guest uses a static arena allocator.
		p1, err1 := allocFn.Call(ctx, 64)
		_, _ = resetFn.Call(ctx)
		p2, err2 := allocFn.Call(ctx, 64)
		_, _ = resetFn.Call(ctx)
		if err1 == nil && err2 == nil && len(p1) > 0 && len(p2) > 0 && p1[0] != 0 && p1[0] == p2[0] {
			staticInPtr = uint32(p1[0])
		}
	}

	return &wasmInstance{
		mod:         mod,
		mapBundleFn: mapBundleFn,
		mapLeafFn:   mapLeafFn,
		allocFn:     allocFn,
		resetFn:     resetFn,
		mem:         mem,
		staticInPtr: staticInPtr,
	}, nil
}

func (inst *wasmInstance) packBundle(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 || n > 256 {
		return nil
	}

	headerLen := 4 + (n+1)*4
	var payloadLen int
	for _, l := range leaves {
		payloadLen += len(l)
	}

	totalLen := headerLen + payloadLen
	if cap(inst.packedBuf) < totalLen {
		inst.packedBuf = make([]byte, totalLen)
	} else {
		inst.packedBuf = inst.packedBuf[:totalLen]
	}
	buf := inst.packedBuf

	binary.LittleEndian.PutUint32(buf[0:4], uint32(n))

	var currentOffset uint32
	binary.LittleEndian.PutUint32(buf[4:8], 0)
	payloadDst := buf[headerLen:]
	var writePos int

	for i, l := range leaves {
		copy(payloadDst[writePos:], l)
		writePos += len(l)
		currentOffset += uint32(len(l))
		binary.LittleEndian.PutUint32(buf[4+(i+1)*4:4+(i+2)*4], currentOffset)
	}

	return buf
}

func (inst *wasmInstance) executeBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	if inst.mapBundleFn != nil {
		n := len(leaves)
		if n == 0 {
			return nil, nil
		}
		if n > 256 {
			return nil, fmt.Errorf("%w: bundle size %d exceeds 256", ErrMalformedOutput, n)
		}

		packedInput := inst.packBundle(leaves)
		var inPtr uint32
		if inst.staticInPtr != 0 && len(packedInput) <= 4*1024*1024 {
			inPtr = inst.staticInPtr
		} else {
			if inst.allocFn == nil {
				return nil, fmt.Errorf("%w: guest module must export 'allocate' or 'malloc'", ErrWasmHalt)
			}
			res, err := inst.allocFn.Call(ctx, uint64(len(packedInput)))
			if err != nil {
				return nil, fmt.Errorf("%w: allocate failed: %v", ErrWasmHalt, err)
			}
			inPtr = uint32(res[0])
			if inPtr == 0 {
				return nil, fmt.Errorf("%w: guest allocator returned null pointer (0)", ErrInvalidMemory)
			}
		}

		if !inst.mem.Write(inPtr, packedInput) {
			return nil, fmt.Errorf("%w: failed to write bundle input to memory at ptr %d len %d",
				ErrInvalidMemory, inPtr, len(packedInput))
		}

		callRes, err := inst.mapBundleFn.Call(ctx, uint64(inPtr), uint64(len(packedInput)))
		if err != nil {
			return nil, fmt.Errorf("%w: map_bundle execution failed: %v", ErrWasmHalt, err)
		}
		if len(callRes) == 0 {
			return nil, fmt.Errorf("%w: map_bundle returned no result", ErrMalformedOutput)
		}

		packed := callRes[0]
		outPtr := uint32(packed >> 32)
		outLen := uint32(packed & 0xFFFFFFFF)
		if outLen == 0 {
			return make([][]MappedEntry, n), nil
		}

		outBuf, ok := inst.mem.Read(outPtr, outLen)
		if !ok {
			return nil, fmt.Errorf("%w: out_ptr=%d out_len=%d exceeds guest memory %d",
				ErrInvalidMemory, outPtr, outLen, inst.mem.Size())
		}

		return decodeBundleOutput(outBuf, n)
	}

	// Fallback to legacy single-leaf map_leaf
	results := make([][]MappedEntry, len(leaves))
	for i, leaf := range leaves {
		entries, err := inst.executeLeaf(ctx, leaf)
		if err != nil {
			return nil, fmt.Errorf("leaf %d in bundle: %w", i, err)
		}
		results[i] = entries

		if inst.resetFn != nil && i+1 < len(leaves) {
			if _, err := inst.resetFn.Call(ctx); err != nil {
				return nil, fmt.Errorf("%w: reset failed on leaf %d: %v", ErrWasmHalt, i, err)
			}
		}
	}
	return results, nil
}

func decodeBundleOutput(outBuf []byte, expectedCount int) ([][]MappedEntry, error) {
	if len(outBuf) < 4+expectedCount*4 {
		return nil, fmt.Errorf("%w: bundle output length %d is too short for %d leaves", ErrMalformedOutput, len(outBuf), expectedCount)
	}

	leafCount := binary.LittleEndian.Uint32(outBuf[0:4])
	if int(leafCount) != expectedCount {
		return nil, fmt.Errorf("%w: bundle output leaf_count %d != expected %d", ErrMalformedOutput, leafCount, expectedCount)
	}

	keyCountsOffset := 4
	preimagesOffset := 4 + expectedCount*4

	var totalKeys int
	for i := 0; i < expectedCount; i++ {
		totalKeys += int(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
	}

	results := make([][]MappedEntry, expectedCount)
	if totalKeys == 0 {
		return results, nil
	}

	allEntries := make([]MappedEntry, totalKeys)
	var curEntryIdx int

	for i := 0; i < expectedCount; i++ {
		kCount := int(binary.LittleEndian.Uint32(outBuf[keyCountsOffset+i*4 : keyCountsOffset+(i+1)*4]))
		if kCount == 0 {
			continue
		}

		startEntryIdx := curEntryIdx
		for j := 0; j < kCount; j++ {
			if preimagesOffset+4 > len(outBuf) {
				return nil, fmt.Errorf("%w: truncated key length header", ErrMalformedOutput)
			}
			keyLen := binary.LittleEndian.Uint32(outBuf[preimagesOffset : preimagesOffset+4])
			preimagesOffset += 4

			if preimagesOffset+int(keyLen) > len(outBuf) {
				return nil, fmt.Errorf("%w: truncated key bytes", ErrMalformedOutput)
			}
			keyBytes := outBuf[preimagesOffset : preimagesOffset+int(keyLen)]
			preimagesOffset += int(keyLen)

			allEntries[curEntryIdx] = MappedEntry{KeyHash: sha256.Sum256(keyBytes)}
			curEntryIdx++
		}

		entries := allEntries[startEntryIdx:curEntryIdx]
		if len(entries) > 1 {
			slices.SortFunc(entries, func(a, b MappedEntry) int {
				return bytes.Compare(a.KeyHash[:], b.KeyHash[:])
			})
			entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
				return a.KeyHash == b.KeyHash
			})
		}
		results[i] = entries
	}

	return results, nil
}

func (inst *wasmInstance) executeLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	if inst.mapBundleFn != nil {
		res, err := inst.executeBundle(ctx, [][]byte{leaf})
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			return nil, nil
		}
		return res[0], nil
	}

	var inputPtr uint32
	leafLen := uint32(len(leaf))
	if leafLen > 0 {
		if inst.staticInPtr != 0 && leafLen <= 4*1024*1024 {
			inputPtr = inst.staticInPtr
		} else {
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
	if len(entries) > 1 {
		slices.SortFunc(entries, func(a, b MappedEntry) int {
			if cmp := bytes.Compare(a.KeyHash[:], b.KeyHash[:]); cmp != 0 {
				return cmp
			}
			return bytes.Compare(a.Value, b.Value)
		})

		entries = slices.CompactFunc(entries, func(a, b MappedEntry) bool {
			return a.KeyHash == b.KeyHash && bytes.Equal(a.Value, b.Value)
		})
	}

	return entries, nil
}

// MapLeaf executes the WASM map_leaf/map_bundle export against leaf payload and returns sorted, deduplicated entries.
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

	var modErr error
	defer func() {
		if modErr != nil {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.closed {
				_ = inst.mod.Close(context.Background())
				return
			}
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				h.closed = true
				h.haltErr = fmt.Errorf("%w: failed to replenish worker instance: %v", ErrWasmHalt, instErr)
				return
			}
			h.pool <- newInst
			return
		}

		var resetErr error
		if inst.resetFn != nil && inst.staticInPtr == 0 {
			_, resetErr = inst.resetFn.Call(context.Background())
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			_ = inst.mod.Close(context.Background())
			return
		}

		if resetErr != nil {
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				h.closed = true
				h.haltErr = fmt.Errorf("%w: failed to replenish worker instance after reset failure: %v", ErrWasmHalt, instErr)
				return
			}
			h.pool <- newInst
			return
		}

		h.pool <- inst
	}()

	entries, err := inst.executeLeaf(ctx, leaf)
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

	var modErr error
	defer func() {
		if modErr != nil {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.closed {
				_ = inst.mod.Close(context.Background())
				return
			}
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				h.closed = true
				h.haltErr = fmt.Errorf("%w: failed to replenish worker instance: %v", ErrWasmHalt, instErr)
				return
			}
			h.pool <- newInst
			return
		}

		var resetErr error
		if inst.resetFn != nil && inst.staticInPtr == 0 {
			_, resetErr = inst.resetFn.Call(context.Background())
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			_ = inst.mod.Close(context.Background())
			return
		}

		if resetErr != nil {
			_ = inst.mod.Close(context.Background())
			newInst, instErr := h.instantiateInstance(context.Background())
			if instErr != nil {
				h.closed = true
				h.haltErr = fmt.Errorf("%w: failed to replenish worker instance after reset failure: %v", ErrWasmHalt, instErr)
				return
			}
			h.pool <- newInst
			return
		}

		h.pool <- inst
	}()

	results, err := inst.executeBundle(ctx, leaves)
	if err != nil {
		modErr = err
		return nil, modErr
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

// WASMRunner is a dedicated, unshared WASM execution environment bound to a single worker.
// It executes mapping calls lock-free without instance pool or mutex contention.
type WASMRunner struct {
	host   *WASMHost
	inst   *wasmInstance
	closed bool
	hadErr bool
}

// NewRunner creates a dedicated WASMRunner from the host.
// The runner has exclusive access to its WASM module instance, eliminating pool and mutex overhead.
func (h *WASMHost) NewRunner(ctx context.Context) (*WASMRunner, error) {
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
	select {
	case inst = <-h.pool:
	default:
		var err error
		inst, err = h.instantiateInstance(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate wasm runner: %w", err)
		}
	}

	return &WASMRunner{
		host: h,
		inst: inst,
	}, nil
}

// NewRunnerMapper creates a dedicated runner satisfying the RunnerProvider interface.
func (h *WASMHost) NewRunnerMapper(ctx context.Context) (LeafMapper, error) {
	return h.NewRunner(ctx)
}

// MapBundle executes WASM mapping across a contiguous bundle of leaves on this dedicated runner.
func (r *WASMRunner) MapBundle(ctx context.Context, leaves [][]byte) ([][]MappedEntry, error) {
	if r.closed {
		return nil, ErrHostClosed
	}

	results, err := r.inst.executeBundle(ctx, leaves)
	if err != nil {
		r.hadErr = true
		return nil, err
	}

	if r.inst.resetFn != nil && r.inst.staticInPtr == 0 {
		if _, err := r.inst.resetFn.Call(context.Background()); err != nil {
			r.hadErr = true
			return nil, fmt.Errorf("%w: reset failed: %v", ErrWasmHalt, err)
		}
	}

	return results, nil
}

// MapLeaf executes WASM mapping for a single leaf on this dedicated runner.
func (r *WASMRunner) MapLeaf(ctx context.Context, leaf []byte) ([]MappedEntry, error) {
	if r.closed {
		return nil, ErrHostClosed
	}

	entries, err := r.inst.executeLeaf(ctx, leaf)
	if err != nil {
		r.hadErr = true
		return nil, err
	}

	if r.inst.resetFn != nil && r.inst.staticInPtr == 0 {
		if _, err := r.inst.resetFn.Call(context.Background()); err != nil {
			r.hadErr = true
			return nil, fmt.Errorf("%w: reset failed: %v", ErrWasmHalt, err)
		}
	}

	return entries, nil
}

// Close releases this runner's WASM module instance, returning it to the host pool if healthy.
func (r *WASMRunner) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	r.closed = true

	if r.inst == nil {
		return nil
	}

	if r.hadErr {
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}

	r.host.mu.Lock()
	defer r.host.mu.Unlock()

	if r.host.closed {
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}

	select {
	case r.host.pool <- r.inst:
		return nil
	default:
		if r.inst.mod != nil {
			return r.inst.mod.Close(ctx)
		}
		return nil
	}
}

