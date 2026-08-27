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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func writeSection(buf *bytes.Buffer, secID byte, secPayload []byte) {
	buf.WriteByte(secID)
	buf.Write(leb128U32(uint32(len(secPayload))))
	buf.Write(secPayload)
}

func assembleWasm(funcBody []byte, dataBytes []byte, dataOffset uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,                   // 2 types
		0x60, 0x02, 0x7f, 0x7f, // type 0: func(i32, i32) -> i64
		0x01, 0x7e,
		0x60, 0x01, 0x7f, // type 1: func(i32) -> i32
		0x01, 0x7f,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x02, 0x00, 0x01} // 2 funcs
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(3) // 3 exports
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2)) // 2 function bodies

	var body bytes.Buffer
	body.Write(leb128U32(0)) // 0 local declarations
	body.Write(funcBody)
	body.WriteByte(0x0b) // end opcode

	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0)) // 0 local declarations
	allocBody.WriteByte(0x41)     // i32.const
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b) // end opcode

	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	if len(dataBytes) > 0 {
		var dataSec bytes.Buffer
		dataSec.Write(leb128U32(1)) // 1 data segment
		dataSec.WriteByte(0x00)     // active segment, memory 0
		dataSec.WriteByte(0x41)
		dataSec.Write(leb128U32(dataOffset))
		dataSec.WriteByte(0x0b)
		dataSec.Write(leb128U32(uint32(len(dataBytes))))
		dataSec.Write(dataBytes)
		writeSection(&buf, 11, dataSec.Bytes())
	}

	return buf.Bytes()
}

func encodeStructuredEntries(entries []MappedEntry) []byte {
	var buf bytes.Buffer
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(entries)))
	buf.Write(count[:])
	for _, e := range entries {
		buf.Write(e.KeyHash[:])
		var vlen [2]byte
		binary.BigEndian.PutUint16(vlen[:], uint16(len(e.Value)))
		buf.Write(vlen[:])
		buf.Write(e.Value)
	}
	return buf.Bytes()
}

func buildStaticOutputWasm(staticBytes []byte) []byte {
	var body bytes.Buffer
	packed := (uint64(1024) << 32) | uint64(len(staticBytes))
	body.WriteByte(0x42) // i64.const
	body.Write(leb128I64(int64(packed)))

	return assembleWasm(body.Bytes(), staticBytes, 1024)
}

func leb128U32(val uint32) []byte {
	var res []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		res = append(res, b)
		if val == 0 {
			break
		}
	}
	return res
}

func leb128I64(val int64) []byte {
	var res []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		sign := (b & 0x40) != 0
		if (val == 0 && !sign) || (val == -1 && sign) {
			res = append(res, b)
			break
		}
		b |= 0x80
		res = append(res, b)
	}
	return res
}

func TestWASMHost_StructuredEntries(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("key_beta"))
	h2 := sha256.Sum256([]byte("key_alpha"))
	h3 := sha256.Sum256([]byte("key_alpha")) // duplicate to test sorting & deduplication

	inputEntries := []MappedEntry{
		{KeyHash: h1, Value: []byte("val_beta")},
		{KeyHash: h2, Value: []byte("val_alpha")},
		{KeyHash: h3, Value: []byte("val_alpha")},
	}
	encoded := encodeStructuredEntries(inputEntries)
	wasmBytes := buildStaticOutputWasm(encoded)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("test_leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}

	expected := []MappedEntry{
		{KeyHash: h1, Value: []byte("val_beta")},
		{KeyHash: h2, Value: []byte("val_alpha")},
	}

	if diff := cmp.Diff(expected, results); diff != "" {
		t.Fatalf("MapLeaf diff (-want +got):\n%s", diff)
	}
}

func TestWASMHost_RawHashes(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("z_key"))
	h2 := sha256.Sum256([]byte("a_key"))

	raw := append(h1[:], h2[:]...)
	wasmBytes := buildStaticOutputWasm(raw)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}

	expected := []MappedEntry{
		{KeyHash: h1},
		{KeyHash: h2},
	}

	if diff := cmp.Diff(expected, results); diff != "" {
		t.Fatalf("MapLeaf diff (-want +got):\n%s", diff)
	}
}

func TestWASMHost_EmptyOutput(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasm(body.Bytes(), nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	results, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected empty results, got %v", results)
	}
}

func TestWASMHost_UnreachableTrap(t *testing.T) {
	ctx := context.Background()

	// Body with unreachable (0x00) instruction
	funcBody := []byte{0x00}
	wasmBytes := assembleWasm(funcBody, nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("trap_leaf"))
	if err == nil {
		t.Fatal("expected error on unreachable instruction, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func TestWASMHost_OutOfBoundsMemory(t *testing.T) {
	ctx := context.Background()

	// Return out_ptr=500000 (exceeds initial 64KB memory)
	var body bytes.Buffer
	packed := (uint64(500000) << 32) | uint64(32)
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasm(body.Bytes(), nil, 0)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("oob_leaf"))
	if err == nil {
		t.Fatal("expected out of bounds error, got nil")
	}
	if !errors.Is(err, ErrInvalidMemory) {
		t.Fatalf("expected ErrInvalidMemory, got: %v", err)
	}
}

func TestWASMHost_MalformedOutput(t *testing.T) {
	ctx := context.Background()

	// Output 17 bytes (neither structured nor a multiple of 32)
	junkData := bytes.Repeat([]byte{0xFF}, 17)
	wasmBytes := buildStaticOutputWasm(junkData)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("malformed"))
	if err == nil {
		t.Fatal("expected malformed output error, got nil")
	}
	if !errors.Is(err, ErrMalformedOutput) {
		t.Fatalf("expected ErrMalformedOutput, got: %v", err)
	}
}

func TestWASMHost_ConcurrentExecution(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("concurrent_key"))
	wasmBytes := buildStaticOutputWasm(h1[:])

	// Pool size 4, 20 concurrent goroutines
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := host.MapLeaf(ctx, []byte("concurrent_leaf"))
				if err != nil {
					t.Errorf("concurrent MapLeaf failed: %v", err)
					return
				}
				if len(res) != 1 || res[0].KeyHash != h1 {
					t.Errorf("unexpected MapLeaf result: %v", res)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestWASMHost_ClosedHost(t *testing.T) {
	ctx := context.Background()

	h1 := sha256.Sum256([]byte("closed_key"))
	wasmBytes := buildStaticOutputWasm(h1[:])

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}

	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = host.MapLeaf(ctx, []byte("leaf"))
	if !errors.Is(err, ErrHostClosed) {
		t.Fatalf("expected ErrHostClosed after Close(), got: %v", err)
	}
}

func assembleWasmWithoutAllocate(funcBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x01,
		0x60, 0x02, 0x7f, 0x7f,
		0x01, 0x7e,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x01, 0x00}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(2)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(1))
	var body bytes.Buffer
	body.Write(leb128U32(0))
	body.Write(funcBody)
	body.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())
	writeSection(&buf, 10, codeSec.Bytes())

	return buf.Bytes()
}

func TestWASMHost_MissingAllocateExport(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasmWithoutAllocate(body.Bytes())

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("non_empty_leaf"))
	if err == nil {
		t.Fatal("expected error on missing allocate export, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
}

func assembleWasmWithNullAllocate(funcBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x02,
		0x60, 0x02, 0x7f, 0x7f,
		0x01, 0x7e,
		0x60, 0x01, 0x7f,
		0x01, 0x7f,
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x02, 0x00, 0x01}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(3)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2))

	var body bytes.Buffer
	body.Write(leb128U32(0))
	body.Write(funcBody)
	body.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(body.Len())))
	codeSec.Write(body.Bytes())

	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.Write([]byte{0x41, 0x00}) // i32.const 0 (NULL)
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())
	return buf.Bytes()
}

func TestWASMHost_NullPointerAllocation(t *testing.T) {
	ctx := context.Background()

	var body bytes.Buffer
	packed := uint64(1024) << 32
	body.WriteByte(0x42)
	body.Write(leb128I64(int64(packed)))
	wasmBytes := assembleWasmWithNullAllocate(body.Bytes())

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	_, err = host.MapLeaf(ctx, []byte("non_empty_leaf"))
	if err == nil {
		t.Fatal("expected error on null pointer allocation, got nil")
	}
	if !errors.Is(err, ErrInvalidMemory) {
		t.Fatalf("expected ErrInvalidMemory, got: %v", err)
	}
}

func assembleWasmWithInfiniteLoop() []byte {
	var body bytes.Buffer
	// loop: 0x03 0x40 (loop empty_block) 0x0c 0x00 (br 0) 0x0b (end)
	body.Write([]byte{0x03, 0x40, 0x0c, 0x00, 0x0b})
	// unreachable return
	body.WriteByte(0x42)
	body.Write(leb128I64(0))
	return assembleWasm(body.Bytes(), nil, 0)
}

func TestWASMHost_Timeout(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithInfiniteLoop()

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leafCtx, leafCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer leafCancel()

	start := time.Now()
	_, err = host.MapLeaf(leafCtx, []byte("infinite_loop"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error for infinite loop, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
	if elapsed < 80*time.Millisecond || elapsed > 2000*time.Millisecond {
		t.Logf("execution elapsed: %v (expected ~100ms timeout)", elapsed)
	}
}

func TestWASMHost_BackgroundContextFallbackTimeout(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithInfiniteLoop()

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// Calling with bare context.Background() should still terminate via the 5s fallback watchdog
	// rather than hanging indefinitely.
	start := time.Now()
	_, err = host.MapLeaf(ctx, []byte("infinite_loop"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error for infinite loop with background context, got nil")
	}
	if !errors.Is(err, ErrWasmHalt) {
		t.Fatalf("expected ErrWasmHalt, got: %v", err)
	}
	if elapsed < 4*time.Second || elapsed > 8*time.Second {
		t.Logf("execution elapsed: %v (expected ~5s fallback timeout)", elapsed)
	}
}

func assembleWasmWithReset(resetBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	typeSec := []byte{
		0x03,                   // 3 types
		0x60, 0x02, 0x7f, 0x7f, // type 0: func(i32, i32) -> i64 (map_leaf)
		0x01, 0x7e,
		0x60, 0x01, 0x7f, // type 1: func(i32) -> i32 (allocate)
		0x01, 0x7f,
		0x60, 0x00, 0x00, // type 2: func() -> () (reset)
	}
	writeSection(&buf, 1, typeSec)

	funcSec := []byte{0x03, 0x00, 0x01, 0x02} // 3 funcs: index 0 (type 0), index 1 (type 1), index 2 (type 2)
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	var expSec bytes.Buffer
	expSec.WriteByte(4) // 4 exports
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02) // memory export
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00) // func export
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00) // func export
	expSec.WriteByte(0x01)
	expSec.WriteByte(5)
	expSec.WriteString("reset")
	expSec.WriteByte(0x00) // func export
	expSec.WriteByte(0x02)
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(3)) // 3 function bodies

	// map_leaf body: returns packed (1024 << 32) | 32
	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.WriteByte(0x42)
	packed := (uint64(1024) << 32) | uint64(32)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	// allocate body: returns 100
	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	// reset body
	var rBody bytes.Buffer
	rBody.Write(leb128U32(0))
	rBody.Write(resetBody)
	rBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(rBody.Len())))
	codeSec.Write(rBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())

	// Static 32 bytes data at offset 1024
	var dataSec bytes.Buffer
	dataSec.Write(leb128U32(1))
	dataSec.WriteByte(0x00)
	dataSec.WriteByte(0x41)
	dataSec.Write(leb128U32(1024))
	dataSec.WriteByte(0x0b)
	dataSec.Write(leb128U32(32))
	dataSec.Write(bytes.Repeat([]byte{0x42}, 32))
	writeSection(&buf, 11, dataSec.Bytes())

	return buf.Bytes()
}

func TestWASMHost_ResetExport(t *testing.T) {
	ctx := context.Background()
	// reset function body is a nop: empty bytes
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// Execute twice to ensure reset is called during reuse
	for i := 0; i < 2; i++ {
		res, err := host.MapLeaf(ctx, []byte("leaf"))
		if err != nil {
			t.Fatalf("run %d failed: %v", i, err)
		}
		if len(res) != 1 {
			t.Fatalf("run %d expected 1 entry, got %d", i, len(res))
		}
	}
}

func TestWASMHost_ResetFailureReplenishesPool(t *testing.T) {
	ctx := context.Background()
	// reset function body traps with unreachable (0x00)
	wasmBytes := assembleWasmWithReset([]byte{0x00})

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// First execution should succeed in MapLeaf, then reset fails in defer, replenishing module
	res, err := host.MapLeaf(ctx, []byte("leaf"))
	if err != nil {
		t.Fatalf("first MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}

	// Second execution should also succeed because a new module instance was replenished
	res, err = host.MapLeaf(ctx, []byte("leaf2"))
	if err != nil {
		t.Fatalf("second MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}
}

func assembleWasmWASIImport() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})

	// Type 0: func(i32, i32) -> i32 (random_get)
	// Type 1: func(i32, i32) -> i64 (map_leaf)
	// Type 2: func(i32) -> i32 (allocate)
	typeSec := []byte{
		0x03,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type 0
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // type 1
		0x60, 0x01, 0x7f, 0x01, 0x7f, // type 2
	}
	writeSection(&buf, 1, typeSec)

	// Import section: wasi_snapshot_preview1.random_get -> func type 0
	var impSec bytes.Buffer
	impSec.WriteByte(1) // 1 import
	impSec.WriteByte(22)
	impSec.WriteString("wasi_snapshot_preview1")
	impSec.WriteByte(10)
	impSec.WriteString("random_get")
	impSec.WriteByte(0x00) // func
	impSec.WriteByte(0x00) // type 0
	writeSection(&buf, 2, impSec.Bytes())

	// Func section: 2 funcs: func index 1 (type 1: map_leaf), func index 2 (type 2: allocate)
	funcSec := []byte{0x02, 0x01, 0x02}
	writeSection(&buf, 3, funcSec)

	memSec := []byte{0x01, 0x00, 0x01}
	writeSection(&buf, 5, memSec)

	// Export section
	var expSec bytes.Buffer
	expSec.WriteByte(3)
	expSec.WriteByte(6)
	expSec.WriteString("memory")
	expSec.WriteByte(0x02)
	expSec.WriteByte(0x00)
	expSec.WriteByte(8)
	expSec.WriteString("map_leaf")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x01) // func 1
	expSec.WriteByte(8)
	expSec.WriteString("allocate")
	expSec.WriteByte(0x00)
	expSec.WriteByte(0x02) // func 2
	writeSection(&buf, 7, expSec.Bytes())

	var codeSec bytes.Buffer
	codeSec.Write(leb128U32(2)) // 2 function bodies

	// map_leaf: calls random_get(1024, 32), then drops ret and returns (1024 << 32) | 32
	var mapBody bytes.Buffer
	mapBody.Write(leb128U32(0))
	mapBody.Write([]byte{
		0x41, 0x80, 0x08, // i32.const 1024
		0x41, 0x20, // i32.const 32
		0x10, 0x00, // call 0 (random_get)
		0x1a, // drop
		0x42, // i64.const
	})
	packed := (uint64(1024) << 32) | uint64(32)
	mapBody.Write(leb128I64(int64(packed)))
	mapBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(mapBody.Len())))
	codeSec.Write(mapBody.Bytes())

	// allocate: returns 100
	var allocBody bytes.Buffer
	allocBody.Write(leb128U32(0))
	allocBody.WriteByte(0x41)
	allocBody.Write(leb128I64(100))
	allocBody.WriteByte(0x0b)
	codeSec.Write(leb128U32(uint32(allocBody.Len())))
	codeSec.Write(allocBody.Bytes())

	writeSection(&buf, 10, codeSec.Bytes())
	return buf.Bytes()
}

func TestWASMHost_WASIInstantiation(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWASIImport()

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed for WASI module: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	res, err := host.MapLeaf(ctx, []byte("wasi_leaf"))
	if err != nil {
		t.Fatalf("MapLeaf failed: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}
}

func TestWASMHost_MapBundle(t *testing.T) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)

	host, err := NewWASMHost(ctx, wasmBytes, 2)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := [][]byte{
		[]byte("leaf0"),
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
	}

	results, err := host.MapBundle(ctx, leaves)
	if err != nil {
		t.Fatalf("MapBundle failed: %v", err)
	}
	if len(results) != len(leaves) {
		t.Fatalf("expected %d bundle results, got %d", len(leaves), len(results))
	}
	for i, r := range results {
		if len(r) != 1 {
			t.Fatalf("leaf %d expected 1 entry, got %d", i, len(r))
		}
	}
}

func TestWASMHost_MapBundle_TrapReplenishesPool(t *testing.T) {
	ctx := context.Background()
	// reset function body traps with unreachable (0x00)
	wasmBytes := assembleWasmWithReset([]byte{0x00})

	host, err := NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		t.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	// Calling MapBundle with 2 leaves should fail on reset between leaves, replenishing module
	leaves := [][]byte{[]byte("leaf0"), []byte("leaf1")}
	_, err = host.MapBundle(ctx, leaves)
	if err == nil {
		t.Fatal("expected error on trapping reset during bundle, got nil")
	}

	// Module pool must have been replenished: single leaf call should succeed
	singleRes, err := host.MapLeaf(ctx, []byte("fresh_leaf"))
	if err != nil {
		t.Fatalf("subsequent MapLeaf failed after replenishment: %v", err)
	}
	if len(singleRes) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(singleRes))
	}
}

func BenchmarkWASMHost_MapLeaf(b *testing.B) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaf := []byte("benchmark_leaf_payload")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := host.MapLeaf(ctx, leaf)
		if err != nil {
			b.Fatalf("MapLeaf failed: %v", err)
		}
	}
}

func BenchmarkWASMHost_MapBundle(b *testing.B) {
	ctx := context.Background()
	wasmBytes := assembleWasmWithReset(nil)
	host, err := NewWASMHost(ctx, wasmBytes, 4)
	if err != nil {
		b.Fatalf("NewWASMHost failed: %v", err)
	}
	defer func() { _ = host.Close(ctx) }()

	leaves := make([][]byte, 256)
	for i := range leaves {
		leaves[i] = []byte("benchmark_leaf_payload")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := host.MapBundle(ctx, leaves)
		if err != nil {
			b.Fatalf("MapBundle failed: %v", err)
		}
	}
}

