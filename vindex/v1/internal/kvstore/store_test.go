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

package kvstore

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestInvertedPrefixComparer_Split(t *testing.T) {
	cmp := InvertedPrefixChunkComparer()

	var keyHash [32]byte
	copy(keyHash[:], []byte("01234567890123456789012345678901"))

	chunkKey := EncodeChunkKey(keyHash, 0)
	if got := cmp.Split(chunkKey); got != 33 {
		t.Fatalf("cmp.Split(chunkKey) = %d, want 33", got)
	}

	shortCKey := []byte("c_short")
	if got := cmp.Split(shortCKey); got != len(shortCKey) {
		t.Fatalf("cmp.Split(shortCKey) = %d, want %d", got, len(shortCKey))
	}

	metaKey := KeyMetaKVSize
	if got := cmp.Split(metaKey); got != len(metaKey) {
		t.Fatalf("cmp.Split(metaKey) = %d, want %d", got, len(metaKey))
	}
}

func TestDB_MetadataAccessors(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db_meta")
	db, err := Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initial reads
	val, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || val != nil {
		t.Fatalf("expected nil for missing key, got err=%v val=%v", err, val)
	}
	size, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || size != 0 {
		t.Fatalf("expected 0 for missing uint64, got err=%v size=%d", err, size)
	}

	// Writes
	if err := db.SetMetadata(KeyMetaKVCheckpoint, []byte("cp_raw_test_val")); err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
	if err := db.SetUint64(KeyMetaKVSize, 123456789); err != nil {
		t.Fatalf("SetUint64 failed: %v", err)
	}

	// Verify reads
	gotCP, err := db.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil || !bytes.Equal(gotCP, []byte("cp_raw_test_val")) {
		t.Fatalf("GetMetadata mismatch: got %q, want %q (err: %v)", string(gotCP), "cp_raw_test_val", err)
	}
	gotSize, err := db.GetUint64(KeyMetaKVSize)
	if err != nil || gotSize != 123456789 {
		t.Fatalf("GetUint64 mismatch: got %d, want 123456789 (err: %v)", gotSize, err)
	}
}
