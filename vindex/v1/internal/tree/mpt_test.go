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

package tree

import (
	"crypto/sha256"
	"testing"
)

func TestMPTWrappers(t *testing.T) {
	mgr := NewMem()
	defer func() { _ = mgr.Close() }()

	k := "com.google.mail."
	v := sha256.Sum256([]byte("val"))
	root, err := mgr.CommitKeys(map[string][sha256.Size]byte{k: v})
	if err != nil {
		t.Fatalf("CommitKeys failed: %v", err)
	}

	proof, gotVal, exists, err := mgr.ProveKey([]byte(k))
	if err != nil || !exists || gotVal != v {
		t.Fatalf("ProveKey = (%v, %x, %v), want (true, %x, nil)", exists, gotVal, err, v)
	}
	if err := VerifyKey(root, []byte(k), gotVal, true, proof); err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	prefixProof, matches, err := mgr.ProvePrefix([]byte("com.google."), 10)
	if err != nil || len(matches) != 1 {
		t.Fatalf("ProvePrefix = (%d, %v), want (1, nil)", len(matches), err)
	}
	if err := VerifyPrefix(root, []byte("com.google."), matches, prefixProof); err != nil {
		t.Fatalf("VerifyPrefix failed: %v", err)
	}
}
