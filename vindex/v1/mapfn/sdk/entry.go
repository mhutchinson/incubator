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

package sdk

import "crypto/sha256"

// Entry represents a single search key and optional value produced by a MapFunc.
type Entry struct {
	KeyHash [sha256.Size]byte
	Value   []byte
}

// MapFunc maps a raw input log leaf to structured searchable entries.
type MapFunc func(leaf []byte) []Entry

// RawMapFunc maps a raw input log leaf to raw 32-byte key hashes.
type RawMapFunc func(leaf []byte) [][sha256.Size]byte
