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

// Entry represents a single search key preimage and optional value produced by a MapFunc.
type Entry struct {
	Key   []byte // Search key preimage (e.g. "golang.org/x/mod", "example.com")
	Value []byte // Optional value payload
}

// MapFunc maps a raw input log leaf to structured searchable entries with preimages.
type MapFunc func(leaf []byte) []Entry

// RawMapFunc maps a raw input log leaf to raw search key preimages.
type RawMapFunc func(leaf []byte) [][]byte

// StringMapFunc maps a raw input log leaf to search key string preimages.
type StringMapFunc func(leaf []byte) []string
