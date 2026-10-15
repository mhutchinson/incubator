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

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/wire"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = wire.ErrOutputLogCorrupted

// ParseOutputLogLeaf parses a raw Output Log leaf payload into the 32-byte MPT MapRoot,
// the parsed Input Log checkpoint header, and the raw Input Log checkpoint bytes.
// The returned rawInCP is guaranteed to have a trailing newline.
func ParseOutputLogLeaf(leafData []byte) (mapRoot [sha256.Size]byte, inCP *log.Checkpoint, rawInCP []byte, err error) {
	return wire.ParseOutputLogLeaf(leafData)
}

// FormatOutputLogLeaf formats an Output Log leaf from the MPT MapRoot and raw Input Log checkpoint note.
// Output format: "<hex(mapRoot)>\n<rawInCP>\n"
func FormatOutputLogLeaf(mapRoot [sha256.Size]byte, rawInputLogCP []byte) []byte {
	return wire.FormatOutputLogLeaf(mapRoot, rawInputLogCP)
}
