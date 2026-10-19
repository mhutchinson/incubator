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
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = wire.ErrOutputLogCorrupted

// OutputLogLeaf is an alias for wire.OutputLogLeaf.
type OutputLogLeaf = wire.OutputLogLeaf

// ParseOutputLogLeafFull parses a raw c2sp.org/tlog-vindex-state@v1 Output Log leaf payload.
func ParseOutputLogLeafFull(leafData []byte) (*wire.OutputLogLeaf, error) {
	return wire.ParseOutputLogLeafFull(leafData)
}

// ParseOutputLogLeaf parses a raw Output Log leaf payload into the 32-byte MPTRoot,
// the parsed Input Log checkpoint header, and the raw Input Log checkpoint bytes.
// The returned rawInCP is guaranteed to have a trailing newline.
func ParseOutputLogLeaf(leafData []byte) (mptRoot [sha256.Size]byte, inCP *log.Checkpoint, rawInCP []byte, err error) {
	return wire.ParseOutputLogLeaf(leafData)
}

// FormatOutputLogLeafFull formats an Output Log leaf according to c2sp.org/tlog-vindex-state@v1.
func FormatOutputLogLeafFull(mptRoot, mapFn [sha256.Size]byte, from uint64, rawInputLogCP []byte) []byte {
	return wire.FormatOutputLogLeafFull(mptRoot, mapFn, from, rawInputLogCP)
}

// FormatOutputLogLeaf formats an Output Log leaf from the MPTRoot and raw Input Log checkpoint note.
func FormatOutputLogLeaf(mptRoot [sha256.Size]byte, rawInputLogCP []byte) []byte {
	return wire.FormatOutputLogLeaf(mptRoot, rawInputLogCP)
}
