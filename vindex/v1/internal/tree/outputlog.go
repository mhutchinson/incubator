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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/transparency-dev/formats/log"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = errors.New("output log leaf format corrupted")

// ParseOutputLogLeaf parses a raw Output Log leaf payload into the 32-byte MPT MapRoot,
// the parsed Input Log checkpoint header, and the raw Input Log checkpoint bytes.
// The returned rawInCP is guaranteed to have a trailing newline.
func ParseOutputLogLeaf(leafData []byte) (mapRoot [sha256.Size]byte, inCP *log.Checkpoint, rawInCP []byte, err error) {
	lines := bytes.SplitN(bytes.TrimSpace(leafData), []byte("\n"), 2)
	if len(lines) < 2 {
		return [sha256.Size]byte{}, nil, nil, fmt.Errorf("%w: expected map root and input checkpoint lines", ErrOutputLogCorrupted)
	}
	mapRootHex := strings.TrimSpace(string(lines[0]))
	if len(mapRootHex) != 64 {
		return [sha256.Size]byte{}, nil, nil, fmt.Errorf("%w: invalid map root hex length %d, expected 64", ErrOutputLogCorrupted, len(mapRootHex))
	}
	mapRootBytes, err := hex.DecodeString(mapRootHex)
	if err != nil {
		return [sha256.Size]byte{}, nil, nil, fmt.Errorf("%w: invalid map root hex %q: %w", ErrOutputLogCorrupted, mapRootHex, err)
	}
	copy(mapRoot[:], mapRootBytes)

	rawInCP = bytes.TrimSpace(lines[1])
	if len(rawInCP) > 0 && rawInCP[len(rawInCP)-1] != '\n' {
		rawInCP = append(rawInCP, '\n')
	}
	inCP, err = ParseCheckpointHeader(rawInCP)
	if err != nil {
		return [sha256.Size]byte{}, nil, nil, fmt.Errorf("%w: invalid input checkpoint header: %w", ErrOutputLogCorrupted, err)
	}
	return mapRoot, inCP, rawInCP, nil
}

// FormatOutputLogLeaf formats an Output Log leaf from the MPT MapRoot and raw Input Log checkpoint note.
// Output format: "<hex(mapRoot)>\n<rawInCP>\n"
func FormatOutputLogLeaf(mapRoot [sha256.Size]byte, rawInputLogCP []byte) []byte {
	hexRoot := hex.EncodeToString(mapRoot[:])
	trimmedInCP := bytes.TrimRight(rawInputLogCP, "\n")
	return []byte(hexRoot + "\n" + string(trimmedInCP) + "\n")
}
