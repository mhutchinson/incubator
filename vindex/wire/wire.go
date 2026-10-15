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

// Package wire implements C2SP tlog-vindex wire formatting, section parsing,
// Output Log leaf encoding, and RFC 6962 mini-log compact range root computation.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = errors.New("output log leaf format corrupted")

// KeySubRoot represents a canonical key and its 32-byte mini-log sub-root yielded by a prefix scan or point lookup.
type KeySubRoot struct {
	Key     string
	SubRoot [sha256.Size]byte
}

// PrefixKeyVal is an alias for KeySubRoot.
type PrefixKeyVal = KeySubRoot

// Section represents a parsed C2SP plain-text response section ("— <name> [arg] —").
type Section struct {
	Name string
	Arg  string
	Body []byte
}

// ParseSections parses a C2SP plain-text response body into named sections delimited by
// "— <name> [arg] —" or "--- <name> [arg] ---" headers.
func ParseSections(body []byte) (map[string]Section, error) {
	lines := strings.Split(string(body), "\n")
	sections := make(map[string]Section)

	var currentName string
	var currentArg string
	var currentLines []string

	flush := func() {
		if currentName != "" {
			sections[currentName] = Section{
				Name: currentName,
				Arg:  currentArg,
				Body: []byte(strings.Join(currentLines, "\n")),
			}
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		var isHeader bool
		var headerContent string

		if strings.HasPrefix(trimmed, "— ") && strings.HasSuffix(trimmed, " —") {
			isHeader = true
			headerContent = strings.TrimSuffix(strings.TrimPrefix(trimmed, "— "), " —")
		} else if strings.HasPrefix(trimmed, "--- ") && strings.HasSuffix(trimmed, " ---") {
			isHeader = true
			headerContent = strings.TrimSuffix(strings.TrimPrefix(trimmed, "--- "), " ---")
		}

		if isHeader {
			flush()
			parts := strings.SplitN(headerContent, " ", 2)
			currentName = parts[0]
			if len(parts) > 1 {
				currentArg = parts[1]
			} else {
				currentArg = ""
			}
			currentLines = nil
		} else if currentName != "" {
			currentLines = append(currentLines, line)
		}
	}
	flush()

	return sections, nil
}

// ParseCheckpointHeader parses a raw signed-note / tlog-checkpoint header extracting Origin, Size, and Hash.
func ParseCheckpointHeader(rawCP []byte) (*log.Checkpoint, error) {
	lines := bytes.Split(rawCP, []byte("\n"))
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid checkpoint format: expected at least 3 lines, got %d", len(lines))
	}
	origin := string(lines[0])
	size, err := strconv.ParseUint(string(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint size %q: %w", string(lines[1]), err)
	}
	hashStr := string(lines[2])
	hashBytes, err := base64.StdEncoding.DecodeString(hashStr)
	if err != nil || len(hashBytes) != 32 {
		if h, hErr := hex.DecodeString(hashStr); hErr == nil && len(h) == 32 {
			hashBytes = h
		} else {
			return nil, fmt.Errorf("failed to decode 32-byte checkpoint root hash %q", hashStr)
		}
	}
	return &log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hashBytes,
	}, nil
}

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

// FormatKeysResponse builds the plain-text C2SP response for GET /vindex/v1/keys/{key...}[?prefix=true].
// mode must be one of "inclusion", "non-inclusion", or "prefix".
func FormatKeysResponse(rawCheckpoint []byte, outputLogIndex uint64, mapRoot [sha256.Size]byte, rawInputLogCP []byte, outputLogProof [][sha256.Size]byte, mode string, mptProof []byte, matches []KeySubRoot) []byte {
	var sb bytes.Buffer

	// Section 1: — vindex/v1 —
	sb.WriteString("— vindex/v1 —\n")
	sb.Write(bytes.TrimRight(rawCheckpoint, "\n"))
	sb.WriteString("\n\n")

	// Section 2: — output-log-leaf-v1 <leaf_index> —
	fmt.Fprintf(&sb, "— output-log-leaf-v1 %d —\n", outputLogIndex)
	sb.WriteString(hex.EncodeToString(mapRoot[:]))
	sb.WriteString("\n")
	sb.Write(bytes.TrimRight(rawInputLogCP, "\n"))
	sb.WriteString("\n\n")

	// Section 3: — output-log-proof-v1 —
	sb.WriteString("— output-log-proof-v1 —\n")
	for _, p := range outputLogProof {
		sb.WriteString(base64.StdEncoding.EncodeToString(p[:]))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Section 4: — mpt-proof-v1 <mode> —
	fmt.Fprintf(&sb, "— mpt-proof-v1 %s —\n", mode)
	sb.WriteString(base64.StdEncoding.EncodeToString(mptProof))
	sb.WriteString("\n\n")

	// Section 5: — keys-v1 —
	sb.WriteString("— keys-v1 —\n")
	for _, m := range matches {
		sb.WriteString(m.Key)
		sb.WriteByte(' ')
		sb.WriteString(hex.EncodeToString(m.SubRoot[:]))
		sb.WriteByte('\n')
	}

	return sb.Bytes()
}

// FormatEntriesResponse builds the plain-text C2SP response for GET /vindex/v1/entries/{key...}?before=X[&limit=Y].
func FormatEntriesResponse(matchedIndices []uint64, prefixCoveredSize uint64, prefixHashes [][sha256.Size]byte, nextBefore *uint64) []byte {
	var sb bytes.Buffer

	// Section 1: — prefix-compact-range-v1 <covered_size> — (omitted when covered_size == 0)
	if prefixCoveredSize > 0 {
		fmt.Fprintf(&sb, "— prefix-compact-range-v1 %d —\n", prefixCoveredSize)
		for _, h := range prefixHashes {
			sb.WriteString(base64.StdEncoding.EncodeToString(h[:]))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Section 2: — indices-v1 [next_before] —
	if nextBefore != nil {
		fmt.Fprintf(&sb, "— indices-v1 %d —\n", *nextBefore)
	} else {
		sb.WriteString("— indices-v1 —\n")
	}
	for _, idx := range matchedIndices {
		sb.WriteString(strconv.FormatUint(idx, 10))
		sb.WriteString("\n")
	}

	return sb.Bytes()
}

// FormatLookupResponse builds the legacy combined plain-text C2SP response for GET /vindex/v1/lookup/{keyhash}.
func FormatLookupResponse(rawCheckpoint []byte, outputLogIndex uint64, mapRoot [sha256.Size]byte, rawInputLogCP []byte, outputLogProof [][sha256.Size]byte, mptProof []byte, exists bool, matchedIndices []uint64, prefixCoveredSize uint64, prefixHashes [][sha256.Size]byte, nextBefore *uint64) []byte {
	var sb bytes.Buffer

	// Section 1: — vindex/v1 —
	sb.WriteString("— vindex/v1 —\n")
	sb.Write(bytes.TrimRight(rawCheckpoint, "\n"))
	sb.WriteString("\n\n")

	// Section 2: — output-log-leaf-v1 <leaf_index> —
	fmt.Fprintf(&sb, "— output-log-leaf-v1 %d —\n", outputLogIndex)
	sb.WriteString(hex.EncodeToString(mapRoot[:]))
	sb.WriteString("\n")
	sb.Write(bytes.TrimRight(rawInputLogCP, "\n"))
	sb.WriteString("\n\n")

	// Section 3: — output-log-proof-v1 —
	sb.WriteString("— output-log-proof-v1 —\n")
	for _, p := range outputLogProof {
		sb.WriteString(base64.StdEncoding.EncodeToString(p[:]))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	if !exists {
		sb.WriteString("— mpt-proof-v1 non-inclusion —\n")
		sb.WriteString(base64.StdEncoding.EncodeToString(mptProof))
		sb.WriteString("\n\n")

		sb.WriteString("— indices-v1 —\n")
		return sb.Bytes()
	}

	sb.WriteString("— mpt-proof-v1 inclusion —\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(mptProof))
	sb.WriteString("\n\n")

	if prefixCoveredSize > 0 {
		fmt.Fprintf(&sb, "— prefix-compact-range-v1 %d —\n", prefixCoveredSize)
		for _, h := range prefixHashes {
			sb.WriteString(base64.StdEncoding.EncodeToString(h[:]))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	if nextBefore != nil {
		fmt.Fprintf(&sb, "— indices-v1 %d —\n", *nextBefore)
	} else {
		sb.WriteString("— indices-v1 —\n")
	}
	for _, idx := range matchedIndices {
		sb.WriteString(strconv.FormatUint(idx, 10))
		sb.WriteString("\n")
	}

	return sb.Bytes()
}

var emptyRoot = sha256.Sum256(nil)

// EmptyRoot returns the RFC 6962 root hash of an empty tree (SHA256("")).
func EmptyRoot() [sha256.Size]byte {
	return emptyRoot
}

// LeafHash computes the RFC 6962 standard leaf hash: SHA256(0x00 || data).
// For leaves up to 511 bytes (including all 8-byte index leaves in VIndex),
// an inline stack buffer avoids heap allocations.
func LeafHash(data []byte) [sha256.Size]byte {
	if len(data) <= 511 {
		var b [512]byte
		b[0] = 0x00
		copy(b[1:], data)
		return sha256.Sum256(b[:1+len(data)])
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

// InteriorHash computes the RFC 6962 standard interior node hash: SHA256(0x01 || left || right).
func InteriorHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	var b [1 + 2*sha256.Size]byte
	b[0] = 0x01
	copy(b[1:], left[:])
	copy(b[1+sha256.Size:], right[:])
	return sha256.Sum256(b[:])
}

// ComputeMiniLogRoot reconstructs the RFC 6962 mini-log root from a prefix compact range
// and a slice of strictly ascending uint64 leaf indices.
func ComputeMiniLogRoot(prefixHashes [][sha256.Size]byte, prefixCoveredSize uint64, indices []uint64) ([sha256.Size]byte, error) {
	if (prefixCoveredSize == 0) != (len(prefixHashes) == 0) {
		return [sha256.Size]byte{}, fmt.Errorf("mismatched prefix-compact-range: coveredSize=%d, hashes=%d", prefixCoveredSize, len(prefixHashes))
	}
	if len(prefixHashes) == 0 && len(indices) == 0 {
		return EmptyRoot(), nil
	}

	rf := &compact.RangeFactory{
		Hash: func(l, r []byte) []byte {
			if len(l) == sha256.Size && len(r) == sha256.Size {
				var left, right [sha256.Size]byte
				copy(left[:], l)
				copy(right[:], r)
				h := InteriorHash(left, right)
				out := make([]byte, sha256.Size)
				copy(out, h[:])
				return out
			}
			return rfc6962.DefaultHasher.HashChildren(l, r)
		},
	}

	var cr *compact.Range
	if prefixCoveredSize > 0 {
		hashes := make([][]byte, len(prefixHashes))
		for i := range prefixHashes {
			hashes[i] = prefixHashes[i][:]
		}
		var err error
		cr, err = rf.NewRange(0, prefixCoveredSize, hashes)
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("invalid prefix range: %w", err)
		}
	} else {
		cr = rf.NewEmptyRange(0)
	}

	for _, idx := range indices {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		lh := LeafHash(b[:])
		if err := cr.Append(lh[:], nil); err != nil {
			return [sha256.Size]byte{}, err
		}
	}

	r, err := cr.GetRootHash(nil)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var root [sha256.Size]byte
	copy(root[:], r)
	return root, nil
}
