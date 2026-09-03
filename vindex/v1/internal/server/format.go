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

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

// FormatResponse builds the standardized plain-text C2SP response for lookup results.
func FormatResponse(state *tree.ServingState, proof []byte, exists bool, matchedIndices []uint64, prefixCR *kvstore.CompactRange, nextBefore *uint64) []byte {
	var sb bytes.Buffer

	// Section 1: — vindex/v1 —
	sb.WriteString("— vindex/v1 —\n")
	sb.Write(bytes.TrimRight(state.RawCheckpoint, "\n"))
	sb.WriteString("\n\n")

	// Section 2: — output-log-leaf-v1 <leaf_index> —
	fmt.Fprintf(&sb, "— output-log-leaf-v1 %d —\n", state.OutputLogIndex)
	sb.WriteString(hex.EncodeToString(state.MapRoot[:]))
	sb.WriteString("\n")
	sb.Write(bytes.TrimRight(state.RawInputLogCP, "\n"))
	sb.WriteString("\n\n")

	// Section 3: — output-log-proof-v1 —
	sb.WriteString("— output-log-proof-v1 —\n")
	for _, p := range state.OutputLogProof {
		sb.WriteString(base64.StdEncoding.EncodeToString(p[:]))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	if !exists {
		// Non-inclusion response
		sb.WriteString("— mpt-proof-v1 non-inclusion —\n")
		sb.WriteString(base64.StdEncoding.EncodeToString(proof))
		sb.WriteString("\n\n")

		sb.WriteString("— indices-v1 —\n")
		return sb.Bytes()
	}

	// Inclusion response
	sb.WriteString("— mpt-proof-v1 inclusion —\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(proof))
	sb.WriteString("\n\n")

	// Section 5: — prefix-compact-range-v1 —
	if prefixCR != nil && prefixCR.CoveredSize > 0 {
		fmt.Fprintf(&sb, "— prefix-compact-range-v1 %d —\n", prefixCR.CoveredSize)
		for _, h := range prefixCR.Hashes {
			sb.WriteString(base64.StdEncoding.EncodeToString(h[:]))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Section 6: — indices-v1 [next_before] —
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

var hexKeyRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

func parseKeyHash(r *http.Request) ([sha256.Size]byte, error) {
	path := r.URL.Path
	var keyStr string
	for _, prefix := range []string{"/vindex/v1/lookup/", "/vindex/lookup/", "/lookup/"} {
		if strings.HasPrefix(path, prefix) {
			keyStr = strings.TrimPrefix(path, prefix)
			break
		}
	}
	keyStr = strings.TrimSpace(keyStr)
	if keyStr == "" {
		return [sha256.Size]byte{}, fmt.Errorf("missing keyhash in URL path")
	}

	if !hexKeyRegexp.MatchString(keyStr) {
		return [sha256.Size]byte{}, fmt.Errorf("key must be a 64-char lowercase hex string, got %q", keyStr)
	}

	b, err := hex.DecodeString(keyStr)
	if err != nil || len(b) != sha256.Size {
		return [sha256.Size]byte{}, fmt.Errorf("invalid hex keyhash: %w", err)
	}

	return [sha256.Size]byte(b), nil
}
