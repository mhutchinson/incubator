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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/internal/kvstore"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/incubator/vindex/v1/wire"
	"golang.org/x/net/publicsuffix"
)

// FormatKeysResponse builds the plain-text C2SP response for GET /vindex/v1/keys/{key...}[?prefix=true].
// mode must be one of "inclusion", "non-inclusion", or "prefix".
func FormatKeysResponse(state *tree.ServingState, mode string, proof []byte, matches []tree.PrefixKeyVal) []byte {
	return wire.FormatKeysResponse(state.RawCheckpoint, state.OutputLogIndex, state.MapRoot, state.RawInputLogCP, state.OutputLogProof, mode, proof, matches)
}

// FormatEntriesResponse builds the plain-text C2SP response for GET /vindex/v1/entries/{key...}?before=X[&limit=Y].
func FormatEntriesResponse(matchedIndices []uint64, prefixCR *kvstore.CompactRange, nextBefore *uint64) []byte {
	var coveredSize uint64
	var hashes [][sha256.Size]byte
	if prefixCR != nil {
		coveredSize = prefixCR.CoveredSize
		hashes = prefixCR.Hashes
	}
	return wire.FormatEntriesResponse(matchedIndices, coveredSize, hashes, nextBefore)
}

// PrefixPolicy validates whether a prefix query (?prefix=true) is permitted.
type PrefixPolicy func(prefix string) error

// AllowAllPrefixPolicy permits any valid canonical key prefix.
func AllowAllPrefixPolicy(_ string) error {
	return nil
}

// DisallowPrefixPolicy rejects all prefix queries.
func DisallowPrefixPolicy(prefix string) error {
	return fmt.Errorf("prefix queries are disabled on this server (prefix %q)", prefix)
}

// DomainETLDP1PrefixPolicy enforces that a reversed-label domain prefix ends with a trailing '.'
// and contains at least a registrable eTLD+1 boundary according to the Mozilla Public Suffix List,
// rejecting bare TLDs or public suffixes such as "com.", "uk.co.", or "io.github.".
func DomainETLDP1PrefixPolicy(prefix string) error {
	if !strings.HasSuffix(prefix, ".") {
		return fmt.Errorf("domain prefix %q must terminate with a trailing dot '.'", prefix)
	}
	trimmed := strings.TrimSuffix(prefix, ".")
	if trimmed == "" {
		return errors.New("domain prefix cannot be empty")
	}
	labels := strings.Split(trimmed, ".")
	// If the last reversed label is a wildcard "*", strip it when checking the parent domain's eTLD+1.
	if len(labels) > 0 && labels[len(labels)-1] == "*" {
		labels = labels[:len(labels)-1]
	}
	if len(labels) == 0 {
		return fmt.Errorf("domain prefix %q must contain a registrable domain before wildcard", prefix)
	}
	reversed := make([]string, len(labels))
	for i, lbl := range labels {
		if !isValidDNSLabel(lbl) {
			return fmt.Errorf("domain prefix %q contains invalid DNS label %q", prefix, lbl)
		}
		reversed[len(labels)-1-i] = lbl
	}
	forwardDomain := strings.Join(reversed, ".")
	etld1, err := publicsuffix.EffectiveTLDPlusOne(forwardDomain)
	if err != nil || etld1 == "" {
		return fmt.Errorf("domain prefix %q (domain %q) is broader than a registrable eTLD+1 boundary: %v", prefix, forwardDomain, err)
	}
	return nil
}

func isValidDNSLabel(lbl string) bool {
	if len(lbl) == 0 || len(lbl) > 63 {
		return false
	}
	if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
		return false
	}
	for i := 0; i < len(lbl); i++ {
		c := lbl[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// ParsePrefixPolicy resolves a prefix policy name ("allow", "domain", "none") to a PrefixPolicy function.
func ParsePrefixPolicy(name string) (PrefixPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "allow", "all":
		return AllowAllPrefixPolicy, nil
	case "domain", "etld+1", "psl":
		return DomainETLDP1PrefixPolicy, nil
	case "none", "disallow", "off":
		return DisallowPrefixPolicy, nil
	default:
		return nil, fmt.Errorf("unknown prefix policy %q (expected allow, domain, or none)", name)
	}
}

func parseCanonicalKey(r *http.Request, routePrefixes []string) (string, error) {
	escapedPath := r.URL.EscapedPath()
	var keyEscaped string
	matched := false
	for _, prefix := range routePrefixes {
		if strings.HasPrefix(escapedPath, prefix) {
			keyEscaped = strings.TrimPrefix(escapedPath, prefix)
			matched = true
			break
		}
		if strings.HasPrefix(r.URL.Path, prefix) {
			keyEscaped = strings.TrimPrefix(r.URL.Path, prefix)
			matched = true
			break
		}
	}
	if !matched || keyEscaped == "" {
		return "", errors.New("missing key in URL path")
	}
	keyStr, err := url.PathUnescape(keyEscaped)
	if err != nil {
		return "", fmt.Errorf("invalid URL-escaped key: %w", err)
	}
	if err := tree.ValidateCanonicalKey([]byte(keyStr)); err != nil {
		return "", err
	}
	return keyStr, nil
}

// FormatResponse builds the standardized plain-text C2SP response for lookup results.
func FormatResponse(state *tree.ServingState, proof []byte, exists bool, matchedIndices []uint64, prefixCR *kvstore.CompactRange, nextBefore *uint64) []byte {
	var coveredSize uint64
	var hashes [][sha256.Size]byte
	if prefixCR != nil {
		coveredSize = prefixCR.CoveredSize
		hashes = prefixCR.Hashes
	}
	return wire.FormatLookupResponse(state.RawCheckpoint, state.OutputLogIndex, state.MapRoot, state.RawInputLogCP, state.OutputLogProof, proof, exists, matchedIndices, coveredSize, hashes, nextBefore)
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
