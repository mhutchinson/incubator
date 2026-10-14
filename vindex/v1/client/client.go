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

// Package client provides client verification library and HTTP client for the Verifiable Index.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/v1/internal/verifier"
	"github.com/transparency-dev/incubator/vindex/v1/wire"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// KeySubRoot is an alias for wire.KeySubRoot.
type KeySubRoot = wire.KeySubRoot

var (
	ErrMissingSection       = errors.New("missing mandatory section in response")
	ErrInvalidSectionHeader = errors.New("invalid section header format")
	ErrCheckpointFailed     = errors.New("checkpoint verification failed")
	ErrInclusionFailed      = errors.New("inclusion proof verification failed")
	ErrMPTFailed            = errors.New("mpt proof verification failed")
	ErrIndexOrder           = errors.New("indices are not strictly monotonically increasing")
	ErrIndexRange           = errors.New("index outside valid bounds [start, InputLogSize)")
	ErrNonInclusionNotEmpty = errors.New("non-inclusion response returned non-empty indices")
)

// VerifierConfig holds the origins and verifiers for cryptographic validation.
type VerifierConfig struct {
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
}

// KeysResponse represents a verified response from GET /vindex/v1/keys/{key...}.
type KeysResponse struct {
	QueryKey      string
	IsPrefix      bool
	Exists        bool
	Keys          []KeySubRoot
	OutputLogSize uint64
	InputLogSize  uint64
	MapRoot       [32]byte
	RawInputLogCP []byte
}

// EntriesResponse represents a verified response from GET /vindex/v1/entries/{key...}.
type EntriesResponse struct {
	Indices         []uint64
	NextBefore      *uint64
	PrefixCoveredSz uint64
	PrefixHashes    [][sha256.Size]byte
	MiniLogRoot     [32]byte
}

// NextExpectedSubRoot computes the expected sub-root for the next backward pagination page.
func (r *EntriesResponse) NextExpectedSubRoot() ([32]byte, error) {
	if r == nil || r.NextBefore == nil || r.PrefixCoveredSz == 0 {
		return [32]byte{}, nil
	}
	return wire.ComputeMiniLogRoot(r.PrefixHashes, r.PrefixCoveredSz, nil)
}

// PrefixKeyResult holds the verified mini-log root and all leaf indices for a single key matched by a prefix lookup.
type PrefixKeyResult struct {
	Key         string
	MiniLogRoot [32]byte
	Indices     []uint64
}

// PrefixLookupResponse holds the verified results of a full prefix lookup across /vindex/v1/keys/ and /vindex/v1/entries/.
type PrefixLookupResponse struct {
	Prefix        string
	Results       []PrefixKeyResult
	OutputLogSize uint64
	InputLogSize  uint64
	MapRoot       [32]byte
	RawInputLogCP []byte
}

// LookupResponse represents a verified lookup result.
type LookupResponse struct {
	Key             string
	KeyHash         [32]byte
	Exists          bool
	Indices         []uint64
	NextBefore      *uint64
	PrefixCoveredSz uint64
	PrefixHashes    [][sha256.Size]byte
	OutputLogSize   uint64
	InputLogSize    uint64
	MapRoot         [32]byte
	MiniLogRoot     [32]byte
	RawInputLogCP   []byte
}

// NextExpectedSubRoot computes the expected sub-root for the next backward pagination page.
func (r *LookupResponse) NextExpectedSubRoot() ([32]byte, error) {
	if r == nil || r.NextBefore == nil || r.PrefixCoveredSz == 0 {
		return [32]byte{}, nil
	}
	return wire.ComputeMiniLogRoot(r.PrefixHashes, r.PrefixCoveredSz, nil)
}

// Verifier verifies plain-text C2SP lookup responses from VIndex servers.
type Verifier struct {
	cfg VerifierConfig
}

// NewVerifier creates a new Verifier instance.
func NewVerifier(cfg VerifierConfig) *Verifier {
	return &Verifier{cfg: cfg}
}

// ParseVerifier parses a verifier string or file path into a note.Verifier.
// It supports standard note format ("<name>+<hash>+<key>") and MTC format
// ("mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>").
func ParseVerifier(keyOrPath string) (note.Verifier, error) {
	return verifier.ParseVerifier(keyOrPath)
}

func (v *Verifier) verifyStateCommitment(sections map[string]wire.Section) (outCP *log.Checkpoint, inCP *log.Checkpoint, mapRoot [32]byte, rawInCP []byte, err error) {
	// 1. Output Log Checkpoint (— vindex/v1 —)
	vindexSec, ok := sections["vindex/v1"]
	if !ok {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: vindex/v1", ErrMissingSection)
	}
	rawOutCP := bytes.TrimSpace(vindexSec.Body)
	if len(rawOutCP) > 0 && rawOutCP[len(rawOutCP)-1] != '\n' {
		rawOutCP = append(rawOutCP, '\n')
	}
	if v.cfg.OutputLogVerifier != nil {
		parsed, _, _, err := log.ParseCheckpoint(rawOutCP, v.cfg.OutputLogOrigin, v.cfg.OutputLogVerifier)
		if err != nil {
			return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: output log checkpoint signature invalid: %v", ErrCheckpointFailed, err)
		}
		outCP = parsed
	} else {
		parsed, err := wire.ParseCheckpointHeader(rawOutCP)
		if err != nil {
			return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: output log checkpoint header invalid: %v", ErrCheckpointFailed, err)
		}
		outCP = parsed
	}

	// 2. Output Log Leaf (— output-log-leaf-v1 <leaf_index> —)
	leafSec, ok := sections["output-log-leaf-v1"]
	if !ok {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: output-log-leaf-v1", ErrMissingSection)
	}
	leafIdx, err := strconv.ParseUint(strings.TrimSpace(leafSec.Arg), 10, 64)
	if err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("invalid leaf index argument %q in output-log-leaf-v1: %w", leafSec.Arg, err)
	}
	leafBody := bytes.TrimSpace(leafSec.Body)

	// 3. Output Log Inclusion Proof (— output-log-proof-v1 —)
	proofSec, ok := sections["output-log-proof-v1"]
	if !ok {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: output-log-proof-v1", ErrMissingSection)
	}
	var outProof [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(proofSec.Body)), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		h, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, nil, [32]byte{}, nil, fmt.Errorf("failed to base64 decode output log proof line %q: %w", l, err)
		}
		outProof = append(outProof, h)
	}

	var inCPHeader *log.Checkpoint
	mapRoot, inCPHeader, rawInCP, err = wire.ParseOutputLogLeaf(leafBody)
	if err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("output-log-leaf-v1 malformed: %w", err)
	}
	rawLeafData := wire.FormatOutputLogLeaf(mapRoot, rawInCP)

	// Verify Output Log inclusion
	leafHash := rfc6962.DefaultHasher.HashLeaf(rawLeafData)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, leafIdx, outCP.Size, leafHash, outProof, outCP.Hash); err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: output log inclusion proof invalid: %v", ErrInclusionFailed, err)
	}
	if v.cfg.InputLogVerifier != nil {
		origin := v.cfg.InputLogOrigin
		if origin == "" {
			origin = v.cfg.InputLogVerifier.Name()
		}
		parsed, _, _, err := log.ParseCheckpoint(rawInCP, origin, v.cfg.InputLogVerifier)
		if err != nil {
			return nil, nil, [32]byte{}, nil, fmt.Errorf("%w: input log checkpoint signature invalid: %v", ErrCheckpointFailed, err)
		}
		inCP = parsed
	} else {
		inCP = inCPHeader
	}
	return outCP, inCP, mapRoot, rawInCP, nil
}

// VerifyKeysResponse verifies a raw response body from GET /vindex/v1/keys/{key...}[?prefix=true].
func (v *Verifier) VerifyKeysResponse(ctx context.Context, queryKey string, isPrefix bool, rawBody []byte) (*KeysResponse, error) {
	sections, err := wire.ParseSections(rawBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response sections: %w", err)
	}

	outCP, inCP, mapRoot, rawInCP, err := v.verifyStateCommitment(sections)
	if err != nil {
		return nil, err
	}

	// 4. MPT Proof (— mpt-proof-v1 <inclusion|non-inclusion|prefix> —)
	mptSec, ok := sections["mpt-proof-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: mpt-proof-v1", ErrMissingSection)
	}
	proofType := strings.TrimSpace(mptSec.Arg)
	mptProofBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(mptSec.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode mpt proof: %w", err)
	}

	// 5. Keys (— keys-v1 —)
	keysSec, ok := sections["keys-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: keys-v1", ErrMissingSection)
	}
	var keys []KeySubRoot
	for _, line := range strings.Split(strings.TrimSpace(string(keysSec.Body)), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		parts := strings.Fields(l)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line in keys-v1 %q: expected '<key> <subRootHex>'", l)
		}
		kStr, subRootHex := parts[0], parts[1]
		if len(subRootHex) != 64 {
			return nil, fmt.Errorf("invalid subRoot hex length in keys-v1 %q", l)
		}
		subRootBytes, err := hex.DecodeString(subRootHex)
		if err != nil {
			return nil, fmt.Errorf("invalid subRoot hex in keys-v1 %q: %w", l, err)
		}
		var subRoot [32]byte
		copy(subRoot[:], subRootBytes)
		keys = append(keys, KeySubRoot{
			Key:     kStr,
			SubRoot: subRoot,
		})
	}

	if !isPrefix {
		if proofType == "non-inclusion" {
			if len(keys) > 0 {
				return nil, fmt.Errorf("%w: got %d keys in non-inclusion response", ErrNonInclusionNotEmpty, len(keys))
			}
			if err := mpt.VerifyKey(mapRoot, []byte(queryKey), [32]byte{}, false, mptProofBytes); err != nil {
				return nil, fmt.Errorf("%w: non-inclusion proof verification failed: %v", ErrMPTFailed, err)
			}
			return &KeysResponse{
				QueryKey:      queryKey,
				IsPrefix:      false,
				Exists:        false,
				Keys:          nil,
				OutputLogSize: outCP.Size,
				InputLogSize:  inCP.Size,
				MapRoot:       mapRoot,
				RawInputLogCP: rawInCP,
			}, nil
		}
		if proofType != "inclusion" {
			return nil, fmt.Errorf("unexpected mpt proof type %q for point lookup", proofType)
		}
		if len(keys) != 1 || keys[0].Key != queryKey {
			return nil, fmt.Errorf("%w: inclusion response must contain exactly 1 matching key %q, got %d", ErrMPTFailed, queryKey, len(keys))
		}
		if err := mpt.VerifyKey(mapRoot, []byte(queryKey), keys[0].SubRoot, true, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: inclusion proof verification failed: %v", ErrMPTFailed, err)
		}
		return &KeysResponse{
			QueryKey:      queryKey,
			IsPrefix:      false,
			Exists:        true,
			Keys:          keys,
			OutputLogSize: outCP.Size,
			InputLogSize:  inCP.Size,
			MapRoot:       mapRoot,
			RawInputLogCP: rawInCP,
		}, nil
	}

	// Prefix lookup verification (two-sided: HasPrefix + strict ascending Key.Compare + TreeHash + VerifyPrefix)
	if proofType != "prefix" {
		return nil, fmt.Errorf("unexpected mpt proof type %q for prefix lookup", proofType)
	}
	if err := mpt.VerifyPrefix(mapRoot, []byte(queryKey), keys, mptProofBytes); err != nil {
		return nil, fmt.Errorf("%w: prefix proof verification failed: %v", ErrMPTFailed, err)
	}
	return &KeysResponse{
		QueryKey:      queryKey,
		IsPrefix:      true,
		Exists:        len(keys) > 0,
		Keys:          keys,
		OutputLogSize: outCP.Size,
		InputLogSize:  inCP.Size,
		MapRoot:       mapRoot,
		RawInputLogCP: rawInCP,
	}, nil
}

// VerifyEntriesResponse verifies a raw response body from GET /vindex/v1/entries/{key...}?before=X against expectedSubRoot.
func (v *Verifier) VerifyEntriesResponse(ctx context.Context, before uint64, expectedSubRoot [32]byte, rawBody []byte) (*EntriesResponse, error) {
	if expectedSubRoot == ([32]byte{}) {
		return nil, fmt.Errorf("%w: VerifyEntriesResponse requires a non-zero expectedSubRoot", ErrMPTFailed)
	}
	sections, err := wire.ParseSections(rawBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entries response sections: %w", err)
	}
	return v.verifyEntriesSections(sections, before, expectedSubRoot)
}

func (v *Verifier) verifyEntriesSections(sections map[string]wire.Section, upperBound uint64, expectedSubRoot [32]byte) (*EntriesResponse, error) {
	indicesSec, ok := sections["indices-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: indices-v1", ErrMissingSection)
	}
	var nextBefore *uint64
	if arg := strings.TrimSpace(indicesSec.Arg); arg != "" {
		nb, err := strconv.ParseUint(arg, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid next_before in indices-v1 argument %q: %w", arg, err)
		}
		nextBefore = &nb
	}

	var indices []uint64
	for _, line := range strings.Split(strings.TrimSpace(string(indicesSec.Body)), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		idx, err := strconv.ParseUint(l, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid index in indices-v1 line %q: %w", l, err)
		}
		indices = append(indices, idx)
	}

	// Validate indices ordering and bounds
	for j, idx := range indices {
		if idx >= upperBound {
			return nil, fmt.Errorf("%w: index %d >= upperBound %d", ErrIndexRange, idx, upperBound)
		}
		if j > 0 && idx <= indices[j-1] {
			return nil, fmt.Errorf("%w: index %d <= previous %d", ErrIndexOrder, idx, indices[j-1])
		}
	}

	var prefixHashes [][sha256.Size]byte
	var prefixCoveredSize uint64
	if pcrSec, ok := sections["prefix-compact-range-v1"]; ok {
		arg := strings.TrimSpace(pcrSec.Arg)
		if arg == "" {
			return nil, fmt.Errorf("missing covered_size argument in prefix-compact-range-v1")
		}
		sz, err := strconv.ParseUint(arg, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid size in prefix-compact-range-v1 %q: %w", arg, err)
		}
		prefixCoveredSize = sz
		for _, line := range strings.Split(strings.TrimSpace(string(pcrSec.Body)), "\n") {
			l := strings.TrimSpace(line)
			if l == "" {
				continue
			}
			h, err := base64.StdEncoding.DecodeString(l)
			if err != nil || len(h) != sha256.Size {
				return nil, fmt.Errorf("invalid base64 hash in prefix-compact-range-v1 %q: %w", l, err)
			}
			var arr [sha256.Size]byte
			copy(arr[:], h)
			prefixHashes = append(prefixHashes, arr)
		}
	}

	// Enforce compact range and pagination invariants (Backlog 2.6.2)
	if (prefixCoveredSize == 0) != (len(prefixHashes) == 0) {
		return nil, fmt.Errorf("mismatched prefix-compact-range-v1: coveredSize=%d with %d hashes", prefixCoveredSize, len(prefixHashes))
	}
	if prefixCoveredSize > upperBound || uint64(len(indices)) > upperBound-prefixCoveredSize {
		return nil, fmt.Errorf("%w: total entries (%d + %d) exceed upperBound %d", ErrIndexRange, prefixCoveredSize, len(indices), upperBound)
	}
	if nextBefore == nil {
		if prefixCoveredSize > 0 || len(prefixHashes) > 0 {
			return nil, fmt.Errorf("truncated response: next_before is nil but prefix-compact-range-v1 has coveredSize=%d", prefixCoveredSize)
		}
	} else {
		if prefixCoveredSize == 0 || len(prefixHashes) == 0 {
			return nil, fmt.Errorf("invalid continuation: next_before=%d but prefix-compact-range-v1 is empty", *nextBefore)
		}
		if len(indices) == 0 || indices[0] != *nextBefore {
			return nil, fmt.Errorf("invalid next_before=%d: must equal first returned index", *nextBefore)
		}
	}

	computedMiniLogRoot, err := wire.ComputeMiniLogRoot(prefixHashes, prefixCoveredSize, indices)
	if err != nil {
		return nil, fmt.Errorf("failed to compute mini-log root: %w", err)
	}
	if expectedSubRoot != ([32]byte{}) && computedMiniLogRoot != expectedSubRoot {
		return nil, fmt.Errorf("%w: continuation mini-log root mismatch: got %x, want %x", ErrMPTFailed, computedMiniLogRoot, expectedSubRoot)
	}

	return &EntriesResponse{
		Indices:         indices,
		NextBefore:      nextBefore,
		PrefixCoveredSz: prefixCoveredSize,
		PrefixHashes:    prefixHashes,
		MiniLogRoot:     computedMiniLogRoot,
	}, nil
}

// VerifyResponse verifies a combined response body against the given search keyHash and before bound.
// When before != nil, expectedSubRoot must be provided to authenticate the continuation page (Backlog 2.6.1).
func (v *Verifier) VerifyResponse(ctx context.Context, keyHash [32]byte, before *uint64, rawBody []byte, expectedSubRoot ...[32]byte) (*LookupResponse, error) {
	sections, err := wire.ParseSections(rawBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response sections: %w", err)
	}

	outCP, inCP, mapRoot, rawInCP, err := v.verifyStateCommitment(sections)
	if err != nil {
		return nil, err
	}
	inputLogSize := inCP.Size

	// 4. MPT Proof (— mpt-proof-v1 <inclusion|non-inclusion> —)
	mptSec, ok := sections["mpt-proof-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: mpt-proof-v1", ErrMissingSection)
	}
	proofType := strings.TrimSpace(mptSec.Arg)
	mptProofBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(mptSec.Body)))
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode mpt proof: %w", err)
	}

	// Non-inclusion verification
	if proofType == "non-inclusion" {
		indicesSec, ok := sections["indices-v1"]
		if !ok {
			return nil, fmt.Errorf("%w: indices-v1", ErrMissingSection)
		}
		if strings.TrimSpace(string(indicesSec.Body)) != "" {
			return nil, fmt.Errorf("%w: non-empty indices in non-inclusion response", ErrNonInclusionNotEmpty)
		}
		if _, ok := sections["prefix-compact-range-v1"]; ok {
			return nil, fmt.Errorf("non-inclusion response must not contain prefix-compact-range-v1")
		}
		if err := mpt.Verify(mapRoot, keyHash, [sha256.Size]byte{}, false, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: non-inclusion proof verification failed: %v", ErrMPTFailed, err)
		}
		return &LookupResponse{
			Key:           hex.EncodeToString(keyHash[:]),
			KeyHash:       keyHash,
			Exists:        false,
			Indices:       nil,
			NextBefore:    nil,
			OutputLogSize: outCP.Size,
			InputLogSize:  inputLogSize,
			MapRoot:       mapRoot,
			MiniLogRoot:   emptyRoot(),
			RawInputLogCP: rawInCP,
		}, nil
	}

	if proofType != "inclusion" {
		return nil, fmt.Errorf("unknown mpt proof type %q", proofType)
	}

	upperBound := inputLogSize
	var wantSubRoot [32]byte
	if before != nil {
		if len(expectedSubRoot) == 0 || expectedSubRoot[0] == ([32]byte{}) {
			return nil, fmt.Errorf("%w: expectedSubRoot is required when before != nil", ErrMPTFailed)
		}
		wantSubRoot = expectedSubRoot[0]
		if *before < upperBound {
			upperBound = *before
		}
	}

	entriesResp, err := v.verifyEntriesSections(sections, upperBound, wantSubRoot)
	if err != nil {
		return nil, err
	}

	if before == nil {
		if err := mpt.Verify(mapRoot, keyHash, entriesResp.MiniLogRoot, true, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: inclusion proof verification failed: %v", ErrMPTFailed, err)
		}
	}

	return &LookupResponse{
		Key:             hex.EncodeToString(keyHash[:]),
		KeyHash:         keyHash,
		Exists:          true,
		Indices:         entriesResp.Indices,
		NextBefore:      entriesResp.NextBefore,
		PrefixCoveredSz: entriesResp.PrefixCoveredSz,
		PrefixHashes:    entriesResp.PrefixHashes,
		OutputLogSize:   outCP.Size,
		InputLogSize:    inputLogSize,
		MapRoot:         mapRoot,
		MiniLogRoot:     entriesResp.MiniLogRoot,
		RawInputLogCP:   rawInCP,
	}, nil
}

func emptyRoot() [sha256.Size]byte {
	return wire.EmptyRoot()
}

func computeMiniLogRoot(prefixHashes [][sha256.Size]byte, prefixCoveredSize uint64, indices []uint64) ([sha256.Size]byte, error) {
	return wire.ComputeMiniLogRoot(prefixHashes, prefixCoveredSize, indices)
}

// Client performs verified lookups against a VIndex HTTP endpoint.
type Client struct {
	baseURL    *url.URL
	verifier   *Verifier
	httpClient *http.Client
}

// New creates a new VIndex Client.
func New(baseURLStr string, cfg VerifierConfig, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", baseURLStr, err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL:    u,
		verifier:   NewVerifier(cfg),
		httpClient: httpClient,
	}, nil
}

// NewClient creates a new VIndex Client (alias for New).
func NewClient(baseURLStr string, cfg VerifierConfig, httpClient *http.Client) (*Client, error) {
	return New(baseURLStr, cfg, httpClient)
}

func (c *Client) endpointURL(routePrefix, key string) *url.URL {
	u := *c.baseURL
	basePath := strings.TrimSuffix(u.Path, "/")
	baseEscaped := strings.TrimSuffix(u.EscapedPath(), "/")
	u.Path = basePath + routePrefix + key
	u.RawPath = baseEscaped + routePrefix + escapeKeyPath(key)
	return &u
}

func escapeKeyPath(key string) string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		switch seg {
		case ".":
			segs[i] = "%2E"
		case "..":
			segs[i] = "%2E%2E"
		default:
			segs[i] = url.PathEscape(seg)
		}
	}
	return strings.Join(segs, "/")
}

// LookupKeys queries GET /vindex/v1/keys/{key...}[?prefix=true] and verifies the state commitment and MPT proof.
func (c *Client) LookupKeys(ctx context.Context, key string, isPrefix bool) (*KeysResponse, error) {
	u := c.endpointURL("/vindex/v1/keys/", key)
	if isPrefix {
		q := u.Query()
		q.Set("prefix", "true")
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct keys request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return c.verifier.VerifyKeysResponse(ctx, key, isPrefix, body)
}

// LookupPrefix queries GET /vindex/v1/keys/{prefix...}?prefix=true and verifies the two-sided MPT prefix proof.
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*KeysResponse, error) {
	return c.LookupKeys(ctx, prefix, true)
}

// LookupEntries queries GET /vindex/v1/entries/{key...}?before=X[&limit=Y] and verifies the returned page against expectedSubRoot.
func (c *Client) LookupEntries(ctx context.Context, key string, before uint64, limit uint64, expectedSubRoot [32]byte) (*EntriesResponse, error) {
	if expectedSubRoot == ([32]byte{}) {
		return nil, fmt.Errorf("%w: expectedSubRoot is required for LookupEntries", ErrMPTFailed)
	}
	u := c.endpointURL("/vindex/v1/entries/", key)
	q := u.Query()
	q.Set("before", strconv.FormatUint(before, 10))
	if limit > 0 {
		q.Set("limit", strconv.FormatUint(limit, 10))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct entries request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read entries response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return c.verifier.VerifyEntriesResponse(ctx, before, expectedSubRoot, body)
}

// LookupKey queries the VIndex server for the canonical key using the two-endpoint protocol and verifies all cryptographic proofs.
// When before != nil, expectedSubRoot must be provided from the preceding page's NextExpectedSubRoot() (Backlog 2.6.1).
func (c *Client) LookupKey(ctx context.Context, key string, before *uint64, limit uint64, expectedSubRoot ...[32]byte) (*LookupResponse, error) {
	kh := sha256.Sum256([]byte(key))
	if before != nil {
		if len(expectedSubRoot) == 0 || expectedSubRoot[0] == ([32]byte{}) {
			return nil, fmt.Errorf("%w: expectedSubRoot is required when before != nil", ErrMPTFailed)
		}
		entriesResp, err := c.LookupEntries(ctx, key, *before, limit, expectedSubRoot[0])
		if err != nil {
			return nil, err
		}
		return &LookupResponse{
			Key:             key,
			KeyHash:         kh,
			Exists:          true,
			Indices:         entriesResp.Indices,
			NextBefore:      entriesResp.NextBefore,
			PrefixCoveredSz: entriesResp.PrefixCoveredSz,
			PrefixHashes:    entriesResp.PrefixHashes,
			InputLogSize:    *before,
			MiniLogRoot:     entriesResp.MiniLogRoot,
		}, nil
	}

	keysResp, err := c.LookupKeys(ctx, key, false)
	if err != nil {
		return nil, err
	}
	if !keysResp.Exists {
		return &LookupResponse{
			Key:           key,
			KeyHash:       kh,
			Exists:        false,
			Indices:       nil,
			NextBefore:    nil,
			OutputLogSize: keysResp.OutputLogSize,
			InputLogSize:  keysResp.InputLogSize,
			MapRoot:       keysResp.MapRoot,
			MiniLogRoot:   emptyRoot(),
			RawInputLogCP: keysResp.RawInputLogCP,
		}, nil
	}

	subRoot := keysResp.Keys[0].SubRoot
	entriesResp, err := c.LookupEntries(ctx, key, keysResp.InputLogSize, limit, subRoot)
	if err != nil {
		return nil, err
	}
	return &LookupResponse{
		Key:             key,
		KeyHash:         kh,
		Exists:          true,
		Indices:         entriesResp.Indices,
		NextBefore:      entriesResp.NextBefore,
		PrefixCoveredSz: entriesResp.PrefixCoveredSz,
		PrefixHashes:    entriesResp.PrefixHashes,
		OutputLogSize:   keysResp.OutputLogSize,
		InputLogSize:    keysResp.InputLogSize,
		MapRoot:         keysResp.MapRoot,
		MiniLogRoot:     entriesResp.MiniLogRoot,
		RawInputLogCP:   keysResp.RawInputLogCP,
	}, nil
}

// Lookup queries the VIndex server for the given 32-byte keyHash (encoded as 64-character lowercase hex) and verifies all cryptographic proofs.
// When before != nil, expectedSubRoot must be provided from the preceding page's NextExpectedSubRoot() (Backlog 2.6.1).
func (c *Client) Lookup(ctx context.Context, keyHash [sha256.Size]byte, before *uint64, limit uint64, expectedSubRoot ...[32]byte) (*LookupResponse, error) {
	hexKey := hex.EncodeToString(keyHash[:])
	resp, err := c.LookupKey(ctx, hexKey, before, limit, expectedSubRoot...)
	if err != nil {
		return nil, err
	}
	resp.KeyHash = keyHash
	return resp, nil
}

func (c *Client) paginateAllEntries(ctx context.Context, key string, inputLogSize uint64, subRoot [32]byte, pageSize uint64) ([]uint64, error) {
	if pageSize == 0 {
		pageSize = 100
	}
	before := inputLogSize
	expectedRoot := subRoot
	var allIndices []uint64

	for {
		entriesResp, err := c.LookupEntries(ctx, key, before, pageSize, expectedRoot)
		if err != nil {
			return nil, err
		}
		allIndices = append(slices.Clone(entriesResp.Indices), allIndices...)
		if entriesResp.NextBefore == nil {
			break
		}
		nextRoot, err := entriesResp.NextExpectedSubRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to compute prefix root: %w", err)
		}
		expectedRoot = nextRoot
		before = *entriesResp.NextBefore
	}
	return allIndices, nil
}

// LookupAllKey verifies the key in the MPT via GET /vindex/v1/keys/{key...} and follows backward pagination
// across GET /vindex/v1/entries/{key...} until all historical indices are retrieved and verified.
func (c *Client) LookupAllKey(ctx context.Context, key string, pageSize uint64) (*LookupResponse, error) {
	kh := sha256.Sum256([]byte(key))
	keysResp, err := c.LookupKeys(ctx, key, false)
	if err != nil {
		return nil, err
	}
	if !keysResp.Exists {
		return &LookupResponse{
			Key:           key,
			KeyHash:       kh,
			Exists:        false,
			Indices:       nil,
			NextBefore:    nil,
			OutputLogSize: keysResp.OutputLogSize,
			InputLogSize:  keysResp.InputLogSize,
			MapRoot:       keysResp.MapRoot,
			MiniLogRoot:   emptyRoot(),
			RawInputLogCP: keysResp.RawInputLogCP,
		}, nil
	}

	subRoot := keysResp.Keys[0].SubRoot
	allIndices, err := c.paginateAllEntries(ctx, key, keysResp.InputLogSize, subRoot, pageSize)
	if err != nil {
		return nil, err
	}

	return &LookupResponse{
		Key:           key,
		KeyHash:       kh,
		Exists:        true,
		Indices:       allIndices,
		NextBefore:    nil,
		OutputLogSize: keysResp.OutputLogSize,
		InputLogSize:  keysResp.InputLogSize,
		MapRoot:       keysResp.MapRoot,
		MiniLogRoot:   subRoot,
		RawInputLogCP: keysResp.RawInputLogCP,
	}, nil
}

// LookupAll follows backward pagination for a 32-byte keyHash (encoded as 64-character lowercase hex)
// until all historical indices are retrieved and verified.
func (c *Client) LookupAll(ctx context.Context, keyHash [sha256.Size]byte, pageSize uint64) (*LookupResponse, error) {
	hexKey := hex.EncodeToString(keyHash[:])
	resp, err := c.LookupAllKey(ctx, hexKey, pageSize)
	if err != nil {
		return nil, err
	}
	resp.KeyHash = keyHash
	return resp, nil
}

// LookupPrefixAll discovers all keys matching prefix via GET /vindex/v1/keys/{prefix...}?prefix=true,
// verifies the two-sided MPT prefix proof, and retrieves and verifies all mini-log indices for each matched key.
func (c *Client) LookupPrefixAll(ctx context.Context, prefix string, pageSize uint64) (*PrefixLookupResponse, error) {
	keysResp, err := c.LookupPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	results := make([]PrefixKeyResult, 0, len(keysResp.Keys))
	for _, ke := range keysResp.Keys {
		indices, err := c.paginateAllEntries(ctx, ke.Key, keysResp.InputLogSize, ke.SubRoot, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch entries for key %q: %w", ke.Key, err)
		}
		results = append(results, PrefixKeyResult{
			Key:         ke.Key,
			MiniLogRoot: ke.SubRoot,
			Indices:     indices,
		})
	}
	return &PrefixLookupResponse{
		Prefix:        prefix,
		Results:       results,
		OutputLogSize: keysResp.OutputLogSize,
		InputLogSize:  keysResp.InputLogSize,
		MapRoot:       keysResp.MapRoot,
		RawInputLogCP: keysResp.RawInputLogCP,
	}, nil
}

// GetCheckpoint retrieves the latest Output Log checkpoint from the vindexd server.
func (c *Client) GetCheckpoint(ctx context.Context) ([]byte, error) {
	u := c.baseURL.JoinPath("vindex", "v1", "checkpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetInputLogCheckpoint retrieves the latest Input Log checkpoint from the vindexd server.
func (c *Client) GetInputLogCheckpoint(ctx context.Context) ([]byte, error) {
	u := c.baseURL.JoinPath("vindex", "v1", "inputlog_checkpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// NewVIndexClient returns a VIndexClient for the given base URL and verifiers.
func NewVIndexClient(vindexUrl string, inV, outV note.Verifier) (*VIndexClient, error) {
	return NewVIndexClientWithOrigin(vindexUrl, inV, outV, "")
}

// NewVIndexClientWithOrigin returns a VIndexClient with origin override.
func NewVIndexClientWithOrigin(vindexUrl string, inV, outV note.Verifier, inLogOrigin string) (*VIndexClient, error) {
	viu, err := url.Parse(vindexUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	return &VIndexClient{
		inV:         inV,
		outV:        outV,
		inLogOrigin: inLogOrigin,
		client:      &Client{baseURL: viu, verifier: NewVerifier(VerifierConfig{OutputLogVerifier: outV, InputLogVerifier: inV, InputLogOrigin: inLogOrigin}), httpClient: http.DefaultClient},
	}, nil
}

// VIndexClient provides lookup methods.
type VIndexClient struct {
	inV, outV   note.Verifier
	inLogOrigin string
	client      *Client
}

// Lookup returns all indices where key appears in the Input Log using full cryptographic verification.
func (c VIndexClient) Lookup(ctx context.Context, key string) ([]uint64, []byte, error) {
	resp, err := c.client.LookupAllKey(ctx, key, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup failed: %w", err)
	}
	return resp.Indices, resp.RawInputLogCP, nil
}

// NewInputLogClient creates an InputLogClient for dereferencing pointers.
func NewInputLogClient(inLogUrl string, origin string, inV note.Verifier, hc *http.Client) (*InputLogClient, error) {
	u, err := url.Parse(inLogUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	c, err := tclient.NewHTTPFetcher(u, hc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP fetcher for %q: %v", u, err)
	}
	return &InputLogClient{
		v:      inV,
		origin: origin,
		lc:     c,
	}, nil
}

// InputLogClient fetches and verifies original Input Log entries.
type InputLogClient struct {
	v      note.Verifier
	origin string
	lc     logClient
}

// Dereference takes pointers and returns an iterator over verified InputLogLeaf entries.
func (c *InputLogClient) Dereference(ctx context.Context, cpRaw []byte, pointers []uint64) iter.Seq2[InputLogLeaf, error] {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, c.origin, c.v)
	if err != nil {
		return func(yield func(InputLogLeaf, error) bool) {
			yield(InputLogLeaf{}, fmt.Errorf("failed to parse input log checkpoint: %v", err))
		}
	}
	pb, err := tclient.NewProofBuilder(ctx, cp.Size, c.lc.ReadTile)
	if err != nil {
		return func(yield func(InputLogLeaf, error) bool) {
			yield(InputLogLeaf{}, fmt.Errorf("failed to parse input log checkpoint: %v", err))
		}
	}
	return func(yield func(InputLogLeaf, error) bool) {
		var cache leafBundleCache
		for _, i := range pointers {
			if i >= cp.Size {
				yield(InputLogLeaf{}, fmt.Errorf("requested leaf %d >= log size %d", i, cp.Size))
				return
			}
			ip, err := pb.InclusionProof(ctx, i)
			if err != nil {
				yield(InputLogLeaf{}, fmt.Errorf("failed to get inclusion proof: %v", err))
				return
			}

			var entry []byte
			if entry = cache.get(i); entry == nil {
				bundle, err := tclient.GetEntryBundle(ctx, c.lc.ReadEntryBundle, i/layout.EntryBundleWidth, cp.Size)
				if err != nil {
					yield(InputLogLeaf{}, fmt.Errorf("failed to get entry bundle: %v", err))
					return
				}
				ti := i % layout.EntryBundleWidth
				cache = leafBundleCache{
					start:  i - ti,
					leaves: bundle.Entries,
				}
				entry = cache.leaves[ti]
			}

			lh := rfc6962.DefaultHasher.HashLeaf(entry)
			if err := proof.VerifyInclusion(rfc6962.DefaultHasher, i, cp.Size, lh, ip, cp.Hash); err != nil {
				yield(InputLogLeaf{}, fmt.Errorf("failed to verify inclusion proof: %v", err))
				return
			}

			if !yield(InputLogLeaf{i, entry}, nil) {
				return
			}
		}
	}
}

// InputLogLeaf is an entry in the Input Log.
type InputLogLeaf struct {
	Index uint64
	Data  []byte
}

type leafBundleCache struct {
	start  uint64
	leaves [][]byte
}

func (tc leafBundleCache) get(i uint64) []byte {
	end := tc.start + uint64(len(tc.leaves))
	if i >= tc.start && i < end {
		return tc.leaves[i-tc.start]
	}
	return nil
}

type logClient interface {
	ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error)
}
