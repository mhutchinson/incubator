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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

const (
	// PathLookup defines the legacy path prefix for lookup.
	PathLookup = "/lookup/"
)

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

// LegacyLookupResponse describes the MVP API lookup result for backward compatibility.
type LegacyLookupResponse struct {
	OutputLogCP    []byte              `json:"output_log_cp"`
	OutputLogLeaf  []byte              `json:"output_log_leaf"`
	OutputLogProof [][sha256.Size]byte `json:"output_log_proof"`
	IndexValue     []uint64            `json:"index_value"`
	IndexProof     []byte              `json:"index_proof"`
}

// VerifierConfig holds the origins and verifiers for cryptographic validation.
type VerifierConfig struct {
	OutputLogOrigin   string
	OutputLogVerifier note.Verifier
	InputLogOrigin    string
	InputLogVerifier  note.Verifier
}

// LookupResponse represents a verified lookup result.
type LookupResponse struct {
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

// Verifier verifies plain-text C2SP lookup responses from VIndex servers.
type Verifier struct {
	cfg VerifierConfig
}

// NewVerifier creates a new Verifier instance.
func NewVerifier(cfg VerifierConfig) *Verifier {
	return &Verifier{cfg: cfg}
}

type section struct {
	name string
	arg  string
	body []byte
}

// VerifyResponse verifies a raw response body against the given search keyHash and before bound.
func (v *Verifier) VerifyResponse(ctx context.Context, keyHash [32]byte, before *uint64, rawBody []byte) (*LookupResponse, error) {
	sections, err := parseSections(rawBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response sections: %w", err)
	}

	// 1. Output Log Checkpoint (— vindex/v1 —)
	vindexSec, ok := sections["vindex/v1"]
	if !ok {
		return nil, fmt.Errorf("%w: vindex/v1", ErrMissingSection)
	}
	rawOutCP := bytes.TrimSpace(vindexSec.body)
	if len(rawOutCP) > 0 && rawOutCP[len(rawOutCP)-1] != '\n' {
		rawOutCP = append(rawOutCP, '\n')
	}
	var outCP *log.Checkpoint
	if v.cfg.OutputLogVerifier != nil {
		parsed, _, _, err := log.ParseCheckpoint(rawOutCP, v.cfg.OutputLogOrigin, v.cfg.OutputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("%w: output log checkpoint signature invalid: %v", ErrCheckpointFailed, err)
		}
		outCP = parsed
	} else {
		parsed, err := tree.ParseCheckpointHeader(rawOutCP)
		if err != nil {
			return nil, fmt.Errorf("%w: output log checkpoint header invalid: %v", ErrCheckpointFailed, err)
		}
		outCP = parsed
	}

	// 2. Output Log Leaf (— output-log-leaf-v1 <leaf_index> —)
	leafSec, ok := sections["output-log-leaf-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: output-log-leaf-v1", ErrMissingSection)
	}
	leafIdx, err := strconv.ParseUint(strings.TrimSpace(leafSec.arg), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid leaf index argument %q in output-log-leaf-v1: %w", leafSec.arg, err)
	}
	leafBody := bytes.TrimSpace(leafSec.body)

	// 3. Output Log Inclusion Proof (— output-log-proof-v1 —)
	proofSec, ok := sections["output-log-proof-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: output-log-proof-v1", ErrMissingSection)
	}
	var outProof [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(proofSec.body)), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		h, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode output log proof line %q: %w", l, err)
		}
		outProof = append(outProof, h)
	}

	mapRoot, inCPHeader, rawInCP, err := tree.ParseOutputLogLeaf(leafBody)
	if err != nil {
		return nil, fmt.Errorf("output-log-leaf-v1 malformed: %w", err)
	}
	rawLeafData := tree.FormatOutputLogLeaf(mapRoot, rawInCP)

	// Verify Output Log inclusion
	leafHash := rfc6962.DefaultHasher.HashLeaf(rawLeafData)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, leafIdx, outCP.Size, leafHash, outProof, outCP.Hash); err != nil {
		return nil, fmt.Errorf("%w: output log inclusion proof invalid: %v", ErrInclusionFailed, err)
	}
	var inCP *log.Checkpoint
	if v.cfg.InputLogVerifier != nil {
		origin := v.cfg.InputLogOrigin
		if origin == "" {
			origin = v.cfg.InputLogVerifier.Name()
		}
		parsed, _, _, err := log.ParseCheckpoint(rawInCP, origin, v.cfg.InputLogVerifier)
		if err != nil {
			return nil, fmt.Errorf("%w: input log checkpoint signature invalid: %v", ErrCheckpointFailed, err)
		}
		inCP = parsed
	} else {
		inCP = inCPHeader
	}
	inputLogSize := inCP.Size

	// 4. MPT Proof (— mpt-proof-v1 <inclusion|non-inclusion> —)
	mptSec, ok := sections["mpt-proof-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: mpt-proof-v1", ErrMissingSection)
	}
	proofType := strings.TrimSpace(mptSec.arg)
	mptProofBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(mptSec.body)))
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode mpt proof: %w", err)
	}

	// 5. Indices (— indices-v1 [next_before] —)
	indicesSec, ok := sections["indices-v1"]
	if !ok {
		return nil, fmt.Errorf("%w: indices-v1", ErrMissingSection)
	}
	var nextBefore *uint64
	if arg := strings.TrimSpace(indicesSec.arg); arg != "" {
		nb, err := strconv.ParseUint(arg, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid next_before in indices-v1 argument %q: %w", arg, err)
		}
		nextBefore = &nb
	}

	var indices []uint64
	for _, line := range strings.Split(strings.TrimSpace(string(indicesSec.body)), "\n") {
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

	// Non-inclusion verification
	if proofType == "non-inclusion" {
		if len(indices) > 0 {
			return nil, fmt.Errorf("%w: got %d indices", ErrNonInclusionNotEmpty, len(indices))
		}
		if _, ok := sections["prefix-compact-range-v1"]; ok {
			return nil, fmt.Errorf("non-inclusion response must not contain prefix-compact-range-v1")
		}
		if err := tree.Verify(mapRoot, keyHash, [sha256.Size]byte{}, false, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: non-inclusion proof verification failed: %v", ErrMPTFailed, err)
		}
		return &LookupResponse{
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

	// Inclusion verification
	if proofType != "inclusion" {
		return nil, fmt.Errorf("unknown mpt proof type %q", proofType)
	}

	// Validate indices ordering and bounds
	upperBound := inputLogSize
	if before != nil && *before < upperBound {
		upperBound = *before
	}
	for j, idx := range indices {
		if idx >= upperBound {
			return nil, fmt.Errorf("%w: index %d >= upperBound %d", ErrIndexRange, idx, upperBound)
		}
		if j > 0 && idx <= indices[j-1] {
			return nil, fmt.Errorf("%w: index %d <= previous %d", ErrIndexOrder, idx, indices[j-1])
		}
	}

	// 6. Prefix Compact Range
	var prefixHashes [][sha256.Size]byte
	var prefixCoveredSize uint64
	if pcrSec, ok := sections["prefix-compact-range-v1"]; ok {
		if arg := strings.TrimSpace(pcrSec.arg); arg != "" {
			sz, err := strconv.ParseUint(arg, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid size in prefix-compact-range-v1 %q: %w", arg, err)
			}
			prefixCoveredSize = sz
		}
		for _, line := range strings.Split(strings.TrimSpace(string(pcrSec.body)), "\n") {
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

	// Compute mini-log root from compact range + indices
	computedMiniLogRoot, err := computeMiniLogRoot(prefixHashes, prefixCoveredSize, indices)
	if err != nil {
		return nil, fmt.Errorf("failed to compute mini-log root: %w", err)
	}

	// Verify MPT inclusion proof against MapRoot for tip queries (before == nil)
	if before == nil {
		if err := tree.Verify(mapRoot, keyHash, computedMiniLogRoot, true, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w: inclusion proof verification failed: %v", ErrMPTFailed, err)
		}
	}

	return &LookupResponse{
		KeyHash:         keyHash,
		Exists:          true,
		Indices:         indices,
		NextBefore:      nextBefore,
		PrefixCoveredSz: prefixCoveredSize,
		PrefixHashes:    prefixHashes,
		OutputLogSize:   outCP.Size,
		InputLogSize:    inputLogSize,
		MapRoot:         mapRoot,
		MiniLogRoot:     computedMiniLogRoot,
		RawInputLogCP:   rawInCP,
	}, nil
}

func emptyRoot() [sha256.Size]byte {
	h := rfc6962.DefaultHasher.EmptyRoot()
	var out [sha256.Size]byte
	copy(out[:], h)
	return out
}

func leafHash(data []byte) [sha256.Size]byte {
	h := rfc6962.DefaultHasher.HashLeaf(data)
	var out [sha256.Size]byte
	copy(out[:], h)
	return out
}

func computeMiniLogRoot(prefixHashes [][sha256.Size]byte, prefixCoveredSize uint64, indices []uint64) ([sha256.Size]byte, error) {
	if len(prefixHashes) == 0 && len(indices) == 0 {
		return emptyRoot(), nil
	}

	rf := &compact.RangeFactory{
		Hash: rfc6962.DefaultHasher.HashChildren,
	}

	var cr *compact.Range
	if len(prefixHashes) > 0 && prefixCoveredSize > 0 {
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
		lh := leafHash(b[:])
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

func parseSections(body []byte) (map[string]section, error) {
	lines := strings.Split(string(body), "\n")
	sections := make(map[string]section)

	var currentName string
	var currentArg string
	var currentLines []string

	flush := func() {
		if currentName != "" {
			sections[currentName] = section{
				name: currentName,
				arg:  currentArg,
				body: []byte(strings.Join(currentLines, "\n")),
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

// Lookup queries the VIndex server for the given keyHash and verifies all cryptographic proofs.
func (c *Client) Lookup(ctx context.Context, keyHash [sha256.Size]byte, before *uint64, limit uint64) (*LookupResponse, error) {
	hexKeyHash := hex.EncodeToString(keyHash[:])
	u := c.baseURL.JoinPath("vindex", "v1", "lookup", hexKeyHash)
	q := u.Query()
	if before != nil {
		q.Set("before", strconv.FormatUint(*before, 10))
	}
	if limit > 0 {
		q.Set("limit", strconv.FormatUint(limit, 10))
	}
	u.RawQuery = q.Encode()

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

	return c.verifier.VerifyResponse(ctx, keyHash, before, body)
}

// LookupKey hashes the string key with SHA-256 and calls Lookup.
func (c *Client) LookupKey(ctx context.Context, key string, before *uint64, limit uint64) (*LookupResponse, error) {
	keyHash := sha256.Sum256([]byte(key))
	return c.Lookup(ctx, keyHash, before, limit)
}

// LookupAll follows backward pagination until all historical indices are retrieved.
// It verifies the MPT proof on the tip page (Page 1) and verifies compact range continuity
// across all subsequent pages back to the beginning of the log.
func (c *Client) LookupAll(ctx context.Context, keyHash [sha256.Size]byte, pageSize uint64) (*LookupResponse, error) {
	if pageSize == 0 {
		pageSize = 100
	}
	var before *uint64
	var allIndices []uint64
	var firstResp *LookupResponse
	var expectedMiniLogRoot *[sha256.Size]byte

	for {
		resp, err := c.Lookup(ctx, keyHash, before, pageSize)
		if err != nil {
			return nil, err
		}
		if !resp.Exists {
			return resp, nil
		}

		if firstResp == nil {
			firstResp = resp
			if resp.NextBefore != nil && resp.PrefixCoveredSz > 0 {
				prefixRoot, err := computeMiniLogRoot(resp.PrefixHashes, resp.PrefixCoveredSz, nil)
				if err != nil {
					return nil, fmt.Errorf("failed to compute prefix root: %w", err)
				}
				expectedMiniLogRoot = &prefixRoot
			}
		} else {
			if expectedMiniLogRoot == nil {
				return nil, fmt.Errorf("unexpected continuation page")
			}
			if resp.MiniLogRoot != *expectedMiniLogRoot {
				return nil, fmt.Errorf("continuation mini-log root mismatch: got %x, want %x", resp.MiniLogRoot, *expectedMiniLogRoot)
			}
			if resp.NextBefore != nil && resp.PrefixCoveredSz > 0 {
				prefixRoot, err := computeMiniLogRoot(resp.PrefixHashes, resp.PrefixCoveredSz, nil)
				if err != nil {
					return nil, fmt.Errorf("failed to compute prefix root: %w", err)
				}
				expectedMiniLogRoot = &prefixRoot
			} else {
				expectedMiniLogRoot = nil
			}
		}

		allIndices = append(slices.Clone(resp.Indices), allIndices...)
		if resp.NextBefore == nil {
			break
		}
		before = resp.NextBefore
	}

	firstResp.Indices = allIndices
	firstResp.NextBefore = nil
	return firstResp, nil
}

// LookupAllKey hashes the key string and calls LookupAll.
func (c *Client) LookupAllKey(ctx context.Context, key string, pageSize uint64) (*LookupResponse, error) {
	keyHash := sha256.Sum256([]byte(key))
	return c.LookupAll(ctx, keyHash, pageSize)
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

// VerifyLookupResponse is the MVP verification helper.
func VerifyLookupResponse(keyHash [sha256.Size]byte, resp LegacyLookupResponse, inV, outV note.Verifier, inLogOrigin string) ([]uint64, []byte, error) {
	olcp, _, _, err := log.ParseCheckpoint(resp.OutputLogCP, outV.Name(), outV)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse output log checkpoint: %v", err)
	}
	outLeafHash := rfc6962.DefaultHasher.HashLeaf(resp.OutputLogLeaf)
	olp := make([][]byte, len(resp.OutputLogProof))
	for i := range olp {
		olp[i] = resp.OutputLogProof[i][:]
	}
	oli := olcp.Size - 1
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, oli, olcp.Size, outLeafHash[:], olp, olcp.Hash); err != nil {
		return nil, nil, fmt.Errorf("failed to verify inclusion in output log: %v", err)
	}

	// Leaf format: MapRoot hex + \n + InputLogCP
	mapRoot, _, inCp, err := tree.ParseOutputLogLeaf(resp.OutputLogLeaf)
	if err != nil {
		return nil, nil, fmt.Errorf("output log leaf malformed: %w", err)
	}

	origin := inLogOrigin
	if origin == "" {
		origin = inV.Name()
	}
	ilcp, _, _, err := log.ParseCheckpoint(inCp, origin, inV)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse input log checkpoint: %v", err)
	}

	rf := &compact.RangeFactory{
		Hash: rfc6962.DefaultHasher.HashChildren,
	}
	cr := rf.NewEmptyRange(0)
	for _, idx := range resp.IndexValue {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], idx)
		lh := leafHash(b[:])
		_ = cr.Append(lh[:], nil)
	}
	miniLogRootBytes, _ := cr.GetRootHash(nil)
	var miniLogRoot [sha256.Size]byte
	copy(miniLogRoot[:], miniLogRootBytes)

	expectFound := len(resp.IndexValue) > 0
	if err := tree.Verify(mapRoot, keyHash, miniLogRoot, expectFound, resp.IndexProof); err != nil {
		// Fallback for legacy MVP linear hash
		sum := sha256.New()
		for _, idx := range resp.IndexValue {
			_ = binary.Write(sum, binary.BigEndian, idx)
		}
		var linearHash [sha256.Size]byte
		copy(linearHash[:], sum.Sum(nil))
		if err2 := tree.Verify(mapRoot, keyHash, linearHash, expectFound, resp.IndexProof); err2 != nil {
			return nil, nil, fmt.Errorf("tree.Verify(): %v (ilcp.Size=%d)", err, ilcp.Size)
		}
	}

	return resp.IndexValue, inCp, nil
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
	lookupURL := viu.JoinPath(PathLookup)

	return &VIndexClient{
		lookupURL:   lookupURL,
		inV:         inV,
		outV:        outV,
		inLogOrigin: inLogOrigin,
		client:      &Client{baseURL: viu, verifier: NewVerifier(VerifierConfig{OutputLogVerifier: outV, InputLogVerifier: inV, InputLogOrigin: inLogOrigin}), httpClient: http.DefaultClient},
	}, nil
}

// VIndexClient provides lookup methods.
type VIndexClient struct {
	lookupURL   *url.URL
	inV, outV   note.Verifier
	inLogOrigin string
	client      *Client
}

// Lookup returns all indices where key appears in the Input Log.
func (c VIndexClient) Lookup(ctx context.Context, key string) ([]uint64, []byte, error) {
	kh := sha256.Sum256([]byte(key))
	resp, err := c.client.Lookup(ctx, kh, nil, 0)
	if err != nil {
		// Fallback to legacy unverified API endpoint if needed
		legacyResp, lErr := c.lookupUnverified(ctx, kh)
		if lErr == nil {
			return VerifyLookupResponse(kh, legacyResp, c.inV, c.outV, c.inLogOrigin)
		}
		return nil, nil, fmt.Errorf("lookup failed: %v", err)
	}
	return resp.Indices, resp.RawInputLogCP, nil
}

func (c VIndexClient) lookupUnverified(ctx context.Context, kh [sha256.Size]byte) (LegacyLookupResponse, error) {
	var lookupResp LegacyLookupResponse
	u := c.lookupURL.JoinPath(hex.EncodeToString(kh[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to get URL %q: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return lookupResp, fmt.Errorf("got non-200 status code: %d, body: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return lookupResp, fmt.Errorf("failed to read response body: %v", err)
	}
	if err := json.Unmarshal(body, &lookupResp); err != nil {
		return lookupResp, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return lookupResp, nil
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
