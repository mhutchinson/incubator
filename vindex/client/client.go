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

// Package client provides a lightweight verification library and HTTP client for VIndex.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"filippo.io/torchwood"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// KeyValueRoot is an alias for wire.KeyValueRoot.
type KeyValueRoot = wire.KeyValueRoot

var (
	ErrInvalidRequest      = errors.New("invalid client request")
	ErrMalformedResponse   = errors.New("malformed response")
	ErrMissingSection      = errors.New("missing mandatory section in response")
	ErrCheckpointFailed    = errors.New("checkpoint verification failed")
	ErrCheckpointRegressed = errors.New("checkpoint size regressed")
	ErrConsistencyFault    = errors.New("state consistency fault")
	ErrCryptographicFault  = errors.New("cryptographic verification fault")
	ErrInclusionFailed     = errors.New("inclusion proof verification failed")
	ErrMPTFailed           = errors.New("mpt proof verification failed")
	ErrIndexOrder          = errors.New("indices are not strictly monotonically increasing")
	ErrIndexRange          = errors.New("index outside valid bounds [from, before)")
	ErrNotFound            = errors.New("not found")
	ErrTooManyKeys         = errors.New("prefix matched too many keys")
	ErrUnavailable         = errors.New("server unavailable")
)

// VerifierConfig holds C2SP tlog-policy verifiers and optional map-fn pinning for stateless proof validation.
type VerifierConfig struct {
	OutputLogPolicy torchwood.Policy
	InputLogPolicy  torchwood.Policy
	ExpectedMapFn   *[sha256.Size]byte
}

// SingleKeyPolicy constructs an origin-bound single-key torchwood.Policy.
func SingleKeyPolicy(origin string, v note.Verifier) (torchwood.Policy, error) {
	return wire.BuildPolicy(origin, v, nil, 0)
}

// WitnessPolicy constructs an origin-bound torchwood.Policy requiring the primary log signature
// plus at least threshold distinct witness cosignatures.
func WitnessPolicy(origin string, v note.Verifier, witnesses []note.Verifier, threshold int) (torchwood.Policy, error) {
	return wire.BuildPolicy(origin, v, witnesses, threshold)
}

// KeysResponse represents a verified response from GET <index-url>/keys?key=<key> or ?prefix=<prefix>.
type KeysResponse struct {
	QueryKey         string
	Mode             string // "inclusion", "non-inclusion", or "prefix"
	Keys             []KeyValueRoot
	MPTRoot          [sha256.Size]byte
	MapFn            [sha256.Size]byte
	From             uint64
	OutputSize       uint64
	OutputRoot       [sha256.Size]byte
	InputSize        uint64
	InputRoot        [sha256.Size]byte
	InputCheckpoint  []byte
	OutputCheckpoint []byte
}

// ValuesResponse represents a verified response from GET <index-url>/values?key=<key>&before=<before>.
type ValuesResponse struct {
	Preceding    uint64
	CompactRange [][sha256.Size]byte
	Indices      []uint64
	ValueRoot    [sha256.Size]byte
}

// NextPage folds CompactRange right-to-left when Preceding > 0, returning the next exclusive
// upper bound (Indices[0]) and expected value log root for backward pagination.
func (r *ValuesResponse) NextPage() (before uint64, expectedValueRoot [sha256.Size]byte, ok bool) {
	if r == nil || r.Preceding == 0 || len(r.Indices) == 0 {
		return 0, [sha256.Size]byte{}, false
	}
	vr, err := wire.ComputeValueLogRoot(r.CompactRange, r.Preceding, nil)
	if err != nil {
		return 0, [sha256.Size]byte{}, false
	}
	return r.Indices[0], vr, true
}

// PrefixKeyResult holds the verified value root and all entry indices for a single key matched by a prefix lookup.
type PrefixKeyResult struct {
	Key       string
	ValueRoot [sha256.Size]byte
	Indices   []uint64
}

// PrefixLookupResponse holds the verified results of a full prefix lookup across /keys and /values.
type PrefixLookupResponse struct {
	Prefix     string
	Results    []PrefixKeyResult
	MPTRoot    [sha256.Size]byte
	MapFn      [sha256.Size]byte
	From       uint64
	OutputSize uint64
	OutputRoot [sha256.Size]byte
	InputSize  uint64
	InputRoot  [sha256.Size]byte
}

// VerifyKeysResponse verifies a raw response body from GET <index-url>/keys?key=<target> or ?prefix=<target>.
// It is a pure, stateless function that performs zero network I/O or state mutations.
func VerifyKeysResponse(rawBody []byte, target string, isPrefix bool, cfg VerifierConfig) (*KeysResponse, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		if isPrefix {
			return nil, fmt.Errorf("%w: invalid query prefix %q: %w", ErrInvalidRequest, target, err)
		}
		return nil, fmt.Errorf("%w: invalid query key %q: %w", ErrInvalidRequest, target, err)
	}
	if cfg.OutputLogPolicy == nil {
		return nil, fmt.Errorf("%w: output log policy is required", ErrCheckpointFailed)
	}
	if cfg.InputLogPolicy == nil {
		return nil, fmt.Errorf("%w: input log policy is required", ErrCheckpointFailed)
	}

	stanzas := bytes.SplitN(rawBody, []byte("\n\n"), 2)
	if len(stanzas) != 2 {
		return nil, fmt.Errorf("%w (%w): keys response must contain keys block and proof block", ErrMissingSection, ErrMalformedResponse)
	}

	keysSec, err := wire.ParseKeysSection(stanzas[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse keys section: %w", ErrCryptographicFault, err)
	}
	bindSec, err := wire.ParseBindingSection(stanzas[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse binding section: %w", ErrCryptographicFault, err)
	}

	outCP, _, err := torchwood.VerifyCheckpoint(bindSec.OutSignedCP, cfg.OutputLogPolicy)
	if err != nil {
		return nil, fmt.Errorf("%w: output log checkpoint verification failed: %w", ErrCheckpointFailed, err)
	}
	if outCP.N < 1 {
		return nil, fmt.Errorf("%w (%w): output log checkpoint size is %d, want >= 1", ErrInclusionFailed, ErrCryptographicFault, outCP.N)
	}
	outputSize := uint64(outCP.N)
	if bindSec.OutLeafIdx != outputSize-1 {
		return nil, fmt.Errorf("%w (%w): output log leaf index %d != output_size - 1 (%d)", ErrInclusionFailed, ErrCryptographicFault, bindSec.OutLeafIdx, outputSize-1)
	}

	if err := torchwood.VerifyProof(cfg.OutputLogPolicy, tlog.RecordHash(bindSec.RawOutLeaf), bindSec.RawProofAndCP); err != nil {
		return nil, fmt.Errorf("%w (%w): output log inclusion proof invalid: %w", ErrInclusionFailed, ErrCryptographicFault, err)
	}

	if cfg.ExpectedMapFn != nil && bindSec.MapFn != *cfg.ExpectedMapFn {
		return nil, fmt.Errorf("%w: map-fn hash mismatch: got %x, want %x", ErrCryptographicFault, bindSec.MapFn, *cfg.ExpectedMapFn)
	}

	inCP, _, err := torchwood.VerifyCheckpoint(bindSec.InSignedCP, cfg.InputLogPolicy)
	if err != nil {
		return nil, fmt.Errorf("%w: input log checkpoint verification failed: %w", ErrCheckpointFailed, err)
	}
	if inCP.N < 0 {
		return nil, fmt.Errorf("%w: negative input log checkpoint size %d", ErrCheckpointFailed, inCP.N)
	}
	inputSize := uint64(inCP.N)

	if bindSec.From > inputSize {
		return nil, fmt.Errorf("%w: state commitment from (%d) exceeds input_size (%d)", ErrCryptographicFault, bindSec.From, inputSize)
	}
	if inputSize == bindSec.From && len(keysSec.Matches) > 0 {
		return nil, fmt.Errorf("%w (%w): matched keys returned when input_size (%d) == from (%d)", ErrMPTFailed, ErrCryptographicFault, inputSize, bindSec.From)
	}

	outRoot := [sha256.Size]byte(outCP.Hash)
	inRoot := [sha256.Size]byte(inCP.Hash)
	mptRoot := bindSec.MPTRoot
	mptProofBytes := keysSec.MPTProof
	keys := keysSec.Matches

	if !isPrefix {
		if len(keys) == 0 {
			if err := mpt.VerifyKey(mptRoot, []byte(target), [sha256.Size]byte{}, false, mptProofBytes); err != nil {
				return nil, fmt.Errorf("%w (%w): non-inclusion proof verification failed: %w", ErrMPTFailed, ErrCryptographicFault, err)
			}
			return &KeysResponse{
				QueryKey:         target,
				Mode:             "non-inclusion",
				Keys:             nil,
				MPTRoot:          mptRoot,
				MapFn:            bindSec.MapFn,
				From:             bindSec.From,
				OutputSize:       outputSize,
				OutputRoot:       outRoot,
				InputSize:        inputSize,
				InputRoot:        inRoot,
				InputCheckpoint:  bindSec.InSignedCP,
				OutputCheckpoint: bindSec.OutSignedCP,
			}, nil
		}
		if len(keys) > 1 {
			return nil, fmt.Errorf("%w (%w): point lookup returned %d keys", ErrMPTFailed, ErrCryptographicFault, len(keys))
		}
		if keys[0].Key != target {
			return nil, fmt.Errorf("%w (%w): inclusion response must contain matching key %q, got %q", ErrMPTFailed, ErrCryptographicFault, target, keys[0].Key)
		}
		if err := mpt.VerifyKey(mptRoot, []byte(target), keys[0].ValueRoot, true, mptProofBytes); err != nil {
			return nil, fmt.Errorf("%w (%w): inclusion proof verification failed: %w", ErrMPTFailed, ErrCryptographicFault, err)
		}
		return &KeysResponse{
			QueryKey:         target,
			Mode:             "inclusion",
			Keys:             keys,
			MPTRoot:          mptRoot,
			MapFn:            bindSec.MapFn,
			From:             bindSec.From,
			OutputSize:       outputSize,
			OutputRoot:       outRoot,
			InputSize:        inputSize,
			InputRoot:        inRoot,
			InputCheckpoint:  bindSec.InSignedCP,
			OutputCheckpoint: bindSec.OutSignedCP,
		}, nil
	}

	if err := mpt.VerifyPrefix(mptRoot, []byte(target), keys, mptProofBytes); err != nil {
		return nil, fmt.Errorf("%w (%w): prefix proof verification failed: %w", ErrMPTFailed, ErrCryptographicFault, err)
	}
	return &KeysResponse{
		QueryKey:         target,
		Mode:             "prefix",
		Keys:             keys,
		MPTRoot:          mptRoot,
		MapFn:            bindSec.MapFn,
		From:             bindSec.From,
		OutputSize:       outputSize,
		OutputRoot:       outRoot,
		InputSize:        inputSize,
		InputRoot:        inRoot,
		InputCheckpoint:  bindSec.InSignedCP,
		OutputCheckpoint: bindSec.OutSignedCP,
	}, nil
}

// VerifyValuesResponse verifies a raw response body from GET <index-url>/values?key=<key>&before=<before>
// against expectedValueRoot and the range [from, before).
// It is a pure, stateless function that performs zero network I/O or state mutations.
func VerifyValuesResponse(rawBody []byte, expectedValueRoot [sha256.Size]byte, from, before uint64) (*ValuesResponse, error) {
	if expectedValueRoot == ([sha256.Size]byte{}) {
		return nil, fmt.Errorf("%w (%w): VerifyValuesResponse requires a non-zero expectedValueRoot", ErrMPTFailed, ErrCryptographicFault)
	}
	if before == 0 || from > before {
		return nil, fmt.Errorf("%w (%w): invalid range [%d, %d)", ErrIndexRange, ErrCryptographicFault, from, before)
	}
	if from == before {
		return nil, fmt.Errorf("%w (%w): empty range [%d, %d) cannot contain value entries", ErrIndexRange, ErrCryptographicFault, from, before)
	}

	valSec, err := wire.ParseValuesResponse(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse values response: %w", ErrCryptographicFault, err)
	}
	if len(valSec.Indices) == 0 {
		return nil, fmt.Errorf("%w (%w): values response must contain at least one index", ErrMalformedResponse, ErrCryptographicFault)
	}

	for i := 1; i < len(valSec.Indices); i++ {
		if valSec.Indices[i] <= valSec.Indices[i-1] {
			return nil, fmt.Errorf("%w (%w): index[%d]=%d <= index[%d]=%d", ErrIndexOrder, ErrCryptographicFault, i, valSec.Indices[i], i-1, valSec.Indices[i-1])
		}
	}

	if valSec.Indices[0] < from {
		return nil, fmt.Errorf("%w (%w): first index %d < from %d", ErrIndexRange, ErrCryptographicFault, valSec.Indices[0], from)
	}
	if valSec.Indices[len(valSec.Indices)-1] >= before {
		return nil, fmt.Errorf("%w (%w): index %d >= before %d", ErrIndexRange, ErrCryptographicFault, valSec.Indices[len(valSec.Indices)-1], before)
	}
	if valSec.Preceding > valSec.Indices[0]-from {
		return nil, fmt.Errorf("%w (%w): preceding count (%d) exceeds available range before first index (%d - %d); total entries exceed upperBound %d", ErrIndexRange, ErrCryptographicFault, valSec.Preceding, valSec.Indices[0], from, before)
	}
	if uint64(len(valSec.Indices)) > before-from-valSec.Preceding {
		return nil, fmt.Errorf("%w (%w): total entries (%d + %d) exceed available range [%d, %d)", ErrIndexRange, ErrCryptographicFault, valSec.Preceding, len(valSec.Indices), from, before)
	}

	computedRoot, err := wire.ComputeValueLogRoot(valSec.CompactRange, valSec.Preceding, valSec.Indices)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute value log root: %w", ErrCryptographicFault, err)
	}
	if computedRoot != expectedValueRoot {
		return nil, fmt.Errorf("%w (%w): value log root mismatch: got %x, want %x", ErrMPTFailed, ErrCryptographicFault, computedRoot, expectedValueRoot)
	}

	return &ValuesResponse{
		Preceding:    valSec.Preceding,
		CompactRange: valSec.CompactRange,
		Indices:      valSec.Indices,
		ValueRoot:    computedRoot,
	}, nil
}

// StateTracker enforces O(1) monotonic checkpoint ratcheting, split-view detection,
// and immutable (map-fn, from) parameter constancy across repeated queries.
type StateTracker struct {
	mu          sync.Mutex
	initialized bool
	outSize     uint64
	outRoot     [sha256.Size]byte
	inSize      uint64
	inRoot      [sha256.Size]byte
	mapFn       [sha256.Size]byte
	from        uint64
}

// NewStateTracker creates an empty StateTracker.
func NewStateTracker() *StateTracker {
	return &StateTracker{}
}

// Observe validates checkpoint monotonicity, equal-size root non-equivocation, and (mapFn, from) constancy
// before atomically updating tracked watermarks. A failed Observe never mutates tracker state.
func (st *StateTracker) Observe(
	outputSize uint64,
	outputRoot [sha256.Size]byte,
	inputSize uint64,
	inputRoot [sha256.Size]byte,
	mapFn [sha256.Size]byte,
	from uint64,
) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.initialized {
		if outputSize < st.outSize {
			return fmt.Errorf("%w: output_size regressed from %d to %d", ErrCheckpointRegressed, st.outSize, outputSize)
		}
		if outputSize == st.outSize && outputRoot != st.outRoot {
			return fmt.Errorf("%w: output log split-view at size %d: got %x, want %x", ErrConsistencyFault, outputSize, outputRoot, st.outRoot)
		}
		if inputSize < st.inSize {
			return fmt.Errorf("%w: input_size regressed from %d to %d", ErrCheckpointRegressed, st.inSize, inputSize)
		}
		if inputSize == st.inSize && inputRoot != st.inRoot {
			return fmt.Errorf("%w: input log split-view at size %d: got %x, want %x", ErrConsistencyFault, inputSize, inputRoot, st.inRoot)
		}
		if mapFn != st.mapFn {
			return fmt.Errorf("%w: map-fn changed from %x to %x", ErrConsistencyFault, st.mapFn, mapFn)
		}
		if from != st.from {
			return fmt.Errorf("%w: from changed from %d to %d", ErrConsistencyFault, st.from, from)
		}
	}

	st.initialized = true
	st.outSize = outputSize
	st.outRoot = outputRoot
	st.inSize = inputSize
	st.inRoot = inputRoot
	st.mapFn = mapFn
	st.from = from
	return nil
}

// ObserveKeysResponse ratchets the StateTracker against a verified KeysResponse.
func (st *StateTracker) ObserveKeysResponse(resp *KeysResponse) error {
	if resp == nil {
		return fmt.Errorf("%w: nil KeysResponse", ErrInvalidRequest)
	}
	return st.Observe(resp.OutputSize, resp.OutputRoot, resp.InputSize, resp.InputRoot, resp.MapFn, resp.From)
}

const upperHex = "0123456789ABCDEF"

func isRFC3986Unreserved(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func encodeRFC3986Unreserved(s string) string {
	var needsEncoding bool
	for i := 0; i < len(s); i++ {
		if !isRFC3986Unreserved(s[i]) {
			needsEncoding = true
			break
		}
	}
	if !needsEncoding {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isRFC3986Unreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0F])
		}
	}
	return b.String()
}

// Client performs cryptographically verified lookups against a VIndex HTTP endpoint.
// By default Client is stateless per-request; attach a StateTracker via SetStateTracker for monotonic ratcheting.
type Client struct {
	baseURL    *url.URL
	cfg        VerifierConfig
	tracker    atomic.Pointer[StateTracker]
	httpClient *http.Client
}

// New creates a new VIndex Client targeting indexURL. HTTP redirects (3xx) are rejected per tlog-vindex.
func New(indexURL string, cfg VerifierConfig, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("invalid index URL %q: %w", indexURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: index URL %q must use http or https with a non-empty host", ErrInvalidRequest, indexURL)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clonedClient := *httpClient
	clonedClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("HTTP redirects (3xx) are forbidden by tlog-vindex spec (redirected to %q)", req.URL.String())
	}
	return &Client{
		baseURL:    u,
		cfg:        cfg,
		httpClient: &clonedClient,
	}, nil
}

// SetStateTracker attaches or detaches an optional StateTracker on the Client.
func (c *Client) SetStateTracker(st *StateTracker) {
	c.tracker.Store(st)
}

// StateTracker returns the optional StateTracker currently attached to the Client (nil by default).
func (c *Client) StateTracker() *StateTracker {
	return c.tracker.Load()
}

func (c *Client) queryEndpointURL(routePath string) *url.URL {
	u := *c.baseURL
	basePath := strings.TrimSuffix(u.Path, "/")
	u.Path = basePath + routePath
	u.RawPath = ""
	return &u
}

func appendRawQuery(existing, param string) string {
	if existing == "" {
		return param
	}
	return existing + "&" + param
}

func mapHTTPStatusError(statusCode int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	switch statusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("%w: server returned status 400: %s", ErrInvalidRequest, msg)
	case http.StatusNotFound:
		return fmt.Errorf("%w: server returned status 404: %s", ErrNotFound, msg)
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: server returned status 413: %s", ErrTooManyKeys, msg)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w: server returned status 503: %s", ErrUnavailable, msg)
	default:
		return fmt.Errorf("server returned status %d: %s", statusCode, msg)
	}
}

func (c *Client) lookupKeys(ctx context.Context, target string, isPrefix bool) (*KeysResponse, error) {
	if err := mpt.ValidateCanonicalKey([]byte(target)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	u := c.queryEndpointURL("/keys")
	if isPrefix {
		u.RawQuery = appendRawQuery(u.RawQuery, "prefix="+encodeRFC3986Unreserved(target))
	} else {
		u.RawQuery = appendRawQuery(u.RawQuery, "key="+encodeRFC3986Unreserved(target))
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
		return nil, mapHTTPStatusError(resp.StatusCode, body)
	}

	res, err := VerifyKeysResponse(body, target, isPrefix, c.cfg)
	if err != nil {
		return nil, err
	}
	if st := c.StateTracker(); st != nil {
		if err := st.ObserveKeysResponse(res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// LookupKey queries GET <index-url>/keys?key=<key> and verifies the state commitment and MPT proof.
func (c *Client) LookupKey(ctx context.Context, key string) (*KeysResponse, error) {
	return c.lookupKeys(ctx, key, false)
}

// LookupPrefix queries GET <index-url>/keys?prefix=<prefix> and verifies the two-sided MPT prefix proof.
func (c *Client) LookupPrefix(ctx context.Context, prefix string) (*KeysResponse, error) {
	return c.lookupKeys(ctx, prefix, true)
}

// LookupValues queries GET <index-url>/values?key=<key>&before=<before>[&limit=<limit>] and verifies
// the returned page against expectedValueRoot and [from, before).
func (c *Client) LookupValues(
	ctx context.Context,
	key string,
	expectedValueRoot [sha256.Size]byte,
	from, before, limit uint64,
) (*ValuesResponse, error) {
	if err := mpt.ValidateCanonicalKey([]byte(key)); err != nil {
		return nil, fmt.Errorf("%w: invalid key %q: %w", ErrInvalidRequest, key, err)
	}
	if expectedValueRoot == ([sha256.Size]byte{}) {
		return nil, fmt.Errorf("%w (%w): expectedValueRoot is required for LookupValues", ErrMPTFailed, ErrCryptographicFault)
	}
	if before == 0 || from >= before {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrInvalidRequest, from, before)
	}

	u := c.queryEndpointURL("/values")
	rawQuery := "key=" + encodeRFC3986Unreserved(key) + "&before=" + strconv.FormatUint(before, 10)
	if limit > 0 {
		rawQuery += "&limit=" + strconv.FormatUint(limit, 10)
	}
	u.RawQuery = appendRawQuery(u.RawQuery, rawQuery)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct values request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", u.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read values response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, mapHTTPStatusError(resp.StatusCode, body)
	}

	return VerifyValuesResponse(body, expectedValueRoot, from, before)
}

func (c *Client) paginateAllValues(
	ctx context.Context,
	key string,
	from, inputSize uint64,
	valueRoot [sha256.Size]byte,
	pageSize uint64,
) ([]uint64, error) {
	before := inputSize
	expectedRoot := valueRoot
	var allIndices []uint64

	for {
		page, err := c.LookupValues(ctx, key, expectedRoot, from, before, pageSize)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: unexpected HTTP 404 on promised value log page for key %q (before=%d): %w", ErrCryptographicFault, key, before, err)
			}
			return nil, err
		}
		allIndices = append(slices.Clone(page.Indices), allIndices...)
		nextBefore, nextRoot, ok := page.NextPage()
		if !ok {
			break
		}
		before = nextBefore
		expectedRoot = nextRoot
	}
	return allIndices, nil
}

// LookupAllValues queries GET <index-url>/keys?key=<key> and walks backward pagination across
// GET <index-url>/values until all matching Input Log entry indices in [from, InputSize) are retrieved
// and verified in strictly ascending order.
func (c *Client) LookupAllValues(ctx context.Context, key string, pageSize uint64) ([]uint64, error) {
	keysResp, err := c.LookupKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(keysResp.Keys) == 0 {
		return nil, nil
	}
	return c.paginateAllValues(ctx, key, keysResp.From, keysResp.InputSize, keysResp.Keys[0].ValueRoot, pageSize)
}

// LookupPrefixAll discovers all keys matching prefix via GET <index-url>/keys?prefix=<prefix>,
// verifies the two-sided MPT prefix proof, and walks backward /values pagination for each matched key.
func (c *Client) LookupPrefixAll(ctx context.Context, prefix string, pageSize uint64) (*PrefixLookupResponse, error) {
	keysResp, err := c.LookupPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	results := make([]PrefixKeyResult, 0, len(keysResp.Keys))
	for _, ke := range keysResp.Keys {
		indices, err := c.paginateAllValues(ctx, ke.Key, keysResp.From, keysResp.InputSize, ke.ValueRoot, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch values for key %q: %w", ke.Key, err)
		}
		results = append(results, PrefixKeyResult{
			Key:       ke.Key,
			ValueRoot: ke.ValueRoot,
			Indices:   indices,
		})
	}
	return &PrefixLookupResponse{
		Prefix:     prefix,
		Results:    results,
		MPTRoot:    keysResp.MPTRoot,
		MapFn:      keysResp.MapFn,
		From:       keysResp.From,
		OutputSize: keysResp.OutputSize,
		OutputRoot: keysResp.OutputRoot,
		InputSize:  keysResp.InputSize,
		InputRoot:  keysResp.InputRoot,
	}, nil
}
