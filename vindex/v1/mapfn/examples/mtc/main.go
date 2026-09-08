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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o mtc.wasm ."

// Package main implements the MTC (Merkle Tree Certificates) WASM MapFn plugin.
package main

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
	"golang.org/x/net/publicsuffix"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapMTCLeaf)
}

type etldCacheEntry struct {
	domain string
	etld1  string
}

const etldCacheSize = 256

// etldCache is a 256-slot direct-mapped cache for EffectiveTLDPlusOne lookups.
//
// Performance rationale:
// 1. publicsuffix.EffectiveTLDPlusOne internally calls netip.ParseAddr on every domain name.
//    Because valid hostnames are not IP addresses, this allocates an error value on every call.
// 2. It then performs a binary search (find) across the compiled Mozilla Public Suffix List trie.
// 3. CT/MTC certificate logs exhibit high domain locality (e.g. repeated apexes like cloudflare.com).
//    A direct-mapped cache reduces ~1,000ns trie walks to ~5ns lookups and eliminates heap churn.
var etldCache [etldCacheSize]etldCacheEntry

// getETLD1 retrieves the eTLD+1 for a domain using the direct-mapped cache.
// On cache hit, unsafe.String enables non-allocating string comparison against the cached domain.
// A heap string is only allocated on initial cache miss to populate the persistent slot.
func getETLD1(cnBytes []byte) string {
	// FNV-1a hash over domain bytes
	var h uint32 = 2166136261
	for _, b := range cnBytes {
		h ^= uint32(b)
		h *= 16777619
	}
	slot := h & (etldCacheSize - 1)

	cached := &etldCache[slot]
	// Non-allocating comparison: unsafe.String creates a stack string header pointing directly
	// to cnBytes, avoiding heap allocation when comparing with cached.domain.
	if len(cached.domain) == len(cnBytes) && cached.domain == unsafe.String(unsafe.SliceData(cnBytes), len(cnBytes)) {
		return cached.etld1
	}

	// Cache miss: allocate permanent string for cache slot and query PSL.
	domainStr := string(cnBytes)
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domainStr)
	if err != nil {
		return ""
	}
	*cached = etldCacheEntry{
		domain: domainStr,
		etld1:  etld1,
	}
	return etld1
}

func readTagLen(b []byte) (tag byte, content []byte, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if b[1] < 0x80 {
		l := int(b[1])
		if len(b) < 2+l {
			return 0, nil, nil, false
		}
		return tag, b[2 : 2+l], b[2+l:], true
	}
	numBytes := int(b[1] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
		return 0, nil, nil, false
	}
	var l int
	for i := 0; i < numBytes; i++ {
		l = (l << 8) | int(b[2+i])
	}
	if l < 0 || len(b) < 2+numBytes+l {
		return 0, nil, nil, false
	}
	return tag, b[2+numBytes : 2+numBytes+l], b[2+numBytes+l:], true
}

func extractDNSNamesFromDER(der []byte, emit func(item []byte)) {
	tag, tbsContent, _, ok := readTagLen(der)
	if !ok || tag != 0x30 {
		return
	}

	for len(tbsContent) > 0 {
		var field []byte
		tag, field, tbsContent, ok = readTagLen(tbsContent)
		if !ok {
			return
		}
		if tag == 0xa3 { // [3] EXPLICIT Extensions
			tag, extSeq, _, ok := readTagLen(field)
			if !ok || tag != 0x30 {
				return
			}
			for len(extSeq) > 0 {
				var ext []byte
				tag, ext, extSeq, ok = readTagLen(extSeq)
				if !ok || tag != 0x30 {
					return
				}
				tag, oid, ext, ok := readTagLen(ext)
				if !ok || tag != 0x06 {
					continue
				}
				if len(oid) != 3 || oid[0] != 0x55 || oid[1] != 0x1d || oid[2] != 0x11 {
					continue
				}
				tag, val, ext, ok := readTagLen(ext)
				if !ok {
					return
				}
				if tag == 0x01 { // critical BOOLEAN
					tag, val, _, ok = readTagLen(ext)
					if !ok {
						return
					}
				}
				if tag != 0x04 { // extnValue OCTET STRING
					return
				}
				tag, sanSeq, _, ok := readTagLen(val)
				if !ok || tag != 0x30 {
					return
				}
				for len(sanSeq) > 0 {
					var item []byte
					tag, item, sanSeq, ok = readTagLen(sanSeq)
					if !ok {
						return
					}
					if tag == 0x82 { // [2] IMPLICIT dNSName
						emit(item)
					}
				}
				return
			}
		}
	}
}

type domainSpan struct {
	start uint16
	end   uint16
}

// Static storage buffers for zero-allocation domain processing within the WASM guest.
//
// Performance rationale:
// 1. WASM guest instances in VIndex are dedicated per-worker and run single-threaded sequentially.
// 2. Defining leafStorage and leafSpans in package-level static memory (BSS) prevents Go compiler
//    escape analysis from moving buffers to the heap when passed to closures or emit.
// 3. RFC 1035 limits domain names to 253 octets. 2048 bytes accommodates ~20-50 domains per certificate.
var (
	leafStorage [2048]byte
	leafSpans   [64]domainSpan
)

// MapMTCLeaf extracts all canonical domain names and hierarchical sub-roots from an MTC log leaf.
func MapMTCLeaf(leaf []byte, emit func(key []byte)) {
	if len(leaf) < 2 {
		return
	}
	entryType := binary.BigEndian.Uint16(leaf[:2])
	if entryType != 1 {
		return
	}

	storageUsed := 0
	spanCount := 0

	// addSpan inserts a unique sub-slice span into leafSpans without copying or heap allocation.
	addSpan := func(start, end uint16) {
		target := leafStorage[start:end]
		for i := 0; i < spanCount; i++ {
			sp := leafSpans[i]
			if bytes.Equal(leafStorage[sp.start:sp.end], target) {
				return
			}
		}
		if spanCount < len(leafSpans) {
			leafSpans[spanCount] = domainSpan{start: start, end: end}
			spanCount++
		}
	}

	// Stack buffer for in-place ASCII lowercasing (max DNS name length is 253 bytes).
	var lowerBuf [256]byte

	extractDNSNamesFromDER(leaf[2:], func(item []byte) {
		// Strip leading wildcard prefixes (*. or *)
		if len(item) >= 2 && item[0] == '*' && item[1] == '.' {
			item = item[2:]
		} else if len(item) >= 1 && item[0] == '*' {
			item = item[1:]
		}
		if len(item) == 0 || len(item) > 253 {
			return
		}

		// In-place ASCII lowercasing avoids Unicode table lookup overhead and allocations.
		for i := 0; i < len(item); i++ {
			c := item[i]
			if c >= 'A' && c <= 'Z' {
				lowerBuf[i] = c + ('a' - 'A')
			} else {
				lowerBuf[i] = c
			}
		}
		clean := lowerBuf[:len(item)]

		// Fast-path deduplication: check if the base domain is already in leafSpans.
		for i := 0; i < spanCount; i++ {
			sp := leafSpans[i]
			if bytes.Equal(leafStorage[sp.start:sp.end], clean) {
				return
			}
		}

		// Guard against overflow on pathological certificates with massive SAN counts.
		if storageUsed+len(clean) > len(leafStorage) || spanCount >= len(leafSpans) {
			return
		}
		baseStart := uint16(storageUsed)
		baseEnd := baseStart + uint16(len(clean))
		copy(leafStorage[baseStart:], clean)
		storageUsed = int(baseEnd)
		leafSpans[spanCount] = domainSpan{start: baseStart, end: baseEnd}
		spanCount++

		etld1 := getETLD1(clean)
		etld1Len := len(etld1)
		if etld1Len == 0 || len(clean) == etld1Len {
			return
		}

		// Single-pass subdomain hierarchy extraction down to eTLD+1.
		// Instead of calling strings.Index iteratively and creating substring slices,
		// scan forward for '.' separators and record suffix spans directly into leafStorage.
		for i := baseStart; i < baseEnd; i++ {
			if leafStorage[i] == '.' {
				subStart := i + 1
				subLen := int(baseEnd - subStart)
				if subLen < etld1Len {
					break
				}
				addSpan(subStart, baseEnd)
				if subLen == etld1Len {
					break
				}
			}
		}
	})

	// Direct emission of raw byte slices avoids all string conversions and allocations.
	for i := 0; i < spanCount; i++ {
		sp := leafSpans[i]
		emit(leafStorage[sp.start:sp.end])
	}
}
