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

//go:generate sh -c "GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags=\"-buildid=\" -buildmode=c-shared -o ct.wasm ."

// Package main implements an optimized, zero-alloc CT (Certificate Transparency) WASM MapFn plugin.
package main

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
	"golang.org/x/net/publicsuffix"
)

func main() {}

func init() {
	sdk.RegisterEmit(MapCTLeaf)
}

var (
	oidSANRaw = []byte{0x55, 0x1d, 0x11} // 2.5.29.17 (Subject Alternative Name)
	oidCNRaw  = []byte{0x55, 0x04, 0x03} // 2.5.4.3 (Common Name)
)

// MapCTLeaf extracts all domain names (CN + SANs) and hierarchical sub-roots from a CT log leaf.
func MapCTLeaf(data []byte, emit func(key []byte)) {
	names := extractRawDomainNames(data)
	if len(names) == 0 {
		return
	}

	uniqueNames := make(map[string]struct{}, len(names)*2)
	for _, rawName := range names {
		norm := normalizeDomain(rawName)
		if norm == "" {
			continue
		}
		uniqueNames[norm] = struct{}{}

		// Compute hierarchical domain sub-roots down to eTLD+1
		etld1, err := publicsuffix.EffectiveTLDPlusOne(norm)
		if err == nil && etld1 != "" {
			uniqueNames[etld1] = struct{}{}
			curr := norm
			for {
				idx := strings.Index(curr, ".")
				if idx == -1 {
					break
				}
				curr = curr[idx+1:]
				if len(curr) < len(etld1) {
					break
				}
				uniqueNames[curr] = struct{}{}
				if curr == etld1 {
					break
				}
			}
		} else {
			// Fallback if publicsuffix fails: generate sub-labels down to top 2 labels
			curr := norm
			for {
				idx := strings.Index(curr, ".")
				if idx == -1 {
					break
				}
				curr = curr[idx+1:]
				if !strings.Contains(curr, ".") {
					break
				}
				uniqueNames[curr] = struct{}{}
			}
		}
	}

	sortedNames := make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		sortedNames = append(sortedNames, name)
	}
	slices.Sort(sortedNames)
	for _, name := range sortedNames {
		emit([]byte(name))
	}
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	} else if strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	name = strings.TrimSuffix(name, ".")
	return name
}

// readASN1Header parses tag and length at pos. Returns (tag, contentStart, contentEnd, nextElem, ok).
func readASN1Header(b []byte, pos int) (tag byte, start, end, next int, ok bool) {
	if pos >= len(b) {
		return 0, 0, 0, 0, false
	}
	tag = b[pos]
	pos++
	if pos >= len(b) {
		return 0, 0, 0, 0, false
	}
	lByte := b[pos]
	pos++
	var length int
	if lByte < 0x80 {
		length = int(lByte)
	} else {
		numBytes := int(lByte & 0x7f)
		if numBytes == 0 || numBytes > 4 || pos+numBytes > len(b) {
			return 0, 0, 0, 0, false
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(b[pos+i])
		}
		pos += numBytes
	}
	if pos+length > len(b) {
		return 0, 0, 0, 0, false
	}
	return tag, pos, pos + length, pos + length, true
}

// fastExtractDomainsFromTBS extracts CommonName and SAN DNSNames from raw TBSCertificate DER.
func fastExtractDomainsFromTBS(tbs []byte) []string {
	tag, start, end, _, ok := readASN1Header(tbs, 0)
	if !ok || tag != 0x30 {
		return nil
	}
	payload := tbs[start:end]

	var names []string
	pos := 0

	// 1. Optional version [0] EXPLICIT
	if pos < len(payload) && payload[pos] == 0xa0 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return nil
		}
		pos = next
	}

	// 2. serialNumber INTEGER (0x02)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x02 {
		pos = next
	} else {
		return nil
	}

	// 3. signature AlgorithmIdentifier SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return nil
	}

	// 4. issuer Name SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return nil
	}

	// 5. validity Validity SEQUENCE (0x30)
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return nil
	}

	// 6. subject Name SEQUENCE (0x30)
	if tag, sStart, sEnd, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
		subjectBytes := payload[sStart:sEnd]
		sPos := 0
		for sPos < len(subjectBytes) {
			_, setStart, setEnd, setNext, ok := readASN1Header(subjectBytes, sPos)
			if !ok {
				break
			}
			setBytes := subjectBytes[setStart:setEnd]
			subPos := 0
			for subPos < len(setBytes) {
				_, seqStart, seqEnd, seqNext, ok := readASN1Header(setBytes, subPos)
				if !ok {
					break
				}
				seqBytes := setBytes[seqStart:seqEnd]
				oTag, oStart, oEnd, oNext, ok := readASN1Header(seqBytes, 0)
				if ok && oTag == 0x06 && bytes.Equal(seqBytes[oStart:oEnd], oidCNRaw) {
					_, vStart, vEnd, _, ok := readASN1Header(seqBytes, oNext)
					if ok {
						val := string(seqBytes[vStart:vEnd])
						if val != "" {
							names = append(names, val)
						}
					}
				}
				subPos = seqNext
			}
			sPos = setNext
		}
	} else {
		return nil
	}

	// 7. subjectPublicKeyInfo SEQUENCE (0x30) - SKIP without parsing keys!
	if tag, _, _, next, ok := readASN1Header(payload, pos); ok && tag == 0x30 {
		pos = next
	} else {
		return nil
	}

	// Optional: issuerUniqueID [1]
	if pos < len(payload) && payload[pos] == 0x81 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return nil
		}
		pos = next
	}

	// Optional: subjectUniqueID [2]
	if pos < len(payload) && payload[pos] == 0x82 {
		_, _, _, next, ok := readASN1Header(payload, pos)
		if !ok {
			return nil
		}
		pos = next
	}

	// Optional: extensions [3] EXPLICIT (0xa3)
	if pos < len(payload) && payload[pos] == 0xa3 {
		_, eStart, eEnd, _, ok := readASN1Header(payload, pos)
		if ok {
			extContainer := payload[eStart:eEnd]
			tag, sStart, sEnd, _, ok := readASN1Header(extContainer, 0)
			if ok && tag == 0x30 {
				extList := extContainer[sStart:sEnd]
				ePos := 0
				for ePos < len(extList) {
					_, itemStart, itemEnd, itemNext, ok := readASN1Header(extList, ePos)
					if !ok {
						break
					}
					itemBytes := extList[itemStart:itemEnd]
					iPos := 0
					tag, oStart, oEnd, next, ok := readASN1Header(itemBytes, iPos)
					if ok && tag == 0x06 {
						isSAN := bytes.Equal(itemBytes[oStart:oEnd], oidSANRaw)
						iPos = next
						if iPos < len(itemBytes) && itemBytes[iPos] == 0x01 { // critical BOOLEAN
							_, _, _, next, ok := readASN1Header(itemBytes, iPos)
							if ok {
								iPos = next
							}
						}
						tag, vStart, vEnd, _, ok := readASN1Header(itemBytes, iPos) // extnValue OCTET STRING
						if ok && tag == 0x04 && isSAN {
							sanVal := itemBytes[vStart:vEnd]
							tag, gnStart, gnEnd, _, ok := readASN1Header(sanVal, 0)
							if ok && tag == 0x30 {
								gnList := sanVal[gnStart:gnEnd]
								gnPos := 0
								for gnPos < len(gnList) {
									tag, dStart, dEnd, gnNext, ok := readASN1Header(gnList, gnPos)
									if !ok {
										break
									}
									if tag == 0x82 { // dNSName [2]
										names = append(names, string(gnList[dStart:dEnd]))
									}
									gnPos = gnNext
								}
							}
						}
					}
					ePos = itemNext
				}
			}
		}
	}

	return names
}

// fastExtractDomainsFromCert unwraps the outer Certificate SEQUENCE and parses TBSCertificate.
func fastExtractDomainsFromCert(certDer []byte) []string {
	tag, start, end, _, ok := readASN1Header(certDer, 0)
	if !ok || tag != 0x30 {
		return nil
	}
	outer := certDer[start:end]
	tag, _, _, _, ok = readASN1Header(outer, 0)
	if !ok || tag != 0x30 {
		return nil
	}
	return fastExtractDomainsFromTBS(outer)
}

func extractRawDomainNames(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	// 1. Try RFC 6962 MerkleTreeLeaf parsing (starts with 0x00, 0x00 version & leaf_type)
	if len(data) >= 12 && data[0] == 0 && data[1] == 0 {
		entryType := binary.BigEndian.Uint16(data[10:12])
		if entryType == 0 && len(data) >= 15 { // x509_entry
			certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
			if len(data) >= 15+certLen {
				if names := fastExtractDomainsFromCert(data[15 : 15+certLen]); len(names) > 0 {
					return names
				}
			}
		} else if entryType == 1 && len(data) >= 47 { // precert_entry
			tbsLen := int(data[44])<<16 | int(data[45])<<8 | int(data[46])
			if len(data) >= 47+tbsLen {
				if names := fastExtractDomainsFromTBS(data[47 : 47+tbsLen]); len(names) > 0 {
					return names
				}
			}
		}
	}

	// 2. Try C2SP Static-CT TileLeaf parsing (starts directly with 8-byte timestamp)
	if len(data) >= 13 {
		entryType := binary.BigEndian.Uint16(data[8:10])
		if entryType == 0 { // x509_entry
			certLen := int(data[10])<<16 | int(data[11])<<8 | int(data[12])
			if certLen > 0 && len(data) >= 13+certLen {
				if names := fastExtractDomainsFromCert(data[13 : 13+certLen]); len(names) > 0 {
					return names
				}
			}
		} else if entryType == 1 && len(data) >= 45 { // precert_entry
			tbsLen := int(data[42])<<16 | int(data[43])<<8 | int(data[44])
			if tbsLen > 0 && len(data) >= 45+tbsLen {
				if names := fastExtractDomainsFromTBS(data[45 : 45+tbsLen]); len(names) > 0 {
					return names
				}
			}
		}
	}

	// 3. Try raw X.509 Certificate DER
	if names := fastExtractDomainsFromCert(data); len(names) > 0 {
		return names
	}

	// 4. Try raw TBSCertificate DER
	if names := fastExtractDomainsFromTBS(data); len(names) > 0 {
		return names
	}

	// 5. Fallback: plaintext domains (line separated)
	var plainNames []string
	lines := bytes.Split(data, []byte("\n"))
	for _, l := range lines {
		s := strings.TrimSpace(string(l))
		if s != "" && !strings.Contains(s, " ") {
			plainNames = append(plainNames, s)
		}
	}
	return plainNames
}
