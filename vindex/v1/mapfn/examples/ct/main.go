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

// Package main implements the CT (Certificate Transparency) WASM MapFn plugin.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"slices"
	"strings"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/mapfn/sdk"
	"golang.org/x/net/publicsuffix"
)

func main() {}

func init() {
	sdk.RegisterRaw(MapCTLeaf)
}

var (
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCommonName              = asn1.ObjectIdentifier{2, 5, 4, 3}
)

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            pkix.RDNSequence
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.BitString  `asn1:"optional,implicit,tag:1"`
	SubjectUniqueID    asn1.BitString  `asn1:"optional,implicit,tag:2"`
	Extensions         []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

type extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional,default:false"`
	Value    []byte
}

// MapCTLeaf extracts all domain names (CN + SANs) and hierarchical sub-roots from a CT log leaf.
func MapCTLeaf(data []byte) [][sha256.Size]byte {
	names := extractRawDomainNames(data)
	if len(names) == 0 {
		return nil
	}

	uniqueNames := make(map[string]struct{})
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

	results := make([][sha256.Size]byte, 0, len(sortedNames))
	for _, name := range sortedNames {
		results = append(results, sha256.Sum256([]byte(name)))
	}
	return results
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

func extractRawDomainNames(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	// 1. Try RFC 6962 MerkleTreeLeaf parsing
	if len(data) >= 12 && data[0] == 0 && data[1] == 0 {
		entryType := binary.BigEndian.Uint16(data[10:12])
		if entryType == 0 && len(data) >= 15 { // x509_entry
			certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
			if len(data) >= 15+certLen {
				certDer := data[15 : 15+certLen]
				if names := parseX509DER(certDer); len(names) > 0 {
					return names
				}
			}
		} else if entryType == 1 && len(data) >= 47 { // precert_entry
			tbsLen := int(data[44])<<16 | int(data[45])<<8 | int(data[46])
			if len(data) >= 47+tbsLen {
				tbsDer := data[47 : 47+tbsLen]
				if names := parseTBSDER(tbsDer); len(names) > 0 {
					return names
				}
			}
		}
	}

	// 2. Try raw X.509 Certificate DER
	if names := parseX509DER(data); len(names) > 0 {
		return names
	}

	// 3. Try raw TBSCertificate DER
	if names := parseTBSDER(data); len(names) > 0 {
		return names
	}

	// 4. Fallback: plaintext domains (line separated)
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

func parseX509DER(der []byte) []string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	return names
}

func parseTBSDER(der []byte) []string {
	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(der, &tbs); err != nil {
		return nil
	}

	var names []string
	// Extract CN from Subject
	for _, rdn := range tbs.Subject {
		for _, atv := range rdn {
			if atv.Type.Equal(oidCommonName) {
				if s, ok := atv.Value.(string); ok && s != "" {
					names = append(names, s)
				}
			}
		}
	}

	// Extract DNS names from SAN Extension
	for _, rawExt := range tbs.Extensions {
		var ext extension
		if _, err := asn1.Unmarshal(rawExt.FullBytes, &ext); err != nil {
			continue
		}
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}
		var sequence []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &sequence); err != nil {
			continue
		}
		for _, raw := range sequence {
			if raw.Class == 2 && raw.Tag == 2 {
				names = append(names, string(raw.Bytes))
			}
		}
	}

	return names
}
