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

package main

import (
	_ "embed"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string, sans []string) []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	return der
}

func buildRFC6962Leaf(entryType uint16, payload []byte) []byte {
	var buf []byte
	buf = append(buf, 0x00) // version 0
	buf = append(buf, 0x00) // leaf_type = timestamped_entry
	var ts [8]byte
	buf = append(buf, ts[:]...)
	var et [2]byte
	binary.BigEndian.PutUint16(et[:], entryType)
	buf = append(buf, et[:]...)

	switch entryType {
	case 0: // x509_entry
		certLen := len(payload)
		buf = append(buf, byte(certLen>>16), byte(certLen>>8), byte(certLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	case 1: // precert_entry
		var keyHash [32]byte
		buf = append(buf, keyHash[:]...)
		tbsLen := len(payload)
		buf = append(buf, byte(tbsLen>>16), byte(tbsLen>>8), byte(tbsLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	}
	return buf
}

func TestMapCTLeaf_X509Certificate(t *testing.T) {
	certDer := generateTestCert(t, "example.com", []string{"foo.bar.example.com", "*.sub.example.org"})
	leaf := buildRFC6962Leaf(0, certDer)

	var domains []string
	MapCTLeaf(leaf, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"example.com",
		"foo.bar.example.com",
		"bar.example.com",
		"sub.example.org",
		"example.org",
	}

	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries", d)
		}
	}
}

func TestMapCTLeaf_EffectiveTLDPlusOne(t *testing.T) {
	certDer := generateTestCert(t, "deep.sub.service.co.uk", nil)
	var domains []string
	MapCTLeaf(certDer, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"deep.sub.service.co.uk",
		"sub.service.co.uk",
		"service.co.uk", // eTLD+1
	}

	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries", d)
		}
	}

	// Verify "co.uk" (public suffix) is NOT included as a sub-root
	if domainMap["co.uk"] {
		t.Errorf("unexpected public suffix 'co.uk' found in mapped entries")
	}
}

func TestMapCTLeaf_PlaintextFallback(t *testing.T) {
	plain := []byte("alpha.example.com\n*.beta.example.com\n")
	var domains []string
	MapCTLeaf(plain, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	for _, d := range []string{"alpha.example.com", "beta.example.com", "example.com"} {
		if !domainMap[d] {
			t.Errorf("expected %q in mapped entries", d)
		}
	}
}

func TestMapCTLeaf_Empty(t *testing.T) {
	var count int
	emitCount := func(key []byte) { count++ }

	count = 0
	MapCTLeaf(nil, emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for nil input, got %d", count)
	}

	count = 0
	MapCTLeaf([]byte("   \n\t  "), emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for whitespace input, got %d", count)
	}
}

func splitStaticCTTile(data []byte) ([][]byte, error) {
	var leaves [][]byte
	offset := 0
	for offset < len(data) {
		start := offset
		if offset+10 > len(data) {
			return nil, fmt.Errorf("truncated at offset %d", offset)
		}
		entryType := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if entryType == 0 { // x509_entry
			if offset+3 > len(data) {
				return nil, fmt.Errorf("truncated cert len at %d", offset)
			}
			certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + certLen
		} else if entryType == 1 { // precert_entry
			if offset+32+3 > len(data) {
				return nil, fmt.Errorf("truncated precert header at %d", offset)
			}
			offset += 32
			tbsLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + tbsLen
		} else {
			return nil, fmt.Errorf("unknown entry type %d at offset %d", entryType, offset-10)
		}

		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated ext len at %d", offset)
		}
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + extLen

		if entryType == 1 {
			if offset+3 > len(data) {
				return nil, fmt.Errorf("truncated precert len at %d", offset)
			}
			pLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3 + pLen
		}

		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated chain len at %d", offset)
		}
		chainLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + chainLen

		if offset > len(data) {
			return nil, fmt.Errorf("tile overflow: offset %d > len %d", offset, len(data))
		}
		leaves = append(leaves, data[start:offset])
	}
	return leaves, nil
}

func TestMapCTLeaf_RealStaticCTTile(t *testing.T) {
	data, err := os.ReadFile("/tmp/sycamore_tile_000.bin")
	if err != nil {
		t.Skipf("skipping: /tmp/sycamore_tile_000.bin not found: %v", err)
	}
	leaves, err := splitStaticCTTile(data)
	if err != nil {
		t.Fatalf("failed to split static-ct tile: %v", err)
	}
	if len(leaves) != 256 {
		t.Fatalf("expected 256 entries in tile, got %d", len(leaves))
	}

	totalKeys := 0
	for i, leaf := range leaves {
		emittedCount := 0
		MapCTLeaf(leaf, func(key []byte) {
			emittedCount++
			totalKeys++
		})
		if emittedCount == 0 {
			t.Errorf("leaf %d emitted 0 search keys", i)
		}
	}
	t.Logf("Successfully mapped 256 real static-CT leaves into %d search keys", totalKeys)
}

//go:embed testdata/golden_leaves.json
var goldenLeavesJSON []byte

type goldenCase struct {
	Index      int    `json:"index"`
	EntryType  string `json:"entry_type"`
	Category   string `json:"category"`
	LeafHex    string `json:"leaf_hex"`
	ByteLength int    `json:"byte_length"`
}

func TestMapCTLeaf_GoldenDataset(t *testing.T) {
	var cases []goldenCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		t.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty golden dataset")
	}

	for _, tc := range cases {
		leafBytes, err := hex.DecodeString(tc.LeafHex)
		if err != nil {
			t.Fatalf("case %d: failed to decode hex: %v", tc.Index, err)
		}
		if len(leafBytes) != tc.ByteLength {
			t.Fatalf("case %d: byte length mismatch: got %d, want %d", tc.Index, len(leafBytes), tc.ByteLength)
		}

		var domains []string
		MapCTLeaf(leafBytes, func(key []byte) {
			domains = append(domains, string(key))
		})

		if len(domains) == 0 {
			t.Errorf("case %d [%s/%s]: emitted 0 search keys", tc.Index, tc.EntryType, tc.Category)
		}
		t.Logf("Case %d [%s]: %d domains emitted: %v", tc.Index, tc.EntryType, len(domains), domains)
	}
}


