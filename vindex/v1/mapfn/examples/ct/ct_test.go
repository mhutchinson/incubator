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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
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

	domains := MapCTLeaf(leaf)
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
	domains := MapCTLeaf(certDer)
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
	domains := MapCTLeaf(plain)
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
	if res := MapCTLeaf(nil); len(res) != 0 {
		t.Fatalf("expected empty result for nil input, got %d", len(res))
	}
	if res := MapCTLeaf([]byte("   \n\t  ")); len(res) != 0 {
		t.Fatalf("expected empty result for whitespace input, got %d", len(res))
	}
}
