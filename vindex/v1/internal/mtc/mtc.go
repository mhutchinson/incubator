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

// Package mtc implements parsing, checkpoint verification, and leaf mapping for Merkle Tree Certificates.
package mtc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/publicsuffix"
)

// Validity represents the validity period of a certificate.
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// TBSCertificateLogEntry represents the ASN.1 structure inside a tile entry.
type TBSCertificateLogEntry struct {
	Version                  int `asn1:"optional,explicit,default:0,tag:0"`
	Issuer                   pkix.RDNSequence
	Validity                 Validity
	Subject                  pkix.RDNSequence
	SubjectPublicKeyInfoHash []byte
	IssuerUniqueID           asn1.BitString  `asn1:"optional,implicit,tag:1"`
	SubjectUniqueID          asn1.BitString  `asn1:"optional,implicit,tag:2"`
	Extensions               []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

type extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional,default:false"`
	Value    []byte
}

// ParseTBSCertificateLogEntry parses the ASN.1 DER encoded TBSCertificateLogEntry.
func ParseTBSCertificateLogEntry(der []byte) (*TBSCertificateLogEntry, error) {
	var entry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(der, &entry)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TBSCertificateLogEntry: %w", err)
	}
	// We allow trailing data because some test cases might have it.
	_ = rest
	return &entry, nil
}

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ExtractDNSNames extracts DNS names from the SAN extension of the entry.
func ExtractDNSNames(entry *TBSCertificateLogEntry) []string {
	var dnsNames []string
	for _, rawExt := range entry.Extensions {
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
				dnsNames = append(dnsNames, string(raw.Bytes))
			}
		}
	}
	return dnsNames
}

// MTCVerifier implements note.Verifier for MTC checkpoint signatures.
type MTCVerifier struct {
	name            string
	pubKey          ed25519.PublicKey
	keyHash         uint32
	cosignerIDBytes []byte
	logIDBytes      []byte
}

// NewMTCVerifier creates a new MTCVerifier.
func NewMTCVerifier(name string, pubKey ed25519.PublicKey, cosignerIDStr, logIDStr string) (*MTCVerifier, error) {
	// Compute key hash: SHA-256(key name || 0x0A || 0xFF || "mtc-checkpoint/v1")[:4]
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0a, 0xff})
	h.Write([]byte("mtc-checkpoint/v1"))
	sum := h.Sum(nil)
	keyHash := binary.BigEndian.Uint32(sum[:4])

	cosignerIDBytes, err := encodeRelativeOIDStr(cosignerIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cosigner ID: %w", err)
	}

	logIDBytes, err := encodeRelativeOIDStr(logIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode log ID: %w", err)
	}

	return &MTCVerifier{
		name:            name,
		pubKey:          pubKey,
		keyHash:         keyHash,
		cosignerIDBytes: cosignerIDBytes,
		logIDBytes:      logIDBytes,
	}, nil
}

// Name returns the verifier name.
func (v *MTCVerifier) Name() string {
	return v.name
}

// KeyHash returns the verifier key hash.
func (v *MTCVerifier) KeyHash() uint32 {
	return v.keyHash
}

// Verify verifies the signature over the checkpoint message.
func (v *MTCVerifier) Verify(msg, sig []byte) bool {
	// Parse checkpoint to get size and hash
	// msg should be:
	// [origin]
	// [size]
	// [hash]
	lines := strings.Split(string(msg), "\n")
	if len(lines) < 3 {
		return false
	}
	sizeStr := lines[1]
	hashB64 := lines[2]

	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return false
	}

	hash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}

	if len(hash) != 32 {
		return false
	}

	// Construct MTCSubtreeSignatureInput:
	// "mtc-subtree/v1\n" + 0 (byte) + len(cosignerID) (1 byte) + cosignerID + len(logID) (1 byte) + logID + start (8 bytes uint64 big-endian) + end (8 bytes uint64 big-endian) + hash (32 bytes)
	var input []byte
	input = append(input, []byte("mtc-subtree/v1\n")...)
	input = append(input, 0)

	if len(v.cosignerIDBytes) > 255 || len(v.logIDBytes) > 255 {
		return false // Length must fit in 1 byte
	}

	input = append(input, byte(len(v.cosignerIDBytes)))
	input = append(input, v.cosignerIDBytes...)
	input = append(input, byte(len(v.logIDBytes)))
	input = append(input, v.logIDBytes...)

	var startBytes [8]byte
	binary.BigEndian.PutUint64(startBytes[:], 0)
	input = append(input, startBytes[:]...)

	var endBytes [8]byte
	binary.BigEndian.PutUint64(endBytes[:], size)
	input = append(input, endBytes[:]...)

	input = append(input, hash...)

	return ed25519.Verify(v.pubKey, input, sig)
}

// Interface check
var _ note.Verifier = (*MTCVerifier)(nil)

// Helper functions for relative OID encoding

func encodeRelativeOIDStr(s string) ([]byte, error) {
	parts := strings.Split(s, ".")
	var components []uint32
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, err
		}
		components = append(components, uint32(v))
	}
	return encodeRelativeOID(components), nil
}

func encodeRelativeOID(components []uint32) []byte {
	var encoded []byte
	for _, c := range components {
		encoded = append(encoded, encodeBase128(c)...)
	}
	return encoded
}

func encodeBase128(v uint32) []byte {
	if v == 0 {
		return []byte{0}
	}
	var chunks []byte
	for v > 0 {
		chunks = append(chunks, byte(v&0x7f))
		v >>= 7
	}
	var encoded []byte
	for i := len(chunks) - 1; i >= 0; i-- {
		b := chunks[i]
		if i > 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
	}
	return encoded
}

// MTCLeafMapper implements ingest.LeafMapper for MTC log entries.
type MTCLeafMapper struct{}

// MapLeaf parses an MTC log leaf and returns mapped entries for all extracted domain names.
func (m *MTCLeafMapper) MapLeaf(_ context.Context, leaf []byte) ([]ingest.MappedEntry, error) {
	if len(leaf) < 2 {
		return nil, nil
	}
	entryType := binary.BigEndian.Uint16(leaf[:2])
	if entryType != 1 {
		return nil, nil
	}
	entry, err := ParseTBSCertificateLogEntry(leaf[2:])
	if err != nil {
		return nil, nil
	}
	dnsNames := ExtractDNSNames(entry)
	uniqueNames := make(map[string]bool)
	for _, cn := range dnsNames {
		cn = strings.ToLower(cn)
		if strings.HasPrefix(cn, "*.") {
			cn = cn[2:]
		} else if strings.HasPrefix(cn, "*") {
			cn = cn[1:]
		}
		if cn == "" {
			continue
		}
		uniqueNames[cn] = true

		etld1, err := publicsuffix.EffectiveTLDPlusOne(cn)
		if err != nil {
			continue
		}
		if cn == etld1 {
			continue
		}
		curr := cn
		for {
			idx := strings.Index(curr, ".")
			if idx == -1 {
				break
			}
			curr = curr[idx+1:]
			if len(curr) < len(etld1) {
				break
			}
			uniqueNames[curr] = true
			if curr == etld1 {
				break
			}
		}
	}

	entries := make([]ingest.MappedEntry, 0, len(uniqueNames))
	for name := range uniqueNames {
		entries = append(entries, ingest.MappedEntry{
			KeyHash: sha256.Sum256([]byte(name)),
		})
	}
	return entries, nil
}

// Close releases any resources held by the mapper.
func (m *MTCLeafMapper) Close(_ context.Context) error {
	return nil
}

var _ ingest.LeafMapper = (*MTCLeafMapper)(nil)
