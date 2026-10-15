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

// Package verifier provides public key verifier parsers supporting multiple log signature schemes.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// ParseVerifier parses a public key verifier string or file path into a note.Verifier.
//
// Supported schemes:
//  1. Standard note format (RFC 6962 / SumDB):
//     "<name>+<hash>+<key>"
//     Example: "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
//
//  2. MTC format (Merkle Tree Certificates cosigned subtree signature):
//     "mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>"
//     Example: "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
func ParseVerifier(vKey string) (note.Verifier, error) {
	vKey = strings.TrimSpace(vKey)
	if vKey == "" {
		return nil, errors.New("empty verifier key")
	}
	if data, err := os.ReadFile(vKey); err == nil {
		vKey = string(bytes.TrimSpace(data))
	}

	if strings.HasPrefix(vKey, "mtc+") {
		parts := strings.SplitN(vKey, "+", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("invalid MTC verifier %q: expected 'mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>'", vKey)
		}
		name := parts[1]
		cosignerID := parts[2]
		logID := parts[3]
		pubKeyB64 := parts[4]

		pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MTC public key base64: %w", err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid MTC Ed25519 public key size %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
		}
		return NewMTCVerifier(name, ed25519.PublicKey(pubKeyBytes), cosignerID, logID)
	}

	return note.NewVerifier(vKey)
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
