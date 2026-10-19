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

package wire

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

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

// ParseVerifier parses a public key verifier string or file path into a note.Verifier.
//
// Supported schemes:
//  1. Torchwood / C2SP log verifier or standard note format:
//     "<name>+<hash>+<key>"
//  2. MTC format (Merkle Tree Certificates cosigned subtree signature):
//     "mtc+<name>+<cosignerID>+<logID>+<ed25519_base64_pubkey>"
func ParseVerifier(keyOrPath string) (note.Verifier, error) {
	s := strings.TrimSpace(keyOrPath)
	if s == "" {
		return nil, errors.New("empty verifier key")
	}
	if !strings.Contains(s, "+") {
		if data, err := os.ReadFile(s); err == nil {
			s = string(bytes.TrimSpace(data))
		}
		if s == "" {
			return nil, errors.New("empty verifier key")
		}
	}

	if strings.HasPrefix(s, "mtc+") {
		parts := strings.SplitN(s, "+", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("invalid MTC verifier %q: expected 'mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>'", s)
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

	if v, err := torchwood.NewLogVerifier(s); err == nil {
		return v, nil
	}
	return note.NewVerifier(s)
}

// ParseWitnessVerifier parses a witness cosignature verifier key string or file path.
// It tries c2sp.org/tlog-cosignature@v1 (torchwood.NewCosignatureVerifier) first,
// falling back to ParseVerifier.
func ParseWitnessVerifier(keyOrPath string) (note.Verifier, error) {
	s := strings.TrimSpace(keyOrPath)
	if s == "" {
		return nil, errors.New("empty witness verifier key")
	}
	if !strings.Contains(s, "+") {
		if data, err := os.ReadFile(s); err == nil {
			s = string(bytes.TrimSpace(data))
		}
		if s == "" {
			return nil, errors.New("empty witness verifier key")
		}
	}
	if v, err := torchwood.NewCosignatureVerifier(s); err == nil {
		return v, nil
	}
	return ParseVerifier(s)
}

// BuildPolicy constructs a torchwood.Policy enforcing log origin, primary log verifier,
// and an optional witness quorum.
func BuildPolicy(origin string, v note.Verifier, witnesses []note.Verifier, witnessThreshold int) (torchwood.Policy, error) {
	if v == nil {
		return nil, errors.New("verifier is required")
	}
	effOrigin := strings.TrimSpace(origin)
	if effOrigin == "" {
		effOrigin = v.Name()
	}
	logPol := torchwood.ThresholdPolicy(2, torchwood.OriginPolicy(effOrigin), torchwood.SingleVerifierPolicy(v))
	if witnessThreshold <= 0 {
		return logPol, nil
	}

	type verifierID struct {
		name string
		hash uint32
	}
	primaryID := verifierID{name: v.Name(), hash: v.KeyHash()}
	seen := make(map[verifierID]struct{}, len(witnesses))
	uniqueWitnesses := make([]note.Verifier, 0, len(witnesses))
	for _, w := range witnesses {
		if w == nil {
			continue
		}
		id := verifierID{name: w.Name(), hash: w.KeyHash()}
		if id == primaryID {
			return nil, errors.New("witness verifier collides with primary log verifier")
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniqueWitnesses = append(uniqueWitnesses, w)
	}
	if len(uniqueWitnesses) < witnessThreshold {
		return nil, fmt.Errorf("insufficient distinct witness verifiers: got %d, threshold %d", len(uniqueWitnesses), witnessThreshold)
	}

	witnessPols := make([]torchwood.Policy, len(uniqueWitnesses))
	for i, w := range uniqueWitnesses {
		witnessPols[i] = torchwood.SingleVerifierPolicy(w)
	}
	return torchwood.ThresholdPolicy(2, logPol, torchwood.ThresholdPolicy(witnessThreshold, witnessPols...)), nil
}

// ParsePolicyFile reads a c2sp.org/tlog-policy file from disk and parses it into a torchwood.Policy.
func ParsePolicyFile(policyPath string) (torchwood.Policy, error) {
	b, err := os.ReadFile(strings.TrimSpace(policyPath))
	if err != nil {
		return nil, err
	}
	return torchwood.ParsePolicy(b)
}

// ParsePolicyOrVerifier resolves either a tlog-policy file (when policyPath is non-empty)
// or builds a policy from pubKeyOrPath, origin, and optional witness quorum parameters.
func ParsePolicyOrVerifier(policyPath, pubKeyOrPath, origin string, witnesses []note.Verifier, witnessThreshold int) (torchwood.Policy, error) {
	if strings.TrimSpace(policyPath) != "" {
		return ParsePolicyFile(policyPath)
	}
	v, err := ParseVerifier(pubKeyOrPath)
	if err != nil {
		return nil, err
	}
	return BuildPolicy(origin, v, witnesses, witnessThreshold)
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
func NewMTCVerifier(name string, pubKey ed25519.PublicKey, cosignerID, logID string) (*MTCVerifier, error) {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0a, 0xff})
	h.Write([]byte("mtc-checkpoint/v1"))
	sum := h.Sum(nil)
	keyHash := binary.BigEndian.Uint32(sum[:4])

	cosignerIDBytes, err := encodeRelativeOIDStr(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cosigner ID: %w", err)
	}

	logIDBytes, err := encodeRelativeOIDStr(logID)
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
	lines := strings.Split(string(msg), "\n")
	if len(lines) < 3 {
		return false
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return false
	}
	hash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(hash) != sha256.Size {
		return false
	}

	if len(v.cosignerIDBytes) > 255 || len(v.logIDBytes) > 255 {
		return false
	}

	var input []byte
	input = append(input, []byte("mtc-subtree/v1\n")...)
	input = append(input, 0)
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

var _ note.Verifier = (*MTCVerifier)(nil)

func encodeRelativeOIDStr(s string) ([]byte, error) {
	parts := strings.Split(s, ".")
	components := make([]uint32, 0, len(parts))
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
	encoded := make([]byte, 0, len(chunks))
	for i := len(chunks) - 1; i >= 0; i-- {
		b := chunks[i]
		if i > 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
	}
	return encoded
}
