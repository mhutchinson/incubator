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
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/internal/mtc"
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
		return mtc.NewMTCVerifier(name, ed25519.PublicKey(pubKeyBytes), cosignerID, logID)
	}

	return note.NewVerifier(vKey)
}
