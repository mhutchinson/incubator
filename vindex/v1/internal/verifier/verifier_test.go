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

package verifier

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/formats/log"
)

func TestParseVerifier(t *testing.T) {
	tests := []struct {
		name       string
		keyStr     string
		wantName   string
		wantErr    bool
		testVerify func(t *testing.T, v interface{})
	}{
		{
			name:     "Standard note verifier",
			keyStr:   "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
			wantName: "sum.golang.org",
			wantErr:  false,
		},
		{
			name:     "Valid MTC verifier",
			keyStr:   "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=",
			wantName: "oid/1.3.6.1.4.1.44363.47.1.44363.48.8",
			wantErr:  false,
		},
		{
			name:    "MTC verifier insufficient parts",
			keyStr:  "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9",
			wantErr: true,
		},
		{
			name:    "MTC verifier invalid base64",
			keyStr:  "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+not-base-64!!!",
			wantErr: true,
		},
		{
			name:    "MTC verifier wrong key size",
			keyStr:  "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+" + base64.StdEncoding.EncodeToString([]byte("too-short")),
			wantErr: true,
		},
		{
			name:    "Invalid standard note string",
			keyStr:  "invalid-note-key-without-pluses",
			wantErr: true,
		},
		{
			name:    "Empty verifier string",
			keyStr:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVerifier(tt.keyStr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseVerifier(%q) error = %v, wantErr %v", tt.keyStr, err, tt.wantErr)
			}
			if err == nil {
				if v.Name() != tt.wantName {
					t.Errorf("v.Name() = %q, want %q", v.Name(), tt.wantName)
				}
			}
		})
	}
}

func TestMTCVerifier_Verification(t *testing.T) {
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	v, err := ParseVerifier(mtcKey)
	if err != nil {
		t.Fatalf("ParseVerifier failed: %v", err)
	}

	checkpointText := `bootstrap-mtca.cloudflareresearch.com/logs/shard3
197762974
7NWRnNW49lCjHOLMyMLBYRkRTGxDhVEmQhTw2gD/Pig=`

	sigB64 := "jmo7GsZLYkXSa+C4eXII6rUTN8BECzdUogRIlzML8wqeWnFuTjOjAOGrHu79pnjuZBx1syo5FYNs5sKpj2D93QEkLws="
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	// Signature in note format skips 4-byte keyhash prefix
	rawSig := sigBytes[4:]
	if !v.Verify([]byte(checkpointText), rawSig) {
		t.Error("MTCVerifier failed to verify valid authentic checkpoint signature")
	}
}

func TestParseVerifier_File(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "mtc.pub")
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=\n"
	if err := os.WriteFile(keyFile, []byte(mtcKey), 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	v, err := ParseVerifier(keyFile)
	if err != nil {
		t.Fatalf("ParseVerifier failed for file: %v", err)
	}
	if v.Name() != "oid/1.3.6.1.4.1.44363.47.1.44363.48.8" {
		t.Errorf("v.Name() = %q, want %q", v.Name(), "oid/1.3.6.1.4.1.44363.47.1.44363.48.8")
	}
}

func TestMTCVerifier_LogParseCheckpoint(t *testing.T) {
	mtcKey := "mtc+oid/1.3.6.1.4.1.44363.47.1.44363.48.8+44363.48.9+44363.48.8+teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	v, err := ParseVerifier(mtcKey)
	if err != nil {
		t.Fatalf("ParseVerifier failed: %v", err)
	}

	rawCP := []byte("bootstrap-mtca.cloudflareresearch.com/logs/shard3\n" +
		"257823832\n" +
		"7X1AigV5K/y4Cvwg1URypKrHTW1G1NGE26UuJnrx4UY=\n\n" +
		"— bootstrap-mtca.cloudflareresearch.com/logs/shard3 d2AwDA6oSfWjDFQokmCDTCvePFXBUBbi/gjpAm0JDmMU1Z7VWYd+Yyj1NIkwT8H18zYx/aF08UqO9GOEzdLA4COKMHHOh1bRm99eXbaEx4duENRslP0t1599QY8K\n" +
		"— grease.invalid T9OPNbbcCT04lu8QaHJ4JQ8v/PrvUPLQjBJQ1eOUa3NW7tr7BlvcmmZ6269lXilIz7QUvCCr\n" +
		"— oid/1.3.6.1.4.1.44363.47.1.44363.48.8 jmo7GmHZ+b+1fu1lWpxTL3Tf2YyFenDyp+5JKc1xTq7GJQbyrqrMBH+jlJwdYca3fKHokgN1svd0XR81K0UA5IUuuws=\n")

	cp, _, _, err := log.ParseCheckpoint(rawCP, "bootstrap-mtca.cloudflareresearch.com/logs/shard3", v)
	if err != nil {
		t.Fatalf("log.ParseCheckpoint failed with MTCVerifier: %v", err)
	}
	if cp.Size != 257823832 {
		t.Errorf("cp.Size = %d, want 257823832", cp.Size)
	}
}

