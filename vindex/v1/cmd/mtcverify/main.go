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

// mtcverify queries and cryptographically verifies domain lookups in an MTC verifiable index.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/client"
	"github.com/transparency-dev/incubator/vindex/v1/internal/mtc"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexURL    = flag.String("vindex_url", "http://localhost:8088", "Base URL of the VIndex server")
	outLogOrigin = flag.String("out_log_origin", "MTCIndex", "Expected origin for Output Log")
	outLogPubKey = flag.String("out_log_pubkey", "", "Public key note verifier string for Output Log")
	inLogOrigin  = flag.String("in_log_origin", "bootstrap-mtca.cloudflareresearch.com/logs/shard3", "Expected origin for Input Log")
	inLogPubKey  = flag.String("in_log_pubkey", "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=", "Public key for Input Log checkpoint verification (note verifier or base64 Ed25519 public key)")
	keyName      = flag.String("key_name", "oid/1.3.6.1.4.1.44363.47.1.44363.48.8", "Key name for MTCVerifier if using Ed25519 public key")
	cosignerID   = flag.String("cosigner_id", "44363.48.9", "Cosigner ID for MTCVerifier")
	logID        = flag.String("log_id", "44363.48.8", "Log ID for MTCVerifier")
	domain       = flag.String("domain", "", "Domain name to search and verify")
	inLogURL     = flag.String("in_log_url", "", "Base URL of Input Log for dereferencing pointers (optional)")
	dereference  = flag.Bool("dereference", false, "Dereference and print original leaves from Input Log")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if *domain == "" {
		return errors.New("--domain must be specified")
	}
	if *vindexURL == "" {
		return errors.New("--vindex_url must be specified")
	}

	searchDomain := strings.ToLower(*domain)
	if strings.HasPrefix(searchDomain, "*.") {
		searchDomain = searchDomain[2:]
	} else if strings.HasPrefix(searchDomain, "*") {
		searchDomain = searchDomain[1:]
	}

	var outVerifier note.Verifier
	if *outLogPubKey != "" {
		v, err := note.NewVerifier(*outLogPubKey)
		if err != nil {
			return fmt.Errorf("failed to create output log verifier: %w", err)
		}
		outVerifier = v
	}

	var inVerifier note.Verifier
	if *inLogPubKey != "" {
		v, err := note.NewVerifier(*inLogPubKey)
		if err == nil {
			inVerifier = v
		} else {
			pubKeyBytes, bErr := base64.StdEncoding.DecodeString(*inLogPubKey)
			if bErr == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
				mtcV, mErr := mtc.NewMTCVerifier(*keyName, ed25519.PublicKey(pubKeyBytes), *cosignerID, *logID)
				if mErr != nil {
					return fmt.Errorf("failed to create MTCVerifier: %w", mErr)
				}
				inVerifier = mtcV
			} else {
				return fmt.Errorf("failed to construct input log verifier from %q: %v", *inLogPubKey, err)
			}
		}
	}

	cfg := client.VerifierConfig{
		OutputLogOrigin:   *outLogOrigin,
		OutputLogVerifier: outVerifier,
		InputLogOrigin:    *inLogOrigin,
		InputLogVerifier:  inVerifier,
	}

	cli, err := client.New(*vindexURL, cfg, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	keyHash := sha256.Sum256([]byte(searchDomain))
	resp, err := cli.LookupAll(ctx, keyHash, 10000)
	if err != nil {
		return fmt.Errorf("lookup verification failed: %w", err)
	}

	fmt.Printf("Domain:         %s\n", searchDomain)
	fmt.Printf("Key Hash:       %x\n", resp.KeyHash)
	fmt.Printf("Exists:         %v\n", resp.Exists)
	fmt.Printf("Map Root:       %x\n", resp.MapRoot)
	fmt.Printf("Output Log Size:%d\n", resp.OutputLogSize)
	fmt.Printf("Input Log Size: %d\n", resp.InputLogSize)

	if !resp.Exists {
		fmt.Println("Domain not found in verifiable index (cryptographically verified non-inclusion).")
		return nil
	}

	fmt.Printf("Mini-Log Root:  %x\n", resp.MiniLogRoot)
	fmt.Printf("Verified leaf indices (%d):\n", len(resp.Indices))
	for _, idx := range resp.Indices {
		fmt.Printf("  - %d\n", idx)
	}

	if *dereference && *inLogURL != "" && inVerifier != nil {
		inClient, err := client.NewInputLogClient(*inLogURL, *inLogOrigin, inVerifier, http.DefaultClient)
		if err != nil {
			return fmt.Errorf("failed to create InputLogClient: %w", err)
		}

		fmt.Println("\nDereferencing verified leaves from Input Log:")
		for leaf, err := range inClient.Dereference(ctx, resp.RawInputLogCP, resp.Indices) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", leaf.Index, err)
				continue
			}
			if len(leaf.Data) >= 2 && binary.BigEndian.Uint16(leaf.Data[:2]) == 1 {
				entry, pErr := mtc.ParseTBSCertificateLogEntry(leaf.Data[2:])
				if pErr == nil {
					dnsNames := mtc.ExtractDNSNames(entry)
					fmt.Printf("  [%d]: SANs: %v\n", leaf.Index, dnsNames)
					continue
				}
			}
			fmt.Printf("  [%d]: (raw leaf length: %d bytes)\n", leaf.Index, len(leaf.Data))
		}
	}

	return nil
}
