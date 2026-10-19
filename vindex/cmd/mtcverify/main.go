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

	"filippo.io/torchwood"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexURL    = flag.String("vindex_url", "http://localhost:8088", "Base URL of the VIndex server")
	outLogPolicy = flag.String("out_log_policy", "", "Path to C2SP tlog-policy file for Output Log")
	outLogOrigin = flag.String("out_log_origin", "MTCIndex", "Expected origin for Output Log")
	outLogPubKey = flag.String("out_log_pubkey", "", "Public key note verifier string for Output Log")
	inLogPolicy  = flag.String("in_log_policy", "", "Path to C2SP tlog-policy file for Input Log")
	inLogOrigin  = flag.String("in_log_origin", "bootstrap-mtca.cloudflareresearch.com/logs/shard3", "Expected origin for Input Log")
	inLogPubKey  = flag.String("in_log_pubkey", "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=", "Public key for Input Log checkpoint verification (note verifier, mtc+... verifier, or base64 Ed25519 public key)")
	keyName      = flag.String("key_name", "oid/1.3.6.1.4.1.44363.47.1.44363.48.8", "Key name for MTCVerifier if using Ed25519 public key")
	cosignerID   = flag.String("cosigner_id", "44363.48.9", "Cosigner ID for MTCVerifier")
	logID        = flag.String("log_id", "44363.48.8", "Log ID for MTCVerifier")
	domain       = flag.String("domain", "", "Domain name to search and verify")
	prefixQuery  = flag.Bool("prefix", false, "Perform a prefix subtree lookup (?prefix=<domain>) for all subdomains under --domain")
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

	searchKey, ok := mtc.CanonicalizeDomain(*domain)
	if !ok {
		return fmt.Errorf("invalid domain %q", *domain)
	}

	var outPolicy torchwood.Policy
	if strings.TrimSpace(*outLogPolicy) != "" {
		var err error
		outPolicy, err = wire.ParsePolicyOrVerifier(*outLogPolicy, "", "", nil, 0)
		if err != nil {
			return fmt.Errorf("failed to parse output log policy: %w", err)
		}
	} else {
		if *outLogPubKey == "" {
			return errors.New("--out_log_policy or --out_log_pubkey must be specified")
		}
		outVerifier, err := wire.ParseVerifier(*outLogPubKey)
		if err != nil {
			return fmt.Errorf("failed to create output log verifier: %w", err)
		}
		outOrigin := strings.TrimSpace(*outLogOrigin)
		if outOrigin == "" {
			outOrigin = outVerifier.Name()
		}
		outPolicy, err = client.SingleKeyPolicy(outOrigin, outVerifier)
		if err != nil {
			return fmt.Errorf("failed to create output log policy: %w", err)
		}
	}

	var inPolicy torchwood.Policy
	if strings.TrimSpace(*inLogPolicy) != "" {
		var err error
		inPolicy, err = wire.ParsePolicyOrVerifier(*inLogPolicy, "", "", nil, 0)
		if err != nil {
			return fmt.Errorf("failed to parse input log policy: %w", err)
		}
	} else {
		if *inLogPubKey == "" {
			return errors.New("--in_log_policy or --in_log_pubkey must be specified")
		}
		var inVerifier note.Verifier
		if v, err := wire.ParseVerifier(*inLogPubKey); err == nil {
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
		inOrigin := strings.TrimSpace(*inLogOrigin)
		if inOrigin == "" {
			inOrigin = inVerifier.Name()
		}
		var err error
		inPolicy, err = client.SingleKeyPolicy(inOrigin, inVerifier)
		if err != nil {
			return fmt.Errorf("failed to create input log policy: %w", err)
		}
	}

	cfg := client.VerifierConfig{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
	}

	cli, err := client.New(*vindexURL, cfg, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	cli.SetStateTracker(client.NewStateTracker())

	if *prefixQuery {
		pResp, err := cli.LookupPrefixAll(ctx, searchKey, 10000)
		if err != nil {
			return fmt.Errorf("prefix lookup verification failed: %w", err)
		}
		fmt.Printf("Domain Prefix:  %s\n", *domain)
		fmt.Printf("Canonical Key:  %s\n", searchKey)
		fmt.Printf("Matched Keys:   %d\n", len(pResp.Results))
		fmt.Printf("MPT Root:       %x\n", pResp.MPTRoot)
		fmt.Printf("Output Log Size:%d\n", pResp.OutputSize)
		fmt.Printf("Input Log Size: %d\n", pResp.InputSize)
		for _, kr := range pResp.Results {
			fmt.Printf("  Key %s (%x): %v\n", kr.Key, kr.ValueRoot, kr.Indices)
		}
		return nil
	}

	keysResp, err := cli.LookupKey(ctx, searchKey)
	if err != nil {
		return fmt.Errorf("lookup verification failed: %w", err)
	}

	exists := len(keysResp.Keys) > 0
	fmt.Printf("Domain:         %s\n", *domain)
	fmt.Printf("Canonical Key:  %s\n", searchKey)
	fmt.Printf("Key Hash:       %x\n", sha256.Sum256([]byte(searchKey)))
	fmt.Printf("Exists:         %v\n", exists)
	fmt.Printf("MPT Root:       %x\n", keysResp.MPTRoot)
	fmt.Printf("Output Log Size:%d\n", keysResp.OutputSize)
	fmt.Printf("Input Log Size: %d\n", keysResp.InputSize)

	if !exists {
		fmt.Println("Domain not found in verifiable index (cryptographically verified non-inclusion).")
		return nil
	}

	indices, err := cli.LookupAllValues(ctx, searchKey, 10000)
	if err != nil {
		return fmt.Errorf("values lookup verification failed: %w", err)
	}

	fmt.Printf("Value Root:     %x\n", keysResp.Keys[0].ValueRoot)
	fmt.Printf("Verified leaf indices (%d):\n", len(indices))
	for _, idx := range indices {
		fmt.Printf("  - %d\n", idx)
	}

	if *dereference && *inLogURL != "" {
		fmt.Println("\nDereferencing verified leaves from Input Log:")
		for _, idx := range indices {
			leafData, err := ingest.FetchEntryByIndex(ctx, http.DefaultClient, *inLogURL, idx, keysResp.InputSize)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", idx, err)
				continue
			}
			if len(leafData) >= 2 && binary.BigEndian.Uint16(leafData[:2]) == 1 {
				entry, pErr := mtc.ParseTBSCertificateLogEntry(leafData[2:])
				if pErr == nil {
					dnsNames := mtc.ExtractDNSNames(entry)
					fmt.Printf("  [%d]: SANs: %v\n", idx, dnsNames)
					continue
				}
			}
			fmt.Printf("  [%d]: (raw leaf length: %d bytes)\n", idx, len(leafData))
		}
	}

	return nil
}
