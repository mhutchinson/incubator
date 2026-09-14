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

// vindex is a CLI client for looking up keys in a Verifiable Index with full cryptographic verification.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/transparency-dev/incubator/vindex/v1/client"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	vindexURL    = flag.String("vindex_url", "http://localhost:8080", "Base URL of the VIndex server.")
	key          = flag.String("key", "", "Key string to search.")
	keyHashHex   = flag.String("key_hash", "", "32-byte hex encoded key hash to search.")
	outLogOrigin = flag.String("out_log_origin", "", "Expected origin for Output Log.")
	outLogPubKey = flag.String("out_log_pubkey", "", "Public key note verifier string for Output Log.")
	inLogOrigin  = flag.String("in_log_origin", "", "Expected origin for Input Log.")
	inLogPubKey  = flag.String("in_log_pubkey", "", "Public key note verifier string for Input Log.")
	before       = flag.Uint64("before", 0, "Upper bound Input Log index (exclusive) for lookup.")
	limitCount   = flag.Uint64("limit", 10000, "Maximum number of indices to return per page.")
	fetchAll     = flag.Bool("all", false, "Fetch all matching indices across pages.")
	inLogURL     = flag.String("in_log_url", "", "Base URL of Input Log for dereferencing pointers.")
	dereference  = flag.Bool("dereference", false, "Dereference and print original leaves from Input Log.")
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
	var keyHash [sha256.Size]byte
	if *keyHashHex != "" {
		b, err := hex.DecodeString(*keyHashHex)
		if err != nil || len(b) != sha256.Size {
			return fmt.Errorf("invalid 32-byte hex --key_hash: %q", *keyHashHex)
		}
		copy(keyHash[:], b)
	} else if *key != "" {
		keyHash = sha256.Sum256([]byte(*key))
	} else {
		return errors.New("must specify either --key or --key_hash")
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
		if err != nil {
			return fmt.Errorf("failed to create input log verifier: %w", err)
		}
		inVerifier = v
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

	var beforePtr *uint64
	if *before > 0 {
		beforePtr = before
	}

	var resp *client.LookupResponse
	if *fetchAll {
		resp, err = cli.LookupAll(ctx, keyHash, *limitCount)
	} else {
		resp, err = cli.Lookup(ctx, keyHash, beforePtr, *limitCount)
	}
	if err != nil {
		return fmt.Errorf("lookup verification failed: %w", err)
	}

	fmt.Printf("Key Hash:       %x\n", resp.KeyHash)
	fmt.Printf("Exists:         %v\n", resp.Exists)
	fmt.Printf("Map Root:       %x\n", resp.MapRoot)
	fmt.Printf("Output Log Size:%d\n", resp.OutputLogSize)
	fmt.Printf("Input Log Size: %d\n", resp.InputLogSize)

	if !resp.Exists {
		fmt.Println("No occurrences found in Input Log (cryptographically verified non-inclusion).")
		return nil
	}

	fmt.Printf("Mini-Log Root:  %x\n", resp.MiniLogRoot)
	fmt.Printf("Found %d verified occurrences:\n", len(resp.Indices))
	for _, idx := range resp.Indices {
		fmt.Printf("  Index: %d\n", idx)
	}

	if resp.NextBefore != nil {
		fmt.Printf("Next before offset: %d (use --all to fetch all pages)\n", *resp.NextBefore)
	}

	if *dereference && *inLogURL != "" && inVerifier != nil {
		inClient, err := client.NewInputLogClient(*inLogURL, *inLogOrigin, inVerifier, http.DefaultClient)
		if err != nil {
			return fmt.Errorf("failed to create InputLogClient: %w", err)
		}

		fmt.Println("\nDereferencing leaves from Input Log:")
		for leaf, err := range inClient.Dereference(ctx, resp.RawInputLogCP, resp.Indices) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", leaf.Index, err)
				continue
			}
			fmt.Printf("  [%d]: %s\n", leaf.Index, string(leaf.Data))
		}
	}

	return nil
}
