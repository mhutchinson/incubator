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

// vindex-client is a CLI client for looking up keys in a Verifiable Index with full cryptographic verification.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

// prefixFlag supports both boolean mode (--prefix --key="foo") and string value mode (--prefix="foo").
type prefixFlag struct {
	enabled bool
	value   string
}

func (p *prefixFlag) IsBoolFlag() bool { return true }

func (p *prefixFlag) String() string {
	if p.value != "" {
		return p.value
	}
	if p.enabled {
		return "true"
	}
	return "false"
}

func (p *prefixFlag) Set(s string) error {
	switch strings.ToLower(s) {
	case "true":
		p.enabled = true
	case "false":
		p.enabled = false
		p.value = ""
	default:
		p.enabled = true
		p.value = s
	}
	return nil
}

var (
	vindexURL     = flag.String("vindex_url", "http://localhost:8080", "Base URL of the VIndex server.")
	key           = flag.String("key", "", "Canonical key (or prefix when --prefix is set) to search.")
	prefix        prefixFlag
	outLogPolicy  = flag.String("out_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
	outLogOrigin  = flag.String("out_log_origin", "", "Expected origin for Output Log.")
	outLogPubKey  = flag.String("out_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	inLogPolicy   = flag.String("in_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	inLogOrigin   = flag.String("in_log_origin", "", "Expected origin for Input Log.")
	inLogPubKey   = flag.String("in_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+...).")
	expectedMapFn = flag.String("expected_map_fn", "", "Expected 32-byte MapFn SHA-256 digest (base64 or 64-char hex).")
	before        = flag.Uint64("before", 0, "Upper bound Input Log index (exclusive) for manual value pagination.")
	valueRootStr  = flag.String("value_root", "", "Expected 32-byte Value Log root (hex or base64) for manual continuation queries (--before > 0).")
	limitCount    = flag.Uint64("limit", 10000, "Maximum number of indices to return per page.")
	fetchAll      = flag.Bool("all", false, "Fetch all matching indices across pages.")
	inLogURL      = flag.String("in_log_url", "", "Base URL of Input Log for dereferencing pointers.")
	dereference   = flag.Bool("dereference", false, "Dereference and print original leaves from Input Log.")
)

func init() {
	flag.Var(&prefix, "prefix", "Perform a prefix query (?prefix=<prefix>); accepts boolean (--prefix --key=...) or prefix string (--prefix=...).")
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	target := *key
	isPrefix := prefix.enabled
	if prefix.value != "" {
		if target != "" && target != prefix.value {
			return errors.New("cannot specify different values for --key and --prefix=<str>")
		}
		target = prefix.value
	} else if isPrefix && target == "" && flag.NArg() == 1 {
		target = flag.Arg(0)
	}
	if target == "" {
		return errors.New("must specify --key (or --prefix=<prefix>)")
	}

	if strings.TrimSpace(*outLogPolicy) == "" && strings.TrimSpace(*outLogPubKey) == "" {
		return errors.New("must specify --out_log_policy or --out_log_pubkey")
	}
	outOrigin := *outLogOrigin
	if outOrigin == "" && strings.TrimSpace(*outLogPolicy) == "" {
		if v, err := wire.ParseVerifier(*outLogPubKey); err == nil {
			outOrigin = v.Name()
		}
	}
	outPolicy, err := wire.ParsePolicyOrVerifier(*outLogPolicy, *outLogPubKey, outOrigin, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to build output log policy: %w", err)
	}

	if strings.TrimSpace(*inLogPolicy) == "" && strings.TrimSpace(*inLogPubKey) == "" {
		return errors.New("must specify --in_log_policy or --in_log_pubkey")
	}
	inOrigin := *inLogOrigin
	if inOrigin == "" && strings.TrimSpace(*inLogPolicy) == "" {
		if v, err := wire.ParseVerifier(*inLogPubKey); err == nil {
			inOrigin = v.Name()
		}
	}
	inPolicy, err := wire.ParsePolicyOrVerifier(*inLogPolicy, *inLogPubKey, inOrigin, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to build input log policy: %w", err)
	}

	cfg := client.VerifierConfig{
		OutputLogPolicy: outPolicy,
		InputLogPolicy:  inPolicy,
	}
	if strings.TrimSpace(*expectedMapFn) != "" {
		d, err := parseDigest32(*expectedMapFn)
		if err != nil {
			return fmt.Errorf("invalid --expected_map_fn %q: %w", *expectedMapFn, err)
		}
		cfg.ExpectedMapFn = &d
	}

	cli, err := client.New(*vindexURL, cfg, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	cli.SetStateTracker(client.NewStateTracker())

	if isPrefix {
		if *fetchAll {
			resp, err := cli.LookupPrefixAll(ctx, target, *limitCount)
			if err != nil {
				return fmt.Errorf("prefix lookup verification failed: %w", err)
			}
			fmt.Printf("Prefix:          %s\n", resp.Prefix)
			fmt.Printf("Matching Keys:   %d\n", len(resp.Results))
			fmt.Printf("MPT Root:        %x\n", resp.MPTRoot)
			fmt.Printf("Output Log Size: %d\n", resp.OutputSize)
			fmt.Printf("Input Log Size:  %d\n", resp.InputSize)
			for _, kr := range resp.Results {
				fmt.Printf("  Key %s (%x): %d occurrences %v\n", kr.Key, kr.ValueRoot, len(kr.Indices), kr.Indices)
				if *dereference && *inLogURL != "" {
					dereferenceIndices(ctx, *inLogURL, kr.Indices, resp.InputSize)
				}
			}
			return nil
		}
		keysResp, err := cli.LookupPrefix(ctx, target)
		if err != nil {
			return fmt.Errorf("prefix keys verification failed: %w", err)
		}
		fmt.Printf("Prefix:          %s\n", keysResp.QueryKey)
		fmt.Printf("Matching Keys:   %d\n", len(keysResp.Keys))
		fmt.Printf("MPT Root:        %x\n", keysResp.MPTRoot)
		fmt.Printf("Output Log Size: %d\n", keysResp.OutputSize)
		fmt.Printf("Input Log Size:  %d\n", keysResp.InputSize)
		for _, kv := range keysResp.Keys {
			fmt.Printf("  Key: %s ValueRoot: %x\n", kv.Key, kv.ValueRoot)
		}
		return nil
	}

	keysResp, err := cli.LookupKey(ctx, target)
	if err != nil {
		return fmt.Errorf("key lookup verification failed: %w", err)
	}

	exists := len(keysResp.Keys) > 0
	fmt.Printf("Key:             %s\n", keysResp.QueryKey)
	fmt.Printf("Exists:          %v\n", exists)
	fmt.Printf("MPT Root:        %x\n", keysResp.MPTRoot)
	fmt.Printf("Output Log Size: %d\n", keysResp.OutputSize)
	fmt.Printf("Input Log Size:  %d\n", keysResp.InputSize)

	if !exists {
		fmt.Println("No occurrences found in Input Log (cryptographically verified non-inclusion).")
		return nil
	}

	if *before > 0 {
		if strings.TrimSpace(*valueRootStr) == "" {
			return errors.New("--value_root (32-byte hex or base64 expected Value Log root from previous page) is required when --before > 0; or use --all for automatic verified pagination")
		}
		vr, err := parseDigest32(*valueRootStr)
		if err != nil {
			return fmt.Errorf("invalid --value_root %q: %w", *valueRootStr, err)
		}
		valResp, err := cli.LookupValues(ctx, target, vr, keysResp.From, *before, *limitCount)
		if err != nil {
			return fmt.Errorf("values lookup verification failed: %w", err)
		}
		fmt.Printf("Value Root:      %x\n", valResp.ValueRoot)
		fmt.Printf("Found %d verified occurrences:\n", len(valResp.Indices))
		for _, idx := range valResp.Indices {
			fmt.Printf("  Index: %d\n", idx)
		}
		if nextBefore, nextVR, ok := valResp.NextPage(); ok {
			fmt.Printf("Next before offset: %d --value_root=%x (or use --all to fetch all pages)\n", nextBefore, nextVR)
		}
		if *dereference && *inLogURL != "" {
			dereferenceIndices(ctx, *inLogURL, valResp.Indices, keysResp.InputSize)
		}
		return nil
	}

	valueRoot := keysResp.Keys[0].ValueRoot
	fmt.Printf("Value Root:      %x\n", valueRoot)

	var indices []uint64
	if *fetchAll {
		indices, err = cli.LookupAllValues(ctx, target, *limitCount)
		if err != nil {
			return fmt.Errorf("paginated values verification failed: %w", err)
		}
	} else {
		valResp, err := cli.LookupValues(ctx, target, valueRoot, keysResp.From, keysResp.InputSize, *limitCount)
		if err != nil {
			return fmt.Errorf("values lookup verification failed: %w", err)
		}
		indices = valResp.Indices
		if nextBefore, nextVR, ok := valResp.NextPage(); ok {
			defer fmt.Printf("Next before offset: %d --value_root=%x (or use --all to fetch all pages)\n", nextBefore, nextVR)
		}
	}

	fmt.Printf("Found %d verified occurrences:\n", len(indices))
	for _, idx := range indices {
		fmt.Printf("  Index: %d\n", idx)
	}

	if *dereference && *inLogURL != "" {
		dereferenceIndices(ctx, *inLogURL, indices, keysResp.InputSize)
	}

	return nil
}

func dereferenceIndices(ctx context.Context, baseURL string, indices []uint64, treeSize uint64) {
	fmt.Println("\nDereferencing leaves from Input Log:")
	for _, idx := range indices {
		data, err := ingest.FetchEntryByIndex(ctx, http.DefaultClient, baseURL, idx, treeSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error fetching leaf at index %d: %v\n", idx, err)
			continue
		}
		fmt.Printf("  [%d]: %s\n", idx, string(data))
	}
}

func parseDigest32(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == sha256.Size {
			copy(out[:], b)
			return out, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == sha256.Size {
		copy(out[:], b)
		return out, nil
	}
	return out, errors.New("expected 44-char base64 or 64-char hex SHA-256 digest")
}
