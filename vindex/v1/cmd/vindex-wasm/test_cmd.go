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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/transparency-dev/incubator/vindex/v1/internal/ingest"
)

type testJSONEntry struct {
	Index   int    `json:"index"`
	KeyHash string `json:"key_hash"`
	Value   string `json:"value,omitempty"`
}

type testJSONOutput struct {
	Total   int             `json:"total"`
	Entries []testJSONEntry `json:"entries"`
}

func runTestCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	wasmPath := fs.String("wasm", "", "Path to compiled WASM plugin file (required).")
	inputStr := fs.String("input", "", "Literal string input payload.")
	inputFile := fs.String("input_file", "", "Path to file containing input leaf payload.")
	inputHex := fs.String("hex", "", "Hex-encoded input leaf payload.")
	format := fs.String("format", "plain", "Output format: plain or json.")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *wasmPath == "" {
		if fs.NArg() > 0 && (strings.HasSuffix(fs.Arg(0), ".wasm") || *inputStr != "") {
			*wasmPath = fs.Arg(0)
		} else {
			return errors.New("--wasm flag is required")
		}
	}

	wasmBytes, err := os.ReadFile(*wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM file %q: %w", *wasmPath, err)
	}

	var inputBytes []byte
	if *inputHex != "" {
		b, err := hex.DecodeString(*inputHex)
		if err != nil {
			return fmt.Errorf("invalid hex input %q: %w", *inputHex, err)
		}
		inputBytes = b
	} else if *inputFile == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read input from stdin: %w", err)
		}
		inputBytes = b
	} else if *inputFile != "" {
		b, err := os.ReadFile(*inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file %q: %w", *inputFile, err)
		}
		inputBytes = b
	} else if *inputStr != "" {
		inputBytes = []byte(*inputStr)
	} else if fs.NArg() > 0 {
		// Positional argument as input string
		arg := fs.Arg(0)
		if arg == *wasmPath && fs.NArg() > 1 {
			arg = fs.Arg(1)
		}
		if arg != *wasmPath {
			inputBytes = []byte(arg)
		}
	}

	host, err := ingest.NewWASMHost(ctx, wasmBytes, 1)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host: %w", err)
	}
	defer func() { _ = host.Close(ctx) }()

	entries, err := host.MapLeaf(ctx, inputBytes)
	if err != nil {
		return fmt.Errorf("MapLeaf execution failed: %w", err)
	}

	if *format == "json" {
		out := testJSONOutput{
			Total:   len(entries),
			Entries: make([]testJSONEntry, len(entries)),
		}
		for i, e := range entries {
			out.Entries[i] = testJSONEntry{
				Index:   i,
				KeyHash: hex.EncodeToString(e.KeyHash[:]),
			}
			if len(e.Value) > 0 {
				out.Entries[i].Value = hex.EncodeToString(e.Value)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("Mapped %d entries from input (%d bytes):\n", len(entries), len(inputBytes))
	for i, e := range entries {
		if len(e.Value) > 0 {
			fmt.Printf("  [%d] KeyHash: %x | Value: %s (hex: %x)\n", i, e.KeyHash, string(e.Value), e.Value)
		} else {
			fmt.Printf("  [%d] KeyHash: %x\n", i, e.KeyHash)
		}
	}

	return nil
}
