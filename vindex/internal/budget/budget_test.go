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

package budget

import (
	"strings"
	"testing"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
		hasErr   bool
	}{
		{"1024", 1024, false},
		{"1024B", 1024, false},
		{"1024bytes", 1024, false},
		{"1K", 1024, false},
		{"4KB", 4 * 1024, false},
		{"64KiB", 64 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		{"512MB", 512 * 1024 * 1024, false},
		{"512MiB", 512 * 1024 * 1024, false},
		{"16G", 16 * 1024 * 1024 * 1024, false},
		{"16GB", 16 * 1024 * 1024 * 1024, false},
		{"16GiB", 16 * 1024 * 1024 * 1024, false},
		{"1.5GB", uint64(1.5 * 1024 * 1024 * 1024), false},
		{"1T", 1024 * 1024 * 1024 * 1024, false},
		{"", 0, true},
		{"xyz", 0, true},
		{"-10GB", 0, true},
	}

	for _, tc := range tests {
		got, err := ParseBytes(tc.input)
		if tc.hasErr {
			if err == nil {
				t.Errorf("ParseBytes(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseBytes(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("ParseBytes(%q) = %d, expected %d", tc.input, got, tc.expected)
			}
		}
	}
}

func TestParseCount(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
		hasErr   bool
	}{
		{"4096", 4096, false},
		{"10k", 10_000, false},
		{"10K", 10_000, false},
		{"10ki", 10_240, false},
		{"50M", 50_000_000, false},
		{"2.5M", 2_500_000, false},
		{"1B", 1_000_000_000, false},
		{"", 0, true},
		{"abc", 0, true},
	}

	for _, tc := range tests {
		got, err := ParseCount(tc.input)
		if tc.hasErr {
			if err == nil {
				t.Errorf("ParseCount(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseCount(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("ParseCount(%q) = %d, expected %d", tc.input, got, tc.expected)
			}
		}
	}
}

func TestResolve_Defaults(t *testing.T) {
	b, err := Resolve(ResourceBudget{})
	if err != nil {
		t.Fatalf("Resolve with empty budget failed: %v", err)
	}

	if b.MaxMemoryBytes == 0 {
		t.Error("MaxMemoryBytes should not be 0")
	}
	if b.MaxCPUs <= 0 {
		t.Errorf("MaxCPUs should be > 0, got %d", b.MaxCPUs)
	}
	if b.GenesisKeyBufferSize < 1_000_000 {
		t.Errorf("GenesisKeyBufferSize too small: %d", b.GenesisKeyBufferSize)
	}
	if b.PebbleBlockCacheSizeMB < 256 {
		t.Errorf("PebbleBlockCacheSizeMB too small: %d", b.PebbleBlockCacheSizeMB)
	}
	if b.FetchWorkers < 2 {
		t.Errorf("FetchWorkers too small: %d", b.FetchWorkers)
	}
	if b.WASMWorkers < 1 {
		t.Errorf("WASMWorkers too small: %d", b.WASMWorkers)
	}

	summary := b.LogSummary()
	if !strings.Contains(summary, "VINDEX RESOURCE BUDGET RESOLUTION") {
		t.Errorf("LogSummary missing header: %s", summary)
	}
}

func TestResolve_Explicit16GB(t *testing.T) {
	b, err := Resolve(ResourceBudget{
		MaxMemory: "16GB",
		MaxCPUs:   16,
	})
	if err != nil {
		t.Fatalf("Resolve(16GB, 16 cpus) failed: %v", err)
	}

	const expectedBytes = 16 * 1024 * 1024 * 1024
	if b.MaxMemoryBytes != expectedBytes {
		t.Errorf("expected MaxMemoryBytes %d, got %d", expectedBytes, b.MaxMemoryBytes)
	}
	if b.MaxCPUs != 16 {
		t.Errorf("expected MaxCPUs 16, got %d", b.MaxCPUs)
	}

	// 25% of 16GiB = 4GiB. 4GiB / 80B ≈ 53,687,091 keys
	expectedKeys := uint64((expectedBytes * 25 / 100) / 80)
	if b.GenesisKeyBufferSize != expectedKeys {
		t.Errorf("expected GenesisKeyBufferSize %d, got %d", expectedKeys, b.GenesisKeyBufferSize)
	}

	// 20% of 16GiB = 3.2GiB = 3276 MB
	expectedCacheMB := int((expectedBytes * 20 / 100) / (1024 * 1024))
	if b.PebbleBlockCacheSizeMB != expectedCacheMB {
		t.Errorf("expected PebbleBlockCacheSizeMB %d, got %d", expectedCacheMB, b.PebbleBlockCacheSizeMB)
	}

	if b.PebbleMemTableSizeMB != 128 {
		t.Errorf("expected MemTable 128MB, got %d", b.PebbleMemTableSizeMB)
	}
	if b.WASMWorkers != 14 {
		t.Errorf("expected WASMWorkers 14 (16-2), got %d", b.WASMWorkers)
	}
	if b.FetchWorkers != 4 {
		t.Errorf("expected FetchWorkers 4 (16/4), got %d", b.FetchWorkers)
	}
}

func TestResolve_TuningOverrides(t *testing.T) {
	tune := "genesis_key_buffer=25M,db_cache=4096MB,wasm_workers=8,fetch_workers=6,chan_capacity=2048,coarse_checkpoint_interval=500k"
	b, err := Resolve(ResourceBudget{
		MaxMemory: "32GB",
		MaxCPUs:   32,
		Tune:      tune,
	})
	if err != nil {
		t.Fatalf("Resolve with tuning failed: %v", err)
	}

	if b.GenesisKeyBufferSize != 25_000_000 {
		t.Errorf("expected tuned GenesisKeyBufferSize 25M, got %d", b.GenesisKeyBufferSize)
	}
	if b.PebbleBlockCacheSizeMB != 4096 {
		t.Errorf("expected tuned PebbleBlockCacheSizeMB 4096, got %d", b.PebbleBlockCacheSizeMB)
	}
	if b.WASMWorkers != 8 {
		t.Errorf("expected tuned WASMWorkers 8, got %d", b.WASMWorkers)
	}
	if b.FetchWorkers != 6 {
		t.Errorf("expected tuned FetchWorkers 6, got %d", b.FetchWorkers)
	}
	if b.PipelineChannelCapacity != 2048 {
		t.Errorf("expected tuned PipelineChannelCapacity 2048, got %d", b.PipelineChannelCapacity)
	}
	if b.CoarseCheckpointInterval != 500_000 {
		t.Errorf("expected tuned CoarseCheckpointInterval 500000, got %d", b.CoarseCheckpointInterval)
	}

	summary := b.LogSummary()
	if !strings.Contains(summary, "Active Tuning Overrides:") {
		t.Errorf("LogSummary missing Overrides section: %s", summary)
	}
	if !strings.Contains(summary, "db_cache = 4096MB") {
		t.Errorf("LogSummary missing db_cache override: %s", summary)
	}
}

func TestResolve_InvalidTuneKey(t *testing.T) {
	_, err := Resolve(ResourceBudget{
		MaxMemory: "16GB",
		Tune:      "invalid_parameter=123",
	})
	if err == nil {
		t.Fatal("expected error for invalid tuning parameter, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tuning parameter") {
		t.Errorf("unexpected error message: %v", err)
	}
}
