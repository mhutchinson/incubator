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
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

// ResourceBudget defines the high-level system resource constraints.
type ResourceBudget struct {
	// MaxMemory specifies maximum process memory budget (e.g. "32GB", "16GiB", "8000M", "34359738368").
	// If empty or "0", it defaults to 16GB (or host physical memory if lower).
	MaxMemory string

	// MaxCPUs specifies the CPU core budget (e.g. 16).
	// If 0, it defaults to runtime.GOMAXPROCS(0).
	MaxCPUs int

	// Tune provides comma-separated fine-grained overrides in "key=val" format.
	// Example: "genesis_key_buffer=25M,db_cache=4096MB,wasm_workers=14".
	Tune string
}

// ResolvedBudget contains all derived and validated resource parameters across subsystems.
type ResolvedBudget struct {
	// Raw constraints
	MaxMemoryBytes uint64
	MaxCPUs        int

	// Memory allocations
	GenesisKeyBufferSize     uint64 // Number of coalescing keys (default 25% of budget, ~80B/key)
	PebbleBlockCacheSizeMB   int    // Block cache for Pebble in MB (default 20% of budget, min 256MB)
	PebbleMemTableSizeMB     int    // MemTable size in MB (64MB < 16GB, 128MB < 64GB, 256MB >= 64GB)
	PebbleMemTableStopWrites int    // Max memtables before write stall (default 8)
	PebbleMaxOpenFiles       int    // Max open SSTables (0 defaults to kvstore autoTuneMaxOpenFiles)
	PipelineChannelCapacity  int    // Capacity of stage queue channels (min 512, max 4096)

	// Concurrency allocations
	FetchWorkers          int // Tile fetch goroutines (default max(2, min(8, cpus/4)))
	FetchBatchBundles     int // Bundles per fetch batch (default 50)
	KVIndexerWorkers      int // Parallel key indexer goroutines (default max(2, min(8, cpus/4)))
	WASMWorkers           int // WASM mapper instances (default max(1, cpus - 2))
	ConcurrentCompactions int // Pebble background compaction workers (default max(2, min(16, cpus/2)))

	// Checkpointing & Commit sizing
	CoarseCheckpointInterval uint64 // Genesis backfill coarse checkpoint interval (default 1M)
	CommitBatchSize          uint64 // Ingest slab commit size (default 4096)

	// Overrides records explicit tuning keys applied
	Overrides map[string]string
}

// Resolve validates and calculates concrete operational parameters from the given ResourceBudget.
func Resolve(rb ResourceBudget) (*ResolvedBudget, error) {
	var maxMem uint64
	if strings.TrimSpace(rb.MaxMemory) == "" || rb.MaxMemory == "0" {
		hostMem := detectHostMemory()
		const defaultBudget = 16 * 1024 * 1024 * 1024 // 16 GiB
		if hostMem > 0 && hostMem < defaultBudget {
			maxMem = (hostMem * 3) / 4
			if maxMem < 1024*1024*1024 {
				maxMem = 1024 * 1024 * 1024 // 1 GiB floor
			}
		} else {
			maxMem = defaultBudget
		}
	} else {
		parsed, err := ParseBytes(rb.MaxMemory)
		if err != nil {
			return nil, fmt.Errorf("invalid max_memory %q: %w", rb.MaxMemory, err)
		}
		if parsed < 512*1024*1024 {
			return nil, fmt.Errorf("max_memory must be at least 512MB (got %d bytes)", parsed)
		}
		maxMem = parsed
	}

	cpus := rb.MaxCPUs
	if cpus <= 0 {
		cpus = runtime.GOMAXPROCS(0)
	}
	if cpus < 1 {
		cpus = 1
	}

	r := &ResolvedBudget{
		MaxMemoryBytes: maxMem,
		MaxCPUs:        cpus,
		Overrides:      make(map[string]string),
	}

	// 1. Memory partitioning
	// Genesis Key Buffer: 25% of memory budget (~80 bytes per entry in map[[32]byte][32]byte)
	const bytesPerKeyEntry = 80
	keyBufferBytes := (maxMem * 25) / 100
	r.GenesisKeyBufferSize = keyBufferBytes / bytesPerKeyEntry
	if r.GenesisKeyBufferSize < 1_000_000 {
		r.GenesisKeyBufferSize = 1_000_000
	}

	// Pebble Block Cache: 20% of memory budget, min 256MB
	cacheBytes := (maxMem * 20) / 100
	r.PebbleBlockCacheSizeMB = int(cacheBytes / (1024 * 1024))
	if r.PebbleBlockCacheSizeMB < 256 {
		r.PebbleBlockCacheSizeMB = 256
	}

	// Pebble MemTable sizing: 15% budget partition, scaled by memory tier
	if maxMem < 16*1024*1024*1024 {
		r.PebbleMemTableSizeMB = 64
	} else if maxMem < 64*1024*1024*1024 {
		r.PebbleMemTableSizeMB = 128
	} else {
		r.PebbleMemTableSizeMB = 256
	}
	r.PebbleMemTableStopWrites = 8
	r.PebbleMaxOpenFiles = 0 // 0 delegates to kvstore autoTuneMaxOpenFiles

	// Pipeline Channel Capacity
	chanCap := cpus * 32
	if chanCap < 512 {
		chanCap = 512
	}
	if chanCap > 4096 {
		chanCap = 4096
	}
	r.PipelineChannelCapacity = chanCap

	// 2. CPU concurrency partitioning
	fetchWorkers := cpus / 4
	if fetchWorkers < 2 {
		fetchWorkers = 2
	}
	if fetchWorkers > 8 {
		fetchWorkers = 8
	}
	r.FetchWorkers = fetchWorkers
	r.FetchBatchBundles = 50

	kvWorkers := cpus / 4
	if kvWorkers < 2 {
		kvWorkers = 2
	}
	if kvWorkers > 8 {
		kvWorkers = 8
	}
	r.KVIndexerWorkers = kvWorkers

	wasmWorkers := cpus - 2
	if wasmWorkers < 1 {
		wasmWorkers = 1
	}
	r.WASMWorkers = wasmWorkers

	compactions := cpus / 2
	if compactions < 2 {
		compactions = 2
	}
	if compactions > 16 {
		compactions = 16
	}
	r.ConcurrentCompactions = compactions

	// 3. Checkpointing & Slab sizing
	r.CoarseCheckpointInterval = 1_000_000
	r.CommitBatchSize = 4_096

	// 4. Apply fine-grained tune overrides
	if strings.TrimSpace(rb.Tune) != "" {
		if err := applyTune(r, rb.Tune); err != nil {
			return nil, err
		}
	}

	return r, nil
}

func applyTune(r *ResolvedBudget, tuneStr string) error {
	pairs := strings.Split(tuneStr, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid tune parameter %q: expected key=value", pair)
			}
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		k = strings.ReplaceAll(k, "-", "_")
		v := strings.TrimSpace(parts[1])

		r.Overrides[k] = v

		switch k {
		case "key_buffer", "genesis_key_buffer", "pre_set_buffer", "coalescing_buffer":
			// Can be count (e.g. "50M") or bytes (e.g. "4GB")
			lowerV := strings.ToLower(v)
			if strings.HasSuffix(lowerV, "b") {
				b, err := ParseBytes(v)
				if err != nil {
					return fmt.Errorf("tune %s: %w", k, err)
				}
				r.GenesisKeyBufferSize = b / 80
			} else {
				c, err := ParseCount(v)
				if err != nil {
					return fmt.Errorf("tune %s: %w", k, err)
				}
				r.GenesisKeyBufferSize = c
			}

		case "db_cache", "db_cache_mb", "db_cache_size_mb":
			if val, err := strconv.Atoi(v); err == nil {
				r.PebbleBlockCacheSizeMB = val
			} else {
				b, bErr := ParseBytes(v)
				if bErr != nil {
					return fmt.Errorf("tune %s: %w", k, bErr)
				}
				r.PebbleBlockCacheSizeMB = int(b / (1024 * 1024))
			}

		case "memtable", "memtable_mb", "memtable_size_mb":
			if val, err := strconv.Atoi(v); err == nil {
				r.PebbleMemTableSizeMB = val
			} else {
				b, bErr := ParseBytes(v)
				if bErr != nil {
					return fmt.Errorf("tune %s: %w", k, bErr)
				}
				r.PebbleMemTableSizeMB = int(b / (1024 * 1024))
			}

		case "memtable_stop_writes":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.PebbleMemTableStopWrites = val

		case "max_open_files", "db_max_open_files":
			val, err := strconv.Atoi(v)
			if err != nil || val < 0 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.PebbleMaxOpenFiles = val

		case "fetch_workers":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.FetchWorkers = val

		case "fetch_batch_bundles":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.FetchBatchBundles = val

		case "wasm_workers":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.WASMWorkers = val

		case "kv_indexer_workers", "indexer_workers":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.KVIndexerWorkers = val

		case "concurrent_compactions", "max_concurrent_compactions":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.ConcurrentCompactions = val

		case "pipeline_chan_cap", "chan_capacity", "channel_capacity":
			val, err := strconv.Atoi(v)
			if err != nil || val < 1 {
				return fmt.Errorf("tune %s: invalid integer %q", k, v)
			}
			r.PipelineChannelCapacity = val

		case "coarse_checkpoint_interval", "checkpoint_interval":
			c, err := ParseCount(v)
			if err != nil {
				return fmt.Errorf("tune %s: %w", k, err)
			}
			r.CoarseCheckpointInterval = c

		case "commit_batch_size", "slab_size":
			c, err := ParseCount(v)
			if err != nil {
				return fmt.Errorf("tune %s: %w", k, err)
			}
			r.CommitBatchSize = c

		default:
			return fmt.Errorf("unknown tuning parameter %q; valid keys: key_buffer, db_cache, memtable, memtable_stop_writes, max_open_files, fetch_workers, fetch_batch_bundles, wasm_workers, indexer_workers, concurrent_compactions, chan_capacity, checkpoint_interval, commit_batch_size", k)
		}
	}
	return nil
}

// ParseBytes parses a size string (e.g., "16GB", "8GiB", "512MB", "1073741824", "1.5G") into bytes.
func ParseBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty byte string")
	}

	i := 0
	for i < len(s) && (unicode.IsDigit(rune(s[i])) || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("missing numeric value in %q", s)
	}

	numStr := s[:i]
	unit := strings.TrimSpace(strings.ToLower(s[i:]))

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid number %q: %w", numStr, err)
	}

	var mult uint64
	switch unit {
	case "", "b", "bytes":
		mult = 1
	case "k", "kb", "kib":
		mult = 1024
	case "m", "mb", "mib":
		mult = 1024 * 1024
	case "g", "gb", "gib":
		mult = 1024 * 1024 * 1024
	case "t", "tb", "tib":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown byte unit %q in %q", unit, s)
	}

	res := uint64(val * float64(mult))
	return res, nil
}

// ParseCount parses human-readable quantities (e.g. "50M", "10k", "1B", "4096") into uint64.
func ParseCount(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty count string")
	}

	i := 0
	for i < len(s) && (unicode.IsDigit(rune(s[i])) || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("missing numeric value in %q", s)
	}

	numStr := s[:i]
	unit := strings.TrimSpace(strings.ToLower(s[i:]))

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid count %q: %w", numStr, err)
	}

	var mult float64
	switch unit {
	case "":
		mult = 1
	case "k", "thousand":
		mult = 1_000
	case "ki":
		mult = 1_024
	case "m", "million":
		mult = 1_000_000
	case "mi":
		mult = 1_024 * 1_024
	case "b", "billion":
		mult = 1_000_000_000
	case "gi":
		mult = 1_024 * 1_024 * 1_024
	default:
		return 0, fmt.Errorf("unknown count multiplier %q in %q", unit, s)
	}

	return uint64(val * mult), nil
}

// detectHostMemory inspects cgroups and /proc/meminfo to identify available physical host memory.
func detectHostMemory() uint64 {
	// 1. Check cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		str := strings.TrimSpace(string(data))
		if str != "max" && str != "" {
			if v, err := strconv.ParseUint(str, 10, 64); err == nil && v > 0 {
				return v
			}
		}
	}

	// 2. Check cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		str := strings.TrimSpace(string(data))
		if v, err := strconv.ParseUint(str, 10, 64); err == nil && v > 0 && v < 0x7FFFFFFFFFFFF000 {
			return v
		}
	}

	// 3. Check /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						return kb * 1024
					}
				}
			}
		}
	}

	return 0
}

// LogSummary returns a clean, structured multi-line string detailing the active resource budget.
func (r *ResolvedBudget) LogSummary() string {
	var b strings.Builder
	memGiB := float64(r.MaxMemoryBytes) / float64(1024*1024*1024)
	keyBufGiB := float64(r.GenesisKeyBufferSize*80) / float64(1024*1024*1024)
	cacheGiB := float64(r.PebbleBlockCacheSizeMB) / 1024.0

	b.WriteString("================================================================================\n")
	b.WriteString("VINDEX RESOURCE BUDGET RESOLUTION\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString(fmt.Sprintf("Memory Budget:           %.2f GiB (%d bytes)\n", memGiB, r.MaxMemoryBytes))
	b.WriteString(fmt.Sprintf("CPU Budget:              %d cores\n", r.MaxCPUs))
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("Derived Memory Partitions:\n")
	b.WriteString(fmt.Sprintf("  • Genesis Key Buffer:   %s keys (~%.2f GiB, ~%.1f%% of memory budget)\n",
		formatWithCommas(r.GenesisKeyBufferSize), keyBufGiB, (keyBufGiB/memGiB)*100))
	b.WriteString(fmt.Sprintf("  • Pebble Block Cache:   %d MB (~%.2f GiB, ~%.1f%% of memory budget)\n",
		r.PebbleBlockCacheSizeMB, cacheGiB, (cacheGiB/memGiB)*100))
	b.WriteString(fmt.Sprintf("  • Pebble MemTable Size: %d MB (stop writes threshold: %d memtables)\n",
		r.PebbleMemTableSizeMB, r.PebbleMemTableStopWrites))
	b.WriteString(fmt.Sprintf("  • Pipeline Channel Cap: %d batches\n", r.PipelineChannelCapacity))
	headroomGiB := memGiB - keyBufGiB - cacheGiB - (float64(r.PebbleMemTableSizeMB*r.PebbleMemTableStopWrites) / 1024.0)
	if headroomGiB < 0 {
		headroomGiB = 0
	}
	b.WriteString(fmt.Sprintf("  • Uncommitted Headroom: ~%.2f GiB (OS page cache, GC slack, runtime heap)\n", headroomGiB))
	b.WriteString("Derived Concurrency Partitions:\n")
	b.WriteString(fmt.Sprintf("  • WASM Workers:         %d instances\n", r.WASMWorkers))
	b.WriteString(fmt.Sprintf("  • Fetch Workers:        %d workers (%d bundles/batch)\n", r.FetchWorkers, r.FetchBatchBundles))
	b.WriteString(fmt.Sprintf("  • KV Indexer Workers:   %d workers\n", r.KVIndexerWorkers))
	b.WriteString(fmt.Sprintf("  • Pebble Compactions:   %d concurrent workers\n", r.ConcurrentCompactions))
	b.WriteString("Checkpoints & Commits:\n")
	b.WriteString(fmt.Sprintf("  • Commit Batch Size:    %s leaves\n", formatWithCommas(r.CommitBatchSize)))
	b.WriteString(fmt.Sprintf("  • Coarse Checkpoint:    %s leaves\n", formatWithCommas(r.CoarseCheckpointInterval)))

	if len(r.Overrides) > 0 {
		b.WriteString("Active Tuning Overrides:\n")
		for k, v := range r.Overrides {
			b.WriteString(fmt.Sprintf("  • %s = %s\n", k, v))
		}
	} else {
		b.WriteString("Active Tuning Overrides:  none\n")
	}
	b.WriteString("================================================================================\n")
	return b.String()
}

func formatWithCommas(n uint64) string {
	in := strconv.FormatUint(n, 10)
	var out []byte
	l := len(in)
	for i, c := range []byte(in) {
		if i > 0 && (l-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
