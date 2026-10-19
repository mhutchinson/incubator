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

// Package hammer provides synthetic load generation and verification tools for VIndex.
package hammer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

// Distribution defines the key selection distribution.
type Distribution string

const (
	DistZipf    Distribution = "zipf"
	DistPareto  Distribution = "pareto" // Alias for discrete Pareto / Zipfian skew.
	DistUniform Distribution = "uniform"
)

// LeafFormat defines the raw payload formatting for synthetic leaves.
type LeafFormat string

const (
	FormatRaw   LeafFormat = "raw"   // Leaf is the raw key bytes (identity mapping)
	FormatSumDB LeafFormat = "sumdb" // Leaf is structured: "<key> v1.<ver>.0 h1:<hash>\n"
	FormatCT    LeafFormat = "ct"    // Leaf is an RFC 6962 X.509 MerkleTreeLeaf with SAN dNSNames (reversed-DNS keys)
)

// GeneratorConfig configures the synthetic leaf generator.
type GeneratorConfig struct {
	Distribution Distribution
	NumKeys      uint64
	ZipfS        float64 // Skew parameter for Zipf (s > 1.0, e.g. 1.2)
	ZipfV        float64 // Scale parameter for Zipf (v >= 1.0, e.g. 1.0)
	Seed         int64
	LeafFormat   LeafFormat
	CTMinDomains int
	CTMaxDomains int
}

// DefaultGeneratorConfig returns a production-like default generator configuration.
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		Distribution: DistZipf,
		NumKeys:      10000,
		ZipfS:        1.2,
		ZipfV:        1.0,
		Seed:         42,
		LeafFormat:   FormatRaw,
		CTMinDomains: 1,
		CTMaxDomains: 50,
	}
}

// LeafEntry represents a generated leaf with its primary canonical key.
type LeafEntry struct {
	LeafData []byte
	Key      string
	Version  uint64
}

// Generator generates synthetic leaves with configurable key distributions.
type Generator struct {
	mu          sync.Mutex
	cfg         GeneratorConfig
	rng         *rand.Rand
	zipf        *rand.Zipf
	ctPriv      ed25519.PrivateKey
	ctPub       ed25519.PublicKey
	totalLeaves uint64
}

// NewGenerator creates a new Generator instance.
func NewGenerator(cfg GeneratorConfig) *Generator {
	if cfg.NumKeys == 0 {
		cfg.NumKeys = 10000
	}
	if cfg.ZipfS <= 1.0 {
		cfg.ZipfS = 1.2
	}
	if cfg.ZipfV < 1.0 {
		cfg.ZipfV = 1.0
	}
	if cfg.Seed == 0 {
		cfg.Seed = 42
	}
	if cfg.LeafFormat == "" {
		cfg.LeafFormat = FormatRaw
	}
	if cfg.CTMinDomains <= 0 {
		cfg.CTMinDomains = 1
	}
	if cfg.CTMaxDomains <= 0 {
		cfg.CTMaxDomains = 50
	}
	if cfg.CTMaxDomains < cfg.CTMinDomains {
		cfg.CTMaxDomains = cfg.CTMinDomains
	}

	rng := rand.New(rand.NewSource(cfg.Seed))
	var zipf *rand.Zipf
	if cfg.Distribution != DistUniform && cfg.NumKeys > 1 {
		zipf = rand.NewZipf(rng, cfg.ZipfS, cfg.ZipfV, cfg.NumKeys-1)
	}

	var seedHash [sha256.Size]byte
	binary.BigEndian.PutUint64(seedHash[:8], uint64(cfg.Seed))
	ctSeed := sha256.Sum256(seedHash[:])
	ctPriv := ed25519.NewKeyFromSeed(ctSeed[:])
	ctPub := ctPriv.Public().(ed25519.PublicKey)

	return &Generator{
		cfg:    cfg,
		rng:    rng,
		zipf:   zipf,
		ctPriv: ctPriv,
		ctPub:  ctPub,
	}
}

func (g *Generator) keyForIDLocked(id uint64) string {
	if g.cfg.LeafFormat == FormatCT {
		return fmt.Sprintf("com.domain-%d.", id)
	}
	return KeyForID(id)
}

func buildRFC6962X509Leaf(rng *rand.Rand, serial uint64, dnsNames []string, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(serial),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Unix(1_700_000_000, 0).UTC(),
		NotAfter:     time.Unix(1_800_000_000, 0).UTC(),
	}
	certDER, err := x509.CreateCertificate(rng, tmpl, tmpl, pub, priv)
	if err != nil {
		panic(fmt.Sprintf("hammer: failed to build synthetic X.509 certificate: %v", err))
	}
	// RFC 6962 MerkleTreeLeaf: version(0) || leaf_type(0) || timestamp(8) || entry_type(0=x509) || cert_len(3) || certDER || ext_len(2=0)
	leaf := make([]byte, 17+len(certDER))
	binary.BigEndian.PutUint64(leaf[2:10], 1_700_000_000_000+serial)
	leaf[12] = byte(len(certDER) >> 16)
	leaf[13] = byte(len(certDER) >> 8)
	leaf[14] = byte(len(certDER))
	copy(leaf[15:], certDER)
	return leaf
}

// NextLeaf generates the next sequential leaf entry according to the configured distribution.
func (g *Generator) NextLeaf() LeafEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.totalLeaves++
	ver := g.totalLeaves

	if g.cfg.LeafFormat == FormatCT {
		count := g.cfg.CTMinDomains
		if g.cfg.CTMaxDomains > g.cfg.CTMinDomains {
			count = g.cfg.CTMinDomains + g.rng.Intn(g.cfg.CTMaxDomains-g.cfg.CTMinDomains+1)
		}

		domainIDs := make([]uint64, 0, count)
		seen := make(map[uint64]struct{}, count)
		for range count {
			id := g.sampleKeyIDLocked()
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				domainIDs = append(domainIDs, id)
			}
		}
		if len(domainIDs) == 0 {
			domainIDs = append(domainIDs, g.sampleKeyIDLocked())
		}

		dnsNames := make([]string, 0, len(domainIDs)*2)
		for i, id := range domainIDs {
			dnsNames = append(dnsNames,
				fmt.Sprintf("domain-%d.com", id),
				fmt.Sprintf("sub-%d.domain-%d.com", i+1, id),
			)
		}

		return LeafEntry{
			LeafData: buildRFC6962X509Leaf(g.rng, ver, dnsNames, g.ctPub, g.ctPriv),
			Key:      g.keyForIDLocked(domainIDs[0]),
			Version:  ver,
		}
	}

	keyStr := g.keyForIDLocked(g.sampleKeyIDLocked())
	var leafData []byte
	if g.cfg.LeafFormat == FormatSumDB {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s@v1.%d.0", keyStr, ver)))
		leafData = []byte(fmt.Sprintf("%s v1.%d.0 h1:%s\n", keyStr, ver, hex.EncodeToString(h[:16])))
	} else {
		leafData = []byte(keyStr)
	}

	return LeafEntry{
		LeafData: leafData,
		Key:      keyStr,
		Version:  ver,
	}
}

// SampleExistingKey samples a key from the existing key distribution for reading.
func (g *Generator) SampleExistingKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.keyForIDLocked(g.sampleKeyIDLocked())
}

// SampleHotKey samples from the top 1% hottest keys in the working set.
func (g *Generator) SampleHotKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	hotCount := max(g.cfg.NumKeys/100, 1)
	if hotCount > math.MaxInt64 {
		hotCount = math.MaxInt64
	}
	keyID := uint64(g.rng.Int63n(int64(hotCount)))
	return g.keyForIDLocked(keyID)
}

// SampleNonInclusionKey returns a key guaranteed not to exist in the log.
func (g *Generator) SampleNonInclusionKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := g.cfg.NumKeys + uint64(g.rng.Int63n(1000000)) + 1
	if g.cfg.LeafFormat == FormatCT {
		return fmt.Sprintf("com.nonexistent-domain-%d.", id)
	}
	return fmt.Sprintf("nonexistent/pkg-%d", id)
}

func (g *Generator) sampleKeyIDLocked() uint64 {
	if g.cfg.Distribution == DistUniform || g.zipf == nil {
		numKeys := g.cfg.NumKeys
		if numKeys > math.MaxInt64 {
			numKeys = math.MaxInt64
		}
		return uint64(g.rng.Int63n(int64(numKeys)))
	}
	return g.zipf.Uint64()
}

// KeyForID returns the deterministic string key name for a given key ID.
func KeyForID(id uint64) string {
	return fmt.Sprintf("example.com/module-%d", id)
}
