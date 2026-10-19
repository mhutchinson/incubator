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

// sumdbverify looks up versions for a Go module in a Go Checksum Verifiable Index
// and compares those verified entries against local git tags and zip/go.mod hashes.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/zip"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	vindexURL       = flag.String("vindex_url", "", "Base URL of the server hosting the SumDB VIndex.")
	inputLogURLFlag = flag.String("input_log_url", "", "Base URL of the tiled SumDB Input Log (defaults to <vindex_url>/sumdb/).")
	inputLogOrigin  = flag.String("input_log_origin", "go.sum database tree", "Expected origin for the Input Log.")
	outputLogPolicy = flag.String("output_log_policy", "", "Path to C2SP tlog-policy file for the Output Log.")
	outputLogPubKey = flag.String("output_log_pubkey", "", "Public key or key file to verify the Output Log checkpoint.")
	outputLogOrigin = flag.String("output_log_origin", "", "Expected origin for the Output Log (inferred from --output_log_policy or --output_log_pubkey when unset).")
	modRoot         = flag.String("mod_root", "", "Path to a Go module checked out locally via git.")
	maxFrom         = flag.Uint64("max_from", 0, "Maximum acceptable VIndex start index (from); defaults to 0 so suffix-indexed instances cannot silently omit older releases.")
)

var (
	line0RE = regexp.MustCompile(`(.*) (.*) (h1:.*)`)
	line1RE = regexp.MustCompile(`(.*) (.*)/go.mod (h1:.*)`)
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if err := run(context.Background()); err != nil {
		klog.Exitf("run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	targetBaseURL := strings.TrimSpace(*vindexURL)
	targetModRoot := strings.TrimSpace(*modRoot)
	if targetModRoot == "" {
		return errors.New("--mod_root flag must be provided")
	}
	if s, err := os.Stat(targetModRoot); err != nil || !s.IsDir() {
		return fmt.Errorf("mod_root %q does not exist or is not a directory", targetModRoot)
	}

	var sumFetcher func(ctx context.Context, modName string) (map[string]modData, error)
	if targetBaseURL == "" {
		klog.Warningf("--vindex_url is not provided. Using NON-VERIFIABLE lookup to source SumDB data.")
		sumFetcher = fetchUnverifiedSumDB
	} else {
		cli, err := newClientFromFlags(targetBaseURL)
		if err != nil {
			return err
		}
		inLogURL := strings.TrimSpace(*inputLogURLFlag)
		if inLogURL == "" {
			inLogURL, err = url.JoinPath(targetBaseURL, "/sumdb/")
			if err != nil {
				return fmt.Errorf("failed to construct input log URL: %w", err)
			}
		}
		sumFetcher = func(ctx context.Context, modName string) (map[string]modData, error) {
			return queryIndex(ctx, cli, inLogURL, modName, *maxFrom)
		}
	}

	report, reportErr := getReport(ctx, targetModRoot, sumFetcher)
	if reportErr != nil && len(report.versions) == 0 {
		return fmt.Errorf("failed to compile report: %w", reportErr)
	}

	fmt.Printf("%s (./%s)\n", report.modName, report.modPath)

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "VERSION\tINDEX\tFOUND\tgo.mod\tzip\t"); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}
	var reportErrors []error
	if reportErr != nil {
		reportErrors = append(reportErrors, reportErr)
	}
	for _, v := range report.versions {
		if !v.sumFound {
			reportErrors = append(reportErrors, fmt.Errorf("local git tag %q is missing from SumDB", v.version))
			if _, err := fmt.Fprintf(tw, "%s\t--\t✅\t--\t--\t\n", v.version); err != nil {
				return fmt.Errorf("failed to output report: %w", err)
			}
			continue
		}
		sumIndex := strconv.FormatUint(v.sumIndex, 10)

		gitHash := "✅"
		if v.gitCommit == "" {
			gitHash = "❌"
		}

		goMod := "✅"
		if v.gitCommit == "" || v.gitModHash == "" {
			goMod = "⚠️"
		} else if v.gitModHash != v.sumModHash {
			reportErrors = append(reportErrors, fmt.Errorf("failed to reproduce go.mod hash for version %q", v.version))
			goMod = "❌"
		}

		goZip := "✅"
		if v.gitCommit == "" || v.gitModHash == "" {
			goZip = "⚠️"
		} else if v.gitZipHash != v.sumZipHash {
			reportErrors = append(reportErrors, fmt.Errorf("failed to reproduce zip hash for version %q", v.version))
			goZip = "❌"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", v.version, sumIndex, gitHash, goMod, goZip); err != nil {
			return fmt.Errorf("failed to output report: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush report to stdout: %w", err)
	}

	return errors.Join(reportErrors...)
}

func fetchUnverifiedSumDB(ctx context.Context, modName string) (map[string]modData, error) {
	escaped, err := module.EscapePath(modName)
	if err != nil {
		return nil, fmt.Errorf("failed to escape module path %q: %w", modName, err)
	}
	body, err := httpGetBody(ctx, fmt.Sprintf("https://proxy.golang.org/%s/@v/list", escaped))
	if err != nil {
		return nil, fmt.Errorf("failed to get module listing: %w", err)
	}
	result := make(map[string]modData)
	for v := range strings.Lines(string(body)) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		escVer, err := module.EscapeVersion(v)
		if err != nil {
			return nil, fmt.Errorf("failed to escape version %q: %w", v, err)
		}
		vBody, err := httpGetBody(ctx, fmt.Sprintf("https://sum.golang.org/lookup/%s@%s", escaped, escVer))
		if err != nil {
			return nil, fmt.Errorf("failed to get version info for %s@%s: %w", modName, v, err)
		}
		lines := bytes.Split(vBody, []byte{'\n'})
		if len(lines) < 3 {
			return nil, fmt.Errorf("unexpected lookup response for %s@%s: expected at least 3 lines, got %d", modName, v, len(lines))
		}
		idx, err := strconv.ParseUint(string(lines[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse index: %w", err)
		}
		leaf := bytes.Join([][]byte{lines[1], lines[2], nil}, []byte{'\n'})
		v2, md, err := parseLeaf(idx, leaf, modName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf: %w", err)
		}
		if v != v2 {
			return nil, fmt.Errorf("performed lookup for %s@%s but got version %s", modName, v, v2)
		}
		result[v] = md
	}
	return result, nil
}

func httpGetBody(ctx context.Context, reqURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func findGoMod(modRoot string) (string, error) {
	const rootMod = "go.mod"
	if s, err := os.Stat(filepath.Join(modRoot, rootMod)); err == nil && !s.IsDir() {
		return rootMod, nil
	}

	var found string
	err := filepath.WalkDir(modRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == rootMod {
			relPath, err := filepath.Rel(modRoot, path)
			if err != nil {
				return err
			}
			found = relPath
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to search for go.mod: %w", err)
	}
	if found == "" {
		return "", errors.New("go.mod not found")
	}
	return found, nil
}

func runGit(ctx context.Context, modRoot string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-C", modRoot}, args...)
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	return cmd.Output()
}

func getReport(ctx context.Context, modRoot string, sumFetcher func(context.Context, string) (map[string]modData, error)) (diffReport, error) {
	if s, err := os.Stat(modRoot); err != nil || !s.IsDir() {
		return diffReport{}, errors.New("mod_root flag must be a directory")
	}
	goModPath, err := findGoMod(modRoot)
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to find go.mod file in %s: %w", modRoot, err)
	}
	modPathBytes, err := os.ReadFile(filepath.Join(modRoot, goModPath))
	if err != nil {
		return diffReport{}, fmt.Errorf("failed to read go.mod file: %w", err)
	}
	modName := modfile.ModulePath(modPathBytes)
	if modName == "" {
		return diffReport{}, errors.New("failed to parse module path from go.mod")
	}

	report := diffReport{
		modName:  modName,
		modPath:  goModPath,
		versions: make([]versionReport, 0),
	}

	if _, err := runGit(ctx, modRoot, "rev-parse", "--git-dir"); err != nil {
		return report, fmt.Errorf("directory at mod_root %q is not a git repository: %w", modRoot, err)
	}

	eg, egctx := errgroup.WithContext(ctx)
	var versions map[string]modData
	var tags map[string]struct{}

	eg.Go(func() error {
		var fErr error
		versions, fErr = sumFetcher(egctx, modName)
		return fErr
	})
	eg.Go(func() error {
		out, gErr := runGit(egctx, modRoot, "tag", "--list")
		if gErr != nil {
			return fmt.Errorf("failed to list git tags: %w", gErr)
		}
		tags = make(map[string]struct{})
		for line := range strings.Lines(string(out)) {
			if tag := strings.TrimSpace(line); tag != "" {
				tags[tag] = struct{}{}
			}
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return report, err
	}

	sv := make([]string, 0, len(versions))
	for v := range versions {
		sv = append(sv, v)
	}
	semver.Sort(sv)

	tagPrefix := ""
	if dir := filepath.ToSlash(filepath.Dir(goModPath)); dir != "." && dir != "" {
		tagPrefix = dir + "/"
	}

	var vErrors []error
	for _, v := range sv {
		sumHashes := versions[v]
		vr, err := reportVersion(ctx, modRoot, goModPath, modName, tagPrefix, v)
		if err != nil {
			vErrors = append(vErrors, fmt.Errorf("failed to get report for version %q: %w", v, err))
		}
		vr.sumFound = true
		vr.sumModHash = sumHashes.modHash
		vr.sumZipHash = sumHashes.zipHash
		vr.sumIndex = sumHashes.index
		report.versions = append(report.versions, vr)
		if vr.gitCommit != "" {
			delete(tags, tagPrefix+v)
		}
	}

	for rawTag := range tags {
		if !strings.HasPrefix(rawTag, tagPrefix) {
			continue
		}
		v := strings.TrimPrefix(rawTag, tagPrefix)
		if !semver.IsValid(v) {
			continue
		}
		commitOut, err := runGit(ctx, modRoot, "rev-parse", "--verify", "--quiet", "refs/tags/"+rawTag+"^{commit}")
		if err != nil {
			continue
		}
		report.versions = append(report.versions, versionReport{
			version:   v,
			gitCommit: strings.TrimSpace(string(commitOut)),
			sumFound:  false,
		})
	}
	slices.SortFunc(report.versions, func(a, b versionReport) int {
		if c := semver.Compare(a.version, b.version); c != 0 {
			return c
		}
		return strings.Compare(a.version, b.version)
	})
	return report, errors.Join(vErrors...)
}

func reportVersion(ctx context.Context, modRoot, goModPath, modName, tagPrefix, v string) (versionReport, error) {
	report := versionReport{version: v}
	if !semver.IsValid(v) || strings.ContainsAny(v, "\x00\r\n\t ") {
		return report, fmt.Errorf("invalid semver tag %q", v)
	}

	commitOut, err := runGit(ctx, modRoot, "rev-parse", "--verify", "--quiet", "refs/tags/"+tagPrefix+v+"^{commit}")
	if err != nil {
		return report, fmt.Errorf("failed to resolve tag %q to a commit: %w", v, err)
	}
	commitHex := strings.TrimSpace(string(commitOut))
	report.gitCommit = commitHex

	slashModPath := filepath.ToSlash(goModPath)
	treeSpec := commitHex + ":" + slashModPath
	if _, err := runGit(ctx, modRoot, "cat-file", "-e", treeSpec); err != nil {
		// Pre-modules release without a go.mod file in git tree.
		return report, nil
	}
	modBlob, err := runGit(ctx, modRoot, "cat-file", "blob", treeSpec)
	if err != nil {
		return report, fmt.Errorf("failed to read %s: %w", treeSpec, err)
	}

	// dirhash.Hash1 hashes the logical filename "go.mod" regardless of subdirectory nesting.
	hs, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(modBlob)), nil
	})
	if err != nil {
		return report, fmt.Errorf("failed to calculate go.mod hash: %w", err)
	}
	report.gitModHash = hs

	f, err := os.CreateTemp("", "goModZip")
	if err != nil {
		return report, fmt.Errorf("failed to create temp file: %w", err)
	}
	zipName := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(zipName)
	}()

	subdir := filepath.Dir(goModPath)
	if subdir == "." {
		subdir = ""
	}
	modVer := module.Version{Path: modName, Version: v}
	if err := zip.CreateFromVCS(f, modVer, modRoot, commitHex, subdir); err != nil {
		return report, fmt.Errorf("failed to create zip file: %w", err)
	}
	if err := f.Close(); err != nil {
		return report, fmt.Errorf("failed to close zip file: %w", err)
	}
	report.gitZipHash, err = dirhash.HashZip(zipName, dirhash.Hash1)
	if err != nil {
		return report, fmt.Errorf("failed to hash zip file: %w", err)
	}

	return report, nil
}

type diffReport struct {
	modName  string
	modPath  string
	versions []versionReport
}

type versionReport struct {
	version    string
	gitCommit  string
	gitModHash string
	gitZipHash string

	sumFound   bool
	sumIndex   uint64
	sumModHash string
	sumZipHash string
}

type modData struct {
	index   uint64
	zipHash string
	modHash string
}

func queryIndex(ctx context.Context, cli *client.Client, inLogURL, modName string, maxFromHorizon uint64) (map[string]modData, error) {
	escapedMod, err := module.EscapePath(modName)
	if err != nil {
		return nil, fmt.Errorf("failed to escape module path %q: %w", modName, err)
	}
	keysResp, err := cli.LookupKey(ctx, escapedMod)
	if err != nil {
		return nil, fmt.Errorf("failed to look up key: %w", err)
	}
	if keysResp.From > maxFromHorizon {
		return nil, fmt.Errorf("VIndex covers entries starting at from=%d (exceeds --max_from=%d); historical releases before %d would be omitted", keysResp.From, maxFromHorizon, keysResp.From)
	}
	if len(keysResp.Keys) == 0 {
		return make(map[string]modData), nil
	}

	var indices []uint64
	for idx, err := range keysResp.Keys[0].Values(ctx) {
		if err != nil {
			return nil, fmt.Errorf("failed to look up values: %w", err)
		}
		indices = append(indices, idx)
	}
	if len(indices) == 0 {
		return make(map[string]modData), nil
	}

	versions := make(map[string]modData, len(indices))
	for _, idx := range indices {
		leafData, err := ingest.FetchVerifiedEntryByIndex(ctx, http.DefaultClient, inLogURL, idx, keysResp.InputSize, keysResp.InputRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to get leaf at index %d: %w", idx, err)
		}
		version, data, err := parseLeaf(idx, leafData, modName)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf at index %d: %w", idx, err)
		}
		if prev, found := versions[version]; found {
			return nil, fmt.Errorf("conflicting versions for version %q found: %v vs %v", version, prev, data)
		}
		versions[version] = data
	}
	return versions, nil
}

func parseLeaf(idx uint64, data []byte, expectedMod ...string) (string, modData, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return "", modData{}, fmt.Errorf("expected at least 2 lines but got %d", len(lines))
	}

	line0Parts := line0RE.FindStringSubmatch(lines[0])
	if len(line0Parts) < 4 {
		return "", modData{}, fmt.Errorf("invalid line 0 format: %q", lines[0])
	}
	line0Module, line0Version, zipHashB64 := line0Parts[1], line0Parts[2], line0Parts[3]

	line1Parts := line1RE.FindStringSubmatch(lines[1])
	if len(line1Parts) < 4 {
		return "", modData{}, fmt.Errorf("invalid line 1 format: %q", lines[1])
	}
	line1Module, line1Version, modHashB64 := line1Parts[1], line1Parts[2], line1Parts[3]

	if line0Module != line1Module {
		return "", modData{}, fmt.Errorf("mismatched module names: (%s, %s)", line0Module, line1Module)
	}
	if len(expectedMod) > 0 && expectedMod[0] != "" && line0Module != expectedMod[0] {
		return "", modData{}, fmt.Errorf("leaf module %q does not match expected module %q", line0Module, expectedMod[0])
	}
	if line0Version != line1Version {
		return "", modData{}, fmt.Errorf("mismatched version names: (%s, %s)", line0Version, line1Version)
	}

	return line0Version, modData{
		index:   idx,
		zipHash: zipHashB64,
		modHash: modHashB64,
	}, nil
}

func newClientFromFlags(targetBaseURL string) (*client.Client, error) {
	pubKey := strings.TrimSpace(*outputLogPubKey)
	policyPath := strings.TrimSpace(*outputLogPolicy)
	if policyPath == "" && pubKey == "" {
		return nil, errors.New("--output_log_policy or --output_log_pubkey flag must be provided when --vindex_url is set")
	}

	outOrigin := strings.TrimSpace(*outputLogOrigin)
	outPolicy, err := wire.ParsePolicyOrVerifier(policyPath, pubKey, outOrigin, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to build output log policy: %w", err)
	}
	if outOrigin == "" {
		outOrigin = wire.PolicyOrigin(outPolicy)
	}

	return client.New(targetBaseURL, client.Config{
		ExpectedOutputLogOrigin: outOrigin,
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  strings.TrimSpace(*inputLogOrigin),
	}, client.WithHTTPClient(http.DefaultClient))
}
