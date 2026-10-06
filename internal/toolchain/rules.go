package toolchain

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// RuleSet is a downloadable community Opengrep rule pack. It is fetched on demand
// and NEVER embedded in the binary or committed to this repository.
//
// LICENSE WARNING: the opengrep-rules repository is semgrep-rules (LGPL-2.1) with a
// "Commons Clause" condition on top: you may not "Sell" the rules, including
// offering hosting/consulting services whose value derives substantially from
// them. That is why Achilles (a) never bundles them, (b) installs them only on an
// explicit `achilles tools install` (or `... rules`), and (c) does not load them
// under `--mode commercial`.
type RuleSet struct {
	Name    string
	Repo    string
	Commit  string // full commit SHA on the default branch
	URL     string // GitHub archive tarball of exactly that commit
	SHA256  string // digest of the tarball (see provenance below)
	License string
}

// communityRules is pinned to opengrep/opengrep-rules main as of 2026-10-05.
//
// Provenance: SHA256 is `shasum -a 256` of the tarball downloaded from URL on that
// date (1,144,289 bytes). GitHub does not promise byte-stable archive tarballs, so
// if a later install fails with a sha256 mismatch for an unchanged commit, re-pin
// (download, inspect, update SHA256) rather than bypassing the check.
var communityRules = RuleSet{
	Name:    "opengrep-rules",
	Repo:    "opengrep/opengrep-rules",
	Commit:  "f1d2b562b414783763fd02a6ed2736eaed622efa",
	URL:     "https://github.com/opengrep/opengrep-rules/archive/f1d2b562b414783763fd02a6ed2736eaed622efa.tar.gz",
	SHA256:  "9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d",
	License: "LGPL-2.1 + Commons Clause",
}

// CommunityRules returns the pinned community rule pack.
func CommunityRules() RuleSet { return communityRules }

// ShortSHA is the 12-character commit prefix used in the install directory name.
func (r RuleSet) ShortSHA() string {
	if len(r.Commit) < 12 {
		return r.Commit
	}
	return r.Commit[:12]
}

// DirName is the directory the pack installs into, under RulesDir().
func (r RuleSet) DirName() string { return r.Name + "-" + r.ShortSHA() }

// InstalledRules describes the community pack on disk.
type InstalledRules struct {
	Installed bool
	Dir       string
	Files     int
}

// InstalledCommunityRules reports whether the PINNED pack is installed. A pack
// from an older Achilles (different commit) is not used until reinstalled.
func InstalledCommunityRules() InstalledRules {
	root, err := RulesDir()
	if err != nil {
		return InstalledRules{}
	}
	dir := filepath.Join(root, communityRules.DirName())
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && isRuleFile(d.Name()) {
			n++
		}
		return nil
	})
	if n == 0 {
		return InstalledRules{Dir: dir}
	}
	return InstalledRules{Installed: true, Dir: dir, Files: n}
}

func isRuleFile(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml")
}

const (
	maxRuleFileBytes  = 1 << 20  // one rule file
	maxRuleTotalBytes = 64 << 20 // everything kept
	maxRuleFiles      = 5000
)

// ruleLanguageDirs are the top-level language directories of opengrep-rules that
// are kept: the mainstream application languages, plus `generic` (secrets, CI,
// nginx/gradle/HTML-template security rules that are language-agnostic).
var ruleLanguageDirs = map[string]bool{
	"python": true, "javascript": true, "typescript": true, "java": true, "go": true,
	"ruby": true, "php": true, "csharp": true, "kotlin": true, "scala": true,
	"generic": true,
}

// ruleSkipSegments are directory names never kept anywhere in the tree.
var ruleSkipSegments = map[string]bool{
	"test": true, "tests": true, "testdata": true, "fixtures": true, "fixture": true,
	".github": true, "docs": true, "node_modules": true,
}

// KeepRulePath decides whether a file at rel (slash-separated, relative to the
// repository root) is installed. Only security rules in the language
// directories survive:
//
//   - the first path segment must be one of ruleLanguageDirs, or rel is the root LICENSE;
//   - the file must be .yaml/.yml (test fixtures in other languages sit next to the
//     rules and are dropped), and not a *.test.yaml / *.fixed.yaml fixture;
//   - some directory segment (or the file stem) must be `security` or `secrets`;
//     `audit`, `correctness`, `best-practice`, `performance` etc. are quality or
//     noisy-audit rules, not findings you want in a security report;
//   - no segment may be a test/fixtures/.github/docs directory.
func KeepRulePath(rel string) bool {
	if rel == "LICENSE" {
		return true
	}
	segs := strings.Split(rel, "/")
	if len(segs) < 2 || !ruleLanguageDirs[segs[0]] {
		return false
	}
	name := segs[len(segs)-1]
	if !isRuleFile(name) {
		return false
	}
	l := strings.ToLower(name)
	for _, suf := range []string{".test.yaml", ".test.yml", ".fixed.yaml", ".fixed.yml"} {
		if strings.HasSuffix(l, suf) {
			return false
		}
	}
	security := false
	for _, s := range segs[1 : len(segs)-1] {
		if ruleSkipSegments[s] {
			return false
		}
		if s == "security" || s == "secrets" {
			security = true
		}
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(l, ".yaml"), ".yml")
	return security || stem == "security"
}

// InstallRules downloads the pinned pack, verifies its sha256 (fail closed) and
// extracts only the files KeepRulePath selects into
// $ACHILLES_HOME/rules/<DirName>, replacing any earlier copy atomically.
func (in *Installer) InstallRules(ctx context.Context, rs RuleSet, rulesRoot string) (InstalledRules, error) {
	in.logf("%s %s: downloading %s", rs.Name, rs.ShortSHA(), rs.URL)
	dir, err := in.installRulesArchive(ctx, Asset{URL: rs.URL, Archive: TarGz, SHA256: rs.SHA256}, rulesRoot, rs.DirName())
	if err != nil {
		return InstalledRules{}, fmt.Errorf("%s: %w", rs.Name, err)
	}
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && isRuleFile(d.Name()) {
			n++
		}
		return nil
	})
	return InstalledRules{Installed: true, Dir: dir, Files: n}, nil
}

func (in *Installer) installRulesArchive(ctx context.Context, a Asset, rulesRoot, dirName string) (string, error) {
	if in.BinDir == "" || rulesRoot == "" {
		return "", errors.New("no install directory")
	}
	if err := checkSHA256Hex(a.SHA256); err != nil {
		return "", fmt.Errorf("manifest digest: %w", err)
	}
	if err := in.requireHTTPS(a.URL); err != nil {
		return "", err
	}
	if err := ensureDir(in.BinDir); err != nil { // the temp download lives here
		return "", err
	}
	if err := os.MkdirAll(rulesRoot, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", rulesRoot, err)
	}

	dl, err := in.downloadVerified(ctx, a)
	if err != nil {
		return "", err
	}
	defer func() {
		dl.Close()
		os.Remove(dl.Name())
	}()

	tmp, err := os.MkdirTemp(rulesRoot, ".rules-tmp-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp) // no-op after the rename
	if err := extractRules(dl, tmp); err != nil {
		return "", err
	}

	dest := filepath.Join(rulesRoot, dirName)
	if _, err := os.Lstat(dest); err == nil {
		if err := os.RemoveAll(dest); err != nil {
			return "", fmt.Errorf("replace %s: %w", dest, err)
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", fmt.Errorf("install %s: %w", dest, err)
	}
	return dest, nil
}

// extractRules unpacks the kept files of a GitHub archive tarball (whose single
// top-level directory is stripped) into dst. Every entry name is checked first;
// an unsafe name fails the whole install.
func extractRules(src io.ReadSeeker, dst string) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var files, rules int
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // GitHub's archive carries the commit id here
		}
		if unsafeEntryName(hdr.Name) {
			return fmt.Errorf("archive entry %q has an unsafe path", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue // directories, symlinks: never materialized
		}
		// Strip the leading "<repo>-<sha>/" directory.
		_, rel, ok := strings.Cut(path.Clean(hdr.Name), "/")
		if !ok || !KeepRulePath(rel) {
			continue
		}
		if hdr.Size > maxRuleFileBytes {
			return fmt.Errorf("archive entry %q is %d bytes, over the %d byte limit", hdr.Name, hdr.Size, maxRuleFileBytes)
		}
		if files++; files > maxRuleFiles {
			return fmt.Errorf("archive keeps more than %d files", maxRuleFiles)
		}
		if total += hdr.Size; total > maxRuleTotalBytes {
			return fmt.Errorf("kept files exceed %d bytes", maxRuleTotalBytes)
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		cerr := copyCapped(f, tr, maxRuleFileBytes)
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return cerr
		}
		if isRuleFile(rel) {
			rules++
		}
	}
	if rules == 0 {
		return errors.New("archive contained no security rule files")
	}
	return nil
}
