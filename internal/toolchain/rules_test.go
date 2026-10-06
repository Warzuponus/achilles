package toolchain

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const top = "opengrep-rules-abc123/"

func fakeRulesTarball(t *testing.T, extra ...tarEntry) []byte {
	t.Helper()
	y := []byte("rules: []\n")
	entries := []tarEntry{
		{name: top, typ: tar.TypeDir},
		{name: top + "LICENSE", body: []byte("lgpl + commons clause")},
		{name: top + "README.md", body: []byte("readme")},
		{name: top + "python/lang/security/a.yaml", body: y},
		{name: top + "python/lang/security/a.py", body: []byte("fixture")},
		{name: top + "python/lang/security/a.test.yaml", body: y},
		{name: top + "python/lang/security/a.fixed.yaml", body: y},
		{name: top + "python/distributed/security.yaml", body: y},
		{name: top + "python/lang/correctness/b.yaml", body: y},
		{name: top + "python/pyramid/audit/c.yaml", body: y},
		{name: top + "python/tests/security/d.yaml", body: y},
		{name: top + "go/lang/security/e.yml", body: y},
		{name: top + "generic/secrets/gitleaks/f.yaml", body: y},
		{name: top + "generic/ci/audit/g.yaml", body: y},
		{name: top + "terraform/lang/security/h.yaml", body: y},
		{name: top + ".github/security/i.yaml", body: y},
		{name: top + "docs/security/j.yaml", body: y},
		{name: top + "go/lang/security/link.yaml", typ: tar.TypeSymlink, link: "/etc/passwd"},
	}
	return makeTarGz(t, append(entries, extra...)...)
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func TestKeepRulePath(t *testing.T) {
	keep := []string{
		"LICENSE", "python/lang/security/a.yaml", "go/x/security/e.yml",
		"python/distributed/security.yaml", "generic/secrets/gitleaks/f.yaml",
		"generic/nginx/security/n.yaml", "java/lang/security/audit/x.yaml",
	}
	drop := []string{
		"README.md", "python/lang/security/a.py", "python/lang/security/a.test.yaml",
		"python/lang/correctness/b.yaml", "python/pyramid/audit/c.yaml",
		"python/tests/security/d.yaml", "generic/ci/audit/g.yaml",
		"terraform/lang/security/h.yaml", "yaml/security/y.yaml", ".github/security/i.yaml",
		"python/foo.yaml", "python", "scripts/security/s.yaml", "python/fixtures/security/z.yaml",
	}
	for _, p := range keep {
		if !KeepRulePath(p) {
			t.Errorf("KeepRulePath(%q) = false, want true", p)
		}
	}
	for _, p := range drop {
		if KeepRulePath(p) {
			t.Errorf("KeepRulePath(%q) = true, want false", p)
		}
	}
}

func TestInstallRulesExtractsOnlySecurityRules(t *testing.T) {
	arc := fakeRulesTarball(t)
	in, url := serve(t, arc)
	root := filepath.Join(t.TempDir(), "rules")
	dir, err := in.installRulesArchive(context.Background(), Asset{URL: url, Archive: TarGz, SHA256: sum(arc)}, root, "opengrep-rules-abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := listFiles(t, dir)
	want := []string{
		"LICENSE",
		"generic/secrets/gitleaks/f.yaml",
		"go/lang/security/e.yml",
		"python/distributed/security.yaml",
		"python/lang/security/a.yaml",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("extracted:\n got  %v\n want %v", got, want)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dir, "python/lang/security/a.yaml"))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", st.Mode().Perm())
		}
		st, _ = os.Stat(dir)
		if st.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v, want 0700", st.Mode().Perm())
		}
	}
	// Nothing but the install dir remains in the rules root or the download dir.
	if names := dirEntries(t, root); len(names) != 1 {
		t.Errorf("rules root = %v", names)
	}
	if names := dirEntries(t, in.BinDir); len(names) != 0 {
		t.Errorf("download left files in bin dir: %v", names)
	}

	// Reinstall replaces the old copy (a stale file must not survive).
	os.WriteFile(filepath.Join(dir, "stale.yaml"), []byte("x"), 0o600)
	if _, err := in.installRulesArchive(context.Background(), Asset{URL: url, Archive: TarGz, SHA256: sum(arc)}, root, "opengrep-rules-abc123"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "stale.yaml")); !os.IsNotExist(err) {
		t.Error("stale file survived reinstall")
	}
}

func TestInstallRulesFailsClosed(t *testing.T) {
	good := fakeRulesTarball(t)
	cases := map[string][]byte{
		"traversal":     fakeRulesTarball(t, tarEntry{name: top + "../../evil.yaml", body: []byte("x")}),
		"absolute":      fakeRulesTarball(t, tarEntry{name: "/tmp/evil.yaml", body: []byte("x")}),
		"oversize file": fakeRulesTarball(t, tarEntry{name: top + "python/big/security/big.yaml", body: bytes.Repeat([]byte("a"), maxRuleFileBytes+1)}),
		"no rules":      makeTarGz(t, tarEntry{name: top + "README.md", body: []byte("x")}),
	}
	for name, arc := range cases {
		in, url := serve(t, arc)
		root := filepath.Join(t.TempDir(), "rules")
		if _, err := in.installRulesArchive(context.Background(), Asset{URL: url, Archive: TarGz, SHA256: sum(arc)}, root, "opengrep-rules-abc123"); err == nil {
			t.Errorf("%s: want error", name)
		}
		if names := dirEntries(t, root); len(names) != 0 {
			t.Errorf("%s: left %v in rules root", name, names)
		}
		if names := dirEntries(t, in.BinDir); len(names) != 0 {
			t.Errorf("%s: left %v in bin dir", name, names)
		}
	}

	// Hash mismatch: nothing extracted, previous install untouched.
	in, url := serve(t, good)
	root := filepath.Join(t.TempDir(), "rules")
	os.MkdirAll(filepath.Join(root, "opengrep-rules-abc123"), 0o700)
	os.WriteFile(filepath.Join(root, "opengrep-rules-abc123", "keep.yaml"), []byte("x"), 0o600)
	if _, err := in.installRulesArchive(context.Background(), Asset{URL: url, Archive: TarGz, SHA256: sum([]byte("other"))}, root, "opengrep-rules-abc123"); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "opengrep-rules-abc123", "keep.yaml")); err != nil {
		t.Error("previous install was disturbed by a failed download")
	}
}

func TestCommunityRulesPinWellFormed(t *testing.T) {
	r := CommunityRules()
	if err := checkSHA256Hex(r.SHA256); err != nil {
		t.Fatal(err)
	}
	if len(r.Commit) != 40 || !strings.Contains(r.URL, r.Commit) || !strings.HasPrefix(r.URL, "https://github.com/opengrep/opengrep-rules/archive/") {
		t.Errorf("bad pin: %+v", r)
	}
	if r.DirName() != "opengrep-rules-"+r.Commit[:12] {
		t.Errorf("DirName = %s", r.DirName())
	}
}

func TestInstalledCommunityRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvHome, home)
	if got := InstalledCommunityRules(); got.Installed {
		t.Fatal("nothing installed yet")
	}
	dir := filepath.Join(home, "rules", CommunityRules().DirName(), "python", "security")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("rules: []"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("rules: []"), 0o600)
	got := InstalledCommunityRules()
	if !got.Installed || got.Files != 2 || !strings.HasSuffix(got.Dir, CommunityRules().DirName()) {
		t.Fatalf("got %+v", got)
	}
}
