package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/configs"
)

// isolate points the user cache dir and the Achilles home at temp dirs.
func isolate(t *testing.T) (cache, home string) {
	t.Helper()
	cache, home = t.TempDir(), t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LocalAppData", cache)
	t.Setenv("ACHILLES_HOME", home)
	return cache, home
}

// The embedded registry must BE the on-disk file, never a stale copy.
func TestEmbeddedConfigIsTheOnDiskFile(t *testing.T) {
	disk, err := os.ReadFile("../../configs/tools.yaml")
	if err != nil {
		t.Fatal(err)
	}
	emb, err := configs.ToolsYAML()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, emb) {
		t.Fatal("embedded tools.yaml differs from configs/tools.yaml")
	}
	entries, err := os.ReadDir("../../configs/rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		d, _ := os.ReadFile(filepath.Join("../../configs/rules", e.Name()))
		b, err := configs.FS.ReadFile("rules/" + e.Name())
		if err != nil || !bytes.Equal(d, b) {
			t.Errorf("rules/%s not embedded identically (%v)", e.Name(), err)
		}
	}
}

func TestLoadEmptyPathUsesEmbeddedConfigAndRealRulesDir(t *testing.T) {
	isolate(t)
	t.Chdir(t.TempDir()) // no configs/ here: the standalone-binary situation
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	var rules string
	for _, tc := range c.Tools {
		if tc.ID == "opengrep" {
			rules = tc.Rules
		}
	}
	if !filepath.IsAbs(rules) {
		t.Fatalf("opengrep rules = %q, want an absolute materialized dir", rules)
	}
	if !strings.Contains(filepath.Base(rules), "rules-") {
		t.Errorf("rules dir not content-addressed: %s", rules)
	}
	if _, err := os.Stat(filepath.Join(rules, "achilles-baseline.yaml")); err != nil {
		t.Fatalf("baseline rules not materialized: %v", err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(rules)
		if st.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v, want 0700", st.Mode().Perm())
		}
		st, _ = os.Stat(filepath.Join(rules, "achilles-baseline.yaml"))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", st.Mode().Perm())
		}
	}

	// Second load reuses the same directory.
	again, err := ResolveRulesDir("configs/rules")
	if err != nil || again != rules {
		t.Fatalf("second resolve = %q, %v; want %q", again, err, rules)
	}
}

func TestResolveRulesDirOnDiskWins(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll("configs/rules", 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile("configs/rules/mine.yaml", []byte("rules: []\n"), 0o644)
	got, err := ResolveRulesDir("configs/rules")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(dir, "configs", "rules"))
	gotReal, _ := filepath.EvalSymlinks(got)
	if gotReal != want {
		t.Fatalf("got %s, want the on-disk dir %s", got, want)
	}
}

func TestResolveRulesDirRepairsTamperedCache(t *testing.T) {
	isolate(t)
	t.Chdir(t.TempDir())
	dir, err := ResolveRulesDir("configs/rules")
	if err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(dir, "evil.yaml")
	os.WriteFile(evil, []byte("rules: []\n"), 0o600)
	dir2, err := ResolveRulesDir("configs/rules")
	if err != nil || dir2 != dir {
		t.Fatalf("resolve after tamper: %q %v", dir2, err)
	}
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Error("injected rule file survived in the cache dir")
	}
}

func TestResolveRulesDirMergesUserOverlay(t *testing.T) {
	_, home := isolate(t)
	t.Chdir(t.TempDir())
	plain, err := ResolveRulesDir("configs/rules")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, "rules", "extra.yaml"), []byte("rules: []\n"), 0o600)
	os.WriteFile(filepath.Join(home, "rules", "notes.txt"), []byte("ignore me"), 0o600)
	merged, err := ResolveRulesDir("configs/rules")
	if err != nil {
		t.Fatal(err)
	}
	if merged == plain {
		t.Fatal("overlay did not change the content-addressed dir")
	}
	if _, err := os.Stat(filepath.Join(merged, "user", "extra.yaml")); err != nil {
		t.Errorf("overlay rule missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(merged, "user", "notes.txt")); err == nil {
		t.Error("non-YAML overlay file was copied")
	}
	if _, err := os.Stat(filepath.Join(merged, "achilles-baseline.yaml")); err != nil {
		t.Errorf("baseline rules missing from merged dir: %v", err)
	}
}

func TestResolveRulesDirOtherPathsUnchanged(t *testing.T) {
	isolate(t)
	t.Chdir(t.TempDir())
	got, err := ResolveRulesDir("custom/rules")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) || filepath.Base(got) != "rules" || strings.Contains(got, "rules-") {
		t.Errorf("unexpected: %s", got)
	}
}

// The README says Trivy covers IaC and misconfiguration. `trivy fs` runs only the
// vuln and secret scanners unless told otherwise, so that claim is only true while
// the registry asks for misconfig explicitly. This pins it.
func TestEmbeddedTrivyRunsTheMisconfigScanner(t *testing.T) {
	isolate(t)
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range c.Tools {
		if tc.ID != "trivy" {
			continue
		}
		scanners := ""
		for i, a := range tc.Argv {
			if a == "--scanners" && i+1 < len(tc.Argv) {
				scanners = tc.Argv[i+1]
			}
		}
		for _, want := range []string{"vuln", "misconfig", "secret"} {
			if !strings.Contains(","+scanners+",", ","+want+",") {
				t.Errorf("trivy --scanners = %q, missing %q", scanners, want)
			}
		}
		if tc.Network != "default" {
			t.Errorf("trivy network = %q; it downloads its DB and checks, so --runner docker must give it egress", tc.Network)
		}
		return
	}
	t.Fatal("no trivy entry in the embedded registry")
}

// gosec exits 0 with a valid report when it cannot type-check, so the registry has
// to name the log line that gives it away. Without this entry a scan on a Go
// version gosec cannot read is reported as complete.
func TestEmbeddedGosecDeclaresItsIncompleteMarker(t *testing.T) {
	isolate(t)
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range c.Tools {
		if tc.ID == "gosec" {
			if len(tc.IncompleteWhen) == 0 {
				t.Error("gosec has no incompleteWhen phrases")
			}
			return
		}
	}
	t.Fatal("no gosec entry in the embedded registry")
}
