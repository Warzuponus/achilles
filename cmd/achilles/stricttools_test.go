package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A registry whose only tool is not installed: the scan cannot have looked at
// anything. Default behavior stays a partial scan (exit 0, a warning); with
// --strict-tools it must fail so a container/CI run can't pass on an empty look.
func missingToolFixture(t *testing.T) (cfg, target, vault string) {
	t.Helper()
	dir := t.TempDir()
	cfg = filepath.Join(dir, "tools.yaml")
	yaml := `tools:
  - id: ghost
    license: MIT
    commercialSafe: true
    enabled: true
    languages: [generic]
    bin: definitely-not-an-installed-binary-xyz
    format: sarif
    argv: ["--out", "{out}/results.sarif", "{src}"]
    outputFile: "{out}/results.sarif"
`
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(dir, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, target, filepath.Join(dir, "vault.jsonl")
}

func TestStrictTools_FailsWhenAToolCouldNotRun(t *testing.T) {
	cfg, target, vault := missingToolFixture(t)
	err := run([]string{"--config", cfg, "--vault", vault, "--strict-tools", target})
	if err == nil || !strings.Contains(err.Error(), "--strict-tools") || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("err = %v, want a --strict-tools failure naming the tool", err)
	}
}

func TestStrictTools_OffKeepsThePartialScanBehavior(t *testing.T) {
	cfg, target, vault := missingToolFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vault, target}); err != nil {
		t.Fatalf("without --strict-tools a failed tool stays a warning, got %v", err)
	}
}

func TestStrictTools_EnvEnablesIt(t *testing.T) {
	t.Setenv("ACHILLES_STRICT_TOOLS", "true")
	cfg, target, vault := missingToolFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vault, target}); err == nil {
		t.Fatal("ACHILLES_STRICT_TOOLS=true must enable fail-closed")
	}
}
