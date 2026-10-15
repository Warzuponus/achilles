package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A registry whose only tool is not installed: the scan cannot have looked at
// anything, so it fails with or without --strict-tools (see
// TestRun_NothingScannedIsAnError). partialScanFixture adds a tool that runs.
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
	cfg, target, vault := partialScanFixture(t)
	err := run([]string{"--config", cfg, "--vault", vault, "--fail-on", "", "--strict-tools", target})
	if err == nil || !strings.Contains(err.Error(), "--strict-tools") || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("err = %v, want a --strict-tools failure naming the tool", err)
	}
}

// partialScanFixture is fakeScanFixture's registry, whose one scanner runs, plus
// a tool that is not installed.
func partialScanFixture(t *testing.T) (cfg, target, vault string) {
	t.Helper()
	cfg, target, vault = fakeScanFixture(t)
	ghost := `  - id: ghost
    license: MIT
    commercialSafe: true
    enabled: true
    languages: [generic]
    bin: definitely-not-an-installed-binary-xyz
    format: sarif
    argv: ["--out", "{out}/results.sarif", "{src}"]
    outputFile: "{out}/results.sarif"
`
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(ghost); err != nil {
		t.Fatal(err)
	}
	return cfg, target, vault
}

func TestStrictTools_OffKeepsThePartialScanBehavior(t *testing.T) {
	cfg, target, vault := partialScanFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vault, "--fail-on", "", target}); err != nil {
		t.Fatalf("without --strict-tools a failed tool stays a warning while another ran, got %v", err)
	}
	if err := run([]string{"--config", cfg, "--vault", vault, "--fail-on", "", "--strict-tools", target}); err == nil ||
		!strings.Contains(err.Error(), "--strict-tools") {
		t.Fatalf("with --strict-tools a partial scan fails, got %v", err)
	}
}

// When no scanner ran, there was no scan: zero findings from it must not pass a
// CI job, so it is an error (exit 2) even without --strict-tools, and the error
// says how to fix it.
func TestRun_NothingScannedIsAnError(t *testing.T) {
	cfg, target, vault := missingToolFixture(t)
	err := run([]string{"--config", cfg, "--vault", vault, target})
	if err == nil || !strings.Contains(err.Error(), "nothing was scanned") ||
		!strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "achilles doctor") {
		t.Fatalf("err = %v, want a nothing-was-scanned error naming the tool and the fix", err)
	}
}

func TestStrictTools_EnvEnablesIt(t *testing.T) {
	t.Setenv("ACHILLES_STRICT_TOOLS", "true")
	cfg, target, vault := partialScanFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vault, "--fail-on", "", target}); err == nil ||
		!strings.Contains(err.Error(), "--strict-tools") {
		t.Fatalf("ACHILLES_STRICT_TOOLS=true must enable fail-closed, got %v", err)
	}
}
