//go:build integration

// Integration test that runs the REAL opengrep binary end-to-end through the
// adapter + normalizer. Opt-in so the default `go test ./...` stays hermetic:
//
//	go test -tags integration ./...
//
// Skips automatically if opengrep is not installed.
package opengrep

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
)

func TestOpengrepRealScan(t *testing.T) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed; skipping integration test")
	}

	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	rulesDir := filepath.Join(dir, "rules")
	mustMkdir(t, srcDir)
	mustMkdir(t, rulesDir)

	mustWrite(t, filepath.Join(srcDir, "app.py"), "import os\neval(user_input)\n")
	// ASCII-only rule (opengrep's config reader is ASCII-only).
	mustWrite(t, filepath.Join(rulesDir, "rule.yaml"), `rules:
  - id: test.dangerous-eval
    languages: [python]
    severity: ERROR
    message: Use of eval() can lead to code execution.
    metadata:
      cwe: ["CWE-95"]
    pattern: eval(...)
`)

	s := New(xexec.LocalRunner{}, rulesDir)
	raw, err := s.Run(context.Background(), scanner.Target{Path: srcDir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings, err := normalize.FromSARIF(raw.Tool, raw.Data)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for eval()")
	}

	f := findings[0]
	if f.Severity != "high" {
		t.Errorf("severity: want high, got %q", f.Severity)
	}
	if len(f.CWE) == 0 || f.CWE[0] != "CWE-95" {
		t.Errorf("cwe: want [CWE-95], got %v", f.CWE)
	}
	if f.Location.Region.StartLine != 2 {
		t.Errorf("line: want 2, got %d", f.Location.Region.StartLine)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
