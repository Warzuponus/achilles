//go:build integration

// Proves the rule flywheel end-to-end with the REAL opengrep engine:
// admitted generated rules actually load into a scan, and the shadow window
// routes newly-admitted rules into a separate report-only pass.
//
//	go test -tags integration ./internal/research/
//
// Skips when opengrep is not installed.
package research

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
)

func evalRule(internalID string) string {
	return "rules:\n  - id: " + internalID + "\n    languages: [python]\n    severity: ERROR\n    message: eval on dynamic input\n    pattern: eval(...)\n"
}

func admitRule(t *testing.T, repo *RuleRepo, fileID, internalID string, created time.Time) {
	t.Helper()
	rule := GeneratedRule{
		ID:         fileID,
		Language:   "python",
		RuleYAML:   evalRule(internalID),
		Provenance: Provenance{SourceCitation: "https://example.com", IssueTitle: "eval", Created: created.Format(admittedCreatedFmt)},
	}
	if err := repo.Admit("run1", rule, ValidationResult{Parses: true, MatchesVulnerable: true}); err != nil {
		t.Fatal(err)
	}
}

func TestProvision_GeneratedRulesLoadIntoScan(t *testing.T) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

	// Two admitted rules that both match eval(...): one aged-in (active), one
	// freshly admitted (shadow). Distinct internal ids so we can tell the passes
	// apart in the SARIF.
	repo := NewRuleRepo(t.TempDir(), nil)
	admitRule(t, repo, "gen-active", "gen.python.active-eval", now.AddDate(0, 0, -30))
	admitRule(t, repo, "gen-shadow", "gen.python.shadow-eval", now.AddDate(0, 0, -1))

	set, cleanup, err := repo.Provision("", 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if set.ActiveGenerated != 1 || set.Shadow != 1 || set.ShadowDir == "" {
		t.Fatalf("unexpected split: %+v", set)
	}

	// A target with a matching sink.
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.py"), []byte("eval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tgt := scanner.Target{Path: target}
	runner := xexec.LocalRunner{}

	// Active pass: the active generated rule fires; the shadow one does NOT.
	activeSARIF := runScan(t, runner, set.ActiveDir, tgt)
	if !strings.Contains(activeSARIF, "active-eval") {
		t.Errorf("active pass should have fired the admitted (aged-in) rule; SARIF:\n%s", activeSARIF)
	}
	if strings.Contains(activeSARIF, "shadow-eval") {
		t.Error("active pass must NOT include the shadow rule")
	}

	// Shadow pass: the shadow rule fires (its findings will be marked report-only).
	shadowSARIF := runScan(t, runner, set.ShadowDir, tgt)
	if !strings.Contains(shadowSARIF, "shadow-eval") {
		t.Errorf("shadow pass should have fired the newly-admitted rule; SARIF:\n%s", shadowSARIF)
	}
}

func runScan(t *testing.T, runner xexec.Runner, rulesDir string, tgt scanner.Target) string {
	t.Helper()
	raw, err := opengrep.New(runner, rulesDir).Run(context.Background(), tgt)
	if err != nil {
		t.Fatalf("opengrep run: %v", err)
	}
	return string(raw.Data)
}
