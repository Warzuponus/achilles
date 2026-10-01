package research

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
)

// Validator runs a generated rule against its fixtures. Split out as an
// interface so the engine's admit/quarantine logic is testable with a fake and
// the real (opengrep-backed) validator is exercised by an integration test.
type Validator interface {
	Validate(ctx context.Context, r GeneratedRule) (ValidationResult, error)
}

// Admit is the §9.3 gate: a rule ships ONLY if it parses, matches the
// vulnerable fixture, and does NOT match the patched fixture. This is the whole
// idea — a rule that can't catch the bug without flagging the fix is quarantined.
func Admit(res ValidationResult) (bool, string) {
	switch {
	case !res.Parses:
		return false, "rule does not parse/compile in the engine"
	case !res.MatchesVulnerable:
		return false, "rule does not match the vulnerable fixture (no true-positive proof)"
	case res.MatchesPatched:
		return false, "rule also matches the patched fixture (false-positive proof)"
	default:
		return true, "passed validation gate"
	}
}

var langExt = map[string]string{
	"python": ".py", "javascript": ".js", "typescript": ".ts", "go": ".go",
	"ruby": ".rb", "java": ".java", "php": ".php", "csharp": ".cs",
}

func extFor(lang string) string {
	if e, ok := langExt[lang]; ok {
		return e
	}
	return ".txt"
}

// OpengrepValidator validates rules by actually running Opengrep on synthetic
// fixtures in a sandbox (DESIGN.md §9.5: only ever runs synthetic snippets).
type OpengrepValidator struct {
	runner xexec.Runner
}

func NewOpengrepValidator(runner xexec.Runner) *OpengrepValidator {
	return &OpengrepValidator{runner: runner}
}

func (v *OpengrepValidator) Validate(ctx context.Context, r GeneratedRule) (ValidationResult, error) {
	base, err := os.MkdirTemp("", "achilles-validate-*")
	if err != nil {
		return ValidationResult{}, err
	}
	defer os.RemoveAll(base)

	rulesDir := filepath.Join(base, "rules")
	vulnDir := filepath.Join(base, "vuln")
	patchedDir := filepath.Join(base, "patched")
	for _, d := range []string{rulesDir, vulnDir, patchedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return ValidationResult{}, err
		}
	}
	ext := extFor(r.Language)
	if err := os.WriteFile(filepath.Join(rulesDir, "rule.yaml"), []byte(r.RuleYAML), 0o644); err != nil {
		return ValidationResult{}, err
	}
	if err := os.WriteFile(filepath.Join(vulnDir, "case"+ext), []byte(r.VulnerableSnippet), 0o644); err != nil {
		return ValidationResult{}, err
	}
	if err := os.WriteFile(filepath.Join(patchedDir, "case"+ext), []byte(r.PatchedSnippet), 0o644); err != nil {
		return ValidationResult{}, err
	}

	vc, ok1 := v.matchCount(ctx, rulesDir, vulnDir)
	pc, ok2 := v.matchCount(ctx, rulesDir, patchedDir)

	return ValidationResult{
		Parses:            ok1 && ok2,
		MatchesVulnerable: vc > 0,
		MatchesPatched:    pc > 0,
		Detail:            fmt.Sprintf("vuln matches=%d patched matches=%d", vc, pc),
	}, nil
}

// matchCount runs Opengrep with the rule over a code dir. ok=false means the
// rule failed to parse/run (Opengrep errored), which the gate treats as no-parse.
func (v *OpengrepValidator) matchCount(ctx context.Context, rulesDir, codeDir string) (int, bool) {
	sc := opengrep.New(v.runner, rulesDir)
	raw, err := sc.Run(ctx, scanner.Target{Path: codeDir})
	if err != nil {
		return 0, false
	}
	findings, err := normalize.FromSARIF(raw.Tool, raw.Data)
	if err != nil {
		return 0, false
	}
	return len(findings), true
}
