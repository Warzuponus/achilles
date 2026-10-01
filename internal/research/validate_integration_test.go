//go:build integration

// Exercises the §9.3 validation gate with the REAL opengrep engine:
//
//	go test -tags integration ./internal/research/
//
// Skips when opengrep is not installed.
package research

import (
	"context"
	"os/exec"
	"testing"

	xexec "github.com/Warzuponus/achilles/internal/exec"
)

const goodRule = `rules:
  - id: gen.python.dangerous-eval
    languages: [python]
    severity: ERROR
    message: eval on dynamic input
    metadata:
      cwe: ["CWE-95"]
    pattern: eval(...)
`

func TestOpengrepValidator_AdmitsGoodRule(t *testing.T) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	v := NewOpengrepValidator(xexec.LocalRunner{})
	rule := GeneratedRule{
		Language:          "python",
		RuleYAML:          goodRule,
		VulnerableSnippet: "eval(user_input)\n",
		PatchedSnippet:    "import ast\nast.literal_eval(user_input)\n",
	}
	res, err := v.Validate(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Parses || !res.MatchesVulnerable || res.MatchesPatched {
		t.Fatalf("expected parses+vuln-match+no-patch-match, got %+v", res)
	}
	if ok, reason := Admit(res); !ok {
		t.Errorf("good rule should be admitted, got: %s", reason)
	}
}

func TestOpengrepValidator_RejectsOverbroadRule(t *testing.T) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	// This rule matches ANY call, so it flags the patched snippet too → reject.
	overbroad := `rules:
  - id: gen.python.too-broad
    languages: [python]
    severity: ERROR
    message: any call
    pattern: $F(...)
`
	v := NewOpengrepValidator(xexec.LocalRunner{})
	rule := GeneratedRule{
		Language:          "python",
		RuleYAML:          overbroad,
		VulnerableSnippet: "eval(user_input)\n",
		PatchedSnippet:    "ast.literal_eval(user_input)\n",
	}
	res, err := v.Validate(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if !res.MatchesPatched {
		t.Fatalf("overbroad rule should match the patched snippet too, got %+v", res)
	}
	if ok, _ := Admit(res); ok {
		t.Error("overbroad rule must NOT be admitted (it flags the fix)")
	}
}
