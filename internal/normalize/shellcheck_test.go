package normalize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestFromShellCheck(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "shellcheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := FromShellCheck("shellcheck", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	// SC2086 info → low; ruleId is SC-prefixed; location mapped.
	a := findings[0]
	if a.RuleID != "SC2086" || a.Tool != "shellcheck" {
		t.Errorf("rule/tool wrong: %+v", a)
	}
	if a.Severity != model.SeverityLow {
		t.Errorf("info should map to low, got %q", a.Severity)
	}
	if a.Location.File != "deploy.sh" || a.Location.Region.StartLine != 3 || a.Location.Region.StartCol != 12 {
		t.Errorf("location wrong: %+v", a.Location)
	}
	if a.Fingerprint == "" || a.ID == "" {
		t.Error("expected stable id + fingerprint")
	}

	// SC2164 warning → medium.
	if findings[1].RuleID != "SC2164" || findings[1].Severity != model.SeverityMedium {
		t.Errorf("SC2164 wrong: rule=%q sev=%q", findings[1].RuleID, findings[1].Severity)
	}
	// Distinct locations → distinct fingerprints.
	if a.Fingerprint == findings[1].Fingerprint {
		t.Error("distinct findings should have distinct fingerprints")
	}
}

func TestFromShellCheck_Empty(t *testing.T) {
	// The wrapper writes "[]" when there are no shell scripts — must be a clean,
	// error-free zero-finding result.
	findings, err := FromShellCheck("shellcheck", []byte("[]"))
	if err != nil || len(findings) != 0 {
		t.Errorf("empty array should yield 0 findings, no error; got %d, err=%v", len(findings), err)
	}
}
