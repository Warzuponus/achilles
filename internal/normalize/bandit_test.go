package normalize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestFromBandit(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "bandit.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := FromBandit("bandit", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	// B105 hardcoded password → LOW, CWE-259, file/line mapped.
	b105 := findings[0]
	if b105.RuleID != "B105" || b105.Tool != "bandit" {
		t.Errorf("rule/tool wrong: %+v", b105)
	}
	if b105.Severity != model.SeverityLow {
		t.Errorf("B105 severity: want low, got %q", b105.Severity)
	}
	if b105.Location.File != "app/db.py" || b105.Location.Region.StartLine != 4 {
		t.Errorf("B105 location wrong: %+v", b105.Location)
	}
	if len(b105.CWE) != 1 || b105.CWE[0] != "CWE-259" {
		t.Errorf("B105 cwe: want [CWE-259], got %v", b105.CWE)
	}
	if b105.Fingerprint == "" || b105.ID == "" {
		t.Error("B105 must have a stable id + fingerprint")
	}

	// B605 shell injection → HIGH.
	if findings[1].RuleID != "B605" || findings[1].Severity != model.SeverityHigh {
		t.Errorf("B605 wrong: rule=%q sev=%q", findings[1].RuleID, findings[1].Severity)
	}

	// Distinct findings → distinct fingerprints.
	if b105.Fingerprint == findings[1].Fingerprint {
		t.Error("distinct findings should have distinct fingerprints")
	}
}

func TestFromBandit_FallbackTool(t *testing.T) {
	findings, err := FromBandit("", []byte(`{"results":[{"filename":"x.py","line_number":1,"test_id":"B101","issue_severity":"HIGH","issue_text":"assert"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Tool != "bandit" {
		t.Errorf("empty fallback should default tool to bandit: %+v", findings)
	}
}
