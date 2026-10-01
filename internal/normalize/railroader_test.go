package normalize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestFromRailroader(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "railroader.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := FromRailroader("railroader", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	sql := findings[0]
	if sql.RuleID != "SQL" || sql.Tool != "railroader" {
		t.Errorf("rule/tool wrong: %+v", sql)
	}
	if sql.Severity != model.SeverityHigh {
		t.Errorf("High confidence should map to high, got %q", sql.Severity)
	}
	if sql.Location.File != "app/controllers/users_controller.rb" || sql.Location.Region.StartLine != 4 {
		t.Errorf("location wrong: %+v", sql.Location)
	}
	// Message must name the warning class (the verify assert greps "injection").
	if !strings.Contains(sql.Message, "SQL Injection") {
		t.Errorf("message should include the warning type: %q", sql.Message)
	}
	if sql.Fingerprint == "" || sql.ID == "" {
		t.Error("expected stable id + fingerprint")
	}

	// Medium confidence → medium.
	if findings[1].RuleID != "Execute" || findings[1].Severity != model.SeverityMedium {
		t.Errorf("command-injection warning wrong: rule=%q sev=%q", findings[1].RuleID, findings[1].Severity)
	}
	if sql.Fingerprint == findings[1].Fingerprint {
		t.Error("distinct warnings should have distinct fingerprints")
	}
}
