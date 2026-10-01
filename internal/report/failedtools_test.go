package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// "No findings" from a scan whose tools did not run is not a clean result.
func TestWriteHuman_FailedToolsAreNeverACleanScan(t *testing.T) {
	var b bytes.Buffer
	WriteHuman(&b, model.Scan{Target: "/x", FailedTools: []string{"gosec", "trivy"}})
	out := b.String()
	if strings.Contains(out, "Clean scan") {
		t.Errorf("a scan with failed tools must not say 'Clean scan':\n%s", out)
	}
	if !strings.Contains(out, "FAILED to run (gosec, trivy)") || !strings.Contains(out, "NOT a clean scan") {
		t.Errorf("failure warning missing:\n%s", out)
	}
}

func TestWriteHuman_CleanScanStillSaysCleanWhenNothingFailed(t *testing.T) {
	var b bytes.Buffer
	WriteHuman(&b, model.Scan{Target: "/x", Tools: []string{"gosec"}})
	if !strings.Contains(b.String(), "No findings. Clean scan.") {
		t.Errorf("unexpected output:\n%s", b.String())
	}
}

func TestWriteHuman_FailedToolsWarnEvenWhenOthersFoundThings(t *testing.T) {
	var b bytes.Buffer
	WriteHuman(&b, model.Scan{Target: "/x", Tools: []string{"gosec"}, FailedTools: []string{"trivy"},
		Findings: []model.Finding{{Tool: "gosec", RuleID: "G1", Severity: model.SeverityHigh, Message: "m",
			Location: model.Location{File: "a.go"}}}})
	if !strings.Contains(b.String(), "FAILED to run (trivy)") {
		t.Errorf("partial-scan warning missing:\n%s", b.String())
	}
}
