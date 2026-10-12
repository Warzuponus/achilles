package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func sampleScan() model.Scan {
	return model.Scan{
		Target: "/x",
		Tools:  []string{"opengrep"},
		Findings: []model.Finding{
			{Tool: "opengrep", RuleID: "eval", Message: "eval on input", Severity: model.SeverityHigh,
				Fingerprint: "fp1", Location: model.Location{File: "app/a.py", Region: model.Region{StartLine: 42}}},
			{Tool: "gosec", RuleID: "g101", Message: "hardcoded creds | bad", Severity: model.SeverityMedium,
				Fingerprint: "fp2", Location: model.Location{File: "b.go", Region: model.Region{StartLine: 7}}},
		},
	}
}

func TestWriteSARIFReport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, sampleScan()); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad SARIF envelope: %+v", log)
	}
	res := log.Runs[0].Results
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	if res[0].Level != "error" || res[1].Level != "warning" {
		t.Errorf("level mapping wrong: %q %q", res[0].Level, res[1].Level)
	}
	if res[0].Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Error("location line not preserved")
	}
}

func TestWriteSARIFReport_EmptyIsValidArray(t *testing.T) {
	// A clean scan must emit `"results": []`, not `null` (GitHub rejects null).
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, model.Scan{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "null") {
		t.Errorf("empty SARIF must not contain null results:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Errorf("empty SARIF should have an empty results array:\n%s", buf.String())
	}
}

func TestWriteJUnit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, sampleScan()); err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("output is not valid JUnit XML: %v", err)
	}
	if suites.Failures != 2 || len(suites.Suites[0].Cases) != 2 {
		t.Errorf("expected 2 failing cases, got %+v", suites)
	}
	if suites.Suites[0].Cases[0].Failure == nil {
		t.Error("finding case should carry a <failure>")
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleScan()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "`eval`") || !strings.Contains(out, "app/a.py:42") {
		t.Errorf("markdown missing finding detail:\n%s", out)
	}
	if strings.Contains(out, "creds | bad") {
		t.Error("pipe in message should be escaped in the table")
	}
}

func TestWriteMarkdown_Empty(t *testing.T) {
	var buf bytes.Buffer
	WriteMarkdown(&buf, model.Scan{})
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("empty scan should say no findings")
	}
}

func TestWriteGitHubAnnotations(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, sampleScan()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "::error file=app/a.py,line=42,title=eval::") {
		t.Errorf("high finding should be an error annotation:\n%s", out)
	}
	if !strings.Contains(out, "::warning file=b.go,line=7") {
		t.Errorf("medium finding should be a warning annotation:\n%s", out)
	}
}

// A JUnit report with no failing case is shown as a green run. A scan in which a
// scanner did not run found nothing because it looked at nothing.
func TestWriteJUnit_AnIncompleteScanIsNotGreen(t *testing.T) {
	scan := model.Scan{
		FailedTools: []string{"gitleaks", "trivy"},
		Triage:      &model.TriageStats{Aborted: "401 invalid api key"},
	}
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, scan); err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("output is not valid JUnit XML: %v\n%s", err, buf.String())
	}
	if suites.Errors != 3 || suites.Failures != 0 || suites.Tests != 3 {
		t.Errorf("tests=%d failures=%d errors=%d, want 3 tests, all errors (two scanners and the review)", suites.Tests, suites.Failures, suites.Errors)
	}
	out := buf.String()
	for _, want := range []string{"scanner gitleaks completed", "scanner trivy completed", "AI review completed", "<error "} {
		if !strings.Contains(out, want) {
			t.Errorf("JUnit report lacks %q:\n%s", want, out)
		}
	}

	// A complete scan with no findings is still an empty, passing suite.
	buf.Reset()
	if err := WriteJUnit(&buf, model.Scan{}); err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil || suites.Errors != 0 || suites.Failures != 0 {
		t.Errorf("a clean, complete scan must have no errors or failures: %+v (%v)", suites, err)
	}
}

func TestWriteJUnit_CredentialMessagesAreMasked(t *testing.T) {
	scan := model.Scan{Findings: []model.Finding{{
		Tool: "gitleaks", RuleID: "generic-api-key", Category: model.CategorySecret,
		Message: "found 0123456789abcdef0123456789abcdef0123 in config",
	}}}
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, scan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "0123456789abcdef0123456789abcdef0123") {
		t.Errorf("the JUnit report quotes a credential:\n%s", buf.String())
	}
}
