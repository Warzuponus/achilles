package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func sarifOf(t *testing.T, s model.Scan) (model.SarifRun, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, s); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil || len(log.Runs) != 1 {
		t.Fatalf("not a SARIF document: %v\n%s", err, buf.String())
	}
	return log.Runs[0], buf.String()
}

// Code scanning files an alert under critical/high/medium/low from the rule's
// security-severity. Without a rule table every alert was sorted by level alone,
// where "critical" does not exist.
func TestSARIF_RuleTableCarriesSeverityAndCWE(t *testing.T) {
	scan := model.Scan{
		Findings: []model.Finding{
			{Tool: "opengrep", RuleID: "sqli", Severity: model.SeverityMedium, CWE: []string{"CWE-89"}, Fingerprint: "a", Location: model.Location{File: "a.py", Region: model.Region{StartLine: 3}}},
			{Tool: "opengrep", RuleID: "sqli", Severity: model.SeverityCritical, CWE: []string{"CWE-89", "CWE-564"}, Fingerprint: "b", Location: model.Location{File: "b.py", Region: model.Region{StartLine: 9}}},
			{Tool: "gosec", RuleID: "G104", Severity: model.SeverityLow, Fingerprint: "c", Location: model.Location{File: "c.go", Region: model.Region{StartLine: 1}}},
		},
		Dismissed: []model.Finding{
			{Tool: "gosec", RuleID: "G404", Severity: model.SeverityHigh, Fingerprint: "d", Location: model.Location{File: "d.go", Region: model.Region{StartLine: 2}}},
		},
	}
	run, raw := sarifOf(t, scan)

	rules := run.Tool.Driver.Rules
	if len(rules) != 3 {
		t.Fatalf("want one rule per distinct id (dismissed findings included), got %d", len(rules))
	}
	byID := map[string]model.SarifRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	sqli := byID["sqli"]
	if sqli.Properties.SecuritySeverity != "9.5" || sqli.DefaultConfiguration.Level != "error" {
		t.Errorf("sqli: severity %q level %q, want the highest of its findings (critical: 9.5, error)", sqli.Properties.SecuritySeverity, sqli.DefaultConfiguration.Level)
	}
	if got := strings.Join(sqli.Properties.Tags, ","); got != "security,external/cwe/cwe-564,external/cwe/cwe-89" {
		t.Errorf("sqli tags = %q", got)
	}
	if byID["G104"].Properties.SecuritySeverity != "2.0" {
		t.Errorf("G104 severity = %q, want 2.0 (low)", byID["G104"].Properties.SecuritySeverity)
	}

	// Each result points at its rule, and the index is right.
	for _, res := range run.Results {
		if res.RuleIndex == nil || rules[*res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %s: ruleIndex does not point at its rule", res.RuleID)
		}
	}
	if strings.Contains(raw, `"properties": {}`) || strings.Contains(raw, `"defaultConfiguration": {}`) {
		t.Errorf("empty objects in the rule table:\n%s", raw)
	}
}

// Achilles' fingerprint ignores line numbers; exposing it as
// primaryLocationLineHash lets code scanning keep one alert across commits instead
// of closing and reopening it when code moves.
func TestSARIF_PartialFingerprintsAndBaselineState(t *testing.T) {
	loc := func(file string, line int) model.Location {
		return model.Location{File: file, Region: model.Region{StartLine: line}}
	}
	scan := model.Scan{Findings: []model.Finding{
		{RuleID: "r", Fingerprint: "abc", Location: loc("a.py", 3)},
		{RuleID: "r", Fingerprint: "abc", Location: loc("a.py", 40)}, // the same code twice in one file
		{RuleID: "r", Fingerprint: "abc", Location: loc("b.py", 3)},  // and once in another
		{RuleID: "r", Fingerprint: "", Location: loc("c.py", 1)},
	}}
	run, _ := sarifOf(t, scan)
	var got []string
	for _, r := range run.Results {
		got = append(got, r.PartialFingerprints["primaryLocationLineHash"])
		if r.BaselineState != "" {
			t.Errorf("no baseline was applied, so no baselineState: %q", r.BaselineState)
		}
	}
	if strings.Join(got, " ") != "abc:1 abc:2 abc:1 " {
		t.Errorf("primaryLocationLineHash = %q", got)
	}

	scan.BaselineApplied = true
	run, _ = sarifOf(t, scan)
	for _, r := range run.Results {
		if r.BaselineState != "new" {
			t.Errorf("with a baseline every reported finding is new: %q", r.BaselineState)
		}
	}
}

// A patch that passed re-scan verification is offered as a SARIF fix. One that did
// not is never offered: a consumer may apply a fix with one click.
func TestSARIF_VerifiedFixBecomesAFix(t *testing.T) {
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,9 +1,9 @@\n import os\n-os.system(cmd)\n+subprocess.run([cmd])\n print('x')\n" +
		"@@ -20,0 +21,1 @@\n+import subprocess\n"
	finding := func(status model.FixVerificationStatus) model.Finding {
		return model.Finding{
			RuleID: "cmd-injection", Fingerprint: "fp", Location: model.Location{File: "app.py", Region: model.Region{StartLine: 2}},
			Remediation: &model.Remediation{Summary: "use an argument list", Diff: diff, Verification: &model.FixVerification{Status: status}},
		}
	}

	run, _ := sarifOf(t, model.Scan{Findings: []model.Finding{finding(model.FixVerified)}})
	fixes := run.Results[0].Fixes
	if len(fixes) != 1 || len(fixes[0].ArtifactChanges) != 1 {
		t.Fatalf("want one fix with one file change, got %+v", fixes)
	}
	ch := fixes[0].ArtifactChanges[0]
	if ch.ArtifactLocation.URI != "app.py" || len(ch.Replacements) != 2 {
		t.Fatalf("change = %+v", ch)
	}
	// Hunk 1: the header's counts are wrong (9), the body has three old lines.
	first := ch.Replacements[0]
	if first.DeletedRegion.StartLine != 1 || first.DeletedRegion.EndLine != 3 {
		t.Errorf("first replacement covers lines %d-%d, want 1-3 (counted from the hunk body)", first.DeletedRegion.StartLine, first.DeletedRegion.EndLine)
	}
	if first.InsertedContent.Text != "import os\nsubprocess.run([cmd])\nprint('x')" {
		t.Errorf("first replacement text = %q", first.InsertedContent.Text)
	}
	// Hunk 2: a pure insertion after line 20.
	second := ch.Replacements[1]
	if second.DeletedRegion.StartLine != 21 || second.DeletedRegion.StartColumn != 1 || second.DeletedRegion.EndColumn != 1 || second.InsertedContent.Text != "import subprocess\n" {
		t.Errorf("insertion = %+v %q", second.DeletedRegion, second.InsertedContent.Text)
	}
	if !strings.Contains(fixes[0].Description.Text, "use an argument list") || !strings.Contains(fixes[0].Description.Text, "verified") {
		t.Errorf("description = %q", fixes[0].Description.Text)
	}

	for _, status := range []model.FixVerificationStatus{model.FixNotFixed, model.FixIntroducesNew, model.FixPatchFailed, model.FixSkipped, model.FixError} {
		run, _ := sarifOf(t, model.Scan{Findings: []model.Finding{finding(status)}})
		if len(run.Results[0].Fixes) != 0 {
			t.Errorf("a patch with status %q was offered as a fix", status)
		}
	}
	unverified := finding(model.FixVerified)
	unverified.Remediation.Verification = nil
	if run, _ := sarifOf(t, model.Scan{Findings: []model.Finding{unverified}}); len(run.Results[0].Fixes) != 0 {
		t.Error("a patch that was never verified was offered as a fix")
	}
}

func TestWriteJSON(t *testing.T) {
	scan := model.Scan{
		Target: "/repo",
		Findings: []model.Finding{
			{Tool: "opengrep", RuleID: "sqli", Severity: model.SeverityHigh, Message: "query built from input", Fingerprint: "a",
				Verdict: &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9}},
			{Tool: "gitleaks", RuleID: "generic-api-key", Category: model.CategorySecret, CodeContext: "leftover",
				Message: "found 0123456789abcdef0123456789abcdef0123 in config", Fingerprint: "b", Raw: json.RawMessage(`{"rawScannerOutput":"x"}`)},
		},
		Dismissed:   []model.Finding{{RuleID: "G404", Fingerprint: "c"}},
		FailedTools: []string{"trivy"},
		Triage:      &model.TriageStats{Total: 2, Triaged: 1},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, scan); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	var doc struct {
		SchemaVersion int             `json:"schemaVersion"`
		Complete      bool            `json:"complete"`
		Findings      []model.Finding `json:"findings"`
		Dismissed     []model.Finding `json:"dismissed"`
		FailedTools   []string        `json:"failedTools"`
		Triage        *model.TriageStats
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.SchemaVersion != JSONSchemaVersion || len(doc.Findings) != 2 || len(doc.Dismissed) != 1 || len(doc.FailedTools) != 1 {
		t.Errorf("document = %+v", doc)
	}
	if doc.Complete {
		t.Error("a scan with a failed scanner must not be marked complete")
	}
	if doc.Findings[0].Verdict == nil || doc.Findings[0].Verdict.Classification != model.ClassTruePositive {
		t.Error("verdicts must be in the document")
	}
	for _, leak := range []string{"0123456789abcdef0123456789abcdef0123", "leftover", "rawScannerOutput"} {
		if strings.Contains(out, leak) {
			t.Errorf("the JSON report contains %q", leak)
		}
	}
	// The caller's scan is not modified by the masking.
	if !strings.Contains(scan.Findings[1].Message, "0123456789abcdef") {
		t.Error("WriteJSON modified the scan it was given")
	}

	buf.Reset()
	if err := WriteJSON(&buf, model.Scan{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) || !strings.Contains(buf.String(), `"complete": true`) {
		t.Errorf("an empty, complete scan:\n%s", buf.String())
	}
}
