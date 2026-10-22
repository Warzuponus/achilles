package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// The report side of the result contract: hardening notes listed apart from false
// positives, needs-validation questions and impact detail shown, unchecked line
// references flagged, and languages no scanner covered named.

func lessonsScan() model.Scan {
	return model.Scan{
		Target: "/r",
		Findings: []model.Finding{
			{RuleID: "sqli", Severity: model.SeverityHigh, Fingerprint: "a", Message: "sql from input", Tool: "opengrep",
				Location: model.Location{File: "db.py", Region: model.Region{StartLine: 4}},
				Verdict: &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9, Exploitability: model.ExploitReachable,
					Attacker: "unauthenticated remote user", Impact: "reads every customer row", AssessedSeverity: model.SeverityCritical,
					UnverifiedCitations: []string{"line 99"}}},
			{RuleID: "open-redirect", Severity: model.SeverityMedium, Fingerprint: "b", Message: "redirect", Tool: "opengrep",
				Location: model.Location{File: "web.py", Region: model.Region{StartLine: 8}},
				Verdict: &model.Verdict{Classification: model.ClassUncertain, Confidence: 0.4, Exploitability: model.ExploitUnknown,
					Blockers:       []string{"whether next= is checked against an allowlist upstream"},
					ValidationPlan: &model.ValidationPlan{Local: "grep for safe_redirect in views/", Owner: "check the proxy's redirect policy"}}},
		},
		Dismissed: []model.Finding{
			{RuleID: "md5", Severity: model.SeverityMedium, Fingerprint: "c", Message: "weak hash",
				Location: model.Location{File: "cache.py", Region: model.Region{StartLine: 2}},
				Verdict:  &model.Verdict{Classification: model.ClassHardening, Confidence: 0.9, Reasoning: "hashes a cache key, not a secret"}},
			{RuleID: "G104", Severity: model.SeverityLow, Fingerprint: "d", Message: "unhandled error",
				Verdict: &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9, Reasoning: "checked on the next line"}},
		},
		UncoveredLanguages: []string{"rust"},
		Triage:             &model.TriageStats{Model: "m", Total: 4, Triaged: 4, Dismissed: 2},
	}
}

func TestLessons_HTML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, HTMLReport{Target: "/r", Scan: lessonsScan()}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Hardening notes", "hashes a cache key, not a secret",
		"needs validation", "whether next= is checked against an allowlist upstream", "check the proxy&#39;s redirect policy",
		"unauthenticated remote user", "AI-assessed severity", "critical (advisory",
		"Unchecked references", "line 99",
		"Not covered by any scanner that ran:</strong> rust",
		"1 hardening note(s)", "1 more ruled out as false positives",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestLessons_Markdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, lessonsScan()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"1 hardening note(s)", "1 finding(s) ruled out by the AI review",
		"needs validation: whether next= is checked", "(assessed critical)",
		"Not covered by any scanner that ran:** rust",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown report missing %q\n%s", want, out)
		}
	}
}

func TestLessons_Human(t *testing.T) {
	var buf bytes.Buffer
	WriteHuman(&buf, lessonsScan())
	out := buf.String()
	for _, want := range []string{
		"no scanner that ran covers rust", "1 hardening note(s)", "1 more finding(s) ruled out as false positives",
		"needs validation (uncertain)", "open question: whether next=", "ask whoever runs it: check the proxy",
		"attacker: unauthenticated remote user",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human report missing %q\n%s", want, out)
		}
	}
}

func TestLessons_SARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, lessonsScan()); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	if got := res[0].Properties["achilles/assessedSeverity"]; got != "critical" {
		t.Errorf("assessed severity property = %v", got)
	}
	if _, ok := res[1].Properties["achilles/blockers"]; !ok {
		t.Error("blockers should be exported for an uncertain verdict")
	}
	if j := res[2].Suppressions[0].Justification; !strings.HasPrefix(j, "Hardening note") {
		t.Errorf("hardening suppression justification = %q", j)
	}
}

func TestLessons_SecretFindingShowsNoDetail(t *testing.T) {
	s := model.Scan{Target: "/r", Findings: []model.Finding{{Tool: "gitleaks", RuleID: "aws-key", Severity: model.SeverityHigh,
		Verdict: &model.Verdict{Classification: model.ClassUncertain, Blockers: []string{"AKIAABCDEFGHIJKLMNOP"}}}}}
	var buf bytes.Buffer
	WriteHuman(&buf, s)
	if strings.Contains(buf.String(), "AKIA") {
		t.Error("a credential finding's verdict detail must not be printed")
	}
}
