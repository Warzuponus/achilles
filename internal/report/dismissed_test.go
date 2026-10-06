package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func dismissedScan() model.Scan {
	return model.Scan{
		Target: "/r",
		Findings: []model.Finding{{RuleID: "G204", Severity: model.SeverityHigh, Fingerprint: "aaa", Message: "cmd injection",
			Verdict: &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9, Exploitability: model.ExploitReachable}}},
		Dismissed: []model.Finding{{RuleID: "G104", Severity: model.SeverityHigh, Fingerprint: "bbb", Message: "unhandled error",
			Verdict: &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9, Reasoning: "error is checked on the next line"}}},
		FailedTools: []string{"trivy"},
		Triage:      &model.TriageStats{Model: "m", Total: 2, Triaged: 2, Dismissed: 1},
	}
}

func TestSARIFSuppressesDismissedAndRecordsFailedTools(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, dismissedScan()); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want kept + dismissed", len(run.Results))
	}
	if len(run.Results[0].Suppressions) != 0 {
		t.Error("an actionable finding must not be suppressed")
	}
	sup := run.Results[1].Suppressions
	if len(sup) != 1 || !strings.Contains(sup[0].Justification, "checked on the next line") {
		t.Errorf("dismissed finding should carry the AI's reason as a suppression, got %+v", sup)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Errorf("failed tool must mark the run unsuccessful, got %+v", run.Invocations)
	}
	if run.Results[0].Properties["achilles/verdict"] != "true_positive" {
		t.Errorf("verdict missing from properties: %v", run.Results[0].Properties)
	}
}

func TestMarkdownListsDismissedAndWarnsOnFailedTools(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, dismissedScan()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Incomplete scan", "trivy", "ruled out by the AI review", "G104", "checked on the next line", "verdict on 2 of 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLShowsGatesStabilityDeepAndFixVerification(t *testing.T) {
	v := &model.Verdict{
		Classification: model.ClassTruePositive, Confidence: 0.8,
		Gates: &model.Gates{
			Reachable:          model.Gate{Answer: model.GateYes, Evidence: "route /run calls it"},
			AttackerControlled: model.Gate{Answer: model.GateYes},
			Sanitized:          model.Gate{Answer: model.SanitizedNone},
		},
		Stability: &model.Stability{Samples: 3, Agreeing: 2,
			Classifications: map[model.Classification]int{model.ClassTruePositive: 2, model.ClassUncertain: 1}},
	}
	f := model.Finding{
		RuleID: "G204", Severity: model.SeverityHigh, Verdict: v,
		Deep:        &model.DeepVerification{Steps: 3, Conclusion: model.ClassTruePositive, Confidence: 0.9, Reasoning: "no auth middleware"},
		Remediation: &model.Remediation{Summary: "use exec args", Verification: &model.FixVerification{Status: model.FixVerified}},
	}
	out := renderHTML(t, model.Scan{Target: "/r", Findings: []model.Finding{f}})
	for _, want := range []string{
		"Reachable?", "route /run calls it", "Attacker-controlled?",
		"Asked 3 times", "disagreed", "Deep check (3 step(s))", "no auth middleware",
		"Verified by re-scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	f.Remediation.Verification = &model.FixVerification{Status: model.FixNotFixed, Detail: "still reported"}
	if out := renderHTML(t, model.Scan{Target: "/r", Findings: []model.Finding{f}}); !strings.Contains(out, "Not verified (not fixed): still reported") {
		t.Error("an unverified fix must say so")
	}
}
