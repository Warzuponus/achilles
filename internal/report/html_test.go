package report

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/threatmodel"
)

func TestWriteHTML(t *testing.T) {
	scan := model.Scan{
		Target: "/repo",
		Tools:  []string{"gosec", "osv-scanner"},
		Findings: []model.Finding{
			{RuleID: "G401", Severity: model.SeverityHigh, Tool: "gosec",
				Location:    model.Location{File: "hash.go", Region: model.Region{StartLine: 10}},
				Message:     "Use of weak crypto MD5",
				Verdict:     &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.95, Reasoning: "hashes passwords"},
				Remediation: &model.Remediation{Summary: "Use bcrypt", Diff: "- md5\n+ bcrypt"}},
			{RuleID: "SHADOW", Severity: model.SeverityHigh, Shadow: true,
				Location: model.Location{File: "x.go"}}, // must be excluded
		},
	}
	rep := HTMLReport{
		Target: "/repo", GeneratedAt: "2026-07-14 00:00 UTC", Tools: scan.Tools, Scan: scan,
		Review: &review.Review{Summary: "Systemic dependency rot.",
			Risks: []review.Risk{{Title: "Unmaintained deps", Severity: "high", Area: "sca",
				Rationale: "many CVEs", Recommendation: "upgrade"}}},
		Advice: &advisor.Advice{Summary: "Upgrade jinja2.",
			Upgrades: []advisor.Upgrade{{Package: "jinja2", CurrentVersion: "3.1.0", RecommendedVersion: "3.1.4",
				UpgradeType: "patch", MergeRisk: "low", SecurityDriven: true, Rationale: "fixes SSTI"}}},
		ThreatModel: &threatmodel.ThreatModel{
			TrustZones: []threatmodel.TrustZone{{Name: "Internet"}},
			Threats:    []threatmodel.Threat{{Name: "SSTI", Category: "Tampering", Risk: "high", Mitigation: "sandbox"}}},
	}

	var sb strings.Builder
	if err := WriteHTML(&sb, rep); err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	for _, want := range []string{
		"<!doctype html>", "Achilles Security Report", "/repo",
		"G401", "Use of weak crypto MD5", "Use bcrypt", // finding + fix
		"true_positive", "95%", // verdict scaled from 0.95
		"Unmaintained deps", "Systemic dependency rot", // review
		"jinja2", "3.1.0", "3.1.4", "security", // advice
		"SSTI", "Internet", // threat model
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(out, "SHADOW") {
		t.Error("shadow finding should be excluded from the report")
	}
	// Balanced tags (rough well-formedness check).
	if strings.Count(out, "<section") != strings.Count(out, "</section>") {
		t.Error("unbalanced <section> tags")
	}
}

func TestWriteHTML_FindingsOnly(t *testing.T) {
	// No agents (all nil) → still renders, no AI panels, no crash.
	scan := model.Scan{Target: "/r", Tools: []string{"gosec"},
		Findings: []model.Finding{{RuleID: "G101", Severity: model.SeverityMedium, Message: "hardcoded creds"}}}
	var sb strings.Builder
	if err := WriteHTML(&sb, HTMLReport{Target: "/r", Scan: scan, Tools: scan.Tools}); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "G101") || strings.Contains(out, "AI review") {
		t.Errorf("findings-only report wrong (should have G101, no AI panels)")
	}
}

func renderHTML(t *testing.T, scan model.Scan) string {
	t.Helper()
	var sb strings.Builder
	if err := WriteHTML(&sb, HTMLReport{Target: "/r", Scan: scan, Tools: scan.Tools}); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func TestWriteHTML_WarnsWhenScanIncomplete(t *testing.T) {
	out := renderHTML(t, model.Scan{Target: "/r", Tools: []string{"gosec"}, FailedTools: []string{"trivy", "gitleaks"}})
	for _, want := range []string{"Incomplete scan", "trivy, gitleaks", "No findings from the tools that ran"} {
		if !strings.Contains(out, want) {
			t.Errorf("incomplete-scan report missing %q", want)
		}
	}
	if strings.Contains(out, "No findings. ✅") {
		t.Error("an incomplete scan must not read as a clean one")
	}
}

func TestWriteHTML_ShowsAICoverageAndDismissed(t *testing.T) {
	fp := &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9, Reasoning: "input is a constant"}
	scan := model.Scan{
		Target: "/r", Tools: []string{"gosec"},
		Findings: []model.Finding{
			{RuleID: "G204", Severity: model.SeverityHigh, Message: "real one",
				Verdict: &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9}},
			{RuleID: "G999", Severity: model.SeverityHigh, Message: "never reviewed"},
		},
		Dismissed: []model.Finding{{RuleID: "G104", Severity: model.SeverityHigh, Verdict: fp}},
		Triage:    &model.TriageStats{Model: "m1", Total: 3, Triaged: 2, Failed: 1},
	}
	out := renderHTML(t, scan)
	for _, want := range []string{
		"gave a verdict on 2 of 3 findings", "1 failed", // coverage is honest about the gap
		"Ruled out by the AI review", "G104", "input is a constant",
		"confirmed", "not reviewed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// A confirmed finding sorts ahead of an unreviewed one of equal severity.
	if strings.Index(out, "G204") > strings.Index(out, "G999") {
		t.Error("confirmed finding should be listed before the unreviewed one")
	}
}

func TestWriteHTML_WithholdsSecretMaterial(t *testing.T) {
	scan := model.Scan{Target: "/r", Tools: []string{"gitleaks"}, Findings: []model.Finding{{
		Tool: "gitleaks", RuleID: "generic-api-key", Severity: model.SeverityHigh,
		Message:     `found key = "AKIAIOSFODNN7EXAMPLE"`,
		CodeContext: `aws_key = "AKIAIOSFODNN7EXAMPLE"`,
	}}}
	out := renderHTML(t, scan)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("report leaked a credential")
	}
	if !strings.Contains(out, "matched text is withheld") {
		t.Error("report should say why the snippet is missing")
	}
}
