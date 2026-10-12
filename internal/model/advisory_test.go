package model

import "testing"

func TestIsDependencyAdvisory(t *testing.T) {
	yes := []Finding{
		{Tool: "osv-scanner", RuleID: "CVE-2023-32681"},
		{Tool: "osv-scanner", RuleID: "anything-it-reports"}, // the tool alone is enough
		{Tool: "OSV-Scanner", RuleID: "GHSA-j8r2-6x86-q33q"},
		{Tool: "govulncheck", RuleID: "GO-2024-2687"},
		{Tool: "Trivy", RuleID: "CVE-2024-3094"}, // Trivy reports a vulnerable package by its CVE id
		{Tool: "trivy", RuleID: "ghsa-j8r2-6x86-q33q"},
		{Tool: "trivy", RuleID: "PYSEC-2023-74"},
		{Tool: "x", RuleID: "RUSTSEC-2024-0003"},
		{Tool: "x", RuleID: "MAL-2024-1234"},
		{Tool: "grype", RuleID: "CVE-2021-44228"},
	}
	no := []Finding{
		{Tool: "gosec", RuleID: "G204"},
		{Tool: "opengrep", RuleID: "go-sqli-concat"}, // starts with "go-" but is no advisory
		{Tool: "opengrep", RuleID: "go.lang.security.x"},
		{Tool: "trivy", RuleID: "AVD-AWS-0086"},            // a Trivy misconfiguration check
		{Tool: "trivy", RuleID: "DS002"},                   // a Dockerfile check
		{Tool: "trivy", RuleID: "aws-access-key-id"},       // a secret
		{Tool: "opengrep", RuleID: "cve-2021-44228-log4j"}, // a code rule ABOUT a CVE is still a code finding
		{Tool: "opengrep", RuleID: "CVE-2021"},             // not a complete id
		{Tool: "", RuleID: ""},
	}
	for _, f := range yes {
		if !f.IsDependencyAdvisory() {
			t.Errorf("%s/%s should be a dependency advisory", f.Tool, f.RuleID)
		}
	}
	for _, f := range no {
		if f.IsDependencyAdvisory() {
			t.Errorf("%s/%s should NOT be a dependency advisory", f.Tool, f.RuleID)
		}
	}
}

// The bug: a CVE finding was triaged with a prompt about attacker data reaching a
// sink, with a lockfile line (or nothing) as its "code". A confident
// "false_positive: no usage shown" took a vulnerable dependency out of the gate.
func TestDependencyAdvisoryIsNeverDismissed(t *testing.T) {
	confidentFP := &Verdict{Classification: ClassFalsePositive, Confidence: 0.99}
	backedRefute := &Verdict{Classification: ClassTruePositive, Confidence: 0.75, Refuted: true, RefuteSupported: true}

	for _, v := range []*Verdict{confidentFP, backedRefute} {
		if !(Finding{Tool: "gosec", RuleID: "G204", Verdict: v}).Dismissed() {
			t.Fatalf("precondition: this verdict dismisses a code finding: %+v", v)
		}
		for _, f := range []Finding{
			{Tool: "osv-scanner", RuleID: "GHSA-j8r2-6x86-q33q", Verdict: v},
			{Tool: "trivy", RuleID: "CVE-2024-3094", Verdict: v},
		} {
			if f.Dismissed() {
				t.Errorf("%s/%s must never be dismissed by a verdict: %+v", f.Tool, f.RuleID, v)
			}
		}
	}

	s := Scan{Findings: []Finding{
		{Fingerprint: "a", Tool: "trivy", RuleID: "CVE-2024-3094", Verdict: confidentFP},
		{Fingerprint: "b", Tool: "gosec", RuleID: "G204", Verdict: confidentFP},
	}}
	if n := s.PartitionDismissed(); n != 1 {
		t.Fatalf("moved %d, want 1", n)
	}
	if fingerprints(s.Findings) != "a" || fingerprints(s.Dismissed) != "b" {
		t.Errorf("kept %q / dismissed %q; the advisory must stay in the gate",
			fingerprints(s.Findings), fingerprints(s.Dismissed))
	}
}

// What the scanner declares outranks what the tool name and rule id suggest.
func TestCategoryDecidesSecretAndAdvisory(t *testing.T) {
	sec := Finding{Tool: "Trivy", RuleID: "slack-web-hook", Category: CategorySecret}
	if !sec.IsSecret() {
		t.Error("a scanner-declared secret is a credential finding whatever its rule is called")
	}
	if (Finding{Tool: "Trivy", RuleID: "slack-web-hook"}).IsSecret() {
		t.Error("precondition: without the category this rule id is not recognised")
	}
	dep := Finding{Tool: "Trivy", RuleID: "DSA-5678-1", Category: CategoryDependency}
	if !dep.IsDependencyAdvisory() {
		t.Error("a scanner-declared vulnerable package is a dependency advisory whatever its id format")
	}
	// A confident verdict dismisses neither.
	fp := &Verdict{Classification: ClassFalsePositive, Confidence: 0.99}
	sec.Verdict, dep.Verdict = fp, fp
	if sec.Dismissed() || dep.Dismissed() {
		t.Error("neither a credential nor an advisory may be dismissed by a verdict")
	}
}
