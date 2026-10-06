package model

import "testing"

func TestVerdictDismissed(t *testing.T) {
	cases := []struct {
		name string
		v    Verdict
		want bool
	}{
		{"confident false positive", Verdict{Classification: ClassFalsePositive, Confidence: 0.9}, true},
		{"at the floor", Verdict{Classification: ClassFalsePositive, Confidence: DismissFloor}, true},
		{"shaky false positive is kept", Verdict{Classification: ClassFalsePositive, Confidence: 0.5}, false},
		{"overturned by judge is kept", Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Overturned: true}, false},
		{"refuted true positive is dismissed", Verdict{Classification: ClassTruePositive, Confidence: 0.9, Refuted: true}, true},
		{"true positive is kept", Verdict{Classification: ClassTruePositive, Confidence: 0.9}, false},
		{"uncertain is kept", Verdict{Classification: ClassUncertain, Confidence: 0.99}, false},
	}
	for _, c := range cases {
		if got := c.v.Dismissed(); got != c.want {
			t.Errorf("%s: Dismissed() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPartitionDismissedKeepsOrderAndUnreviewed(t *testing.T) {
	fp := &Verdict{Classification: ClassFalsePositive, Confidence: 0.9}
	tp := &Verdict{Classification: ClassTruePositive, Confidence: 0.9}
	s := Scan{Findings: []Finding{
		{Fingerprint: "a", Verdict: tp},
		{Fingerprint: "b", Verdict: fp},
		{Fingerprint: "c"}, // never reviewed: must stay
		{Fingerprint: "d", Verdict: fp},
	}}
	if n := s.PartitionDismissed(); n != 2 {
		t.Fatalf("moved %d, want 2", n)
	}
	if got := fingerprints(s.Findings); got != "ac" {
		t.Errorf("kept %q, want ac", got)
	}
	if got := fingerprints(s.Dismissed); got != "bd" {
		t.Errorf("dismissed %q, want bd", got)
	}
}

func fingerprints(fs []Finding) string {
	out := ""
	for _, f := range fs {
		out += f.Fingerprint
	}
	return out
}

func TestIsSecret(t *testing.T) {
	yes := []Finding{
		{Tool: "gitleaks", RuleID: "generic-api-key"},
		{Tool: "trivy", RuleID: "aws-access-key-id"},
		{Tool: "opengrep", RuleID: "hardcoded-password"},
		{Tool: "gosec", RuleID: "G101", CWE: []string{"CWE-798"}},
	}
	no := []Finding{
		{Tool: "gosec", RuleID: "G204", CWE: []string{"CWE-78"}},
		{Tool: "opengrep", RuleID: "python-eval"},
	}
	for _, f := range yes {
		if !f.IsSecret() {
			t.Errorf("%s/%s should be secret", f.Tool, f.RuleID)
		}
	}
	for _, f := range no {
		if f.IsSecret() {
			t.Errorf("%s/%s should not be secret", f.Tool, f.RuleID)
		}
	}
}
