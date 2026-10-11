package model

import (
	"encoding/json"
	"testing"
)

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
		{"refuted true positive, refutation not backed, is kept", Verdict{Classification: ClassTruePositive, Confidence: 0.8, Refuted: true}, false},
		{"refuted true positive, refutation backed, is dismissed", Verdict{Classification: ClassTruePositive, Confidence: 0.8, Refuted: true, RefuteSupported: true}, true},
		{"a sure true positive is kept even against a backed refutation", Verdict{Classification: ClassTruePositive, Confidence: SureFloor, Refuted: true, RefuteSupported: true}, false},
		{"refuted uncertain is kept", Verdict{Classification: ClassUncertain, Confidence: 0.5, Refuted: true, RefuteSupported: true}, false},
		{"refuted flag on a false positive does not dismiss a shaky one", Verdict{Classification: ClassFalsePositive, Confidence: 0.5, Refuted: true, RefuteSupported: true}, false},
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

func TestVerdictDisputed(t *testing.T) {
	kept := Verdict{Classification: ClassTruePositive, Confidence: 0.95, Refuted: true, RefuteSupported: true}
	if !kept.Disputed() {
		t.Error("refuted but not dismissed is a dispute")
	}
	gone := Verdict{Classification: ClassTruePositive, Confidence: 0.8, Refuted: true, RefuteSupported: true}
	if gone.Disputed() {
		t.Error("a dismissed finding is not disputed, it is ruled out")
	}
	if (Verdict{Classification: ClassTruePositive, Confidence: 0.9}).Disputed() {
		t.Error("no refutation, no dispute")
	}
}

func TestNormalizeConfidence(t *testing.T) {
	nan := 0.0
	nan = nan / nan
	for _, c := range []struct{ in, want float64 }{
		{0, 0}, {0.7, 0.7}, {1, 1}, {85, 0.85}, {100, 1}, {101, 0}, {-0.1, 0}, {nan, 0},
	} {
		if got := NormalizeConfidence(c.in); got != c.want {
			t.Errorf("NormalizeConfidence(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{
		"critical": SeverityCritical, "HIGH": SeverityHigh, " medium ": SeverityMedium, "low": SeverityLow, "info": SeverityInfo,
	} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "unknown", "hgih", "error", "warning"} {
		if got, ok := ParseSeverity(bad); ok {
			t.Errorf("ParseSeverity(%q) accepted as %q", bad, got)
		}
	}
}

func TestSarifScoreDecodesStringsAndNumbers(t *testing.T) {
	var p SarifRuleProps
	for in, want := range map[string]float64{`"9.8"`: 9.8, `9.8`: 9.8, `" 7 "`: 7, `10`: 10} {
		if err := json.Unmarshal([]byte(`{"security-severity":`+in+`}`), &p); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got, ok := p.SecuritySeverity.Value(); !ok || got != want {
			t.Errorf("%s -> %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{`"n/a"`, `null`, `""`, `0`, `11`, `-1`, `true`, `[1]`} {
		p = SarifRuleProps{}
		if err := json.Unmarshal([]byte(`{"security-severity":`+bad+`}`), &p); err != nil {
			t.Errorf("%s must not fail the decode: %v", bad, err)
		}
		if _, ok := p.SecuritySeverity.Value(); ok {
			t.Errorf("%s must not be a usable score", bad)
		}
	}
}
