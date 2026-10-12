package normalize

import (
	"fmt"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// sarifDoc builds a one-result SARIF document. rule and result are raw JSON
// fragments spliced into the rule object and the result object.
func sarifDoc(tool, ruleID, rule, result string) []byte {
	if rule != "" {
		rule = "," + rule
	}
	if result != "" {
		result = "," + result
	}
	return []byte(fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":%q,
	  "rules":[{"id":%q%s}]}},
	  "results":[{"ruleId":%q,"message":{"text":"m"}%s,
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.txt"},"region":{"startLine":1}}}]}]}]}`,
		tool, ruleID, rule, ruleID, result))
}

func severityOf(t *testing.T, doc []byte) model.Severity {
	t.Helper()
	fs, err := FromSARIF("x", doc)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	return fs[0].Severity
}

// The bug: nothing ever produced "critical", so --fail-on critical never fired and
// a CVSS 9.8 dependency vulnerability was reported the same as a 7.0.
func TestSeverity_SecuritySeverityReachesCritical(t *testing.T) {
	// Trivy's shape: level "error" for both CRITICAL and HIGH, the score on the rule.
	doc := sarifDoc("Trivy", "CVE-2024-0001", `"properties":{"security-severity":"9.8"}`, `"level":"error"`)
	if got := severityOf(t, doc); got != model.SeverityCritical {
		t.Errorf("a 9.8 must be critical, got %q", got)
	}
	doc = sarifDoc("Trivy", "CVE-2024-0002", `"properties":{"security-severity":"7.5"}`, `"level":"error"`)
	if got := severityOf(t, doc); got != model.SeverityHigh {
		t.Errorf("a 7.5 must stay high, got %q", got)
	}
}

func TestSeverity_ScoreBands(t *testing.T) {
	for score, want := range map[string]model.Severity{
		"10.0": model.SeverityCritical, "9.0": model.SeverityCritical,
		"8.9": model.SeverityHigh, "7.0": model.SeverityHigh,
		"6.9": model.SeverityMedium, "4.0": model.SeverityMedium,
		"3.9": model.SeverityLow, "0.1": model.SeverityLow,
	} {
		// level "none" (info) so the score alone decides.
		doc := sarifDoc("t", "r", `"properties":{"security-severity":"`+score+`"}`, `"level":"none"`)
		if got := severityOf(t, doc); got != want {
			t.Errorf("score %s: got %q, want %q", score, got, want)
		}
	}
}

func TestSeverity_ScoreNeverLowersTheToolsOwnLevel(t *testing.T) {
	// The tool said "error". A modest score must not quietly turn that into medium.
	doc := sarifDoc("t", "r", `"properties":{"security-severity":"5.0"}`, `"level":"error"`)
	if got := severityOf(t, doc); got != model.SeverityHigh {
		t.Errorf("level error with a 5.0 score: got %q, want high (the more severe of the two)", got)
	}
}

func TestSeverity_ScoreAsABareNumberAndOnTheResult(t *testing.T) {
	// Some tools emit the score as a JSON number. That must neither fail the whole
	// document nor be ignored.
	doc := sarifDoc("t", "r", `"properties":{"security-severity":9.1}`, `"level":"warning"`)
	if got := severityOf(t, doc); got != model.SeverityCritical {
		t.Errorf("numeric rule score: got %q, want critical", got)
	}
	// A score on the result itself is read too, and wins over the rule's.
	doc = sarifDoc("t", "r", `"properties":{"security-severity":"2.0"}`,
		`"level":"note","properties":{"security-severity":"9.5"}`)
	if got := severityOf(t, doc); got != model.SeverityCritical {
		t.Errorf("result-level score: got %q, want critical", got)
	}
	doc = sarifDoc("t", "r", "", `"level":"note","properties":{"security-severity":7.2}`)
	if got := severityOf(t, doc); got != model.SeverityHigh {
		t.Errorf("numeric result score: got %q, want high", got)
	}
}

func TestSeverity_GarbageScoresAreIgnored(t *testing.T) {
	for _, bad := range []string{`"n/a"`, `""`, `"-3"`, `"42"`, `null`, `"0"`, `true`, `{"x":1}`} {
		doc := sarifDoc("t", "r", `"properties":{"security-severity":`+bad+`}`, `"level":"warning"`)
		if got := severityOf(t, doc); got != model.SeverityMedium {
			t.Errorf("score %s must be ignored (level warning stays medium), got %q", bad, got)
		}
	}
}

// The bug: a result with no level at all came out "unknown", which ranks below
// every --fail-on threshold. Gitleaks states no level, so a leaked credential could
// never fail a gate.
func TestSeverity_NoLevelDefaults(t *testing.T) {
	// SARIF §3.27.10: an absent level is "warning".
	if got := severityOf(t, sarifDoc("sometool", "some-rule", "", "")); got != model.SeverityMedium {
		t.Errorf("no level, not a secret: got %q, want medium (the SARIF default)", got)
	}
	// A secret scanner that states no severity is still reporting a leaked credential.
	if got := severityOf(t, sarifDoc("gitleaks", "generic-api-key", "", "")); got != model.SeverityHigh {
		t.Errorf("gitleaks finding with no level: got %q, want high", got)
	}
	// An explicit level is respected even for a secret.
	if got := severityOf(t, sarifDoc("gitleaks", "generic-api-key", "", `"level":"note"`)); got != model.SeverityLow {
		t.Errorf("explicit note on a secret: got %q, want low", got)
	}
}

func TestSeverity_CriticalTag(t *testing.T) {
	doc := sarifDoc("t", "r", `"properties":{"tags":["security","CRITICAL"]}`, "")
	if got := severityOf(t, doc); got != model.SeverityCritical {
		t.Errorf("a critical tag with no level: got %q, want critical", got)
	}
}
