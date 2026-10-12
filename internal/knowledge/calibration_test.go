package knowledge

import (
	"fmt"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
)

func seedFeedback(t *testing.T, fbs ...Feedback) *FeedbackStore {
	t.Helper()
	fs := NewFeedbackStore(newVault(t))
	for _, fb := range fbs {
		if err := fs.Record("seed", fb); err != nil {
			t.Fatal(err)
		}
	}
	return fs
}

// labels returns n feedback records for one rule, each on its own finding.
func labels(tool, rule string, label Label, n int, prefix string) []Feedback {
	out := make([]Feedback, n)
	for i := range out {
		out[i] = Feedback{Fingerprint: fmt.Sprintf("%s%d", prefix, i), Tool: tool, RuleID: rule, Label: label}
	}
	return out
}

// loose is a small policy for tests of the counting itself.
var loose = Policy{MinFindings: 3, FPThreshold: 0.8, MaxSeverity: model.SeverityMedium}

func TestCalibrator_RulesAndSuppresses(t *testing.T) {
	// eval: 4 FP, so noisy. sqli: 3 TP, 1 FP, so 25% FP (watch).
	fbs := append(labels("opengrep", "eval", LabelFP, 4, "e"), labels("gosec", "sqli", LabelTP, 3, "s")...)
	fbs = append(fbs, Feedback{Fingerprint: "s-fp", Tool: "gosec", RuleID: "sqli", Label: LabelFP})
	cal := NewCalibrator(seedFeedback(t, fbs...), loose, time.Now())

	rules := cal.Rules()
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	// Noisiest first: eval (100% FP) before sqli (25% FP).
	if rules[0].RuleID != "eval" || rules[1].RuleID != "sqli" {
		t.Errorf("rules not sorted noisiest-first: %+v", rules)
	}
	if !cal.Suppresses(rules[0]) {
		t.Error("eval (4/4 FP) should be eligible")
	}
	if cal.Suppresses(rules[1]) {
		t.Error("sqli (25% FP) should NOT be eligible")
	}
	if rules[1].Samples() != 4 || rules[1].FP != 1 {
		t.Errorf("sqli health wrong: %+v", rules[1])
	}
}

func TestCalibrator_AutoResolvesNoisyRule(t *testing.T) {
	cal := NewCalibrator(seedFeedback(t, labels("opengrep", "eval", LabelFP, 4, "e")...), loose, time.Now())

	v, ok := cal.AutoResolve(model.Finding{Tool: "opengrep", RuleID: "eval", Severity: model.SeverityMedium})
	if !ok {
		t.Fatal("expected auto-resolve for a chronically-FP rule")
	}
	if v.Classification != model.ClassFalsePositive {
		t.Errorf("want false_positive verdict, got %q", v.Classification)
	}
}

func TestCalibrator_DoesNotResolveWithFewSamples(t *testing.T) {
	cal := NewCalibrator(seedFeedback(t, labels("opengrep", "eval", LabelFP, 1, "e")...), loose, time.Now())
	if _, ok := cal.AutoResolve(model.Finding{Tool: "opengrep", RuleID: "eval"}); ok {
		t.Error("should NOT auto-resolve with too few samples")
	}
}

func TestCalibrator_DoesNotResolveTrustworthyRule(t *testing.T) {
	// Mostly true positives: keep sending to the LLM.
	fbs := append(labels("gosec", "g101x", LabelTP, 3, "t"), labels("gosec", "g101x", LabelFP, 1, "f")...)
	cal := NewCalibrator(seedFeedback(t, fbs...), loose, time.Now())
	if _, ok := cal.AutoResolve(model.Finding{Tool: "gosec", RuleID: "g101x"}); ok {
		t.Error("should NOT auto-resolve a mostly-true-positive rule")
	}
	h, _ := cal.Health("gosec", "g101x")
	if h.Samples() != 4 || h.FPRate() != 0.25 {
		t.Errorf("health wrong: %+v rate=%.2f", h, h.FPRate())
	}
}

// The failure this policy exists to prevent: three "fp" clicks used to take every
// future finding of a rule out of the gate, forever, with no model review.
func TestDefaultPolicy_ThreeLabelsAreNowhereNearEnough(t *testing.T) {
	medium := model.Finding{Tool: "gosec", RuleID: "G304", Severity: model.SeverityMedium}

	cal := NewCalibrator(seedFeedback(t, labels("gosec", "G304", LabelFP, 3, "g")...), DefaultPolicy, time.Now())
	if _, ok := cal.AutoResolve(medium); ok {
		t.Fatal("3 labels must not auto-resolve a rule under the shipped policy")
	}
	cal = NewCalibrator(seedFeedback(t, labels("gosec", "G304", LabelFP, 9, "g")...), DefaultPolicy, time.Now())
	if _, ok := cal.AutoResolve(medium); ok {
		t.Error("9 labels is still below the bar of 10")
	}
	cal = NewCalibrator(seedFeedback(t, labels("gosec", "G304", LabelFP, 10, "g")...), DefaultPolicy, time.Now())
	if _, ok := cal.AutoResolve(medium); !ok {
		t.Error("10 distinct false-positive findings clears the shipped policy")
	}
}

func TestCalibrator_RelabelingOneFindingIsOneSample(t *testing.T) {
	// Ten clicks on the same finding are one opinion about one finding.
	var fbs []Feedback
	for i := 0; i < 10; i++ {
		fbs = append(fbs, Feedback{Fingerprint: "same", Tool: "gosec", RuleID: "G304", Label: LabelFP})
	}
	cal := NewCalibrator(seedFeedback(t, fbs...), loose, time.Now())
	if h, _ := cal.Health("gosec", "G304"); h.Samples() != 1 {
		t.Errorf("samples = %d, want 1 distinct finding", h.Samples())
	}
	if _, ok := cal.AutoResolve(model.Finding{Tool: "gosec", RuleID: "G304"}); ok {
		t.Error("one finding labeled many times must not look like many findings")
	}
}

func TestCalibrator_LatestLabelWins(t *testing.T) {
	// An analyst who changes their mind is believed: fp, then tp, is a true positive.
	fbs := append(labels("gosec", "G304", LabelFP, 3, "g"),
		Feedback{Fingerprint: "g0", Tool: "gosec", RuleID: "G304", Label: LabelTP})
	cal := NewCalibrator(seedFeedback(t, fbs...), loose, time.Now())
	h, _ := cal.Health("gosec", "G304")
	if h.TP != 1 || h.FP != 2 {
		t.Errorf("health = %+v, want TP 1 / FP 2", h)
	}
	if cal.Suppresses(h) {
		t.Error("2 of 3 false positive is below the 80% threshold")
	}
}

func TestCalibrator_NeverResolvesAboveTheSeverityCap(t *testing.T) {
	cal := NewCalibrator(seedFeedback(t, labels("gosec", "G304", LabelFP, 20, "g")...), DefaultPolicy, time.Now())
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityCritical} {
		if _, ok := cal.AutoResolve(model.Finding{Tool: "gosec", RuleID: "G304", Severity: sev}); ok {
			t.Errorf("a %s finding must always be reviewed, however noisy its rule", sev)
		}
	}
	for _, sev := range []model.Severity{model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if _, ok := cal.AutoResolve(model.Finding{Tool: "gosec", RuleID: "G304", Severity: sev}); !ok {
			t.Errorf("a %s finding of a noisy rule should resolve", sev)
		}
	}
}

func TestCalibrator_NeverResolvesACredentialFinding(t *testing.T) {
	cal := NewCalibrator(seedFeedback(t, labels("gitleaks", "generic-api-key", LabelFP, 20, "k")...), DefaultPolicy, time.Now())
	if _, ok := cal.AutoResolve(model.Finding{Tool: "gitleaks", RuleID: "generic-api-key", Severity: model.SeverityLow}); ok {
		t.Error("feedback must not be able to rule out a leaked credential")
	}
}

func TestCalibrator_OldLabelsExpire(t *testing.T) {
	low := model.Finding{Tool: "gosec", RuleID: "G304", Severity: model.SeverityLow}
	fs := seedFeedback(t, labels("gosec", "G304", LabelFP, 20, "g")...)
	if _, ok := NewCalibrator(fs, DefaultPolicy, time.Now()).AutoResolve(low); !ok {
		t.Fatal("precondition: fresh labels resolve")
	}
	// The same labels, seen from a year later, no longer count.
	later := time.Now().Add(365 * 24 * time.Hour)
	cal := NewCalibrator(fs, DefaultPolicy, later)
	if _, ok := cal.AutoResolve(low); ok {
		t.Error("labels older than MaxAge must stop suppressing the rule")
	}
	if len(cal.Rules()) != 0 {
		t.Errorf("expired labels should not appear in rule health: %+v", cal.Rules())
	}
	// MaxAge 0 keeps them forever.
	forever := DefaultPolicy
	forever.MaxAge = 0
	if _, ok := NewCalibrator(fs, forever, later).AutoResolve(low); !ok {
		t.Error("MaxAge 0 means labels do not expire")
	}
}

func TestCalibrator_LabelsWithNoRuleAreIgnored(t *testing.T) {
	// --feedback on a fingerprint the vault does not know records an empty tool/rule.
	cal := NewCalibrator(seedFeedback(t, labels("", "", LabelFP, 20, "x")...), loose, time.Now())
	if len(cal.Rules()) != 0 {
		t.Errorf("labels with no rule must not form a rule: %+v", cal.Rules())
	}
	if _, ok := cal.AutoResolve(model.Finding{}); ok {
		t.Error("an empty finding must not match them")
	}
}
