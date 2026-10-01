package knowledge

import (
	"testing"

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

func TestCalibrator_RulesAndSuppresses(t *testing.T) {
	// eval: 4 FP → noisy (auto-suppressed). sqli: 3 TP, 1 FP → 25% FP (watch).
	fs := seedFeedback(t,
		Feedback{Fingerprint: "a", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "b", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "c", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "d", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "e", Tool: "gosec", RuleID: "sqli", Label: LabelTP},
		Feedback{Fingerprint: "f", Tool: "gosec", RuleID: "sqli", Label: LabelTP},
		Feedback{Fingerprint: "g", Tool: "gosec", RuleID: "sqli", Label: LabelTP},
		Feedback{Fingerprint: "h", Tool: "gosec", RuleID: "sqli", Label: LabelFP},
	)
	cal := NewCalibrator(fs, 3, 0.8)

	rules := cal.Rules()
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	// Noisiest first: eval (100% FP) before sqli (25% FP).
	if rules[0].RuleID != "eval" || rules[1].RuleID != "sqli" {
		t.Errorf("rules not sorted noisiest-first: %+v", rules)
	}
	if !cal.Suppresses(rules[0]) {
		t.Error("eval (4/4 FP) should be auto-suppressed")
	}
	if cal.Suppresses(rules[1]) {
		t.Error("sqli (25% FP) should NOT be auto-suppressed")
	}
	if rules[1].Samples() != 4 || rules[1].FP != 1 {
		t.Errorf("sqli health wrong: %+v", rules[1])
	}
}

func TestCalibrator_AutoResolvesNoisyRule(t *testing.T) {
	// Rule "eval" ruled FP 4x, TP 0x → should auto-resolve as FP.
	fs := seedFeedback(t,
		Feedback{Fingerprint: "a", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "b", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "c", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
		Feedback{Fingerprint: "d", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
	)
	cal := NewCalibrator(fs, 3, 0.8)

	f := model.Finding{Tool: "opengrep", RuleID: "eval"}
	v, ok := cal.AutoResolve(f)
	if !ok {
		t.Fatal("expected auto-resolve for a chronically-FP rule")
	}
	if v.Classification != model.ClassFalsePositive {
		t.Errorf("want false_positive verdict, got %q", v.Classification)
	}
}

func TestCalibrator_DoesNotResolveWithFewSamples(t *testing.T) {
	fs := seedFeedback(t,
		Feedback{Fingerprint: "a", Tool: "opengrep", RuleID: "eval", Label: LabelFP},
	)
	cal := NewCalibrator(fs, 3, 0.8) // only 1 sample < minSamples
	if _, ok := cal.AutoResolve(model.Finding{Tool: "opengrep", RuleID: "eval"}); ok {
		t.Error("should NOT auto-resolve with too few samples")
	}
}

func TestCalibrator_DoesNotResolveTrustworthyRule(t *testing.T) {
	// Mostly true positives → keep sending to the LLM.
	fs := seedFeedback(t,
		Feedback{Fingerprint: "a", Tool: "gosec", RuleID: "g101", Label: LabelTP},
		Feedback{Fingerprint: "b", Tool: "gosec", RuleID: "g101", Label: LabelTP},
		Feedback{Fingerprint: "c", Tool: "gosec", RuleID: "g101", Label: LabelTP},
		Feedback{Fingerprint: "d", Tool: "gosec", RuleID: "g101", Label: LabelFP},
	)
	cal := NewCalibrator(fs, 3, 0.8) // FP rate 0.25 < 0.8
	if _, ok := cal.AutoResolve(model.Finding{Tool: "gosec", RuleID: "g101"}); ok {
		t.Error("should NOT auto-resolve a mostly-true-positive rule")
	}
	h, _ := cal.Health("gosec", "g101")
	if h.Samples() != 4 || h.FPRate() != 0.25 {
		t.Errorf("health wrong: %+v rate=%.2f", h, h.FPRate())
	}
}
