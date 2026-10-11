package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// seedNoisyRule labels n distinct findings of opengrep/rule as false positives.
func seedNoisyRule(t *testing.T, ev vault.Store, rule string, n int) {
	t.Helper()
	fb := knowledge.NewFeedbackStore(ev)
	for i := 0; i < n; i++ {
		if err := fb.Record("seed", knowledge.Feedback{
			Fingerprint: fmt.Sprintf("old-%d", i), Tool: "opengrep", RuleID: rule, Label: knowledge.LabelFP,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// Feedback history must never take a finding out of the gate unless the operator
// asked for that: by default every finding still goes to the model.
func TestRunTriage_CalibrationIsOffByDefault(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1")
	scan.Findings[0].Severity = model.SeverityMedium
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m"}); err != nil {
		t.Fatal(err)
	}
	if fe.calls.Load() == 0 {
		t.Fatal("the finding was never sent to the model")
	}
	if len(scan.Dismissed) != 0 || len(scan.Findings) != 1 {
		t.Errorf("without --calibrate, 20 fp labels must not dismiss anything: kept %d, dismissed %d",
			len(scan.Findings), len(scan.Dismissed))
	}
	if scan.Triage.AutoResolved != 0 {
		t.Errorf("AutoResolved = %d, want 0", scan.Triage.AutoResolved)
	}
}

func TestRunTriage_CalibrateResolvesANoisyRuleAndSaysSo(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1", "real-2")
	scan.Findings[0].Severity = model.SeverityMedium // eligible
	scan.Findings[1].Severity = model.SeverityMedium // different rule, no feedback
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", calibrate: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Dismissed) != 1 || scan.Dismissed[0].RuleID != "real-1" {
		t.Fatalf("dismissed = %+v, want only real-1", scan.Dismissed)
	}
	if p := scan.Dismissed[0].Provenance; p == nil || p.PromptVersion != "calibration" {
		t.Errorf("the verdict must be attributed to calibration, not to a model: %+v", p)
	}
	if scan.Triage.AutoResolved != 1 {
		t.Errorf("AutoResolved = %d, want 1 (reports use it to say no model reviewed these)", scan.Triage.AutoResolved)
	}
	if len(scan.Findings) != 1 || scan.Findings[0].RuleID != "real-2" {
		t.Errorf("the rule with no feedback must still be reviewed and kept: %+v", scan.Findings)
	}
}

func TestRunTriage_CalibrateNeverTouchesAHighSeverityFinding(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1") // the fixture's findings are high severity
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", calibrate: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Dismissed) != 0 || scan.Triage.AutoResolved != 0 {
		t.Errorf("a high-severity finding must be reviewed however noisy its rule: dismissed %d, auto-resolved %d",
			len(scan.Dismissed), scan.Triage.AutoResolved)
	}
	if fe.calls.Load() == 0 {
		t.Error("it should have gone to the model instead")
	}
}
