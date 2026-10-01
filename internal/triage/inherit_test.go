package triage

import (
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
	"github.com/Warzuponus/achilles/internal/vault"
)

// triagedRep returns a finding that has already been through triage+judge, as a
// correlation cluster representative would be by the time members inherit.
func triagedRep() model.Finding {
	return model.Finding{
		Tool: "gosec", RuleID: "G201", Severity: model.SeverityHigh,
		Fingerprint: "rep-fp",
		Verdict: &model.Verdict{
			Classification: model.ClassTruePositive, Confidence: 0.9,
			Exploitability: model.ExploitReachable, Reasoning: "concatenated query",
			SuggestedFix: "use a prepared statement",
		},
		Provenance:  &model.Provenance{TriageModel: "m-triage", JudgeModel: "m-judge", PromptVersion: PromptVersion},
		Remediation: &model.Remediation{Summary: "parameterize", Diff: "--- a\n+++ b\n"},
	}
}

func TestInherit_CopiesVerdictWithoutAnyLLMCall(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{`{"classification":"false_positive","confidence":0.1}`}}
	eng := NewEngine(llm.NewRouter(fake), nil, enrich.New(0), "")

	f := newFinding()
	eng.Inherit("run1", f, triagedRep())

	if len(fake.Calls) != 0 {
		t.Errorf("inheriting a verdict must not call the LLM, got %d call(s)", len(fake.Calls))
	}
	if f.Verdict == nil {
		t.Fatal("verdict not attached")
	}
	if f.Verdict.Classification != model.ClassTruePositive || f.Verdict.Confidence != 0.9 {
		t.Errorf("verdict not copied: %+v", f.Verdict)
	}
	if !f.Verdict.HighConfidence() {
		t.Error("an inherited unrefuted TP @0.9 should still be high-confidence")
	}
}

func TestInherit_RecordsWhereTheVerdictCameFrom(t *testing.T) {
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")

	f := newFinding()
	eng.Inherit("run1", f, triagedRep())

	if f.Provenance == nil {
		t.Fatal("provenance not attached")
	}
	if f.Provenance.CorrelatedFrom != "rep-fp" {
		t.Errorf("CorrelatedFrom = %q, want the representative's fingerprint", f.Provenance.CorrelatedFrom)
	}
	// The models that actually produced the verdict carry over, so the audit
	// trail doesn't claim an un-modelled verdict appeared from nowhere.
	if f.Provenance.TriageModel != "m-triage" || f.Provenance.JudgeModel != "m-judge" {
		t.Errorf("models not carried over: %+v", f.Provenance)
	}
}

func TestInherit_DoesNotCopyRemediation(t *testing.T) {
	// A remediation is a diff against one specific finding; replaying it for
	// every tool that reported the same line would hand --fix-pr duplicates.
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")

	f := newFinding()
	eng.Inherit("run1", f, triagedRep())

	if f.Remediation != nil {
		t.Errorf("remediation must not be inherited, got %+v", f.Remediation)
	}
}

func TestInherit_RecordsVerdictToVaultUnderCorrelationSource(t *testing.T) {
	v := newVault(t)
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), v, enrich.New(0), "")

	f := newFinding()
	eng.Inherit("run1", f, triagedRep())

	var verdicts, llmCalls int
	var source string
	for _, r := range v.ByRun("run1") {
		switch r.Kind {
		case vault.KindVerdict:
			verdicts++
			source = r.Source
		case vault.KindLLMCall:
			llmCalls++
		}
	}
	if verdicts != 1 || source != "correlation" {
		t.Errorf("want 1 verdict record sourced 'correlation', got %d sourced %q", verdicts, source)
	}
	if llmCalls != 0 {
		t.Errorf("inheritance makes no LLM calls, so none should be recorded; got %d", llmCalls)
	}
}

func TestInherit_NoOpWhenRepresentativeHasNoVerdict(t *testing.T) {
	// The representative's own triage can fail; the caller falls back to
	// triaging directly, so Inherit must not fabricate a verdict.
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")

	f := newFinding()
	eng.Inherit("run1", f, model.Finding{Tool: "gosec", RuleID: "G201"})

	if f.Verdict != nil {
		t.Errorf("no verdict to inherit, but got %+v", f.Verdict)
	}
}

func TestAutoResolve_ReportsWhetherCalibrationFired(t *testing.T) {
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")

	f := newFinding()
	if eng.AutoResolve("run1", f) {
		t.Error("no calibrator configured, so nothing should resolve")
	}
	if f.Verdict != nil {
		t.Errorf("verdict should be untouched, got %+v", f.Verdict)
	}

	eng.SetCalibrator(stubCalibrator{resolve: true})
	if !eng.AutoResolve("run1", f) {
		t.Fatal("calibrator resolves, so AutoResolve should report true")
	}
	if f.Verdict == nil || f.Verdict.Classification != model.ClassFalsePositive {
		t.Errorf("expected the calibrated FP verdict, got %+v", f.Verdict)
	}
	if f.Provenance == nil || f.Provenance.PromptVersion != "calibration" {
		t.Errorf("provenance should mark calibration, got %+v", f.Provenance)
	}
}
