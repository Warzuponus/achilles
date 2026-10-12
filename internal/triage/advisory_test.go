package triage

import (
	"context"
	"errors"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

func advisoryFinding() *model.Finding {
	return &model.Finding{
		Tool: "osv-scanner", RuleID: "GHSA-j8r2-6x86-q33q", Message: "requests 2.19.1 is vulnerable",
		Severity: model.SeverityMedium, Fingerprint: "adv1",
		Location: model.Location{File: "requirements.txt"},
	}
}

func TestTriage_DependencyAdvisoryIsNotSentToTheModel(t *testing.T) {
	tf := &llmtest.Fake{Responses: []string{jFP}}
	jf := &llmtest.Fake{Responses: []string{jAccept}}
	eng := NewEngine(llm.NewRouter(tf).Set("judge", jf), nil, enrich.New(0), "")

	f := advisoryFinding()
	err := eng.Triage(context.Background(), "r", f)
	if !errors.Is(err, ErrAdvisory) {
		t.Fatalf("err = %v, want ErrAdvisory", err)
	}
	if len(tf.Calls)+len(jf.Calls) != 0 {
		t.Errorf("an advisory must cost no model call, got %d", len(tf.Calls)+len(jf.Calls))
	}
	if f.Verdict != nil {
		t.Errorf("an advisory must not carry a verdict: %+v", f.Verdict)
	}
}

func TestPlan_SkipsFindingsThatAreNeverSent(t *testing.T) {
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")
	secret := model.Finding{Tool: "gitleaks", RuleID: "generic-api-key", Fingerprint: "s"}
	calls := eng.Plan([]model.Finding{*advisoryFinding(), secret, *newFinding()}, PlanOpts{Remediate: true})
	// Only the code finding is planned: triage + judge + remediation.
	if len(calls) != 3 {
		t.Errorf("planned %d call(s), want 3 (advisories and credential findings cost nothing): %+v", len(calls), calls)
	}
}

func TestInherit_AnAdvisoryNeverTakesASiblingsVerdict(t *testing.T) {
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")
	rep := *newFinding()
	rep.Verdict = &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.99}

	f := advisoryFinding()
	eng.Inherit("r", f, rep)
	if f.Verdict != nil {
		t.Errorf("a correlated code finding's verdict must not land on an advisory: %+v", f.Verdict)
	}
}

func TestAutoResolve_NeverAppliesToAnAdvisoryOrACredential(t *testing.T) {
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}), nil, enrich.New(0), "")
	eng.SetCalibrator(stubCalibrator{resolve: true}) // a calibrator that would resolve anything

	if f := advisoryFinding(); eng.AutoResolve("r", f) || f.Verdict != nil {
		t.Error("feedback history must not resolve a dependency advisory")
	}
	secret := &model.Finding{Tool: "gitleaks", RuleID: "generic-api-key", Fingerprint: "s"}
	if eng.AutoResolve("r", secret) || secret.Verdict != nil {
		t.Error("feedback history must not resolve a credential finding")
	}
	if f := newFinding(); !eng.AutoResolve("r", f) {
		t.Error("precondition: the stub resolves an ordinary code finding")
	}
}
