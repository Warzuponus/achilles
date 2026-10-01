package triage

import (
	"context"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

// Loose open models fence their JSON, drop required fields or wander out of the
// enum. The triage seats get ONE repair round-trip (like review/sca/threat-model);
// what must NOT change is the documented fail-safe once repair also fails.

func TestTriage_RepairsVerdictThatOmitsClassification(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{
		`{"confidence":0.9,"reasoning":"looks bad"}`, // parses, but classification is missing
		`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"x"}`,
	}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false}`}}
	f := newFinding()
	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), nil, enrich.New(0), "")
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Verdict.Classification != model.ClassTruePositive {
		t.Errorf("classification = %q, want the repaired true_positive", f.Verdict.Classification)
	}
	if n := len(triageFake.Calls); n != 2 {
		t.Errorf("triage calls = %d, want 2 (original + one repair)", n)
	}
	if last := triageFake.Calls[1]; !last.JSON || last.Schema != nil {
		t.Errorf("repair must ask for plain JSON, got %+v", last)
	}
}

func TestTriage_WellFormedVerdictCostsNoExtraCall(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{`{"classification":"false_positive","confidence":0.8,"reasoning":"x"}`}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false,"reason":""}`}}
	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), nil, enrich.New(0), "")
	if err := eng.Triage(context.Background(), "r", newFinding()); err != nil {
		t.Fatal(err)
	}
	if len(triageFake.Calls) != 1 || len(judgeFake.Calls) != 1 {
		t.Errorf("calls triage=%d judge=%d, want 1 each", len(triageFake.Calls), len(judgeFake.Calls))
	}
}

func TestTriage_JudgeFailSafeSurvivesRepair(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{
		`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"x"}`,
	}}
	// Garbage on the first call AND on the repair.
	judgeFake := &llmtest.Fake{Responses: []string{`I think it is fine.`, `still not json`}}
	f := newFinding()
	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), nil, enrich.New(0), "")
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatalf("an unusable judge answer must not fail triage: %v", err)
	}
	if f.Verdict == nil || f.Verdict.Refuted || f.Verdict.Overturned {
		t.Errorf("unparseable judge must mean 'did not refute', got %+v", f.Verdict)
	}
	if len(judgeFake.Calls) != 2 {
		t.Errorf("judge calls = %d, want 2 (original + one repair)", len(judgeFake.Calls))
	}
}

func TestTriage_RepairsJudgeThatOmitsRefuted(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{
		`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"x"}`,
	}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"reason":"constant input"}`, `{"refuted":true,"reason":"constant input"}`}}
	f := newFinding()
	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), nil, enrich.New(0), "")
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if !f.Verdict.Refuted {
		t.Errorf("repaired judge answer was not applied: %+v", f.Verdict)
	}
}

func TestRemediate_RepairsMissingSummary(t *testing.T) {
	remFake := &llmtest.Fake{Responses: []string{
		`{"diff":"--- a\n+++ b","confidence":0.9}`,
		`{"summary":"use a parameterized query","diff":"--- a\n+++ b","confidence":0.9}`,
	}}
	f := newFinding()
	f.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9}
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}).Set("remediation", remFake), nil, enrich.New(0), "")
	if err := eng.Remediate(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Remediation == nil || f.Remediation.Summary == "" {
		t.Errorf("remediation = %+v, want the repaired summary", f.Remediation)
	}
}
