package triage

import (
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

func planEngine() (*Engine, *llmtest.Fake) {
	fake := &llmtest.Fake{Responses: []string{`{"classification":"true_positive","confidence":0.9}`}}
	return NewEngine(llm.NewRouter(fake), nil, enrich.New(0), ""), fake
}

func TestPlan_MakesNoLLMCall(t *testing.T) {
	// The whole point of a pre-flight estimate is that it costs nothing.
	eng, fake := planEngine()
	eng.Plan([]model.Finding{*newFinding(), *newFinding()}, PlanOpts{Remediate: true})
	if len(fake.Calls) != 0 {
		t.Errorf("planning must not call the LLM, got %d call(s)", len(fake.Calls))
	}
}

func TestPlan_TwoCallsPerFindingByDefault(t *testing.T) {
	eng, _ := planEngine()
	calls := eng.Plan([]model.Finding{*newFinding(), *newFinding(), *newFinding()}, PlanOpts{})

	if len(calls) != 6 {
		t.Fatalf("3 findings × (triage+judge) = 6 calls, got %d", len(calls))
	}
	counts := map[string]int{}
	for _, c := range calls {
		counts[c.Task]++
	}
	if counts["triage"] != 3 || counts["judge"] != 3 || counts["remediation"] != 0 {
		t.Errorf("task mix wrong: %v", counts)
	}
}

func TestPlan_RemediationAddsAThirdCallPerFinding(t *testing.T) {
	eng, _ := planEngine()
	calls := eng.Plan([]model.Finding{*newFinding()}, PlanOpts{Remediate: true})

	counts := map[string]int{}
	for _, c := range calls {
		counts[c.Task]++
	}
	if counts["remediation"] != 1 {
		t.Errorf("remediation should be planned once per finding (upper bound), got %v", counts)
	}
}

func TestPlan_SkipsFindingsTheCalibratorResolves(t *testing.T) {
	// Calibration short-circuits the LLM at run time, so it must also drop out
	// of the estimate — otherwise the projection over-charges for noisy rules.
	eng, _ := planEngine()
	eng.SetCalibrator(stubCalibrator{resolve: true})

	if calls := eng.Plan([]model.Finding{*newFinding(), *newFinding()}, PlanOpts{Remediate: true}); len(calls) != 0 {
		t.Errorf("auto-resolved findings cost nothing, got %d planned call(s)", len(calls))
	}
}

func TestPlan_EveryCallHasPositiveTokenEstimates(t *testing.T) {
	eng, _ := planEngine()
	for _, c := range eng.Plan([]model.Finding{*newFinding()}, PlanOpts{Remediate: true}) {
		if c.InputTokens <= 0 {
			t.Errorf("%s: input tokens must be > 0, got %d", c.Task, c.InputTokens)
		}
		if c.OutputTokens <= 0 {
			t.Errorf("%s: output tokens must be > 0, got %d", c.Task, c.OutputTokens)
		}
		if c.Model != "" {
			t.Errorf("%s: Plan leaves Model to the caller, got %q", c.Task, c.Model)
		}
	}
}

func TestPlan_JudgeInputIncludesTheVerdictUnderReview(t *testing.T) {
	// The judge prompt embeds the triage verdict, so its input must exceed the
	// bare prompt scaffolding by roughly the triage pass's output size.
	eng, _ := planEngine()
	calls := eng.Plan([]model.Finding{*newFinding()}, PlanOpts{})

	var judge cost0
	for _, c := range calls {
		if c.Task == "judge" {
			judge = cost0{c.InputTokens, c.OutputTokens}
		}
	}
	bare := messageTokens(judgeMessages(*newFinding(), "", model.Verdict{}))
	if judge.in <= bare {
		t.Errorf("judge input %d should exceed the bare prompt %d by the verdict size", judge.in, bare)
	}
}

type cost0 struct{ in, out int }

func TestPlan_BiggerCodeContextCostsMore(t *testing.T) {
	// A finding whose context is larger must project a larger prompt — this is
	// what makes widening context (Tier H) visible in the estimate.
	eng, _ := planEngine()

	small := *newFinding()
	small.CodeContext = "eval(x)"
	big := *newFinding()
	big.CodeContext = string(make([]byte, 8000))

	in := func(f model.Finding) int {
		for _, c := range eng.Plan([]model.Finding{f}, PlanOpts{}) {
			if c.Task == "triage" {
				return c.InputTokens
			}
		}
		return 0
	}
	if in(big) <= in(small) {
		t.Errorf("a larger code context should cost more: small=%d big=%d", in(small), in(big))
	}
}

func TestPlan_Empty(t *testing.T) {
	eng, _ := planEngine()
	if calls := eng.Plan(nil, PlanOpts{Remediate: true}); len(calls) != 0 {
		t.Errorf("no findings means no calls, got %d", len(calls))
	}
}
