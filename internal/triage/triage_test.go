package triage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
	"github.com/Warzuponus/achilles/internal/vault"
)

func newFinding() *model.Finding {
	return &model.Finding{
		Tool: "opengrep", RuleID: "eval", Message: "eval on input",
		Severity: model.SeverityHigh, Fingerprint: "fp1",
		Location:    model.Location{File: "a.py", Region: model.Region{StartLine: 1}},
		CodeContext: "eval(user_input)",
	}
}

func newVault(t *testing.T) *vault.FileStore {
	t.Helper()
	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTriage_AttachesVerdict(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{
		`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"attacker-controlled","suggestedFix":"use ast.literal_eval"}`,
	}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false,"reason":""}`}}

	router := llm.NewRouter(triageFake).Set("judge", judgeFake)
	eng := NewEngine(router, newVault(t), enrich.New(2), "")

	f := newFinding()
	if err := eng.Triage(context.Background(), "run1", f); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	if f.Verdict == nil {
		t.Fatal("verdict not attached")
	}
	if f.Verdict.Classification != model.ClassTruePositive || f.Verdict.Confidence != 0.9 {
		t.Errorf("verdict fields wrong: %+v", f.Verdict)
	}
	if f.Verdict.Refuted {
		t.Error("should not be refuted")
	}
	if !f.Verdict.HighConfidence() {
		t.Error("unrefuted TP @0.9 should be high-confidence")
	}
	if f.Provenance == nil || f.Provenance.PromptVersion != PromptVersion {
		t.Errorf("provenance wrong: %+v", f.Provenance)
	}
}

func TestTriage_JudgeRefutes(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{
		`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"x"}`,
	}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":true,"reason":"input is a constant literal"}`}}

	router := llm.NewRouter(triageFake).Set("judge", judgeFake)
	f := newFinding()
	if err := NewEngine(router, nil, enrich.New(2), "").Triage(context.Background(), "run1", f); err != nil {
		t.Fatal(err)
	}
	if !f.Verdict.Refuted || f.Verdict.RefuteReason == "" {
		t.Errorf("judge refutation not applied: %+v", f.Verdict)
	}
	if f.Verdict.HighConfidence() {
		t.Error("a refuted verdict must not be high-confidence")
	}
}

func TestTriage_RoutesTriageAndJudgeSeparately(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{`{"classification":"uncertain","confidence":0.5}`}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false}`}}
	router := llm.NewRouter(triageFake).Set("judge", judgeFake)

	if err := NewEngine(router, nil, enrich.New(0), "").Triage(context.Background(), "r", newFinding()); err != nil {
		t.Fatal(err)
	}
	if len(triageFake.Calls) != 1 {
		t.Errorf("triage client should be called once, got %d", len(triageFake.Calls))
	}
	if len(judgeFake.Calls) != 1 {
		t.Errorf("judge client should be called once, got %d", len(judgeFake.Calls))
	}
	if judgeFake.Calls[0].Schema == nil {
		t.Error("judge request should ask for structured (schema) output")
	}
}

func TestCompleteStructured_FallsBackToJSONOnSchemaError(t *testing.T) {
	// First (schema) call errors → engine retries once with plain JSON mode.
	fake := &llmtest.Fake{
		FirstErr:  errSchemaUnsupported,
		Responses: []string{`{"classification":"true_positive","confidence":0.8,"exploitability":"reachable","reasoning":"x"}`},
	}
	judge := &llmtest.Fake{Responses: []string{`{"refuted":false}`}}
	eng := NewEngine(llm.NewRouter(fake).Set("judge", judge), nil, enrich.New(0), "")

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatalf("Triage should recover via fallback: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("expected 2 triage calls (schema then fallback), got %d", len(fake.Calls))
	}
	if fake.Calls[0].Schema == nil {
		t.Error("first call should have used a schema")
	}
	if fake.Calls[1].Schema != nil || !fake.Calls[1].JSON {
		t.Error("fallback call should drop the schema and use JSON mode")
	}
	if f.Verdict == nil || f.Verdict.Classification != model.ClassTruePositive {
		t.Errorf("verdict should parse from the fallback response: %+v", f.Verdict)
	}
}

func TestRemediate_OnlyHighConfidence(t *testing.T) {
	remFake := &llmtest.Fake{Responses: []string{`{"summary":"use parametrized query","diff":"--- a\n+++ b","confidence":0.9}`}}
	router := llm.NewRouter(&llmtest.Fake{}).Set("remediation", remFake)
	eng := NewEngine(router, nil, enrich.New(0), "")

	// Low-confidence / refuted finding → no remediation, no LLM call.
	weak := newFinding()
	weak.Verdict = &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.2}
	if err := eng.Remediate(context.Background(), "r", weak); err != nil {
		t.Fatal(err)
	}
	if weak.Remediation != nil || len(remFake.Calls) != 0 {
		t.Error("should not remediate a low-confidence finding")
	}

	// High-confidence TP → remediation attached.
	strong := newFinding()
	strong.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.95}
	if err := eng.Remediate(context.Background(), "r", strong); err != nil {
		t.Fatal(err)
	}
	if strong.Remediation == nil || strong.Remediation.Summary == "" {
		t.Errorf("high-confidence finding should get remediation: %+v", strong.Remediation)
	}
	if len(remFake.Calls) != 1 {
		t.Errorf("expected 1 remediation call, got %d", len(remFake.Calls))
	}
}

func TestTriage_CalibrationShortCircuitsLLM(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{`{"classification":"true_positive","confidence":0.9}`}}
	eng := NewEngine(llm.NewRouter(triageFake), nil, enrich.New(0), "")
	eng.SetCalibrator(stubCalibrator{resolve: true})

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if len(triageFake.Calls) != 0 {
		t.Errorf("calibration should skip the LLM entirely, but it was called %d times", len(triageFake.Calls))
	}
	if f.Verdict == nil || f.Verdict.Classification != model.ClassFalsePositive {
		t.Errorf("expected an auto-resolved FP verdict, got %+v", f.Verdict)
	}
	if f.Provenance == nil || f.Provenance.PromptVersion != "calibration" {
		t.Errorf("provenance should mark calibration, got %+v", f.Provenance)
	}
}

func TestTriage_InjectsRAGExamples(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{`{"classification":"uncertain","confidence":0.5}`}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false}`}}
	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), nil, enrich.New(0), "")
	eng.SetRetriever(stubRetriever{examples: []string{"PAST_EXAMPLE_MARKER ruled false_positive"}})

	if err := eng.Triage(context.Background(), "r", newFinding()); err != nil {
		t.Fatal(err)
	}
	// The retrieved example must reach the triage prompt.
	var found bool
	for _, m := range triageFake.Calls[0].Messages {
		if strings.Contains(m.Content, "PAST_EXAMPLE_MARKER") {
			found = true
		}
	}
	if !found {
		t.Error("RAG example was not injected into the triage prompt")
	}
}

type stubCalibrator struct{ resolve bool }

func (s stubCalibrator) AutoResolve(model.Finding) (model.Verdict, bool) {
	if !s.resolve {
		return model.Verdict{}, false
	}
	return model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9}, true
}

type stubRetriever struct{ examples []string }

func (s stubRetriever) Similar(context.Context, string, int) ([]string, error) {
	return s.examples, nil
}

var errSchemaUnsupported = &fakeErr{"json_schema not supported"}

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }

func TestTriage_RecordsProvenanceToVault(t *testing.T) {
	triageFake := &llmtest.Fake{Responses: []string{`{"classification":"true_positive","confidence":0.8}`}}
	judgeFake := &llmtest.Fake{Responses: []string{`{"refuted":false}`}}
	v := newVault(t)

	eng := NewEngine(llm.NewRouter(triageFake).Set("judge", judgeFake), v, enrich.New(0), "")
	if err := eng.Triage(context.Background(), "run1", newFinding()); err != nil {
		t.Fatal(err)
	}

	recs := v.ByRun("run1")
	var llmCalls, verdicts int
	for _, r := range recs {
		switch r.Kind {
		case vault.KindLLMCall:
			llmCalls++
		case vault.KindVerdict:
			verdicts++
		}
	}
	if llmCalls != 2 {
		t.Errorf("want 2 llm_call records (triage+judge), got %d", llmCalls)
	}
	if verdicts != 1 {
		t.Errorf("want 1 verdict record, got %d", verdicts)
	}
}

func TestParseVerdict_ToleratesProseWrappedJSON(t *testing.T) {
	v, err := parseVerdict("Sure!\n```json\n{\"classification\":\"false_positive\",\"confidence\":0.2}\n```\n")
	if err != nil {
		t.Fatalf("should extract JSON from prose: %v", err)
	}
	if v.Classification != model.ClassFalsePositive {
		t.Errorf("got %q", v.Classification)
	}
}

// Verification is the pipeline's record of the re-scan. A model that writes
// "verification": {"status": "verified"} into its own reply must not be believed.
func TestRemediate_ModelCannotMarkItsOwnPatchVerified(t *testing.T) {
	rem := &llmtest.Fake{Responses: []string{
		`{"summary":"fix","diff":"--- a/a.py\n+++ b/a.py\n","confidence":90,"verification":{"status":"verified","detail":"trust me"}}`,
	}}
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{}).Set("remediation", rem), nil, enrich.New(0), "")

	f := newFinding()
	f.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9}
	if err := eng.Remediate(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Remediation == nil {
		t.Fatal("no remediation")
	}
	if f.Remediation.Verification != nil {
		t.Errorf("model-supplied verification was kept: %+v", f.Remediation.Verification)
	}
	if f.Remediation.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9 (90 read as a percentage)", f.Remediation.Confidence)
	}
}
