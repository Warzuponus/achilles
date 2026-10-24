package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

const (
	jTP = `{"classification":"true_positive","confidence":0.95,"exploitability":"reachable","reasoning":"tainted"}`
	jFP = `{"classification":"false_positive","confidence":0.95,"exploitability":"not-reachable","reasoning":"constant"}`
	jUN = `{"classification":"uncertain","confidence":0.5,"exploitability":"unknown","reasoning":"unclear"}`

	jRefute = `{"refuted":true,"reason":"the value is assigned from the request two lines above"}`
	jAccept = `{"refuted":false,"reason":""}`
)

func judgeEngine(t *testing.T, triageResp, judgeResp string) (*Engine, *llmtest.Fake) {
	t.Helper()
	jf := &llmtest.Fake{Responses: []string{judgeResp}}
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{Responses: []string{triageResp}}).Set("judge", jf), nil, enrich.New(0), "")
	return eng, jf
}

// The behaviour this change exists for: a cheap triage model calls a real
// vulnerability a false positive, and the stronger judge — already running on
// every finding — can now recover it. Before, refuting a false_positive was
// discarded and the finding stayed suppressed.
func TestJudge_OverturnsAFalsePositiveAndSurfacesIt(t *testing.T) {
	eng, _ := judgeEngine(t, jFP, jRefute)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	v := f.Verdict
	if v == nil {
		t.Fatal("no verdict")
	}
	if !v.Overturned {
		t.Error("refuting a false_positive must set Overturned")
	}
	if v.Refuted {
		t.Error("Refuted is for knocking DOWN a true positive; it must stay false here")
	}
	if !v.Surfaced() {
		t.Error("an overturned finding must be surfaced — this is the missed-vulnerability path")
	}
	// The triage pass's own words are preserved: we do not rewrite history.
	if v.Classification != model.ClassFalsePositive || v.Confidence != 0.95 {
		t.Errorf("the original verdict must be preserved verbatim, got %+v", v)
	}
	if v.RefuteReason == "" {
		t.Error("the judge's reason is the only justification for surfacing; keep it")
	}
}

func TestJudge_OverturnedIsNotHighConfidence(t *testing.T) {
	// Two models disagreeing is not grounds for automation. Remediation gates on
	// HighConfidence, so an overturned finding must not trigger a patch.
	eng, _ := judgeEngine(t, jFP, jRefute)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Verdict.HighConfidence() {
		t.Error("an overturned verdict must not be high-confidence")
	}
	if !f.Verdict.Surfaced() {
		t.Error("...but it must still be surfaced")
	}
}

func TestJudge_DoesNotRemediateAnOverturnedFinding(t *testing.T) {
	remFake := &llmtest.Fake{Responses: []string{`{"summary":"fix","confidence":0.9}`}}
	jf := &llmtest.Fake{Responses: []string{jRefute}}
	eng := NewEngine(
		llm.NewRouter(&llmtest.Fake{Responses: []string{jFP}}).Set("judge", jf).Set("remediation", remFake),
		nil, enrich.New(0), "")

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if err := eng.Remediate(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if len(remFake.Calls) != 0 {
		t.Errorf("no patch should be written when the two passes disagree, got %d call(s)", len(remFake.Calls))
	}
	if f.Remediation != nil {
		t.Errorf("remediation attached to an overturned finding: %+v", f.Remediation)
	}
}

func TestJudge_UnrefutedFalsePositiveStaysSuppressed(t *testing.T) {
	eng, _ := judgeEngine(t, jFP, jAccept)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Verdict.Overturned {
		t.Error("the judge agreed with the verdict; nothing to overturn")
	}
	if f.Verdict.Surfaced() {
		t.Error("an agreed false positive must stay suppressed — this is the noise the product removes")
	}
}

func TestJudge_TruePositiveDirectionUnchanged(t *testing.T) {
	// The original guard must still work: refuting a true positive suppresses it.
	eng, _ := judgeEngine(t, jTP, jRefute)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if !f.Verdict.Refuted {
		t.Error("refuting a true_positive must still set Refuted")
	}
	if f.Verdict.Overturned {
		t.Error("Overturned is only for the false_positive direction")
	}
	if f.Verdict.Surfaced() || f.Verdict.HighConfidence() {
		t.Error("a refuted true positive must not be surfaced")
	}
}

func TestJudge_UnrefutedTruePositiveIsSurfacedAndActionable(t *testing.T) {
	eng, _ := judgeEngine(t, jTP, jAccept)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if !f.Verdict.HighConfidence() || !f.Verdict.Surfaced() {
		t.Errorf("an unrefuted TP at 0.95 should be both, got %+v", f.Verdict)
	}
}

func TestJudge_UncertainIsNeverOverturned(t *testing.T) {
	// "This verdict is wrong" does not say which way when the verdict was
	// uncertain, so we do not guess a direction from it.
	eng, _ := judgeEngine(t, jUN, jRefute)

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Verdict.Overturned {
		t.Error("refuting an uncertain verdict must not surface it")
	}
	if f.Verdict.Surfaced() {
		t.Error("uncertain stays unsurfaced")
	}
}

func TestJudge_PromptStatesTheBurdenForTheDirection(t *testing.T) {
	// A vague "assume it is wrong" is what left the false-positive direction weak.
	fpMsgs := judgeMessages(*newFinding(), "ctx", model.Verdict{Classification: model.ClassFalsePositive}, false)
	fpSys := fpMsgs[0].Content
	if !strings.Contains(fpSys, "NOT a real problem") || !strings.Contains(fpSys, "Refute it by showing that it IS") {
		t.Errorf("false-positive burden missing:\n%s", fpSys)
	}
	if !strings.Contains(fpSys, "Look past naming") {
		t.Errorf("the naming trap is the measured failure mode; the prompt should name it:\n%s", fpSys)
	}

	tpSys := judgeMessages(*newFinding(), "ctx", model.Verdict{Classification: model.ClassTruePositive}, false)[0].Content
	if !strings.Contains(tpSys, "IS a real, exploitable problem") {
		t.Errorf("true-positive burden missing:\n%s", tpSys)
	}
	if strings.Contains(tpSys, "Refute it by showing that it IS:") {
		t.Error("the two directions must not share the same burden text")
	}
}

func TestJudge_PromptVersionBumpedForTheSemanticChange(t *testing.T) {
	// Verdicts recorded before and after are not comparable; the version is what
	// lets the learning loop and the eval tell them apart.
	if PromptVersion == "triage/v1" {
		t.Error("the judge semantics changed, so PromptVersion must move off v1")
	}
}

func TestJudge_OverturnRecordedInProvenanceAndVault(t *testing.T) {
	v := newVault(t)
	jf := &llmtest.Fake{Responses: []string{jRefute}}
	eng := NewEngine(llm.NewRouter(&llmtest.Fake{Responses: []string{jFP}}).Set("judge", jf), v, enrich.New(0), "")

	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	var verdicts int
	for _, rec := range v.ByRun("r") {
		if rec.Kind == "verdict" {
			verdicts++
			if !strings.Contains(string(rec.Payload), `"overturned":true`) {
				t.Errorf("the vault record must carry the overturn: %s", rec.Payload)
			}
		}
	}
	if verdicts != 1 {
		t.Errorf("want 1 verdict record, got %d", verdicts)
	}
}

// --- triage/v5: a refutation has to be backed before it can dismiss ---

const (
	jTPModest = `{"classification":"true_positive","confidence":0.8,"exploitability":"reachable","reasoning":"tainted"}`

	// newFinding's context is the tool snippet "eval(user_input)".
	jRefuteBacked   = `{"refuted":true,"confidence":0.9,"evidence":"eval(user_input)","reason":"user_input is a module constant"}`
	jRefuteInvented = `{"refuted":true,"confidence":0.9,"evidence":"value = sanitize(request.args)","reason":"it is sanitized"}`
	jRefuteUnsure   = `{"refuted":true,"confidence":0.4,"evidence":"eval(user_input)","reason":"might be a constant"}`
)

func triageWith(t *testing.T, triageResp, judgeResp string) *model.Verdict {
	t.Helper()
	eng, _ := judgeEngine(t, triageResp, judgeResp)
	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	return f.Verdict
}

// The bug this guards: the judge prompt for an uncertain verdict invites a
// refutation in EITHER direction, so "refuted: this is clearly exploitable" used to
// take the finding out of the gate.
func TestJudge_RefutedUncertainIsNeverDismissed(t *testing.T) {
	for _, judge := range []string{jRefute, jRefuteBacked} {
		v := triageWith(t, jUN, judge)
		if v.Refuted {
			t.Errorf("an uncertain verdict has no direction to refute; Refuted must stay false (judge %s)", judge)
		}
		if v.Dismissed() {
			t.Errorf("a refuted uncertain verdict must never be dismissed (judge %s)", judge)
		}
		if !strings.Contains(v.RefuteReason, "no direction taken") {
			t.Errorf("the judge's note should be kept and labelled, got %q", v.RefuteReason)
		}
	}
}

func TestJudge_BareRefutationDisputesButDoesNotDismiss(t *testing.T) {
	// No confidence, no quote: the judge's word alone.
	v := triageWith(t, jTPModest, jRefute)
	if !v.Refuted {
		t.Fatal("the disagreement must still be recorded")
	}
	if v.RefuteSupported || v.Dismissed() {
		t.Errorf("an unbacked refutation must not dismiss: %+v", v)
	}
	if !v.Disputed() {
		t.Error("it should read as disputed")
	}
	if v.HighConfidence() {
		t.Error("a disputed finding must not be auto-remediated")
	}
}

func TestJudge_BackedRefutationDismissesAModestTruePositive(t *testing.T) {
	v := triageWith(t, jTPModest, jRefuteBacked)
	if !v.RefuteSupported || v.JudgeConfidence != 0.9 || v.RefuteEvidence == "" {
		t.Fatalf("support not recorded: %+v", v)
	}
	if !v.Dismissed() || v.Disputed() {
		t.Errorf("a confident refutation quoting real context should dismiss a 0.8 true positive: %+v", v)
	}
}

func TestJudge_RefutationQuotingTextThatIsNotThereDoesNotDismiss(t *testing.T) {
	v := triageWith(t, jTPModest, jRefuteInvented)
	if v.RefuteSupported || v.Dismissed() {
		t.Errorf("an invented quote must not count as evidence: %+v", v)
	}
}

func TestJudge_UnsureRefutationDoesNotDismiss(t *testing.T) {
	v := triageWith(t, jTPModest, jRefuteUnsure)
	if v.RefuteSupported || v.Dismissed() {
		t.Errorf("a judge below the dismissal floor must not dismiss: %+v", v)
	}
}

func TestJudge_SureTruePositiveIsNotDismissedEvenByABackedRefutation(t *testing.T) {
	v := triageWith(t, jTP, jRefuteBacked) // triage confidence 0.95
	if !v.RefuteSupported {
		t.Fatalf("the refutation itself is supported: %+v", v)
	}
	if v.Dismissed() {
		t.Error("a triage pass that was sure is escalated to a human, not overruled")
	}
	if !v.Disputed() {
		t.Error("it should read as disputed")
	}
}

func TestEvidenceInContext(t *testing.T) {
	ctx := "// the finding:\n" +
		"     10 | func run(w http.ResponseWriter, r *http.Request) {\n" +
		">>   11 | \tcmd := exec.Command(\"sh\", \"-c\", r.URL.Query().Get(\"q\"))\n" +
		"     12 | }\n"
	yes := []string{
		`cmd := exec.Command("sh", "-c", r.URL.Query().Get("q"))`,                // the code alone
		`>>   11 | cmd := exec.Command("sh", "-c", r.URL.Query().Get("q"))`,      // gutter copied
		"cmd  :=  exec.Command(\"sh\",   \"-c\", r.URL.Query().Get(\"q\"))",      // spacing differs
		"`r.URL.Query().Get(\"q\")`",                                             // a fragment, in backticks
		"something invented\nfunc run(w http.ResponseWriter, r *http.Request) {", // one real line is enough
	}
	no := []string{
		"",
		"}",        // too short to mean anything
		"12 | }",   // a real line, but nothing in it
		"--------", // long enough, says nothing
		`cmd := exec.Command("ls")`,
		"the value is a constant",
	}
	for _, e := range yes {
		if !evidenceInContext(e, ctx) {
			t.Errorf("should match: %q", e)
		}
	}
	for _, e := range no {
		if evidenceInContext(e, ctx) {
			t.Errorf("should NOT match: %q", e)
		}
	}
	if evidenceInContext("eval(user_input)", "(source code withheld by --llm-no-code)") {
		t.Error("with no code shown, nothing can be quoted from it")
	}
}

func TestParseJudge_LooseRepliesFailSafe(t *testing.T) {
	if j := parseJudge(`not json`); j.Refuted {
		t.Error("an unparseable reply does not refute")
	}
	// A wrong-typed support field must not leave a half-filled refutation.
	j := parseJudge(`{"refuted":true,"confidence":"very","evidence":"x","reason":"r"}`)
	if !j.Refuted || j.Reason != "r" || j.Confidence != 0 || j.Evidence != "" {
		t.Errorf("loose reply = %+v", j)
	}
	if j := parseJudge(`{"refuted":true,"confidence":85}`); j.Confidence != 0.85 {
		t.Errorf("percent confidence = %v, want 0.85", j.Confidence)
	}
}

func TestParseVerdict_ConfidenceIsNormalized(t *testing.T) {
	for in, want := range map[string]float64{"85": 0.85, "0.85": 0.85, "-1": 0, "1000": 0, "1": 1} {
		v, err := parseVerdict(`{"classification":"false_positive","confidence":` + in + `}`)
		if err != nil {
			t.Fatal(err)
		}
		if v.Confidence != want {
			t.Errorf("confidence %s -> %v, want %v", in, v.Confidence, want)
		}
	}
	v, _ := parseVerdict(`{"classification":"true_positive","confidence":0.8,"refuted":true,"refuteSupported":true,"judgeConfidence":1,"refuteEvidence":"x"}`)
	if v.Refuted || v.RefuteSupported || v.JudgeConfidence != 0 || v.RefuteEvidence != "" {
		t.Errorf("a model must not be able to set the judge's fields: %+v", v)
	}
}
