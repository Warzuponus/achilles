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

func verdictJSON(class string, conf string) string {
	return `{"classification":"` + class + `","confidence":` + conf + `,"exploitability":"unknown","reasoning":"` + class + `"}`
}

func samplingEngine(k int, triageResps []string, judgeResp string) (*Engine, *llmtest.Fake, *llmtest.Fake) {
	tf := &llmtest.Fake{Responses: triageResps}
	jf := &llmtest.Fake{Responses: []string{judgeResp}}
	eng := NewEngine(llm.NewRouter(tf).Set("judge", jf), nil, enrich.New(0), "").SetSamples(k)
	return eng, tf, jf
}

func triageOne(t *testing.T, eng *Engine) *model.Finding {
	t.Helper()
	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSamples_DefaultIsOneCallAndNoStability(t *testing.T) {
	eng, tf, _ := samplingEngine(1, []string{verdictJSON("uncertain", "0.4")}, jAccept)
	f := triageOne(t, eng)
	if len(tf.Calls) != 1 || f.Verdict.Stability != nil {
		t.Errorf("k=1 must be today's behavior: %d call(s), stability %+v", len(tf.Calls), f.Verdict.Stability)
	}
	if NewEngine(llm.NewRouter(tf), nil, enrich.New(0), "").Samples() != 1 {
		t.Error("an engine that never called SetSamples samples once")
	}
	if eng.SetSamples(0).Samples() != 1 || eng.SetSamples(-4).Samples() != 1 {
		t.Error("k < 1 must clamp to 1")
	}
}

func TestSamples_ConfidentVerdictIsNotResampled(t *testing.T) {
	eng, tf, _ := samplingEngine(3, []string{verdictJSON("true_positive", "0.95")}, jAccept)
	f := triageOne(t, eng)
	if len(tf.Calls) != 1 || f.Verdict.Stability != nil {
		t.Errorf("a confident, unrefuted verdict must cost nothing extra: %d call(s)", len(tf.Calls))
	}
}

func TestSamples_BorderlineTriggers(t *testing.T) {
	cases := []struct {
		name, tri, judge string
	}{
		{"uncertain", verdictJSON("uncertain", "0.95"), jAccept},
		{"low confidence", verdictJSON("true_positive", "0.84"), jAccept},
		{"judge refuted", verdictJSON("true_positive", "0.95"), jRefute},
		{"judge overturned", verdictJSON("false_positive", "0.95"), jRefute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng, tf, _ := samplingEngine(3, []string{c.tri}, c.judge)
			f := triageOne(t, eng)
			if len(tf.Calls) != 3 {
				t.Fatalf("triage calls = %d, want 3 (1 + 2 samples)", len(tf.Calls))
			}
			if f.Verdict.Stability == nil || f.Verdict.Stability.Samples != 3 {
				t.Errorf("stability = %+v", f.Verdict.Stability)
			}
		})
	}
}

func TestSamples_ExtraSamplesUseTemperatureFirstStaysDeterministic(t *testing.T) {
	eng, tf, _ := samplingEngine(3, []string{verdictJSON("uncertain", "0.5")}, jAccept)
	triageOne(t, eng)
	if tf.Calls[0].Temperature != 0 {
		t.Errorf("first sample temperature = %v, want 0", tf.Calls[0].Temperature)
	}
	for _, c := range tf.Calls[1:] {
		if c.Temperature <= 0 || c.Temperature > 0.5 {
			t.Errorf("extra sample temperature = %v, want slightly above 0", c.Temperature)
		}
	}
}

func TestSamples_MajorityWinsAndConfidenceIsMeanOfAgreeing(t *testing.T) {
	eng, _, _ := samplingEngine(3, []string{
		verdictJSON("true_positive", "0.6"), // borderline: low confidence
		verdictJSON("true_positive", "0.8"),
		verdictJSON("false_positive", "0.9"),
	}, jAccept)
	v := triageOne(t, eng).Verdict
	if v.Classification != model.ClassTruePositive {
		t.Fatalf("classification = %s, want true_positive", v.Classification)
	}
	if v.Confidence != 0.7 {
		t.Errorf("confidence = %v, want mean of the agreeing samples 0.7", v.Confidence)
	}
	s := v.Stability
	if s == nil || s.Samples != 3 || s.Agreeing != 2 || s.Classifications[model.ClassFalsePositive] != 1 || s.Unanimous() {
		t.Errorf("stability = %+v", s)
	}
}

func TestSamples_TieIsUncertainNeverFalsePositive(t *testing.T) {
	eng, _, _ := samplingEngine(2, []string{
		verdictJSON("false_positive", "0.8"),
		verdictJSON("true_positive", "0.8"),
	}, jAccept)
	v := triageOne(t, eng).Verdict
	if v.Classification != model.ClassUncertain {
		t.Fatalf("a 1-1 split must be uncertain, got %s", v.Classification)
	}
	if v.Dismissed() || v.Surfaced() {
		t.Error("a tie is neither dismissed nor surfaced as a confirmed finding")
	}
	if v.Stability == nil || v.Stability.Agreeing != 0 {
		t.Errorf("stability = %+v", v.Stability)
	}
}

func TestSamples_NonUnanimousFalsePositiveIsNeverDismissed(t *testing.T) {
	// The first answer is a shaky FP; the samples mostly agree but one dissents.
	eng, _, _ := samplingEngine(3, []string{
		verdictJSON("false_positive", "0.8"),
		verdictJSON("false_positive", "0.9"),
		verdictJSON("true_positive", "0.9"),
	}, jAccept)
	v := triageOne(t, eng).Verdict
	if v.Classification != model.ClassFalsePositive || v.Confidence < model.DismissFloor {
		t.Fatalf("setup: want a confident FP majority, got %s %.2f", v.Classification, v.Confidence)
	}
	if v.Dismissed() {
		t.Error("a 2-1 false_positive must not be dismissed")
	}
}

func TestSamples_UnanimousFalsePositiveCanStillBeDismissed(t *testing.T) {
	eng, _, _ := samplingEngine(3, []string{verdictJSON("false_positive", "0.8")}, jAccept)
	v := triageOne(t, eng).Verdict
	if v.Stability == nil || !v.Stability.Unanimous() || v.Stability.Agreeing != 3 {
		t.Fatalf("stability = %+v", v.Stability)
	}
	if !v.Dismissed() {
		t.Error("three agreeing samples keep today's dismissal")
	}
}

func TestSamples_JudgeFlagsFollowTheFirstAnswerOnly(t *testing.T) {
	// First answer TP, refuted by the judge. Samples say FP. The result is FP, but
	// the refutation was about a TP verdict: it must not carry over, and the split
	// must keep the finding visible.
	eng, _, _ := samplingEngine(3, []string{
		verdictJSON("true_positive", "0.9"),
		verdictJSON("false_positive", "0.95"),
		verdictJSON("false_positive", "0.95"),
	}, jRefute)
	v := triageOne(t, eng).Verdict
	if v.Classification != model.ClassFalsePositive {
		t.Fatalf("classification = %s", v.Classification)
	}
	if v.Refuted || v.Overturned {
		t.Errorf("judge flags describe the first answer only: %+v", v)
	}
	if !strings.Contains(v.RefuteReason, "first sample") {
		t.Errorf("the judge's reason should be kept, labelled: %q", v.RefuteReason)
	}
	if v.Dismissed() {
		t.Error("a split result must not be dismissed")
	}

	// When the result still matches the first answer, the flags stay.
	eng, _, _ = samplingEngine(3, []string{verdictJSON("true_positive", "0.9")}, jRefute)
	v = triageOne(t, eng).Verdict
	if !v.Refuted {
		t.Error("unanimous TP: the judge's refutation of it must stay")
	}
}

func TestSamples_FailedExtraSamplesDoNotFailTheFinding(t *testing.T) {
	// Samples 2 and 3 error out at the transport.
	tri := &errAfterFirst{inner: &llmtest.Fake{Responses: []string{verdictJSON("uncertain", "0.5")}}}
	eng := NewEngine(llm.NewRouter(tri).Set("judge", &llmtest.Fake{Responses: []string{jAccept}}), nil, enrich.New(0), "").SetSamples(3)
	f := triageOne(t, eng)
	if f.Verdict == nil || f.Verdict.Classification != model.ClassUncertain {
		t.Fatalf("the first answer must survive: %+v", f.Verdict)
	}
	if f.Verdict.Stability != nil {
		t.Errorf("no extra sample came back, so there is nothing to report: %+v", f.Verdict.Stability)
	}
}

type errAfterFirst struct {
	inner *llmtest.Fake
	n     int
}

func (e *errAfterFirst) Complete(ctx context.Context, r llm.Request) (llm.Response, error) {
	e.n++
	if e.n > 1 {
		return llm.Response{}, context.DeadlineExceeded
	}
	return e.inner.Complete(ctx, r)
}

func TestSamples_RecordedInVault(t *testing.T) {
	v := newVault(t)
	tf := &llmtest.Fake{Responses: []string{verdictJSON("uncertain", "0.5")}}
	eng := NewEngine(llm.NewRouter(tf).Set("judge", &llmtest.Fake{Responses: []string{jAccept}}), v, enrich.New(0), "").SetSamples(2)
	triageOne(t, eng)
	found := false
	for _, r := range v.ByRun("r") {
		if r.Source == "triage-sample" {
			found = true
		}
	}
	if !found {
		t.Error("extra samples must be recorded to the evidence vault")
	}
}

func TestPlan_CountsExtraSamplesAsAnUpperBound(t *testing.T) {
	eng, _ := planEngine()
	base := len(eng.Plan([]model.Finding{*newFinding(), *newFinding()}, PlanOpts{}))
	eng.SetSamples(3)
	calls := eng.Plan([]model.Finding{*newFinding(), *newFinding()}, PlanOpts{})
	if len(calls)-base != 4 { // 2 findings x (3-1) extra triage calls
		t.Errorf("extra planned calls = %d, want 4", len(calls)-base)
	}
	n := 0
	for _, c := range calls {
		if c.Task == "triage" {
			n++
		}
	}
	if n != 6 {
		t.Errorf("triage calls planned = %d, want 6", n)
	}
}
