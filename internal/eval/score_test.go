package eval

import (
	"context"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/triage"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

// ---------- context mode ----------

func TestScoreContext_CountsEvidenceVisibility(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	rep := ScoreContext(c, enrich.New(3))

	if rep.Cases != 2 {
		t.Fatalf("want 2 cases, got %d", rep.Cases)
	}
	// Both fixtures are 5 lines with evidence on 3 and 4 — a 3-line radius sees
	// everything, so coverage must be total.
	if rep.CasesComplete != 2 || rep.CoverageRate() != 1 {
		t.Errorf("expected full coverage, got %d complete, rate %.2f", rep.CasesComplete, rep.CoverageRate())
	}
	if rep.TotalTokens <= 0 {
		t.Error("prompt tokens should be counted")
	}
	for _, res := range rep.Results {
		if res.ContextLines <= 0 {
			t.Errorf("%s: context lines not counted", res.CaseID)
		}
	}
}

func TestScoreContext_DetectsMissingEvidence(t *testing.T) {
	// Evidence on line 1 (the package clause) is out of reach of a 0-line radius
	// around line 4, and out of reach of the enclosing function too.
	extra := `
  - id: far-evidence
    fixture: testdata/a.go
    label: fp
    why: the deciding line is at file scope
    finding: {tool: gosec, ruleId: G204, cwe: ["CWE-78"], severity: high, message: subprocess, line: 4}
    evidenceLines: [1, 4]
`
	c, err := LoadCorpus(tinyCorpus(t, extra))
	if err != nil {
		t.Fatal(err)
	}
	e := enrich.New(0)
	rep := ScoreContext(c, e)

	var far ContextResult
	for _, res := range rep.Results {
		if res.CaseID == "far-evidence" {
			far = res
		}
	}
	if far.Complete() {
		t.Error("line 1 cannot be visible from a 0-radius window on line 4")
	}
	if len(far.MissingLines) != 1 || far.MissingLines[0] != 1 {
		t.Errorf("MissingLines = %v, want [1]", far.MissingLines)
	}
	if rep.CasesComplete != 2 {
		t.Errorf("the other two cases should still be complete, got %d", rep.CasesComplete)
	}
}

func TestScoreContext_IsDeterministic(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	first := ScoreContext(c, enrich.New(2))
	for i := 0; i < 5; i++ {
		got := ScoreContext(c, enrich.New(2))
		if got.CoverageRate() != first.CoverageRate() || got.TotalTokens != first.TotalTokens {
			t.Fatal("context scoring must be deterministic — it is the hermetic mode")
		}
		for j := range got.Results {
			if got.Results[j].CaseID != first.Results[j].CaseID {
				t.Fatal("result order must be stable")
			}
		}
	}
}

func TestVisibleLines_ParsesRenderedContext(t *testing.T) {
	rendered := "   11 | a\n>>  12 | b\n   13 | c"
	got := visibleLines(rendered)
	for _, want := range []int{11, 12, 13} {
		if !got[want] {
			t.Errorf("line %d should be visible in %q", want, rendered)
		}
	}
	if got[10] || got[14] {
		t.Errorf("parsed lines outside the window: %v", got)
	}
}

func TestVisibleLines_IgnoresTruncationNotice(t *testing.T) {
	rendered := "// enclosing scope truncated to 30 lines\n   11 | a\n>>  12 | b"
	got := visibleLines(rendered)
	if len(got) != 2 {
		t.Errorf("want 2 source lines, got %v", got)
	}
}

func TestCompareContext_ReportsRegression(t *testing.T) {
	base := ContextReport{Cases: 2, CasesComplete: 2, EvidenceTotal: 4, EvidenceVisible: 4, TotalTokens: 100,
		Results: []ContextResult{
			{CaseID: "a", EvidenceTotal: 2, EvidenceVisible: 2},
			{CaseID: "b", EvidenceTotal: 2, EvidenceVisible: 2},
		}}
	cur := ContextReport{Cases: 2, CasesComplete: 1, EvidenceTotal: 4, EvidenceVisible: 3, TotalTokens: 80,
		Results: []ContextResult{
			{CaseID: "a", EvidenceTotal: 2, EvidenceVisible: 2},
			{CaseID: "b", EvidenceTotal: 2, EvidenceVisible: 1},
		}}

	var b strings.Builder
	CompareContext(base, cur, &b)
	out := b.String()
	if !strings.Contains(out, "REGRESSED") || !strings.Contains(out, "b") {
		t.Errorf("a lost case must be called out as a regression:\n%s", out)
	}
}

// ---------- verdict mode ----------

// engineWith builds a triage engine whose triage and judge passes return fixed
// responses, so scoring can be tested without a model.
func engineWith(t *testing.T, root string, triageResp, judgeResp []string) *triage.Engine {
	t.Helper()
	tf := &llmtest.Fake{Responses: triageResp}
	jf := &llmtest.Fake{Responses: judgeResp}
	return triage.NewEngine(llm.NewRouter(tf).Set("judge", jf), nil, enrich.New(2), root)
}

const (
	respRealTP   = `{"classification":"true_positive","confidence":0.95,"exploitability":"reachable","reasoning":"r"}`
	respRealFP   = `{"classification":"false_positive","confidence":0.9,"exploitability":"not-reachable","reasoning":"r"}`
	respLowConf  = `{"classification":"true_positive","confidence":0.4,"exploitability":"unknown","reasoning":"r"}`
	judgeAccepts = `{"refuted":false,"reason":""}`
	judgeRefutes = `{"refuted":true,"reason":"constant input"}`
)

func TestRunner_PerfectTriageScoresFull(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	// Cases run id-sorted: case-fp then case-tp. Answer each correctly.
	eng := engineWith(t, c.Root,
		[]string{respRealFP, respRealTP},
		[]string{judgeAccepts, judgeAccepts})

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")

	if rep.Correct != 2 || rep.Accuracy != 1 {
		t.Errorf("want 2/2 correct, got %d (accuracy %.2f)", rep.Correct, rep.Accuracy)
	}
	if rep.TPRecall != 1 || rep.FPSuppression != 1 || rep.BalancedAccuracy != 1 {
		t.Errorf("want all metrics at 1.0, got recall %.2f suppression %.2f balanced %.2f",
			rep.TPRecall, rep.FPSuppression, rep.BalancedAccuracy)
	}
	if rep.Errors != 0 {
		t.Errorf("no errors expected, got %d", rep.Errors)
	}
}

func TestRunner_AlwaysTruePositiveScoresHalf(t *testing.T) {
	// The failure mode the corpus exists to catch: a triager that confirms
	// everything has perfect recall and suppresses nothing.
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respRealTP}, []string{judgeAccepts})

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")

	if rep.TPRecall != 1 {
		t.Errorf("TP recall should be perfect, got %.2f", rep.TPRecall)
	}
	if rep.FPSuppression != 0 {
		t.Errorf("FP suppression should be zero, got %.2f", rep.FPSuppression)
	}
	if rep.BalancedAccuracy != 0.5 {
		t.Errorf("balanced accuracy should be 0.5, got %.2f", rep.BalancedAccuracy)
	}
}

func TestRunner_JudgeRefusalCountsAsSuppression(t *testing.T) {
	// A refuted true_positive is not surfaced, so it must score as an FP call —
	// this is what makes the metric measure the shipped chain, not just the
	// first prompt.
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respRealTP}, []string{judgeRefutes})

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")

	if rep.FPSuppression != 1 {
		t.Errorf("the refuted verdict should suppress the FP case, got %.2f", rep.FPSuppression)
	}
	if rep.TPRecall != 0 {
		t.Errorf("it should also lose the TP case, got recall %.2f", rep.TPRecall)
	}
}

func TestRunner_LowConfidenceIsNotSurfaced(t *testing.T) {
	// Below the 0.7 floor nothing reaches a human, so it scores as FP.
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respLowConf}, []string{judgeAccepts})

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	if rep.FPSuppression != 1 || rep.TPRecall != 0 {
		t.Errorf("a 0.4-confidence TP should not surface: recall %.2f suppression %.2f",
			rep.TPRecall, rep.FPSuppression)
	}
}

func TestRunner_ErrorsCountAsWrongNeverCorrect(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	tf := &llmtest.Fake{Err: errFake{}}
	eng := triage.NewEngine(llm.NewRouter(tf), nil, enrich.New(2), c.Root)

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")

	if rep.Errors != 2 {
		t.Errorf("want 2 errors, got %d", rep.Errors)
	}
	if rep.Correct != 0 || rep.Accuracy != 0 {
		t.Errorf("a failed call must never score as correct: %d correct", rep.Correct)
	}
}

type errFake struct{}

func (errFake) Error() string { return "boom" }

func TestRunner_DetectsUnstableCases(t *testing.T) {
	// The fake returns TP then FP, so two repeats of the same case disagree.
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root,
		[]string{respRealTP, respRealFP, respRealTP, respRealFP},
		[]string{judgeAccepts})

	rep := Runner{Engine: eng, Repeat: 2}.Run(context.Background(), c, "r1")

	if rep.Unstable == 0 {
		t.Error("disagreeing repeats must be reported as unstable, not averaged away")
	}
	if rep.Repeat != 2 {
		t.Errorf("Repeat = %d, want 2", rep.Repeat)
	}
	for _, res := range rep.Results {
		if len(res.Runs) != 2 {
			t.Errorf("%s: want 2 runs recorded, got %d", res.CaseID, len(res.Runs))
		}
	}
}

func TestRunner_CalibrationGap(t *testing.T) {
	// Confident and wrong: mean confidence 0.95 against 0.5 accuracy is a 0.45
	// gap — exactly the "overconfident model" signal the prior bake-off saw.
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respRealTP}, []string{judgeAccepts})

	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	if rep.CalibrationGap < 0.44 || rep.CalibrationGap > 0.46 {
		t.Errorf("calibration gap = %.2f, want ~0.45", rep.CalibrationGap)
	}
	if rep.MeanConfidenceWrong <= 0 {
		t.Error("confidence on wrong answers should be recorded")
	}
}

func TestRunner_ProgressCalledPerCase(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respRealTP}, []string{judgeAccepts})
	var seen []string
	Runner{Engine: eng, Repeat: 1, Progress: func(id string, done, total int) {
		seen = append(seen, id)
		if total != 2 {
			t.Errorf("total = %d, want 2", total)
		}
	}}.Run(context.Background(), c, "r1")

	if len(seen) != 2 {
		t.Errorf("progress should fire once per case, got %v", seen)
	}
}

func TestVerdictReport_WriteShowsGroundTruthForWrongAnswers(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	eng := engineWith(t, c.Root, []string{respRealTP}, []string{judgeAccepts})
	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	rep.Model = "fake"

	var b strings.Builder
	rep.Write(&b, true)
	out := b.String()
	for _, want := range []string{"balanced accuracy", "wrong answers", "case-fp", "ground truth", "the argument is a constant"} {
		if !strings.Contains(out, want) {
			t.Errorf("report should contain %q:\n%s", want, out)
		}
	}
}

func TestCompareVerdict_ReportsRegressionAndNoiseCaveat(t *testing.T) {
	base := VerdictReport{Repeat: 1, Cases: 2, TPCases: 1, FPCases: 1, TPRecall: 1, FPSuppression: 1,
		BalancedAccuracy: 1, Results: []VerdictResult{{CaseID: "a", Correct: true}, {CaseID: "b", Correct: true}}}
	cur := VerdictReport{Repeat: 1, Cases: 2, TPCases: 1, FPCases: 1, TPRecall: 1, FPSuppression: 0,
		BalancedAccuracy: 0.5, Results: []VerdictResult{{CaseID: "a", Correct: true}, {CaseID: "b", Correct: false}}}

	var b strings.Builder
	CompareVerdict(base, cur, &b)
	out := b.String()
	if !strings.Contains(out, "REGRESSED") {
		t.Errorf("a lost case must be flagged:\n%s", out)
	}
	if !strings.Contains(out, "model noise") {
		t.Errorf("with repeat=1 the noise caveat must be printed:\n%s", out)
	}
}

func TestMeanAndAbs(t *testing.T) {
	if mean(nil) != 0 {
		t.Error("mean of nothing is 0, not NaN")
	}
	if got := mean([]float64{0.5, 1.0}); got != 0.75 {
		t.Errorf("mean = %v, want 0.75", got)
	}
	if abs(-0.5) != 0.5 || abs(0.5) != 0.5 {
		t.Error("abs is wrong")
	}
}

func TestFlip(t *testing.T) {
	if flip(LabelTP) != LabelFP || flip(LabelFP) != LabelTP {
		t.Error("flip should invert the label")
	}
}

func TestVerdictReport_UnreliableWhenMostRunsFail(t *testing.T) {
	// A kimi-k3 screen once returned 54/54 HTTP 402s and printed "balanced accuracy
	// 0.0%". Arithmetically right, completely misleading: the model was never
	// consulted. The report must refuse to let that read as a capability result.
	r := VerdictReport{Cases: 18, Repeat: 3, Errors: 54}
	if !r.Unreliable() {
		t.Fatalf("54/54 failed runs must be flagged unreliable (rate %.2f)", r.ErrorRate())
	}
	var b strings.Builder
	r.Write(&b, false)
	out := b.String()
	for _, want := range []string{"NOT A MODEL RESULT", "FAILED", "plumbing"} {
		if !strings.Contains(out, want) {
			t.Errorf("report should warn loudly, missing %q:\n%s", want, out)
		}
	}
}

func TestVerdictReport_CleanRunIsNotFlagged(t *testing.T) {
	r := VerdictReport{Cases: 18, Repeat: 3, Errors: 0, BalancedAccuracy: 1}
	if r.Unreliable() {
		t.Error("a run with no errors must not be flagged")
	}
	var b strings.Builder
	r.Write(&b, false)
	if strings.Contains(b.String(), "NOT A MODEL RESULT") {
		t.Error("clean runs must not carry the warning")
	}
}

func TestVerdictReport_ErrorRate(t *testing.T) {
	if got := (VerdictReport{Cases: 10, Repeat: 2, Errors: 4}).ErrorRate(); got != 0.2 {
		t.Errorf("ErrorRate = %v, want 0.2", got)
	}
	if got := (VerdictReport{}).ErrorRate(); got != 0 {
		t.Errorf("an empty report must not divide by zero, got %v", got)
	}
	// A handful of transient failures should not invalidate a run.
	if (VerdictReport{Cases: 18, Repeat: 3, Errors: 2}).Unreliable() {
		t.Error("2 of 54 failures is tolerable, not unreliable")
	}
}

func TestContainedPath(t *testing.T) {
	// Every write in this package targets a path influenced by the corpus manifest
	// or by a model-authored diff header. gosec's taint rule flagged those writes;
	// this is the guard that makes the containment checkable rather than implied.
	base := t.TempDir()
	for _, c := range []struct {
		rel  string
		want bool
		note string
	}{
		{"testdata/a.go", true, "ordinary relative path"},
		{"a.go", true, "bare basename"},
		{"../../etc/passwd", true, "traversal is collapsed, not honoured — stays inside base"},
		{"/etc/passwd", true, "an absolute rel is treated as relative to base"},
		{"", false, "empty is refused"},
	} {
		got, ok := containedPath(base, c.rel)
		if ok != c.want {
			t.Errorf("containedPath(%q) ok=%v, want %v (%s)", c.rel, ok, c.want, c.note)
			continue
		}
		if ok && !strings.HasPrefix(got, base) {
			t.Errorf("containedPath(%q) = %q, which escapes %q", c.rel, got, base)
		}
	}
}

func TestContainedPath_NeverEscapesEvenForHostilePaths(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{
		"../../../../../../../../etc/shadow",
		"foo/../../../../bar",
		"./../..",
		"/../../root/.ssh/id_rsa",
	} {
		got, ok := containedPath(base, rel)
		if ok && !strings.HasPrefix(got, base) {
			t.Errorf("%q resolved to %q, outside %q", rel, got, base)
		}
	}
}

// The headline scores ask "did the review confirm it". The product asks a
// three-way question: confirmed, kept for a human, or removed from the gate. A
// review that answers "uncertain" to everything confirms nothing, so it scored
// 100% FP suppression while every false positive stayed in the user's report, and
// it scored a miss on a real finding that was never removed.
func TestRunner_GateMatrixSeparatesKeptFromDismissed(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	const uncertain = `{"classification":"uncertain","confidence":0.5,"exploitability":"unknown","reasoning":"r"}`
	// Cases run id-sorted: case-fp then case-tp.
	eng := engineWith(t, c.Root, []string{uncertain, uncertain}, []string{judgeAccepts, judgeAccepts})
	rep := Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")

	if rep.FPSuppression != 1 || rep.TPRecall != 0 {
		t.Fatalf("precondition: the confirmation scores read 100%% suppression and 0%% recall, got %.2f / %.2f", rep.FPSuppression, rep.TPRecall)
	}
	want := GateMatrix{TPKept: 1, FPKept: 1}
	if rep.Gate != want {
		t.Errorf("gate = %+v, want %+v: nothing was confirmed and nothing was removed", rep.Gate, want)
	}
	if rep.Gate.NoiseRemoved() != 0 || rep.Gate.MissRate() != 0 {
		t.Errorf("noise removed %.2f, missed %.2f: both must be 0", rep.Gate.NoiseRemoved(), rep.Gate.MissRate())
	}

	// A confident, correct review: the false positive is dismissed, the true one confirmed.
	eng = engineWith(t, c.Root, []string{respRealFP, respRealTP}, []string{judgeAccepts, judgeAccepts})
	rep = Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	if want := (GateMatrix{TPConfirmed: 1, FPDismissed: 1}); rep.Gate != want {
		t.Errorf("gate = %+v, want %+v", rep.Gate, want)
	}

	// The costly error: a confident "false positive" on the genuine issue.
	eng = engineWith(t, c.Root, []string{respRealFP, respRealFP}, []string{judgeAccepts, judgeAccepts})
	rep = Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	if rep.Gate.TPDismissed != 1 || rep.Gate.MissRate() != 1 {
		t.Errorf("gate = %+v: the genuine issue was dismissed and must be counted as that", rep.Gate)
	}

	var b strings.Builder
	rep.Write(&b, false)
	for _, s := range []string{"What the product did", "genuine issues dismissed:    100.0%", "kept, unverified"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("report lacks %q:\n%s", s, b.String())
		}
	}

	// An errored review leaves the finding in place: kept, never dismissed.
	eng = triage.NewEngine(llm.NewRouter(&llmtest.Fake{Err: errFake{}}), nil, enrich.New(2), c.Root)
	rep = Runner{Engine: eng, Repeat: 1}.Run(context.Background(), c, "r1")
	if want := (GateMatrix{TPKept: 1, FPKept: 1}); rep.Gate != want {
		t.Errorf("errors: gate = %+v, want %+v", rep.Gate, want)
	}
}
