package deep

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func vd(class model.Classification, conf float64) *model.Verdict {
	return &model.Verdict{Classification: class, Confidence: conf, Exploitability: model.ExploitUnknown, Reasoning: "earlier reasoning"}
}

func finding(sev model.Severity, v *model.Verdict) model.Finding {
	return model.Finding{Tool: "opengrep", RuleID: "sqli", Severity: sev, Fingerprint: "fp", Verdict: v}
}

func deepRes(class model.Classification, conf float64, steps int, evidence ...string) model.DeepVerification {
	return model.DeepVerification{Steps: steps, Conclusion: class, Confidence: conf, Reasoning: "because", Evidence: evidence}
}

func TestApply_AlwaysRecordsAndNeverTouchesSeverity(t *testing.T) {
	f := finding(model.SeverityCritical, vd(model.ClassFalsePositive, 0.95))
	d := deepRes(model.ClassTruePositive, 0.9, 3, "a.go:1")
	Apply(&f, d)
	if f.Deep == nil || f.Deep.Conclusion != model.ClassTruePositive || f.Deep.Steps != 3 {
		t.Fatalf("deep outcome not recorded: %+v", f.Deep)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity changed to %s", f.Severity)
	}
	// f.Deep is a copy: mutating the caller's evidence must not change the record.
	d.Evidence[0] = "tampered"
	if f.Deep.Evidence[0] != "a.go:1" {
		t.Error("Apply aliased the caller's evidence slice")
	}
}

func TestApply_Confirm(t *testing.T) {
	t.Run("no prior verdict", func(t *testing.T) {
		f := finding(model.SeverityHigh, nil)
		Apply(&f, deepRes(model.ClassTruePositive, 0.8, 2))
		if f.Verdict == nil || f.Verdict.Classification != model.ClassTruePositive || f.Verdict.Confidence != 0.8 {
			t.Fatalf("verdict = %+v", f.Verdict)
		}
		if f.Verdict.Exploitability != model.ExploitUnknown || !strings.Contains(f.Verdict.Reasoning, "Deep verification") {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
	t.Run("lifts a confident dismissal", func(t *testing.T) {
		prior := vd(model.ClassFalsePositive, 0.95)
		prior.Exploitability = model.ExploitNotReachable
		f := finding(model.SeverityHigh, prior)
		Apply(&f, deepRes(model.ClassTruePositive, 0.75, 4))
		v := f.Verdict
		if v.Classification != model.ClassTruePositive || v.Confidence != 0.75 {
			t.Errorf("must use the deep confidence, not the earlier 0.95 false-positive one: %+v", v)
		}
		if v.Exploitability != model.ExploitUnknown {
			t.Errorf("not-reachable contradicts a confirmation: %v", v.Exploitability)
		}
		if f.Dismissed() {
			t.Error("a confirmed finding must not be dismissed")
		}
		if !strings.Contains(v.Reasoning, "Earlier review: false_positive") {
			t.Errorf("the earlier call must stay in the record: %q", v.Reasoning)
		}
	})
	t.Run("lifts a refutation", func(t *testing.T) {
		prior := vd(model.ClassTruePositive, 0.8)
		prior.Refuted, prior.RefuteSupported, prior.RefuteReason = true, true, "judge said no"
		f := finding(model.SeverityHigh, prior)
		if !f.Dismissed() {
			t.Fatal("precondition: a true positive with a backed refutation is dismissed")
		}
		Apply(&f, deepRes(model.ClassTruePositive, 0.8, 2))
		if f.Verdict.Refuted || f.Dismissed() {
			t.Errorf("deep confirmation must survive: %+v", f.Verdict)
		}
		if f.Verdict.RefuteReason != "judge said no" {
			t.Error("the judge's reason is history and must be kept")
		}
	})
	t.Run("never lowers an earlier true-positive confidence", func(t *testing.T) {
		f := finding(model.SeverityHigh, vd(model.ClassTruePositive, 0.95))
		Apply(&f, deepRes(model.ClassTruePositive, 0.6, 2))
		if f.Verdict.Confidence != 0.95 {
			t.Errorf("confidence = %v", f.Verdict.Confidence)
		}
	})
	t.Run("keeps an overturned verdict surfaced", func(t *testing.T) {
		prior := vd(model.ClassFalsePositive, 0.9)
		prior.Overturned = true
		f := finding(model.SeverityHigh, prior)
		Apply(&f, deepRes(model.ClassTruePositive, 0.5, 2))
		if !f.Verdict.Overturned || f.Dismissed() {
			t.Errorf("surfacing must never decrease: %+v", f.Verdict)
		}
	})
	t.Run("a credential finding can still be confirmed", func(t *testing.T) {
		f := finding(model.SeverityHigh, nil)
		f.Tool = "gitleaks"
		Apply(&f, deepRes(model.ClassTruePositive, 0.9, 1))
		if f.Verdict == nil || f.Verdict.Classification != model.ClassTruePositive {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
}

func TestApply_DismissalSupport(t *testing.T) {
	strong := func() model.DeepVerification {
		return deepRes(model.ClassFalsePositive, 0.9, 3, "auth/mw.go:12")
	}
	t.Run("supports dismissing an uncertain finding", func(t *testing.T) {
		f := finding(model.SeverityHigh, vd(model.ClassUncertain, 0.4))
		Apply(&f, strong())
		if f.Verdict.Classification != model.ClassFalsePositive || f.Verdict.Confidence != 0.9 || !f.Dismissed() {
			t.Errorf("verdict = %+v", f.Verdict)
		}
		if f.Verdict.Exploitability != model.ExploitNotReachable {
			t.Errorf("exploitability = %v", f.Verdict.Exploitability)
		}
	})
	t.Run("supports dismissing a low-confidence true positive", func(t *testing.T) {
		f := finding(model.SeverityHigh, vd(model.ClassTruePositive, 0.5))
		Apply(&f, strong())
		if !f.Dismissed() {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
	t.Run("raises a shaky false positive to a dismissal", func(t *testing.T) {
		f := finding(model.SeverityHigh, vd(model.ClassFalsePositive, 0.5))
		Apply(&f, strong())
		if f.Verdict.Confidence != 0.9 || !f.Dismissed() {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
	t.Run("keeps a stronger earlier false positive confidence", func(t *testing.T) {
		f := finding(model.SeverityHigh, vd(model.ClassFalsePositive, 0.99))
		Apply(&f, strong())
		if f.Verdict.Confidence != 0.99 {
			t.Errorf("confidence = %v", f.Verdict.Confidence)
		}
	})
	t.Run("no prior verdict: deep alone may dismiss", func(t *testing.T) {
		f := finding(model.SeverityHigh, nil)
		Apply(&f, strong())
		if f.Verdict == nil || !f.Dismissed() {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
	t.Run("replaces a refuted true positive with a clean false positive", func(t *testing.T) {
		prior := vd(model.ClassTruePositive, 0.9)
		prior.Refuted = true
		f := finding(model.SeverityHigh, prior)
		Apply(&f, strong())
		if f.Verdict.Refuted || f.Verdict.Classification != model.ClassFalsePositive || !f.Dismissed() {
			t.Errorf("verdict = %+v", f.Verdict)
		}
	})
}

func TestApply_DismissalIsRefusedWhenEvidenceIsWeak(t *testing.T) {
	for name, d := range map[string]model.DeepVerification{
		"confidence below the floor": deepRes(model.ClassFalsePositive, model.DismissFloor-0.01, 3, "a.go:1"),
		"no evidence":                deepRes(model.ClassFalsePositive, 0.99, 3),
		"no tool calls":              deepRes(model.ClassFalsePositive, 0.99, 0, "a.go:1"),
		"aborted":                    {Steps: 3, Conclusion: model.ClassFalsePositive, Confidence: 0.99, Evidence: []string{"a.go:1"}, Aborted: "timeout"},
	} {
		prior := vd(model.ClassUncertain, 0.4)
		f := finding(model.SeverityHigh, prior)
		Apply(&f, d)
		if f.Dismissed() {
			t.Errorf("%s: finding was dismissed: %+v", name, f.Verdict)
		}
		if f.Verdict.Classification != model.ClassUncertain || f.Verdict.Confidence != 0.4 {
			t.Errorf("%s: a weak deep result must leave the verdict alone, got %+v", name, f.Verdict)
		}
		if f.Deep == nil {
			t.Errorf("%s: outcome must still be recorded", name)
		}
	}
	// And with no prior verdict, a weak false positive does not invent one.
	f := finding(model.SeverityHigh, nil)
	Apply(&f, deepRes(model.ClassFalsePositive, 0.99, 3))
	if f.Verdict != nil {
		t.Errorf("verdict invented from weak evidence: %+v", f.Verdict)
	}
}

func TestApply_DisagreementWithConfidentTruePositiveIsUncertainAndSurfaced(t *testing.T) {
	prior := vd(model.ClassTruePositive, 0.92)
	prior.Reasoning = "user input flows to the query"
	f := finding(model.SeverityHigh, prior)
	Apply(&f, deepRes(model.ClassFalsePositive, 0.85, 4, "db/q.go:9"))
	v := f.Verdict
	if v.Classification != model.ClassUncertain || f.Dismissed() {
		t.Fatalf("disagreement must be uncertain and kept: %+v", v)
	}
	if v.Confidence != 0.85 {
		t.Errorf("confidence = %v, want the lower of the two", v.Confidence)
	}
	for _, want := range []string{"DISAGREES", "user input flows to the query", "db/q.go:9", "human"} {
		if !strings.Contains(v.Reasoning, want) {
			t.Errorf("reasoning lacks %q: %q", want, v.Reasoning)
		}
	}
	if f.Deep.Conclusion != model.ClassFalsePositive {
		t.Error("the deep outcome must be recorded verbatim")
	}
}

func TestApply_OverturnedVerdictIsNotOutvoted(t *testing.T) {
	prior := vd(model.ClassFalsePositive, 0.9)
	prior.Overturned = true
	f := finding(model.SeverityHigh, prior)
	Apply(&f, deepRes(model.ClassFalsePositive, 0.95, 3, "a.go:1"))
	if f.Dismissed() || !f.Verdict.Overturned {
		t.Errorf("a judge-overturned finding must stay surfaced: %+v", f.Verdict)
	}
	if !strings.Contains(f.Verdict.Reasoning, "overturned") {
		t.Errorf("reasoning = %q", f.Verdict.Reasoning)
	}
}

func TestApply_CredentialFindingIsNeverDismissed(t *testing.T) {
	for _, mk := range []func() model.Finding{
		func() model.Finding {
			f := finding(model.SeverityHigh, vd(model.ClassUncertain, 0.3))
			f.Tool = "gitleaks"
			return f
		},
		func() model.Finding {
			f := finding(model.SeverityHigh, vd(model.ClassUncertain, 0.3))
			f.RuleID = "hardcoded-password"
			return f
		},
		func() model.Finding { f := finding(model.SeverityHigh, nil); f.CWE = []string{"CWE-798"}; return f },
	} {
		f := mk()
		if !f.IsSecret() {
			t.Fatal("precondition: credential finding")
		}
		before := f.Verdict
		Apply(&f, deepRes(model.ClassFalsePositive, 1, 5, "a.go:1"))
		if f.Dismissed() {
			t.Errorf("credential finding dismissed: %+v", f.Verdict)
		}
		if f.Verdict != before {
			t.Errorf("credential verdict was rewritten: %+v", f.Verdict)
		}
	}
}

func TestApply_UncertainAndAbortedLeaveTheVerdictAlone(t *testing.T) {
	for name, d := range map[string]model.DeepVerification{
		"uncertain":             deepRes(model.ClassUncertain, 0.5, 2),
		"aborted":               {Conclusion: model.ClassUncertain, Aborted: "wall-clock timeout"},
		"aborted but claims tp": {Steps: 2, Conclusion: model.ClassTruePositive, Confidence: 1, Aborted: "malformed reply"},
	} {
		prior := vd(model.ClassFalsePositive, 0.95)
		f := finding(model.SeverityHigh, prior)
		Apply(&f, d)
		if f.Verdict != prior || f.Verdict.Classification != model.ClassFalsePositive {
			t.Errorf("%s: verdict changed: %+v", name, f.Verdict)
		}
		if f.Deep == nil {
			t.Errorf("%s: not recorded", name)
		}
	}
}

func TestApply_DoesNotMutateTheEarlierVerdictInPlace(t *testing.T) {
	prior := vd(model.ClassUncertain, 0.4)
	f := finding(model.SeverityHigh, prior)
	Apply(&f, deepRes(model.ClassTruePositive, 0.9, 2))
	if prior.Classification != model.ClassUncertain {
		t.Error("Apply edited the shared verdict value; correlated findings may share it")
	}
}

// ---- Select ---------------------------------------------------------------

func TestSelect_PriorityAndExclusions(t *testing.T) {
	secret := finding(model.SeverityCritical, nil)
	secret.Tool = "trufflehog"
	shadow := finding(model.SeverityCritical, nil)
	shadow.Shadow = true
	done := finding(model.SeverityCritical, nil)
	done.Deep = &model.DeepVerification{}

	overturned := vd(model.ClassFalsePositive, 0.9)
	overturned.Overturned = true
	refuted := vd(model.ClassTruePositive, 0.9)
	refuted.Refuted = true

	fs := []model.Finding{
		finding(model.SeverityMedium, vd(model.ClassTruePositive, 0.9)),    // 0 settled: never
		finding(model.SeverityLow, nil),                                    // 1 no verdict, low
		finding(model.SeverityMedium, vd(model.ClassUncertain, 0.5)),       // 2 uncertain medium
		finding(model.SeverityHigh, vd(model.ClassTruePositive, 0.95)),     // 3 high, settled
		finding(model.SeverityCritical, vd(model.ClassTruePositive, 0.95)), // 4 critical, settled
		finding(model.SeverityHigh, vd(model.ClassUncertain, 0.5)),         // 5 high, uncertain
		finding(model.SeverityMedium, nil),                                 // 6 no verdict, medium
		secret,                                                             // 7
		shadow,                                                             // 8
		done,                                                               // 9
		finding(model.SeverityMedium, overturned),                          // 10 judge disagreement
		finding(model.SeverityLow, refuted),                                // 11 refuted
		finding(model.SeverityLow, vd(model.ClassFalsePositive, 0.95)),     // 12 settled FP: never
		finding(model.SeverityMedium, vd(model.ClassTruePositive, 0.4)),    // 13 low confidence
		finding(model.SeverityHigh, nil),                                   // 14 high, no verdict
	}
	got := Select(fs, 100)
	// Tier 1: critical/high, most severe first, contested/missing before settled.
	// Tier 2: contested verdicts below high, by severity. Tier 3: no verdict.
	want := []int{4, 5, 14, 3, 2, 10, 13, 11, 6, 1}
	// Within severity "high", 5 and 14 need attention (3 does not) and keep scan order; critical 4 leads.
	if !equalInts(got, want) {
		t.Fatalf("Select = %v, want %v", got, want)
	}
	for _, i := range got {
		if i == 7 || i == 8 || i == 9 || i == 0 || i == 12 {
			t.Errorf("index %d must never be selected", i)
		}
	}
	if g := Select(fs, 3); !equalInts(g, want[:3]) {
		t.Errorf("n=3: %v, want %v", g, want[:3])
	}
	if Select(fs, 0) != nil || Select(fs, -2) != nil || Select(nil, 5) != nil {
		t.Error("n<=0 or no findings selects nothing")
	}
}

func TestSelect_IsStable(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, finding(model.SeverityHigh, vd(model.ClassUncertain, 0.5)))
	}
	got := Select(fs, 20)
	for i, idx := range got {
		if idx != i {
			t.Fatalf("ties must keep scan order: %v", got)
		}
	}
	again := Select(fs, 20)
	if !equalInts(got, again) {
		t.Error("Select is not deterministic")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Dependency advisories are often the most severe findings in a scan, so without
// this they would take every --deep-verify slot, for a question (is the vulnerable
// version in use?) the deep pass is not built to answer.
func TestSelect_SkipsDependencyAdvisories(t *testing.T) {
	cve := finding(model.SeverityCritical, nil)
	cve.Tool, cve.RuleID = "trivy", "CVE-2024-3094"
	osv := finding(model.SeverityCritical, nil)
	osv.Tool, osv.RuleID = "osv-scanner", "GHSA-j8r2-6x86-q33q"
	code := finding(model.SeverityHigh, nil)

	got := Select([]model.Finding{cve, osv, code}, 5)
	if len(got) != 1 || got[0] != 2 {
		t.Errorf("selected %v, want only the code finding (index 2)", got)
	}
}

func TestApply_NeverDismissesADependencyAdvisory(t *testing.T) {
	f := finding(model.SeverityHigh, nil)
	f.Tool, f.RuleID = "trivy", "CVE-2024-3094"
	Apply(&f, deepRes(model.ClassFalsePositive, 0.95, 3, "go.mod:7"))
	if f.Verdict != nil || f.Dismissed() {
		t.Errorf("a deep pass must not rule out a known CVE: %+v", f.Verdict)
	}
	if f.Deep == nil {
		t.Error("the outcome is still recorded")
	}
}

// A deep confirmation settles the questions an uncertain verdict had left open, so
// they must not still be shown as open.
func TestApply_ConfirmDropsTheUncertainVerdictsOpenQuestions(t *testing.T) {
	v := vd(model.ClassUncertain, 0.4)
	v.Blockers = []string{"whether the caller sanitizes id"}
	v.ValidationPlan = &model.ValidationPlan{Local: "read the caller"}
	f := finding(model.SeverityHigh, v)
	Apply(&f, deepRes(model.ClassTruePositive, 0.9, 2, "a.go:1"))
	if f.Verdict.Classification != model.ClassTruePositive || f.Verdict.Blockers != nil || f.Verdict.ValidationPlan != nil {
		t.Errorf("open questions survived a confirmation: %+v", f.Verdict)
	}
}
