package triage

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// Tests for the result contract borrowed from Cloudflare's security-audit skill:
// hardening notes, actionable "needs validation" verdicts, impact-based severity,
// cited-line checking and the blind judge.

const (
	jHardening = `{"classification":"hardening","confidence":0.9,"exploitability":"not-reachable",` +
		`"reasoning":"md5 of a cache key, not a secret; the token is compared with hmac.Equal on line 12"}`
	jNeedsValidation = `{"classification":"uncertain","confidence":0.4,"exploitability":"unknown","reasoning":"depends on the router",` +
		`"blockers":["whether /admin is behind the auth middleware","  "],` +
		`"validationPlan":{"local":"read the router setup in routes.py","owner":"check the proxy rule for /admin"},` +
		`"attacker":"anyone","assessedSeverity":"high"}`
	jImpactTP = `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"tainted",` +
		`"attacker":"unauthenticated remote user","impact":"runs shell commands as the service","assessedSeverity":"CRITICAL",` +
		`"blockers":["should be dropped"]}`
)

func TestHardening_ConfidentNoteLeavesTheGateAsHardening(t *testing.T) {
	v := triageWith(t, jHardening, jAccept)
	if v.Classification != model.ClassHardening {
		t.Fatalf("classification = %q, want hardening", v.Classification)
	}
	if !v.Dismissed() || !v.Hardening() {
		t.Error("a confident hardening note should leave the gate, labeled as hardening")
	}
	if v.Surfaced() || v.HighConfidence() {
		t.Error("a hardening note is not a vulnerability: it must not be surfaced or remediated")
	}
}

func TestHardening_JudgeRefutationSurfacesIt(t *testing.T) {
	v := triageWith(t, jHardening, jRefute)
	if !v.Overturned || !v.Surfaced() || v.Dismissed() {
		t.Errorf("refuting a hardening verdict (the control does not hold) must surface the finding: %+v", v)
	}
}

func TestHardening_JudgePromptStatesTheBurden(t *testing.T) {
	sys := judgeMessages(*newFinding(), "ctx", model.Verdict{Classification: model.ClassHardening}, false)[0].Content
	if !strings.Contains(sys, "already stopped by another control") || !strings.Contains(sys, "NOT stopped") {
		t.Errorf("the judge must be told how to refute a hardening verdict:\n%s", sys)
	}
}

func TestHardening_LowConfidenceOrOpenPathStaysInTheGate(t *testing.T) {
	low := model.Verdict{Classification: model.ClassHardening, Confidence: 0.6}
	if low.Dismissed() {
		t.Error("a shaky hardening call must not hide a finding")
	}
	open := model.Verdict{Classification: model.ClassHardening, Confidence: 0.95, Gates: &model.Gates{
		Reachable: model.Gate{Answer: model.GateYes}, AttackerControlled: model.Gate{Answer: model.GateYes},
		Sanitized: model.Gate{Answer: model.SanitizedNone}, NewCapability: model.Gate{Answer: model.GateYes},
	}}
	if open.Dismissed() {
		t.Error("a hardening verdict whose own gates describe an open path contradicts itself and must stay")
	}
}

func TestNeedsValidation_KeepsBlockersAndPlanOnlyOnUncertain(t *testing.T) {
	v := triageWith(t, jNeedsValidation, jAccept)
	if !v.NeedsValidation() {
		t.Fatalf("an uncertain verdict with blockers needs validation: %+v", v)
	}
	if want := []string{"whether /admin is behind the auth middleware"}; !reflect.DeepEqual(v.Blockers, want) {
		t.Errorf("blockers = %q, want %q (blank ones dropped)", v.Blockers, want)
	}
	if v.ValidationPlan == nil || v.ValidationPlan.Owner != "check the proxy rule for /admin" {
		t.Errorf("validation plan lost: %+v", v.ValidationPlan)
	}
	if v.Attacker != "" || v.AssessedSeverity != "" {
		t.Error("attacker and assessed severity belong to a true positive only")
	}
	if v.Dismissed() {
		t.Error("needs validation is never a dismissal")
	}
}

func TestImpact_TruePositiveKeepsAttackerImpactAndSeverity(t *testing.T) {
	v := triageWith(t, jImpactTP, jAccept)
	if v.Attacker != "unauthenticated remote user" || v.Impact == "" {
		t.Errorf("attacker/impact lost: %+v", v)
	}
	if v.AssessedSeverity != model.SeverityCritical {
		t.Errorf("assessed severity = %q, want critical (case-normalized)", v.AssessedSeverity)
	}
	if len(v.Blockers) != 0 {
		t.Error("blockers belong to an uncertain verdict only")
	}
}

func TestImpact_UnknownSeverityIsDropped(t *testing.T) {
	v, err := parseVerdict(`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"r","assessedSeverity":"catastrophic"}`)
	if err != nil {
		t.Fatal(err)
	}
	if v.AssessedSeverity != "" {
		t.Errorf("an off-scale severity must be dropped, got %q", v.AssessedSeverity)
	}
}

func TestPrompt_V7AsksForTheNewFields(t *testing.T) {
	sys := triageMessages(*newFinding(), "code", nil)[0].Content
	for _, want := range []string{"hardening", "blockers", "validationPlan", "assessedSeverity", "unauthenticated code execution", "explicit control fully defeated"} {
		if !strings.Contains(sys, want) {
			t.Errorf("triage prompt should mention %q", want)
		}
	}
	for _, want := range []string{`"hardening"`, `"blockers"`, `"validationPlan"`, `"assessedSeverity"`} {
		if !strings.Contains(string(verdictSchema), want) {
			t.Errorf("verdict schema should declare %s", want)
		}
	}
}

const citeContext = "// the finding:\n   10 | def run(req):\n   11 |     cmd = req.args['c']\n>>   12 |     os.system(cmd)\n   13 |     return 'ok'\n"

func TestCitations_LinesShownAreFine(t *testing.T) {
	got := unverifiedCitations("app/run.py", citeContext,
		"the value is read on line 11 and reaches os.system at run.py:12; see lines 10-13", "")
	if len(got) != 0 {
		t.Errorf("every cited line was shown, got %q", got)
	}
}

func TestCitations_FlagsLinesAndFilesNotShown(t *testing.T) {
	got := unverifiedCitations("app/run.py", citeContext,
		"sanitized on line 40 by the middleware in auth.py:7", "move the check to lines 12-30", "")
	want := []string{"auth.py:7", "line 40", "lines 12-30"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCitations_NoCodeShownMeansNothingIsVerified(t *testing.T) {
	got := unverifiedCitations("a.py", "(source code withheld by --llm-no-code)", "see line 3")
	if !reflect.DeepEqual(got, []string{"line 3"}) {
		t.Errorf("got %q", got)
	}
}

func TestCitations_PipelineOwnsTheField(t *testing.T) {
	v, err := parseVerdict(`{"classification":"uncertain","confidence":0.5,"exploitability":"unknown","reasoning":"r","unverifiedCitations":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if v.UnverifiedCitations != nil {
		t.Error("a model must not be able to set the citation check")
	}
	// And Triage sets it from the text it was given.
	tp := `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"tainted on line 99"}`
	got := triageWith(t, tp, jAccept)
	if !reflect.DeepEqual(got.UnverifiedCitations, []string{"line 99"}) {
		t.Errorf("unverified citations = %q, want [line 99]", got.UnverifiedCitations)
	}
}

func TestBlindJudge_HidesTheFirstPassReasoning(t *testing.T) {
	eng, jf := judgeEngine(t, gatedTP, jAccept)
	eng.SetBlindJudge(true)
	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	user := jf.Calls[0].Messages[1].Content
	sys := jf.Calls[0].Messages[0].Content
	if strings.Contains(user, "first reviewer's reasoning") || strings.Contains(user, "gate answers") {
		t.Errorf("a blind judge must not see the reasoning or gates:\n%s", user)
	}
	if !strings.Contains(user, "classification=true_positive") || !strings.Contains(user, "eval(user_input)") {
		t.Errorf("a blind judge still sees the claim and the code:\n%s", user)
	}
	if !strings.Contains(sys, "not shown the first reviewer's reasoning") {
		t.Errorf("the system prompt should say why the reasoning is missing:\n%s", sys)
	}
}

func TestConsolidate_TieDropsDetailThatNoLongerFits(t *testing.T) {
	tp := model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.8, Attacker: "anyone", AssessedSeverity: model.SeverityHigh}
	fp := model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.8}
	out := consolidate([]model.Verdict{tp, fp})
	if out.Classification != model.ClassUncertain {
		t.Fatalf("a tie is uncertain, got %q", out.Classification)
	}
	if out.Attacker != "" || out.AssessedSeverity != "" {
		t.Errorf("true-positive detail must not survive on an uncertain result: %+v", out)
	}
}

func TestBlindJudge_IsPartOfTheCacheKey(t *testing.T) {
	r := newCacheRig(t, jTP)
	eng := r.engine("scope", []byte("0123456789abcdef0123"))
	f := cacheFinding(3)
	pf, code := eng.promptView(*f)
	open := eng.cacheKey(pf, code, nil)
	eng.SetBlindJudge(true)
	if blind := eng.cacheKey(pf, code, nil); blind == open {
		t.Error("a verdict reached with a blind judge must not be reused for a sighted one, or the reverse")
	}
}
