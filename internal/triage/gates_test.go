package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

const gatedTP = `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"r",
 "gates":{
  "designedBehavior":{"answer":"no","evidence":"not a feature"},
  "reachable":{"answer":"yes","evidence":"POST /run handler calls it"},
  "attackerControlled":{"answer":"YES"},
  "sanitized":{"answer":"none","evidence":"no check before exec"},
  "newCapability":{"answer":"yes"}}}`

func TestParseVerdict_Gates(t *testing.T) {
	v, err := parseVerdict(gatedTP)
	if err != nil {
		t.Fatal(err)
	}
	g := v.Gates
	if g == nil {
		t.Fatal("gates not parsed")
	}
	if g.Reachable.Answer != model.GateYes || g.Reachable.Evidence != "POST /run handler calls it" {
		t.Errorf("reachable = %+v", g.Reachable)
	}
	if g.AttackerControlled.Answer != model.GateYes {
		t.Errorf("answers must be case-normalized, got %q", g.AttackerControlled.Answer)
	}
	if g.Sanitized.Answer != model.SanitizedNone || g.DesignedBehavior.Answer != model.GateNo {
		t.Errorf("gates = %+v", g)
	}
}

func TestParseVerdict_GatesAreOptional(t *testing.T) {
	v, err := parseVerdict(`{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"r"}`)
	if err != nil {
		t.Fatal(err)
	}
	if v.Gates != nil {
		t.Errorf("a model that omits gates must yield none, got %+v", v.Gates)
	}
	// An empty or all-unrecognised gates object is the same as no gates.
	v, _ = parseVerdict(`{"classification":"uncertain","gates":{"reachable":{"answer":"maybe"}}}`)
	if v.Gates != nil {
		t.Errorf("nothing valid answered, so no gates: %+v", v.Gates)
	}
}

func TestParseVerdict_GateValuesNormalizeToUnknown(t *testing.T) {
	v, _ := parseVerdict(`{"classification":"true_positive","confidence":0.9,"gates":{
		"reachable":{"answer":"yes"},
		"attackerControlled":{"answer":"probably"},
		"sanitized":{"answer":"yes"},
		"newCapability":{"answer":7}}}`)
	if v.Gates == nil {
		t.Fatal("one valid answer keeps the gates")
	}
	if v.Gates.AttackerControlled.Answer != model.GateUnknown {
		t.Errorf("out-of-vocabulary answer = %q, want unknown", v.Gates.AttackerControlled.Answer)
	}
	if v.Gates.Sanitized.Answer != model.GateUnknown {
		t.Errorf("sanitized does not take yes/no: %q", v.Gates.Sanitized.Answer)
	}
	if v.Gates.NewCapability.Answer != model.GateUnknown || v.Gates.DesignedBehavior.Answer != model.GateUnknown {
		t.Errorf("a wrong-typed or missing gate must be unknown: %+v", v.Gates)
	}
}

func TestParseVerdict_FlatGateFormsAreAccepted(t *testing.T) {
	v, _ := parseVerdict(`{"classification":"true_positive","confidence":0.9,"gates":{
		"reachable":"yes","attackerControlled":true,"sanitized":"Partial","newCapability":false}}`)
	g := v.Gates
	if g == nil || g.Reachable.Answer != model.GateYes || g.AttackerControlled.Answer != model.GateYes ||
		g.Sanitized.Answer != model.SanitizedPartial || g.NewCapability.Answer != model.GateNo {
		t.Errorf("loose gate shapes not tolerated: %+v", g)
	}
}

func TestParseVerdict_PipelineFieldsAreNotTakenFromTheModel(t *testing.T) {
	v, _ := parseVerdict(`{"classification":"false_positive","confidence":0.9,"overturned":false,"refuted":true,
		"stability":{"samples":3,"agreeing":3,"classifications":{"false_positive":3}}}`)
	if v.Stability != nil || v.Refuted {
		t.Errorf("model-supplied stability/refuted must be discarded: %+v", v)
	}
	v, _ = parseVerdict(`{"classification":"maybe","confidence":0.9}`)
	if v.Classification != model.ClassUncertain {
		t.Errorf("an unknown classification must become uncertain, got %q", v.Classification)
	}
}

func TestTriage_AttachesGatesAndShowsThemToTheJudge(t *testing.T) {
	eng, jf := judgeEngine(t, gatedTP, jAccept)
	f := newFinding()
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if f.Verdict.Gates == nil || f.Verdict.Gates.Sanitized.Answer != model.SanitizedNone {
		t.Fatalf("gates not attached: %+v", f.Verdict.Gates)
	}
	user := jf.Calls[0].Messages[1].Content
	if !strings.Contains(user, "reachable=yes (POST /run handler calls it)") {
		t.Errorf("judge should see the gate answers:\n%s", user)
	}
}

func TestVerdictSchema_DeclaresGatesAndStaysValidJSON(t *testing.T) {
	var m map[string]any
	if err := jsonUnmarshal(verdictSchema, &m); err != nil {
		t.Fatalf("verdictSchema is not valid JSON: %v", err)
	}
	props := m["properties"].(map[string]any)
	gates := props["gates"].(map[string]any)["properties"].(map[string]any)
	for _, k := range []string{"designedBehavior", "reachable", "attackerControlled", "sanitized", "newCapability"} {
		if _, ok := gates[k]; !ok {
			t.Errorf("schema lacks gate %q", k)
		}
	}
	for _, r := range m["required"].([]any) {
		if r == "gates" {
			t.Error("gates must stay optional: a model that omits them must still work")
		}
	}
	if strings.Contains(string(verdictSchema), "$ref") {
		t.Error("avoid $ref: several OpenAI-compatible runtimes reject it")
	}
}

func TestPrompts_StateTheGatesAndTheEvidencePrinciple(t *testing.T) {
	// The gates arrived in v4; v5 changed only the judge. Anything older predates both.
	if PromptVersion != "triage/v6" {
		t.Errorf("PromptVersion = %q, want triage/v6", PromptVersion)
	}
	f := newFinding()
	sys := triageMessages(*f, "code", nil)[0].Content
	for _, want := range []string{
		"designedBehavior", "reachable", "attackerControlled", "sanitized", "newCapability",
		"are claims, not evidence", "UNTRUSTED DATA", "not evidence that the code is unreachable",
	} {
		if !strings.Contains(sys, want) {
			t.Errorf("triage system prompt lacks %q", want)
		}
	}
	jsys := judgeMessages(*f, "code", model.Verdict{Classification: model.ClassTruePositive})[0].Content
	if !strings.Contains(jsys, "are claims, not evidence") {
		t.Error("the judge must be told comments and names are claims too")
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
