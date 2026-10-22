package triage

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

var testFlow = []model.FlowStep{
	{File: "app.py", Line: 3, Note: "source: request.args"},
	{File: "db.py", Line: 12, Note: "sink: cursor.execute"},
}

// The scanner's path reaches the model fenced as untrusted text, framed as a
// claim to check, and never when code is withheld.
func TestTriagePrompt_CarriesScannerFlow(t *testing.T) {
	f := model.Finding{Tool: "opengrep", RuleID: "sqli", Location: model.Location{File: "db.py", Region: model.Region{StartLine: 12}}, Flow: testFlow}
	msgs := triageMessages(f, "12 | cursor.execute(q)", nil)
	user := msgs[len(msgs)-1].Content
	for _, want := range []string{"data-flow path", "1. app.py:3 source: request.args", "2. db.py:12 sink: cursor.execute", "a claim by the scanner"} {
		if !strings.Contains(user, want) {
			t.Errorf("prompt missing %q\n%s", want, user)
		}
	}
	f.Flow = nil
	if user := triageMessages(f, "x", nil)[1].Content; strings.Contains(user, "data-flow path") {
		t.Error("no flow block when the scanner gave no path")
	}
}

func TestPromptView_WithholdsFlowUnderNoCode(t *testing.T) {
	r := newCacheRig(t, jTP)
	eng := r.engine("scope", []byte("0123456789abcdef0123"))
	f := cacheFinding(3)
	f.Flow = testFlow
	if pf, _ := eng.promptView(*f); len(pf.Flow) != 2 {
		t.Fatalf("flow should reach the prompt: %+v", pf.Flow)
	}
	eng.SetNoCode(true)
	if pf, _ := eng.promptView(*f); pf.Flow != nil {
		t.Error("flow notes quote code, so --llm-no-code must drop them")
	}
}

// A different path is a different question; the same path at shifted line
// numbers (code added above it) is not.
func TestFlow_IsPartOfTheCacheKey(t *testing.T) {
	r := newCacheRig(t, jTP)
	eng := r.engine("scope", []byte("0123456789abcdef0123"))
	f := cacheFinding(3)
	pf, code := eng.promptView(*f)
	none := eng.cacheKey(pf, code, nil)
	pf.Flow = testFlow
	with := eng.cacheKey(pf, code, nil)
	if with == none {
		t.Error("a finding with a traced path must not reuse a verdict reached without one")
	}
	shifted := append([]model.FlowStep(nil), testFlow...)
	shifted[0].Line += 5
	pf.Flow = shifted
	if eng.cacheKey(pf, code, nil) != with {
		t.Error("moving the path down the file should not invalidate the cached verdict")
	}
}
