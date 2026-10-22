package triage

import (
	"strings"
	"testing"
)

// The fix prompt asks for a regression test, and the model's test is kept,
// bounded and given a plausible path, never run.
func TestRemediate_KeepsTheProposedRegressionTest(t *testing.T) {
	reply := `{"summary":"s","diff":"","guidance":"g","confidence":0.8,"regressionTest":{"file":"./tests/test_app.py","code":"def test_rejects_shell():\n    assert run('; rm -rf /') is None\n","description":"  sends a shell\n metacharacter  "}}`
	r := newFixRig(t, reply)
	got := r.review(t, r.engine("fix-scope", cacheSecret), "run-1", cacheFinding(4))
	rt := got.Remediation.RegressionTest
	if rt == nil {
		t.Fatal("regression test dropped")
	}
	if rt.File != "tests/test_app.py" || rt.Description != "sends a shell metacharacter" || !strings.HasPrefix(rt.Code, "def test_rejects_shell") {
		t.Errorf("test = %+v", rt)
	}
	sys := r.fixer.Calls[0].Messages[0].Content
	if !strings.Contains(sys, "regressionTest") || !strings.Contains(sys, "never run") {
		t.Error("the fix prompt should ask for a regression test and say it is not run")
	}
}

func TestRemediate_DropsAnEmptyOrEscapingTest(t *testing.T) {
	for name, tc := range map[string]struct {
		reply    string
		keep     bool
		wantFile string
	}{
		"empty code":    {`{"summary":"s","confidence":0.8,"regressionTest":{"file":"t.py","code":"  \n"}}`, false, ""},
		"absolute":      {`{"summary":"s","confidence":0.8,"regressionTest":{"file":"/etc/t.py","code":"x"}}`, true, ""},
		"climbs out":    {`{"summary":"s","confidence":0.8,"regressionTest":{"file":"../../t.py","code":"x"}}`, true, ""},
		"no test asked": {`{"summary":"s","confidence":0.8}`, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := newFixRig(t, tc.reply)
			rt := r.review(t, r.engine("fix-scope", cacheSecret), "run-1", cacheFinding(4)).Remediation.RegressionTest
			if (rt != nil) != tc.keep {
				t.Fatalf("kept = %v, want %v (%+v)", rt != nil, tc.keep, rt)
			}
			if rt != nil && rt.File != tc.wantFile {
				t.Errorf("file = %q, want %q", rt.File, tc.wantFile)
			}
		})
	}
}
