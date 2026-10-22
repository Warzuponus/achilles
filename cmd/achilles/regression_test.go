package main

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestWriteRegressionTests(t *testing.T) {
	var b strings.Builder
	writeRegressionTests(&b, []proposedFix{
		{rule: "sqli", file: "db.py", test: &model.RegressionTest{File: "tests/test_db.py", Code: "def test_q(): pass", Description: "ping @someone"}},
		{rule: "xss", file: "web.py"},
	})
	out := b.String()
	for _, want := range []string{"Proposed regression tests", "Not committed and not run", "Test for `sqli` in `db.py`", "tests/test_db.py", "def test_q(): pass"} {
		if !strings.Contains(out, want) {
			t.Errorf("PR body missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "@someone") || strings.Contains(out, "`xss`") {
		t.Errorf("mentions must be defused and fixes without a test left out\n%s", out)
	}

	b.Reset()
	writeRegressionTests(&b, []proposedFix{{rule: "a"}})
	if b.Len() != 0 {
		t.Error("no section when no fix carries a test")
	}
}

func TestWriteRegressionTests_StaysUnderTheBodyLimit(t *testing.T) {
	var fixes []proposedFix
	for range 30 {
		fixes = append(fixes, proposedFix{rule: "r", file: "f", test: &model.RegressionTest{Code: strings.Repeat("assert f(1) == 2\n", model.MaxRegressionTestCode/17)}})
	}
	var b strings.Builder
	writeRegressionTests(&b, fixes)
	if b.Len() > maxFixPRBody || !strings.Contains(b.String(), "left out") {
		t.Errorf("len = %d; should stop under %d and say so", b.Len(), maxFixPRBody)
	}
}
