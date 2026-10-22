package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func regressionScan() model.Scan {
	s := flowScan()
	s.Findings[0].Flow = nil
	s.Findings[0].Remediation = &model.Remediation{Summary: "parameterise the query", Confidence: 0.8,
		RegressionTest: &model.RegressionTest{File: "tests/test_db.py", Description: "sends a quote",
			Code: "def test_quote():\n    key = 'AKIAABCDEFGHIJKLMNOP'\n    assert lookup(\"'\") == []"}}
	return s
}

func TestRegressionTest_Rendered(t *testing.T) {
	var h, txt bytes.Buffer
	if err := WriteHTML(&h, HTMLReport{Target: "/r", Scan: regressionScan()}); err != nil {
		t.Fatal(err)
	}
	WriteHuman(&txt, regressionScan())
	if out := h.String(); !strings.Contains(out, "Proposed regression test") || !strings.Contains(out, "def test_quote") ||
		!strings.Contains(out, "did not run it") || strings.Contains(out, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("HTML report: test missing, not marked unrun, or a credential shown")
	}
	if out := txt.String(); !strings.Contains(out, "regression test proposed for tests/test_db.py (not run): sends a quote") {
		t.Errorf("human report missing the test line\n%s", out)
	}
}

func TestMarkdownCodeBlock_CannotBeClosedEarly(t *testing.T) {
	got := MarkdownCodeBlock("a ``` b\n````\n")
	if !strings.HasPrefix(got, "`````\n") || !strings.HasSuffix(got, "\n`````") {
		t.Errorf("fence = %q", got)
	}
}
