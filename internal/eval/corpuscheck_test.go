package eval

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestExpectedTool(t *testing.T) {
	for fixture, want := range map[string]string{
		"testdata/a.go":     "gosec",
		"testdata/A.GO":     "gosec",
		"testdata/a.py":     "bandit",
		"testdata/a.js":     "",
		"testdata/Makefile": "",
	} {
		if got := expectedTool(fixture); got != want {
			t.Errorf("expectedTool(%q) = %q, want %q", fixture, got, want)
		}
	}
}

// A tool we would never invoke is a corpus defect, not a skip: the scanner is
// chosen by extension, so such a case would be silently validated against gosec
// while claiming to describe some other tool's rule.
func TestValidateCorpus_UndeclaredToolIsAMismatchNotASkip(t *testing.T) {
	c := mustLoad(t, tinyCorpus(t, `  - id: case-wrong-tool
    fixture: testdata/a.go
    label: tp
    why: claims a tool that never runs for .go
    finding: {tool: trivy, ruleId: AVD-1234, cwe: ["CWE-78"], severity: high, message: x, line: 4}
    evidenceLines: [3, 4]
`))
	rep := ValidateCorpusAgainstTools(c, nil)

	var found *CorpusIssue
	for i := range rep.Issues {
		if rep.Issues[i].CaseID == "case-wrong-tool" {
			found = &rep.Issues[i]
		}
	}
	if found == nil {
		t.Fatalf("no issue reported for the wrong-tool case: %+v", rep.Issues)
	}
	if found.Skipped {
		t.Error("a tool that never runs must not be reported as skipped — it makes every other claim untestable")
	}
	if !strings.Contains(found.Problem, "gosec") {
		t.Errorf("problem should name the tool that actually runs, got %q", found.Problem)
	}
	if rep.Sound() {
		t.Error("report should not be Sound with a contradicted claim")
	}
}

// Unanalyzable extensions are our gap, not the corpus's, and must never fail.
func TestValidateCorpus_UnwiredExtensionSkips(t *testing.T) {
	c := mustLoad(t, tinyCorpus(t, ""))
	c.Cases = []Case{{
		ID: "case-js", Fixture: "testdata/a.js", Label: LabelTP, Why: "x",
		Finding: FindingSpec{Tool: "eslint", RuleID: "no-eval", Line: 1},
	}}
	rep := ValidateCorpusAgainstTools(c, nil)
	if rep.Skipped != 1 || rep.Mismatch != 0 {
		t.Fatalf("want 1 skipped / 0 mismatch, got %d / %d", rep.Skipped, rep.Mismatch)
	}
	if !rep.Sound() {
		t.Error("a case we cannot check must not fail the run")
	}
}

// The headline guarantee: with no scanners on PATH, every case skips and the check
// still passes. `make eval-gate` runs hermetically in CI and must stay green.
func TestValidateCorpus_MissingScannersSkipEverything(t *testing.T) {
	if _, err := exec.LookPath("gosec"); err == nil {
		t.Skip("gosec is installed; this asserts the no-toolchain path")
	}
	c := mustLoad(t, tinyCorpus(t, ""))
	rep := ValidateCorpusAgainstTools(c, nil)
	if rep.Skipped != len(c.Cases) {
		t.Errorf("want every case skipped without gosec, got %d of %d", rep.Skipped, len(c.Cases))
	}
	if !rep.Sound() {
		t.Error("absent scanners must not read as corpus defects")
	}
}

func TestValidateCorpus_ProgressCalledPerCase(t *testing.T) {
	c := mustLoad(t, tinyCorpus(t, ""))
	var seen int
	ValidateCorpusAgainstTools(c, func(_ string, done, total int) {
		seen++
		if total != len(c.Cases) {
			t.Errorf("total = %d, want %d", total, len(c.Cases))
		}
	})
	if seen != len(c.Cases) {
		t.Errorf("progress called %d times, want %d", seen, len(c.Cases))
	}
}

func TestCorpusCheckReport_WriteSeparatesMismatchesFromSkips(t *testing.T) {
	rep := CorpusCheckReport{
		Cases: 2, Checked: 1, Mismatch: 1, Skipped: 1,
		Issues: []CorpusIssue{
			{CaseID: "bad", Problem: "claims G201 but gosec emits G701", Emitted: []string{"G701"}},
			{CaseID: "unchecked", Problem: "bandit unavailable", Skipped: true},
		},
	}
	var b bytes.Buffer
	rep.Write(&b)
	out := b.String()

	if !strings.Contains(out, "MISMATCHES") || !strings.Contains(out, "bad") {
		t.Error("mismatches should be called out")
	}
	if !strings.Contains(out, "not checked") || !strings.Contains(out, "unchecked") {
		t.Error("skips should be listed separately from mismatches")
	}
	// The fix should be readable straight off the report.
	if !strings.Contains(out, "set ruleId to one of G701") {
		t.Errorf("report should name the emitted rule as the fix:\n%s", out)
	}
}

// The bug this file found: runGosec passed -quiet ("only show output when errors
// are found"), so a CLEAN scan emitted zero bytes and was indistinguishable from a
// crashed one. It biased the fix check exactly backwards — a patch that removed
// every finding scored UNKNOWN while a patch that left another finding behind stayed
// verifiable. A clean scan must be trusted AND empty.
func TestScanSource_CleanGoScanIsTrustedNotUnknown(t *testing.T) {
	if _, err := exec.LookPath("gosec"); err != nil {
		t.Skip("gosec not installed")
	}
	cs := Case{ID: "clean", Fixture: "clean.go", Finding: FindingSpec{Tool: "gosec", RuleID: "G304"}}
	out := scanSource(cs, []byte("package p\n\nfunc add(a, b int) int { return a + b }\n"))

	if !out.trusted {
		t.Fatal("a clean gosec scan must be trusted — otherwise 'nothing found' reads as 'scan failed'")
	}
	if len(out.rules) != 0 {
		t.Errorf("clean file reported rules: %v", out.rules)
	}
	if out.absent {
		t.Error("gosec is installed, so absent must be false")
	}
}

func TestScanSource_VulnerableGoScanReportsTheRule(t *testing.T) {
	if _, err := exec.LookPath("gosec"); err != nil {
		t.Skip("gosec not installed")
	}
	cs := Case{ID: "md5", Fixture: "weak.go", Finding: FindingSpec{Tool: "gosec", RuleID: "G401"}}
	src := "package p\n\nimport \"crypto/md5\"\n\nfunc h(b []byte) []byte {\n\ts := md5.Sum(b)\n\treturn s[:]\n}\n"
	out := scanSource(cs, []byte(src))

	if !out.trusted {
		t.Fatal("scan should be trusted")
	}
	// Guards the other direction: a "trusted, empty" result must mean the file is
	// genuinely clean, not that we stopped parsing the tool's output correctly.
	if !out.rules["G401"] {
		t.Errorf("want G401 on an md5 hash, got %v", out.rules)
	}
}

func TestScanSource_AbsentToolForUnwiredExtension(t *testing.T) {
	cs := Case{ID: "x", Fixture: "a.rb", Finding: FindingSpec{Tool: "railroader", RuleID: "X"}}
	out := scanSource(cs, []byte("puts 1\n"))
	if out.trusted {
		t.Error("an extension with no scanner wired cannot be trusted")
	}
}

func mustLoad(t *testing.T, path string) Corpus {
	t.Helper()
	c, err := LoadCorpus(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A case that was already complete and then declared MORE evidence lines is not
// "still incomplete" — the denominator moved, not the coverage. The compare output
// used to assert incompleteness unconditionally on that branch.
func TestCompareContext_GrownDenominatorIsNotReportedIncomplete(t *testing.T) {
	base := ContextReport{Results: []ContextResult{
		{CaseID: "c", EvidenceTotal: 4, EvidenceVisible: 4},
	}}
	cur := ContextReport{Results: []ContextResult{
		{CaseID: "c", EvidenceTotal: 5, EvidenceVisible: 5},
	}}
	var b bytes.Buffer
	CompareContext(base, cur, &b)
	out := b.String()

	if !strings.Contains(out, "4->5 lines") {
		t.Errorf("should report the growth:\n%s", out)
	}
	if strings.Contains(out, "still incomplete") {
		t.Errorf("5/5 is complete; the report must not claim otherwise:\n%s", out)
	}
}

func TestCompareContext_GenuinelyIncompleteStillSaysSo(t *testing.T) {
	base := ContextReport{Results: []ContextResult{
		{CaseID: "c", EvidenceTotal: 5, EvidenceVisible: 2},
	}}
	cur := ContextReport{Results: []ContextResult{
		{CaseID: "c", EvidenceTotal: 5, EvidenceVisible: 3},
	}}
	var b bytes.Buffer
	CompareContext(base, cur, &b)
	if !strings.Contains(b.String(), "still incomplete") {
		t.Errorf("3 of 5 is incomplete and should say so:\n%s", b.String())
	}
}

func TestFieldMismatches(t *testing.T) {
	base := Case{Finding: FindingSpec{
		Tool: "gosec", RuleID: "G701", Line: 25,
		Severity: "high", Message: "SQL injection via taint analysis",
	}}
	hit := ruleHit{line: 25, severity: "high", message: "SQL injection via taint analysis"}

	if p := fieldMismatches(base, hit); len(p) != 0 {
		t.Errorf("matching metadata should report nothing, got %v", p)
	}

	wrongLine := base
	wrongLine.Finding.Line = 24
	if p := fieldMismatches(wrongLine, hit); len(p) != 1 || !strings.Contains(p[0], "line 24") {
		t.Errorf("want a line mismatch, got %v", p)
	}

	wrongSev := base
	wrongSev.Finding.Severity = "low"
	if p := fieldMismatches(wrongSev, hit); len(p) != 1 || !strings.Contains(p[0], "severity") {
		t.Errorf("want a severity mismatch, got %v", p)
	}

	wrongMsg := base
	wrongMsg.Finding.Message = "SQL string formatting"
	if p := fieldMismatches(wrongMsg, hit); len(p) != 1 || !strings.Contains(p[0], "message") {
		t.Errorf("want a message mismatch, got %v", p)
	}

	// Severity is compared case-insensitively: gosec emits HIGH, the corpus writes high.
	upper := base
	upper.Finding.Severity = "HIGH"
	if p := fieldMismatches(upper, hit); len(p) != 0 {
		t.Errorf("severity compare must be case-insensitive, got %v", p)
	}

	// A field we could not read from the tool is our gap, not a contradiction.
	if p := fieldMismatches(wrongLine, ruleHit{severity: "high", message: base.Finding.Message}); len(p) != 0 {
		t.Errorf("an unreadable line must not be reported as a mismatch, got %v", p)
	}
}

func TestFirstLine(t *testing.T) {
	for in, want := range map[string]int{
		"12": 12, "12-14": 12, " 7 ": 7, "": 0, "abc": 0,
	} {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %d, want %d", in, got, want)
		}
	}
}

// When the rule fired and only a field drifted, "set ruleId" points at a value that
// is already correct.
func TestCorpusCheckReport_NoRuleHintWhenTheRuleWasRight(t *testing.T) {
	rep := CorpusCheckReport{
		Cases: 1, Checked: 1, Mismatch: 1,
		Issues: []CorpusIssue{{
			CaseID: "c", ClaimedRule: "G701", Emitted: []string{"G701"},
			Problem: "declares line 11 but gosec reports line 12",
		}},
	}
	var b bytes.Buffer
	rep.Write(&b)
	if strings.Contains(b.String(), "set ruleId") {
		t.Errorf("the rule id was correct; must not suggest changing it:\n%s", b.String())
	}

	rep.Issues[0].ClaimedRule = "G201"
	var b2 bytes.Buffer
	rep.Write(&b2)
	if !strings.Contains(b2.String(), "set ruleId to one of G701") {
		t.Errorf("a genuinely wrong rule id should still get the hint:\n%s", b2.String())
	}
}
