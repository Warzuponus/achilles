package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// tinyCorpus writes a two-case corpus (one tp, one fp) into a temp dir and
// returns the manifest path.
func tinyCorpus(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package p\n\nfunc f(s string) {\n\tdanger(s)\n}\n"
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(dir, "testdata", name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `version: 1
cases:
  - id: case-tp
    fixture: testdata/a.go
    label: tp
    why: the argument is attacker-controlled
    finding: {tool: gosec, ruleId: G204, cwe: ["CWE-78"], severity: high, message: subprocess, line: 4}
    evidenceLines: [3, 4]
  - id: case-fp
    fixture: testdata/b.go
    label: fp
    why: the argument is a constant
    finding: {tool: gosec, ruleId: G204, cwe: ["CWE-78"], severity: high, message: subprocess, line: 4}
    evidenceLines: [3, 4]
` + extra
	path := filepath.Join(dir, "corpus.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCorpus(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Cases) != 2 {
		t.Fatalf("want 2 cases, got %d", len(c.Cases))
	}
	tp, fp := c.Counts()
	if tp != 1 || fp != 1 {
		t.Errorf("counts = %d tp / %d fp, want 1/1", tp, fp)
	}
	if c.Root == "" {
		t.Error("Root should be set so fixtures resolve")
	}
}

func TestLoadCorpus_RejectsBadCases(t *testing.T) {
	cases := map[string]string{
		"bad label": `
  - id: x
    fixture: testdata/a.go
    label: maybe
    why: unsure
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1]
`,
		"missing why": `
  - id: x
    fixture: testdata/a.go
    label: tp
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1]
`,
		"finding line past EOF": `
  - id: x
    fixture: testdata/a.go
    label: tp
    why: because
    finding: {tool: t, ruleId: r, line: 9999}
    evidenceLines: [1]
`,
		"evidence line past EOF": `
  - id: x
    fixture: testdata/a.go
    label: tp
    why: because
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1, 9999]
`,
		"no evidence lines": `
  - id: x
    fixture: testdata/a.go
    label: tp
    why: because
    finding: {tool: t, ruleId: r, line: 1}
`,
		"duplicate id": `
  - id: case-tp
    fixture: testdata/a.go
    label: fp
    why: because
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1]
`,
		"missing fixture file": `
  - id: x
    fixture: testdata/nope.go
    label: tp
    why: because
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1]
`,
		"missing tool": `
  - id: x
    fixture: testdata/a.go
    label: tp
    why: because
    finding: {ruleId: r, line: 1}
    evidenceLines: [1]
`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadCorpus(tinyCorpus(t, extra)); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}
}

func TestLoadCorpus_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ncases: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpus(path); err == nil {
		t.Error("a corpus with no cases should error")
	}
}

func TestLoadCorpus_ValidationListsEveryProblem(t *testing.T) {
	// One error at a time would make fixing a drifted corpus a slow loop.
	extra := `
  - id: bad1
    fixture: testdata/a.go
    label: nope
    finding: {tool: t, ruleId: r, line: 9999}
    evidenceLines: [9999]
`
	_, err := LoadCorpus(tinyCorpus(t, extra))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"label must be", "missing why", "outside", "validation problem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got:\n%v", want, err)
		}
	}
}

func TestCaseToFinding(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	f := c.SortedCases()[1].ToFinding() // case-tp sorts after case-fp
	if f.Tool != "gosec" || f.RuleID != "G204" {
		t.Errorf("tool/rule not mapped: %+v", f)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Location.Region.StartLine != 4 || f.Location.File != "testdata/a.go" {
		t.Errorf("location not mapped: %+v", f.Location)
	}
	if f.Fingerprint != "eval:case-tp" {
		t.Errorf("fingerprint = %q, want a stable eval-scoped one", f.Fingerprint)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-78" {
		t.Errorf("cwe not mapped: %v", f.CWE)
	}
}

func TestCaseToFinding_UnknownSeverity(t *testing.T) {
	cs := Case{ID: "x", Fixture: "a.go", Finding: FindingSpec{Tool: "t", RuleID: "r", Severity: "bogus", Line: 1}}
	if got := cs.ToFinding().Severity; got != model.SeverityUnknown {
		t.Errorf("severity = %q, want unknown", got)
	}
}

func TestSortedCases_IsStable(t *testing.T) {
	c, err := LoadCorpus(tinyCorpus(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	first := c.SortedCases()
	for i := 0; i < 5; i++ {
		got := c.SortedCases()
		for j := range got {
			if got[j].ID != first[j].ID {
				t.Fatalf("ordering not stable: %v vs %v", got[j].ID, first[j].ID)
			}
		}
	}
	if first[0].ID != "case-fp" {
		t.Errorf("want id-sorted order, got %q first", first[0].ID)
	}
}

func TestLoadCorpus_RejectsFixtureEscapingTheCorpusDir(t *testing.T) {
	// A manifest is untrusted data: it must not be able to make the harness read
	// (and prompt with) a file outside the corpus.
	extra := `
  - id: traversal
    fixture: ../../../../../../etc/passwd
    label: tp
    why: attempted escape
    finding: {tool: t, ruleId: r, line: 1}
    evidenceLines: [1]
`
	_, err := LoadCorpus(tinyCorpus(t, extra))
	if err == nil {
		t.Fatal("a fixture outside the corpus directory must be rejected")
	}
	if !strings.Contains(err.Error(), "escapes the corpus directory") {
		t.Errorf("error should name the reason, got: %v", err)
	}
}
