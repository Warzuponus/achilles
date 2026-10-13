package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestParse(t *testing.T) {
	cases := []struct {
		line   string
		ok     bool
		rules  string
		reason string
		alone  bool
		why    string // non-empty: a marker, but not one that can be honoured
	}{
		{line: `x = 1`, ok: false},
		{line: `run(cmd)  # achilles:ignore B602 -- cmd is a constant`, ok: true, rules: "B602", reason: "cmd is a constant"},
		{line: `// achilles:ignore gosec:G204 -- validated by resolveTool`, ok: true, rules: "gosec:G204", reason: "validated by resolveTool", alone: true},
		{line: "\t# achilles:ignore B602, B603 -- both fine here", ok: true, rules: "B602 B603", reason: "both fine here", alone: true},
		{line: `/* achilles:ignore sqli -- parameters are bound */`, ok: true, rules: "sqli", reason: "parameters are bound", alone: true},
		{line: `<!-- achilles:ignore xss -- static page -->`, ok: true, rules: "xss", reason: "static page", alone: true},
		{line: `-- achilles:ignore sqli -- reviewed`, ok: true, rules: "sqli", reason: "reviewed", alone: true},
		{line: `// ACHILLES:IGNORE G204 -- upper case is the same marker`, ok: true, rules: "G204", reason: "upper case is the same marker", alone: true},
		// Not honoured: no reason, an empty reason, no rule.
		{line: `// achilles:ignore G204`, ok: true, rules: "G204", alone: true, why: "no reason"},
		{line: `// achilles:ignore G204 --   `, ok: true, rules: "G204", alone: true, why: "no reason"},
		{line: `// achilles:ignore -- because`, ok: true, reason: "because", alone: true, why: "no rule"},
		{line: `// achilles:ignore`, ok: true, alone: true, why: "no rule"},
		// A longer word is not the marker.
		{line: `// achilles:ignored G204 -- typo`, ok: false},
	}
	for _, c := range cases {
		m, why, ok := Parse(c.line)
		if ok != c.ok {
			t.Errorf("%q: marker found = %v, want %v", c.line, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got := strings.Join(m.Rules, " "); got != c.rules || m.Reason != c.reason || m.Alone != c.alone {
			t.Errorf("%q: rules=%q reason=%q alone=%v, want %q %q %v", c.line, got, m.Reason, m.Alone, c.rules, c.reason, c.alone)
		}
		if (why == "") != (c.why == "") || !strings.Contains(why, c.why) {
			t.Errorf("%q: why = %q, want one about %q", c.line, why, c.why)
		}
	}

	// A reason is bounded: it is copied into every report.
	m, _, _ := Parse("// achilles:ignore R -- " + strings.Repeat("because ", 200))
	if len(m.Reason) > maxReason+8 {
		t.Errorf("reason is %d bytes", len(m.Reason))
	}
}

func TestCovers(t *testing.T) {
	gosec := model.Finding{Tool: "gosec", RuleID: "G204"}
	long := model.Finding{Tool: "opengrep", RuleID: "python.lang.security.dangerous-system-call"}
	for _, c := range []struct {
		rules string
		f     model.Finding
		want  bool
	}{
		{"G204", gosec, true},
		{"g204", gosec, true},
		{"gosec:G204", gosec, true},
		{"bandit:G204", gosec, false}, // another tool's rule of the same name
		{"G20", gosec, false},
		{"G2040", gosec, false},
		{"G101 G204", gosec, true},
		{"python.lang.security.dangerous-system-call", long, true},
		{"dangerous-system-call", long, true},
		{"system-call", long, false}, // a whole segment, not a suffix
		{"security.dangerous-system-call", long, false},
		{"*", gosec, false}, // there is no "everything"
	} {
		m := Marker{Rules: strings.Fields(c.rules)}
		if got := m.Covers(c.f); got != c.want {
			t.Errorf("marker %q covers %s:%s = %v, want %v", c.rules, c.f.Tool, c.f.RuleID, got, c.want)
		}
	}
	if (Marker{Rules: []string{""}}).Covers(model.Finding{}) {
		t.Error("a finding with no rule id cannot be named by a marker")
	}
}

func at(tool, rule, file string, line int) model.Finding {
	return model.Finding{Tool: tool, RuleID: rule, Location: model.Location{File: file, Region: model.Region{StartLine: line}}}
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app.py", strings.Join([]string{
		"import os", // 1
		"os.system(a)  # achilles:ignore B605 -- a is a constant", // 2: same line
		"# achilles:ignore B605 -- reviewed in #12",               // 3: alone, speaks for line 4
		"os.system(b)", // 4
		"os.system(c)  # achilles:ignore B605 -- only this line", // 5
		"os.system(d)",                           // 6: the trailing marker above is not about this line
		"# achilles:ignore B605",                 // 7: no reason
		"os.system(e)",                           // 8
		"# achilles:ignore B602 -- another rule", // 9
		"os.system(f)",                           // 10
		"",
	}, "\n"))
	write(t, root, "win.py", "import os\r\n# achilles:ignore B605 -- CRLF file\r\nos.system(g)\r\n")

	findings := []model.Finding{
		at("bandit", "B605", "app.py", 2),
		at("bandit", "B605", "app.py", 4),
		at("bandit", "B605", "app.py", 5),
		at("bandit", "B605", "app.py", 6),
		at("bandit", "B605", "app.py", 8),
		at("bandit", "B605", "app.py", 10),
		at("bandit", "B605", "win.py", 3),
		at("bandit", "B605", "missing.py", 1),
		at("bandit", "B605", "app.py", 99), // past the end of the file
		at("bandit", "B605", "../outside.py", 1),
	}
	res := Find(root, findings)

	want := map[int]int{0: 2, 1: 3, 2: 5, 6: 2} // finding index -> line of the marker that suppresses it
	if len(res.Markers) != len(want) {
		t.Errorf("suppressed %d finding(s), want %d: %+v", len(res.Markers), len(want), res.Markers)
	}
	for i, line := range want {
		m, ok := res.Markers[i]
		if !ok || m.Line != line {
			t.Errorf("finding %d (%s:%d): marker = %+v (found %v), want the one on line %d",
				i, findings[i].Location.File, findings[i].Location.Region.StartLine, m, ok, line)
		}
	}
	if m := res.Markers[1]; m.Reason != "reviewed in #12" {
		t.Errorf("reason = %q", m.Reason)
	}
	// The marker with no reason is reported, once, and its finding stays.
	if len(res.Problems) != 1 || res.Problems[0].Line != 7 || !strings.Contains(res.Problems[0].Why, "no reason") {
		t.Errorf("problems = %+v", res.Problems)
	}
}

// What a comment may not suppress, however it is written.
func TestFind_KindsThatCannotBeSuppressed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", "KEY = 'x'  # achilles:ignore generic-api-key, GHSA-aaaa-bbbb-cccc, G204 -- it is fine\n")

	secret := at("gitleaks", "generic-api-key", "config.py", 1)
	advisory := at("osv-scanner", "GHSA-aaaa-bbbb-cccc", "config.py", 1)
	inHistory := at("gosec", "G204", "config.py", 1)
	inHistory.Commit = "689bd12734c6a21c4431adae399f29b9d181649b"
	noLine := at("gosec", "G204", "config.py", 0)
	code := at("gosec", "G204", "config.py", 1)

	res := Find(root, []model.Finding{secret, advisory, inHistory, noLine, code})
	if len(res.Markers) != 1 {
		t.Fatalf("suppressed %d finding(s), want only the finding in code: %+v", len(res.Markers), res.Markers)
	}
	if _, ok := res.Markers[4]; !ok {
		t.Errorf("the code finding was not suppressed: %+v", res.Markers)
	}
	for _, f := range []model.Finding{secret, advisory, inHistory, noLine} {
		if Suppressible(f) {
			t.Errorf("%s:%s must not be suppressible by a comment", f.Tool, f.RuleID)
		}
	}
}

// Markers are read from inside the scanned tree only. A link that leaves it is not
// followed, so a repository cannot point a "source file" at a file elsewhere.
func TestFind_DoesNotReadOutsideTheRoot(t *testing.T) {
	outside := t.TempDir()
	write(t, outside, "secret.py", "x()  # achilles:ignore R -- from outside\n")
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.py"), filepath.Join(root, "link.py")); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	res := Find(root, []model.Finding{at("t", "R", "link.py", 1)})
	if len(res.Markers) != 0 {
		t.Errorf("a marker was read through a link that leaves the scanned tree: %+v", res.Markers)
	}
}

func TestFind_NoRoot(t *testing.T) {
	res := Find(filepath.Join(t.TempDir(), "does-not-exist"), []model.Finding{at("t", "R", "a.py", 1)})
	if len(res.Markers) != 0 || len(res.Problems) != 0 {
		t.Errorf("res = %+v", res)
	}
}
