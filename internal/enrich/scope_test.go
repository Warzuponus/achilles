package enrich

import (
	"strings"
	"testing"
)

// lns turns a literal source block into the 1-indexed line slice the scope
// helpers work on. The leading newline in each test's raw string is dropped.
func lns(src string) []string {
	return strings.Split(strings.TrimPrefix(src, "\n"), "\n")
}

const goSrc = `
package app

import "database/sql"

func lookup(db *sql.DB, name string) error {
	if name == "" {
		return nil
	}
	q := "SELECT * FROM users WHERE name = '" + name + "'"
	_, err := db.Query(q)
	return err
}

func other() {}
`

func TestEnclosingScope_GoFunction(t *testing.T) {
	lines := lns(goSrc)
	// line 10 is the concatenated query inside lookup (lines 5-12).
	s, ok := enclosingScope(lines, 10, 10, 120, styleBrace)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "func lookup") {
		t.Errorf("scope should start at the function signature, got line %d: %q", s.lo, got)
	}
	if got := strings.TrimSpace(lines[s.hi-1]); got != "}" {
		t.Errorf("scope should end at the closing brace, got line %d: %q", s.hi, got)
	}
	if s.truncated {
		t.Error("a short function should not be truncated")
	}
}

func TestEnclosingScope_PicksInnermostBlock(t *testing.T) {
	lines := lns(goSrc)
	// line 7 is inside the `if` block (lines 6-8), not just the function.
	s, ok := enclosingScope(lines, 7, 7, 120, styleBrace)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "if name") {
		t.Errorf("want the innermost enclosing block, got line %d: %q", s.lo, got)
	}
}

func TestEnclosingScope_BraceOnOwnLinePullsInSignature(t *testing.T) {
	lines := lns(`
public class T
{
    void run(String cmd)
    {
        Runtime.getRuntime().exec(cmd);
    }
}
`)
	s, ok := enclosingScope(lines, 5, 5, 120, styleBrace)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "void run") {
		t.Errorf("Java-style brace should still capture the signature, got line %d: %q", s.lo, got)
	}
}

func TestEnclosingScope_IgnoresBracesInStringsAndComments(t *testing.T) {
	lines := lns(`
func f() {
	s := "}{ not real braces }"
	// } neither is this {
	danger(s)
}
`)
	s, ok := enclosingScope(lines, 4, 4, 120, styleBrace)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "func f") {
		t.Errorf("braces in literals/comments must not shift the scope, got line %d: %q", s.lo, got)
	}
	if got := strings.TrimSpace(lines[s.hi-1]); got != "}" {
		t.Errorf("scope should close at the real brace, got line %d: %q", s.hi, got)
	}
}

func TestEnclosingScope_PythonFunction(t *testing.T) {
	lines := lns(`
import subprocess


def run(cmd):
    if cmd:
        subprocess.call(cmd, shell=True)
    return 0


def other():
    pass
`)
	s, ok := enclosingScope(lines, 6, 6, 120, styleIndent)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "def run") {
		t.Errorf("want the enclosing def, got line %d: %q", s.lo, got)
	}
	if got := strings.TrimSpace(lines[s.hi-1]); got != "return 0" {
		t.Errorf("scope should end at the last body line, got line %d: %q", s.hi, got)
	}
}

func TestEnclosingScope_PythonMethodInsideClass(t *testing.T) {
	lines := lns(`
class Handler:
    def get(self, raw):
        return eval(raw)

    def post(self):
        pass
`)
	s, ok := enclosingScope(lines, 3, 3, 120, styleIndent)
	if !ok {
		t.Fatal("expected a resolved scope")
	}
	if got := strings.TrimSpace(lines[s.lo-1]); !strings.HasPrefix(got, "def get") {
		t.Errorf("want the method, not the class, got line %d: %q", s.lo, got)
	}
	if s.hi != 3 {
		t.Errorf("scope should stop before the next def, got hi=%d", s.hi)
	}
}

func TestEnclosingScope_TruncatesOversizedScope(t *testing.T) {
	var b strings.Builder
	b.WriteString("\nfunc big() {\n")
	for i := 0; i < 400; i++ {
		b.WriteString("\tstep()\n")
	}
	b.WriteString("}\n")
	lines := lns(b.String())

	s, ok := enclosingScope(lines, 200, 200, 40, styleBrace)
	if !ok {
		t.Fatal("an oversized scope should still resolve, clamped")
	}
	if got := s.hi - s.lo + 1; got > 40 {
		t.Errorf("scope not clamped: %d lines (max 40)", got)
	}
	if !s.truncated {
		t.Error("a clamped scope must be marked truncated")
	}
	if s.lo > 200 || s.hi < 200 {
		t.Errorf("the clamped window must still contain the flagged line: %+v", s)
	}
}

func TestEnclosingScope_UnknownLanguageDeclines(t *testing.T) {
	if _, ok := enclosingScope(lns("\na: 1\nb: 2\n"), 2, 2, 120, styleNone); ok {
		t.Error("styleNone must decline so the caller keeps its fixed radius")
	}
}

func TestEnclosingScope_TopLevelCodeDeclines(t *testing.T) {
	// No enclosing block at all — decline rather than invent one.
	if _, ok := enclosingScope(lns("\npackage app\n\nvar x = 1\n"), 3, 3, 120, styleBrace); ok {
		t.Error("code outside any block should decline")
	}
	if _, ok := enclosingScope(lns("\nimport os\nos.system(cmd)\n"), 2, 2, 120, styleIndent); ok {
		t.Error("python module-level code should decline")
	}
}

func TestEnclosingScope_GuardsBadInput(t *testing.T) {
	lines := lns(goSrc)
	cases := []struct {
		name                 string
		start, end, maxLines int
	}{
		{"line 0", 0, 0, 120},
		{"past EOF", 9999, 9999, 120},
		{"zero cap disables", 10, 10, 0},
	}
	for _, c := range cases {
		if _, ok := enclosingScope(lines, c.start, c.end, c.maxLines, styleBrace); ok {
			t.Errorf("%s: expected no scope", c.name)
		}
	}
}

func TestStyleFor(t *testing.T) {
	cases := map[string]scopeStyle{
		"a/b.go": styleBrace, "x.java": styleBrace, "x.TS": styleBrace,
		"main.tf": styleBrace, "x.cpp": styleBrace,
		"s.py":   styleIndent,
		"c.yaml": styleNone, "s.sh": styleNone, "x.rb": styleNone, "noext": styleNone,
	}
	for path, want := range cases {
		if got := styleFor(path); got != want {
			t.Errorf("styleFor(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestStripNonCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{`if x { // }`, `if x { `},
		{`s := "a{b}c"`, `s := `},
		{`# }{`, ``},
		{`c := '}'`, `c := `},
		{`s := "esc\" }"`, `s := `},
		{"r := `raw } str`", "r := "},
		{`plain { code }`, `plain { code }`},
	}
	for _, c := range cases {
		if got := stripNonCode(c.in); got != c.want {
			t.Errorf("stripNonCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIndentWidth(t *testing.T) {
	// A whitespace-only line counts every column; callers skip blank lines before
	// ever asking, so this case is academic.
	cases := map[string]int{"": 0, "x": 0, "  x": 2, "\tx": 4, "\t  x": 6, "    ": 4}
	for in, want := range cases {
		if got := indentWidth(in); got != want {
			t.Errorf("indentWidth(%q) = %d, want %d", in, got, want)
		}
	}
}
