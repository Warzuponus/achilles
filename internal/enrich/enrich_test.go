package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestContext_ReadsSurroundingLines(t *testing.T) {
	dir := t.TempDir()
	src := "l1\nl2\nl3_BUG\nl4\nl5\n"
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	f := model.Finding{Location: model.Location{File: "a.py", Region: model.Region{StartLine: 3, EndLine: 3}}}
	ctx := New(1).Context(f, dir)

	if !strings.Contains(ctx, "l2") || !strings.Contains(ctx, "l4") {
		t.Errorf("expected 1 line of context each side:\n%s", ctx)
	}
	if strings.Contains(ctx, "l1") || strings.Contains(ctx, "l5") {
		t.Errorf("radius 1 should not include l1/l5:\n%s", ctx)
	}
	// The flagged line is marked.
	for _, line := range strings.Split(ctx, "\n") {
		if strings.Contains(line, "l3_BUG") && !strings.HasPrefix(line, ">>") {
			t.Errorf("flagged line should be marked with >>: %q", line)
		}
	}
}

// write puts src in a temp dir and returns the dir.
func write(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const contextGo = `package app

import "os/exec"

func run(userInput string) error {
	if userInput == "" {
		return nil
	}
	cmd := exec.Command("sh", "-c", userInput)
	return cmd.Run()
}
`

func TestContext_WidensToEnclosingFunction(t *testing.T) {
	dir := write(t, "run.go", contextGo)
	// Line 9 builds the command; a radius of 1 would show only lines 8-10 and
	// hide both the signature and the guard clause that triage needs.
	f := model.Finding{Location: model.Location{File: "run.go", Region: model.Region{StartLine: 9, EndLine: 9}}}
	ctx := New(1).Context(f, dir)

	for _, want := range []string{"func run(userInput string) error", "if userInput ==", "return cmd.Run()"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("context should include %q:\n%s", want, ctx)
		}
	}
	// Still scoped: the package clause above the function is not swept in.
	if strings.Contains(ctx, "package app") {
		t.Errorf("context should stop at the function, not the file:\n%s", ctx)
	}
	if strings.Contains(ctx, "truncated") {
		t.Errorf("a short function should not be marked truncated:\n%s", ctx)
	}
}

func TestContext_RadiusIsAFloorNotACeiling(t *testing.T) {
	// A one-line scope must not shrink the window below the configured radius —
	// scope-awareness can only ever add context.
	dir := write(t, "t.go", "package app\n\nfunc a() { danger() }\n\nfunc b() {}\n")
	f := model.Finding{Location: model.Location{File: "t.go", Region: model.Region{StartLine: 3, EndLine: 3}}}

	ctx := New(2).Context(f, dir)
	if !strings.Contains(ctx, "package app") {
		t.Errorf("radius 2 should still reach line 1:\n%s", ctx)
	}
	if !strings.Contains(ctx, "func b()") {
		t.Errorf("radius 2 should still reach line 5:\n%s", ctx)
	}
}

func TestContext_MarksTruncatedScope(t *testing.T) {
	var b strings.Builder
	b.WriteString("package app\n\nfunc big() {\n")
	for i := 0; i < 300; i++ {
		b.WriteString("\tstep()\n")
	}
	b.WriteString("\tdanger()\n}\n")
	dir := write(t, "big.go", b.String())

	f := model.Finding{Location: model.Location{File: "big.go", Region: model.Region{StartLine: 200, EndLine: 200}}}
	e := New(1)
	e.MaxScopeLines = 30
	ctx := e.Context(f, dir)

	if !strings.Contains(ctx, "truncated") {
		t.Errorf("an oversized scope should say so:\n%s", ctx)
	}
	// Body lines only, plus the one-line notice.
	if got := len(strings.Split(ctx, "\n")); got > 31 {
		t.Errorf("context should be capped near 30 lines, got %d", got)
	}
	if !strings.Contains(ctx, ">>") {
		t.Errorf("the flagged line must survive truncation:\n%s", ctx)
	}
}

func TestContext_MaxScopeLinesZeroRestoresFixedRadius(t *testing.T) {
	dir := write(t, "run.go", contextGo)
	f := model.Finding{Location: model.Location{File: "run.go", Region: model.Region{StartLine: 9, EndLine: 9}}}

	e := New(1)
	e.MaxScopeLines = 0 // the escape hatch
	ctx := e.Context(f, dir)

	if strings.Contains(ctx, "func run(") {
		t.Errorf("with scope disabled, radius 1 must not reach the signature:\n%s", ctx)
	}
	if n := len(strings.Split(ctx, "\n")); n != 3 {
		t.Errorf("radius 1 around one line = 3 lines, got %d:\n%s", n, ctx)
	}
}

func TestContext_UnknownLanguageKeepsRadius(t *testing.T) {
	// YAML has no scope strategy; behaviour must be exactly as before.
	dir := write(t, "c.yaml", "a: 1\nb: 2\nc: BUG\nd: 4\ne: 5\n")
	f := model.Finding{Location: model.Location{File: "c.yaml", Region: model.Region{StartLine: 3, EndLine: 3}}}
	ctx := New(1).Context(f, dir)

	if n := len(strings.Split(ctx, "\n")); n != 3 {
		t.Errorf("want an unchanged 3-line radius window, got %d:\n%s", n, ctx)
	}
}

func TestContext_PythonWidensToDef(t *testing.T) {
	dir := write(t, "h.py", "import subprocess\n\n\ndef run(cmd):\n    if cmd:\n        subprocess.call(cmd, shell=True)\n    return 0\n")
	f := model.Finding{Location: model.Location{File: "h.py", Region: model.Region{StartLine: 6, EndLine: 6}}}
	ctx := New(0).Context(f, dir)

	if !strings.Contains(ctx, "def run(cmd):") {
		t.Errorf("context should include the enclosing def:\n%s", ctx)
	}
	if strings.Contains(ctx, "import subprocess") {
		t.Errorf("context should stop at the def, not the module:\n%s", ctx)
	}
}

func TestContext_FallsBackToSnippet(t *testing.T) {
	f := model.Finding{
		Location:    model.Location{File: "does/not/exist.py", Region: model.Region{StartLine: 1}},
		CodeContext: "eval(x)",
	}
	if got := New(2).Context(f, "/nonexistent-root"); got != "eval(x)" {
		t.Errorf("want fallback to snippet, got %q", got)
	}
}
