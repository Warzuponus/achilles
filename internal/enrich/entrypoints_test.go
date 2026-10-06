package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

const routedGo = `package app

import (
	"net/http"
	"os/exec"
)

func register(mux *http.ServeMux) {
	mux.HandleFunc("POST /run", run)
}

func run(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.FormValue("cmd")).Run()
}
`

func finding(file string, line int) model.Finding {
	return model.Finding{Location: model.Location{File: file, Region: model.Region{StartLine: line, EndLine: line}}}
}

func TestContext_ListsEntryPointsOfTheFindingsOwnFile(t *testing.T) {
	dir := write(t, "app.go", routedGo)
	ctx := New(2).Context(finding("app.go", 13), dir)

	if !strings.Contains(ctx, "HTTP route POST /run (line 9)") {
		t.Errorf("entry-point hint missing:\n%s", ctx)
	}
	if !strings.Contains(ctx, "NOT evidence of unreachability") {
		t.Errorf("hint block must say absence is not evidence:\n%s", ctx)
	}
	// The hints sit ahead of the numbered code, and do not look like code lines to
	// anything that parses the numbered block (the eval harness does).
	if strings.Index(ctx, "This file exposes") > strings.Index(ctx, "|") {
		t.Errorf("hints should precede the code:\n%s", ctx)
	}
}

func TestContext_NoHintsWhenFileHasNone(t *testing.T) {
	dir := write(t, "a.go", contextGo)
	if ctx := New(2).Context(finding("a.go", 6), dir); strings.Contains(ctx, "This file exposes") {
		t.Errorf("no entry points, so no block expected:\n%s", ctx)
	}
}

func TestContext_EntryHintsCanBeDisabled(t *testing.T) {
	dir := write(t, "app.go", routedGo)
	en := New(2)
	en.MaxEntryHints = 0
	if ctx := en.Context(finding("app.go", 13), dir); strings.Contains(ctx, "This file exposes") {
		t.Errorf("MaxEntryHints=0 must disable hints:\n%s", ctx)
	}
}

func TestContext_EntryHintsNeverLookAcrossFiles(t *testing.T) {
	// The route lives in another file; the finding's file must not claim it.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.go"), []byte(routedGo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "util.go"), []byte(contextGo), 0o644); err != nil {
		t.Fatal(err)
	}
	if ctx := New(2).Context(finding("util.go", 6), dir); strings.Contains(ctx, "/run") {
		t.Errorf("a hint from another file leaked in:\n%s", ctx)
	}
}

func TestContext_EntryHintsAreBoundedAndNearestFirst(t *testing.T) {
	var b strings.Builder
	b.WriteString("package app\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "func init%d() { http.HandleFunc(\"/r%d\", h) }\n", i, i)
	}
	dir := write(t, "many.go", b.String())
	ctx := New(0).Context(finding("many.go", 28), dir) // near /r26..

	n := strings.Count(ctx, "HTTP route")
	if n != defaultMaxEntryHints {
		t.Errorf("hints listed = %d, want cap %d", n, defaultMaxEntryHints)
	}
	if !strings.Contains(ctx, "/r26") || strings.Contains(ctx, "/r0 ") {
		t.Errorf("hints nearest the finding should win:\n%s", ctx)
	}
}
