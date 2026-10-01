package enrich

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

const goRefSrc = `package cases

import (
	"crypto/md5"
	"encoding/hex"
)

const reportTable = "monthly_totals"

var allowed = map[string]string{
	"status": "systemctl status nginx",
}

// cacheKey returns a hex digest of the given value.
func cacheKey(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// authenticate reports whether the password matches the stored digest.
func authenticate(password, storedDigest string) bool {
	return cacheKey(password) == storedDigest
}
`

func TestFileScopeDecls_Go(t *testing.T) {
	decls := fileScopeDecls(lns(goRefSrc), styleBrace)
	want := map[string]int{"reportTable": 8, "allowed": 10, "cacheKey": 15, "authenticate": 21}
	for id, line := range want {
		if got := decls[id]; got != line {
			t.Errorf("decls[%q] = %d, want %d", id, got, line)
		}
	}
	// Locals must NOT be treated as file-scope declarations.
	for _, id := range []string{"sum", "value", "password"} {
		if _, ok := decls[id]; ok {
			t.Errorf("%q is a local, not a file-scope decl", id)
		}
	}
}

func TestFileScopeDecls_GoGroupedConsts(t *testing.T) {
	src := `package p

const (
	alpha = "a"
	beta  = "b"
)

var (
	gamma = 1
)
`
	decls := fileScopeDecls(lns(src), styleBrace)
	for id, line := range map[string]int{"alpha": 4, "beta": 5, "gamma": 9} {
		if got := decls[id]; got != line {
			t.Errorf("decls[%q] = %d, want %d", id, got, line)
		}
	}
}

func TestFileScopeDecls_Python(t *testing.T) {
	src := `import subprocess

DATA_DIR = "/var/app/data"
LIMIT: int = 5


def archive():
    user_input = DATA_DIR
    return subprocess.check_output(user_input, shell=True)


class Handler:
    pass
`
	decls := fileScopeDecls(lns(src), styleIndent)
	for id, line := range map[string]int{"DATA_DIR": 3, "LIMIT": 4, "archive": 7, "Handler": 12} {
		if got := decls[id]; got != line {
			t.Errorf("decls[%q] = %d, want %d", id, got, line)
		}
	}
	if _, ok := decls["user_input"]; ok {
		t.Error("an indented assignment is a local, not a module-level decl")
	}
}

func TestFileScopeDecls_IgnoresStringsAndComments(t *testing.T) {
	src := `package p

// const decoy = "x"
var real = "const notADecl = 1"
`
	decls := fileScopeDecls(lns(src), styleBrace)
	if _, ok := decls["decoy"]; ok {
		t.Error("a declaration inside a comment must not register")
	}
	if _, ok := decls["notADecl"]; ok {
		t.Error("a declaration inside a string literal must not register")
	}
	if decls["real"] != 4 {
		t.Errorf("real should be line 4, got %d", decls["real"])
	}
}

func TestIdentsIn_SkipsKeywordsStringsAndComments(t *testing.T) {
	lines := lns(`x := "secretIdentifier" // commentIdentifier
return reportTable
`)
	got := strings.Join(identsIn(lines, 1, 2), ",")
	for _, bad := range []string{"secretIdentifier", "commentIdentifier", "return"} {
		if strings.Contains(got, bad) {
			t.Errorf("identsIn should not yield %q, got %v", bad, got)
		}
	}
	if !strings.Contains(got, "reportTable") {
		t.Errorf("identsIn should yield reportTable, got %v", got)
	}
}

func TestEnclosingFuncName(t *testing.T) {
	lines := lns(goRefSrc)
	if got := enclosingFuncName(lines, 15); got != "cacheKey" {
		t.Errorf("got %q, want cacheKey", got)
	}
	// A blank or non-declaring line yields nothing — the bug that silently
	// disabled call sites was passing such a line in.
	if got := enclosingFuncName(lines, 9); got != "" {
		t.Errorf("a blank line should not yield a name, got %q", got)
	}
	if got := enclosingFuncName(lns("def handler(req):\n    pass\n"), 1); got != "handler" {
		t.Errorf("python def: got %q, want handler", got)
	}
	if got := enclosingFuncName(lns("func (s *Server) Handle(w http.ResponseWriter) {\n}\n"), 1); got != "Handle" {
		t.Errorf("method: got %q, want Handle", got)
	}
}

func TestCallSites(t *testing.T) {
	lines := lns(goRefSrc)
	// cacheKey is declared at 15-18 and called at 22.
	got := callSites(lines, "cacheKey", 15, 18, 3)
	if len(got) != 1 || got[0] != 22 {
		t.Errorf("callSites = %v, want [22]", got)
	}
	if got := callSites(lines, "cacheKey", 1, 40, 3); len(got) != 0 {
		t.Errorf("a call inside the excluded window is not a call site, got %v", got)
	}
	if got := callSites(lines, "", 1, 2, 3); got != nil {
		t.Errorf("no name means no call sites, got %v", got)
	}
	if got := callSites(lines, "cacheKey", 15, 18, 0); got != nil {
		t.Errorf("a zero budget disables call sites, got %v", got)
	}
}

func TestCallSites_SkipsTheDeclarationItself(t *testing.T) {
	// Excluding only [lo,hi] is not enough if another declaration of the same name
	// exists; a header line is never a call.
	lines := lns("package p\n\nfunc run() {}\n\nfunc run2() { run() }\n")
	got := callSites(lines, "run", 1, 1, 3)
	for _, n := range got {
		if n == 3 {
			t.Errorf("line 3 is the declaration, not a call site: %v", got)
		}
	}
}

func TestGatherReferences_PrefersSpanIdentifiersUnderBudget(t *testing.T) {
	// With a budget of 1, the identifier used ON the flagged line wins over one
	// used merely elsewhere in the function.
	src := `package p

const spanConst = "s"
const otherConst = "o"

func f() {
	_ = otherConst
	_ = spanConst
}
`
	refs := gatherReferences(refRequest{
		lines: lns(src), spanLo: 8, spanHi: 8, winLo: 6, winHi: 9, scopeLo: 6,
		maxRefs: 1, maxCalls: 0, style: styleBrace,
	})
	if len(refs) != 1 || refs[0].line != 3 {
		t.Errorf("want only the span's decl (line 3), got %+v", refs)
	}
}

func TestGatherReferences_SkipsAlreadyVisibleLines(t *testing.T) {
	src := `package p

const c = "x"

func f() {
	_ = c
}
`
	// A window that already covers line 3 should not re-add it.
	refs := gatherReferences(refRequest{
		lines: lns(src), spanLo: 6, spanHi: 6, winLo: 1, winHi: 7, scopeLo: 5,
		maxRefs: 5, maxCalls: 2, style: styleBrace,
	})
	for _, r := range refs {
		if r.line == 3 {
			t.Errorf("line 3 is already in the window; refs=%+v", refs)
		}
	}
}

func TestGatherReferences_UnknownLanguageYieldsNothing(t *testing.T) {
	refs := gatherReferences(refRequest{
		lines: lns("a: 1\nb: 2\n"), spanLo: 2, spanHi: 2, winLo: 1, winHi: 2, scopeLo: 1,
		maxRefs: 5, maxCalls: 2, style: styleNone,
	})
	if refs != nil {
		t.Errorf("styleNone must yield no references, got %+v", refs)
	}
}

// ---- Context() integration: the regression this feature exists for ----

func TestContext_IncludesCallSiteOfEnclosingFunction(t *testing.T) {
	// The eval case go-trap-md5-auth-compare: MD5 in a function named cacheKey,
	// proved to be a credential check only by its caller. This was answered
	// false_positive at 0.95 confidence before the caller was in the prompt.
	dir := write(t, "auth.go", goRefSrc)
	f := model.Finding{Location: model.Location{File: "auth.go", Region: model.Region{StartLine: 16, EndLine: 16}}}
	ctx := New(3).Context(f, dir)

	if !strings.Contains(ctx, "cacheKey(password) == storedDigest") {
		t.Errorf("the call site must be in the context:\n%s", ctx)
	}
	if !strings.Contains(ctx, "callers of this function") {
		t.Errorf("the call site needs a heading so it isn't read as adjacent code:\n%s", ctx)
	}
	// Real line numbers are preserved, so the model can see it is not contiguous.
	if !strings.Contains(ctx, "  22 |") {
		t.Errorf("call-site line number should be shown:\n%s", ctx)
	}
}

func TestContext_IncludesReferencedFileScopeDecl(t *testing.T) {
	dir := write(t, "q.go", `package p

import (
	"database/sql"
	"fmt"
)

const reportTable = "monthly_totals"

func totals(db *sql.DB) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s", reportTable)
	return db.Query(query)
}
`)
	// Radius 1, because a radius-3 window would already include line 8 — in which
	// case there is correctly nothing to add.
	f := model.Finding{Location: model.Location{File: "q.go", Region: model.Region{StartLine: 11, EndLine: 11}}}
	ctx := New(1).Context(f, dir)

	if !strings.Contains(ctx, `const reportTable = "monthly_totals"`) {
		t.Errorf("the referenced constant decides the verdict and must be present:\n%s", ctx)
	}
	if !strings.Contains(ctx, "referenced at file scope") {
		t.Errorf("declarations need their own heading:\n%s", ctx)
	}
}

func TestContext_ReferencesDisabledByBudgetZero(t *testing.T) {
	dir := write(t, "q.go", goRefSrc)
	f := model.Finding{Location: model.Location{File: "q.go", Region: model.Region{StartLine: 16, EndLine: 16}}}

	e := New(3)
	e.MaxRefLines, e.MaxCallSites = 0, 0
	ctx := e.Context(f, dir)

	if strings.Contains(ctx, "referenced at file scope") || strings.Contains(ctx, "callers of this function") {
		t.Errorf("zero budgets must disable both sections:\n%s", ctx)
	}
}

func TestContext_ReferencesRespectMaxScopeLinesZero(t *testing.T) {
	// MaxScopeLines = 0 means "pure fixed radius", which implies no references
	// either — otherwise the escape hatch would not restore the old behaviour.
	dir := write(t, "q.go", goRefSrc)
	f := model.Finding{Location: model.Location{File: "q.go", Region: model.Region{StartLine: 16, EndLine: 16}}}

	e := New(1)
	e.MaxScopeLines = 0
	ctx := e.Context(f, dir)

	if strings.Contains(ctx, "callers of this function") || strings.Contains(ctx, "referenced at file scope") {
		t.Errorf("MaxScopeLines=0 should restore pure fixed-radius:\n%s", ctx)
	}
	if n := len(strings.Split(ctx, "\n")); n != 3 {
		t.Errorf("radius 1 around one line = 3 lines, got %d:\n%s", n, ctx)
	}
}

func TestContext_NoReferencesLeavesOutputUnlabelled(t *testing.T) {
	// A self-contained finding should render exactly as before — no headings, so
	// the common case gains no noise.
	dir := write(t, "q.go", "package p\n\nfunc f() {\n\tdanger()\n}\n")
	f := model.Finding{Location: model.Location{File: "q.go", Region: model.Region{StartLine: 4, EndLine: 4}}}
	ctx := New(1).Context(f, dir)

	if strings.Contains(ctx, "// the finding:") {
		t.Errorf("no references means no section headings:\n%s", ctx)
	}
}
