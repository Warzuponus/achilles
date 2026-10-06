package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
	"github.com/Warzuponus/achilles/internal/vault"
)

// ---------- fixtures for the tests ----------

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lines(n int) string { return strings.Repeat("x\n", n) }

func vuln(id, class, file string, s, e int, cwe ...string) Vuln {
	return Vuln{ID: id, Class: class, File: file, StartLine: s, EndLine: e, CWE: cwe, Description: "d " + id}
}

func finding(tool, rule, file string, line int, cwe ...string) model.Finding {
	return model.Finding{
		Tool: tool, RuleID: rule, CWE: cwe, Message: rule + " message",
		Location:    model.Location{File: file, Region: model.Region{StartLine: line, EndLine: line}},
		Fingerprint: tool + "|" + rule + "|" + file,
	}
}

func rec(kind vault.Kind, source, fp string, payload any) vault.Record {
	b, _ := json.Marshal(payload)
	return vault.Record{Kind: kind, Source: source, Fingerprint: fp, Payload: b}
}

// records builds the vault a scan would leave: registered tools, the ones that ran,
// the findings (before any filter), and diagnostics for failures.
func records(registered, ran []string, cands []model.Finding, failures ...ToolFailure) []vault.Record {
	out := []vault.Record{rec(vault.KindScanMeta, "", "", map[string]any{"tools": registered, "target": "t"})}
	for _, r := range ran {
		out = append(out, rec(vault.KindRawOutput, r, "", map[string]any{"sarif": map[string]any{}}))
	}
	for _, c := range cands {
		out = append(out, rec(vault.KindFinding, c.Tool, c.Fingerprint, c))
	}
	if len(failures) > 0 {
		out = append(out, rec(vault.KindScanMeta, "diagnostics", "", map[string]any{"parseFailures": failures}))
	}
	return out
}

// fakeScan is the hermetic ScanRunner: it returns canned output per pass.
type fakeScan struct {
	unfiltered ScanOutput // KeepDismissed pass
	filtered   ScanOutput // the AI-filtered pass
	err        error
	calls      []ScanRequest
}

func (f *fakeScan) RunScan(_ context.Context, req ScanRequest) (ScanOutput, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return ScanOutput{}, f.err
	}
	if req.KeepDismissed {
		return f.unfiltered, nil
	}
	return f.filtered, nil
}

func target(t *testing.T, id string, files map[string]string, vs ...Vuln) DetectTarget {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		writeFile(t, filepath.Join(dir, name), body)
	}
	return DetectTarget{Dir: dir, Truth: GroundTruth{SchemaVersion: 1, ID: id, Source: Source{Path: "."}, Vulns: vs}}
}

func runDetect(t *testing.T, scan ScanRunner, opts DetectOptions, tg DetectTarget) TargetResult {
	t.Helper()
	if opts.LineTolerance == 0 {
		opts.LineTolerance = DefaultLineTolerance
	}
	rep := DetectRunner{Scan: scan, Opts: opts}.Run(context.Background(), []DetectTarget{tg})
	return rep.Targets[0]
}

func entry(t *testing.T, tr TargetResult, id string) EntryResult {
	t.Helper()
	for _, e := range tr.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no entry %s", id)
	return EntryResult{}
}

// ---------- ground truth ----------

func TestCWENumber(t *testing.T) {
	for in, want := range map[string]string{
		"CWE-89": "89", "cwe-089": "89", "89": "89", "CWE-79: Improper Neutralization": "79", "CWE-": "", "abc": "", "": "",
	} {
		if got := cweNumber(in); got != want {
			t.Errorf("cweNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGroundTruthValidation(t *testing.T) {
	good := func() GroundTruth {
		return GroundTruth{SchemaVersion: 1, ID: "t", Source: Source{Path: "x"}, Vulns: []Vuln{vuln("A", "injection", "a.py", 1, 2, "CWE-89")}}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("good ground truth rejected: %v", err)
	}
	cases := map[string]func(*GroundTruth){
		"schemaVersion":         func(g *GroundTruth) { g.SchemaVersion = 9 },
		"target id":             func(g *GroundTruth) { g.ID = "has space" },
		"needs a git url":       func(g *GroundTruth) { g.Source = Source{} },
		"both url and path":     func(g *GroundTruth) { g.Source = Source{URL: "https://x/y.git", Commit: "c", Path: "p"} },
		"needs a pinned commit": func(g *GroundTruth) { g.Source = Source{URL: "https://x/y.git"} },
		"duplicate id":          func(g *GroundTruth) { g.Vulns = append(g.Vulns, g.Vulns[0]) },
		"startLine":             func(g *GroundTruth) { g.Vulns[0].EndLine = 0 },
		"relative, slash":       func(g *GroundTruth) { g.Vulns[0].File = "../etc/passwd" },
		"CWE-<n>":               func(g *GroundTruth) { g.Vulns[0].CWE = []string{"nope"} },
		"missing description":   func(g *GroundTruth) { g.Vulns[0].Description = "" },
		"need a package":        func(g *GroundTruth) { g.Vulns[0].Class = "vulnerable-dependency" },
		"no vulnerabilities":    func(g *GroundTruth) { g.Vulns = nil },
	}
	for want, mutate := range cases {
		g := good()
		mutate(&g)
		err := g.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error mentioning %q, got %v", want, err)
		}
	}
}

func TestLoadGroundTruth_DirSkipsExamplesAndRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	one := `{"schemaVersion":1,"id":"%s","source":{"path":"."},"vulnerabilities":[{"id":"A","class":"xss","file":"a.js","startLine":1,"endLine":1,"description":"d"}]}`
	writeFile(t, filepath.Join(dir, "b.json"), strings.Replace(one, "%s", "b", 1))
	writeFile(t, filepath.Join(dir, "a.json"), strings.Replace(one, "%s", "a", 1))
	writeFile(t, filepath.Join(dir, "ext.example.json"), `[not even json`)
	gts, err := LoadGroundTruth(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(gts) != 2 || gts[0].ID != "a" || gts[1].ID != "b" {
		t.Fatalf("want a,b sorted and the example skipped, got %+v", gts)
	}

	// A misspelled field must not silently become line 0.
	writeFile(t, filepath.Join(dir, "typo.json"), strings.Replace(strings.Replace(one, "%s", "typo", 1), "startLine", "start_line", 1))
	if _, err := LoadGroundTruth(dir); err == nil || !strings.Contains(err.Error(), "start_line") {
		t.Errorf("want an unknown-field error, got %v", err)
	}
}

func TestLoadGroundTruth_DuplicateIDsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	one := `{"schemaVersion":1,"id":"same","source":{"path":"."},"vulnerabilities":[{"id":"A","class":"xss","file":"a.js","startLine":1,"endLine":1,"description":"d"}]}`
	writeFile(t, filepath.Join(dir, "a.json"), one)
	writeFile(t, filepath.Join(dir, "b.json"), one)
	if _, err := LoadGroundTruth(dir); err == nil || !strings.Contains(err.Error(), "duplicate target id") {
		t.Fatalf("want duplicate id error, got %v", err)
	}
}

// The committed corpus must always load and validate against its own fixtures.
func TestCommittedGroundTruthIsValid(t *testing.T) {
	root := filepath.Join("..", "..", "evals", "detect", "ground_truth")
	gts, err := LoadGroundTruth(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(gts) == 0 {
		t.Fatal("no committed targets")
	}
	for _, g := range gts {
		dir, err := ResolveSource(context.Background(), g, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", g.ID, err)
		}
		for id, msg := range g.ValidateAgainstTree(dir) {
			t.Errorf("%s/%s: stale label: %s", g.ID, id, msg)
		}
	}
}

// ---------- pinned commits ----------

func TestExternalExampleIsRefusedUntilPinned(t *testing.T) {
	path := filepath.Join("..", "..", "evals", "detect", "ground_truth", "external.example.json")
	gts, err := LoadGroundTruthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(gts) < 3 {
		t.Fatalf("want juice-shop, nodegoat and webgoat, got %d", len(gts))
	}
	_, err = ResolveTargets(context.Background(), gts, t.TempDir(), nil)
	if err == nil {
		t.Fatal("placeholder commits must be refused")
	}
	for _, want := range []string{"pinned commit SHA", "git rev-parse", "40-character"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should be actionable (missing %q): %v", want, err)
		}
	}
}

func TestCheckPinned(t *testing.T) {
	sha := strings.Repeat("a1", 20)
	ok := GroundTruth{ID: "x", Source: Source{URL: "https://example.test/r.git", Commit: sha}}
	if err := ok.CheckPinned(); err != nil {
		t.Errorf("a full sha is pinned: %v", err)
	}
	for _, bad := range []string{"main", "v1.2.3", "abc123", "REPLACE_ME", sha[:39], strings.ToUpper(sha)} {
		g := ok
		g.Source.Commit = bad
		if err := g.CheckPinned(); err == nil {
			t.Errorf("commit %q must be refused", bad)
		}
	}
	g := ok
	g.Source.URL = "https://github.com/<owner>/<repo>.git"
	if err := g.CheckPinned(); err == nil {
		t.Error("a placeholder url must be refused")
	}
}

func gitOrSkip(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// makeRepo creates a one-commit repository on disk and returns its file:// URL and sha.
func makeRepo(t *testing.T) (url, sha string) {
	t.Helper()
	gitOrSkip(t)
	dir := t.TempDir()
	run := func(args ...string) string {
		out, err := ExecGit{}.Git(context.Background(), dir, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	run("init", "--quiet")
	writeFile(t, filepath.Join(dir, "sub", "app.py"), "print('hi')\n")
	run("add", ".")
	run("-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "init")
	return "file://" + filepath.ToSlash(dir), run("rev-parse", "HEAD")
}

func TestResolveSource_GitCheckoutAndCacheReuse(t *testing.T) {
	url, sha := makeRepo(t)
	cache := t.TempDir()
	g := GroundTruth{ID: "r", Source: Source{URL: url, Commit: sha, Subdir: "sub"}}
	dir, err := ResolveSource(context.Background(), g, cache, ExecGit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.py")); err != nil {
		t.Fatalf("subdir checkout missing the file: %v", err)
	}
	// Second resolve must reuse the checkout, not refetch: break the remote to prove it.
	g2 := g
	g2.Source.URL = "file:///nonexistent/remote"
	if dir2, err := ResolveSource(context.Background(), g2, cache, ExecGit{}); err != nil || dir2 != dir {
		t.Fatalf("cached checkout at the pinned commit should be reused: %v %s", err, dir2)
	}
	// A commit that is not in the repository fails with a clear error and leaves no cache dir behind.
	g3 := g
	g3.Source.Commit = strings.Repeat("0", 40)
	if _, err := ResolveSource(context.Background(), g3, cache, ExecGit{}); err == nil {
		t.Fatal("an unknown commit must fail")
	}
	// A subdir that escapes the checkout is refused.
	g4 := g
	g4.Source.Subdir = "../.."
	if _, err := ResolveSource(context.Background(), g4, cache, ExecGit{}); err == nil {
		t.Fatal("an escaping subdir must be refused")
	}
}

func TestCheckGitURL(t *testing.T) {
	for _, ok := range []string{"https://github.com/o/r.git", "git@github.com:o/r.git", "ssh://git@h/r", "file:///tmp/r"} {
		if err := checkGitURL(ok); err != nil {
			t.Errorf("%s should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"--upload-pack=evil", "ext::sh -c id", "/local/path", "ftp://h/r"} {
		if err := checkGitURL(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

// ---------- matching ----------

func TestMatching_Rule(t *testing.T) {
	v := vuln("V", ClassInjection, "app.py", 20, 22, "CWE-89")
	tol := 3
	cases := []struct {
		name string
		f    model.Finding
		want matchKind
	}{
		{"same file, in range, same CWE", finding("opengrep", "r", "app.py", 21, "CWE-89"), matchExact},
		{"CWE written differently", finding("opengrep", "r", "app.py", 21, "CWE-089: SQL Injection"), matchExact},
		{"class via CWE (code injection is injection)", finding("opengrep", "r", "app.py", 21, "CWE-95"), matchExact},
		{"class via rule id keyword", finding("opengrep", "py.sql-injection-audit", "app.py", 21), matchExact},
		{"class via gosec id", finding("gosec", "G201", "app.py", 21), matchExact},
		{"inside tolerance below", finding("opengrep", "r", "app.py", 17, "CWE-89"), matchExact},
		{"inside tolerance above", finding("opengrep", "r", "app.py", 25, "CWE-89"), matchExact},
		{"outside tolerance", finding("opengrep", "r", "app.py", 26, "CWE-89"), matchNone},
		{"other file", finding("opengrep", "r", "other.py", 21, "CWE-89"), matchNone},
		{"right place, wrong class", finding("opengrep", "r", "app.py", 21, "CWE-79"), matchAmbiguous},
		{"right place, no metadata", finding("opengrep", "audit.generic", "app.py", 21), matchAmbiguous},
	}
	for _, c := range cases {
		if got := classify(v, c.f, tol); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestMatching_FilePathsAreNormalized(t *testing.T) {
	roots := []string{"/tmp/scan", "/private/tmp/scan"}
	for in, want := range map[string]string{
		"/tmp/scan/a/b.py":              "a/b.py",
		"/private/tmp/scan/a/b.py":      "a/b.py",
		"file:///tmp/scan/req.txt":      "req.txt",
		"./a/b.py":                      "a/b.py",
		"a/./b.py":                      "a/b.py",
		"a\\b.py":                       "a\\b.py", // backslashes are not separators on this platform's slash path
		"/elsewhere/a.py":               "/elsewhere/a.py",
		"/tmp/scanner-other/a.py":       "/tmp/scanner-other/a.py",
		"file:///private/tmp/scan/x.go": "x.go",
	} {
		if runtimeIsWindows() && strings.Contains(in, `\`) {
			continue
		}
		if got := normalizeFindingPath(in, roots); got != want {
			t.Errorf("normalizeFindingPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func runtimeIsWindows() bool { return filepath.Separator == '\\' }

func TestMatching_DependencyFindingsMatchByFileAndPackage(t *testing.T) {
	v := Vuln{ID: "D", Class: ClassVulnDependency, File: "requirements.txt", StartLine: 2, EndLine: 2, Package: "requests"}
	hit := finding("osv-scanner", "CVE-2018-18074", "requirements.txt", 0)
	hit.Message = "Package 'requests@2.19.1' is vulnerable to 'CVE-2018-18074'"
	other := finding("osv-scanner", "CVE-2020-14343", "requirements.txt", 0)
	other.Message = "Package 'PyYAML@5.3.1' is vulnerable"
	if classify(v, hit, 3) != matchExact {
		t.Error("a lineless dependency finding naming the package should match by file")
	}
	if classify(v, other, 3) != matchNone {
		t.Error("a finding for a different package must not match")
	}
	// A lineless finding never vouches for a non-dependency entry.
	nv := vuln("N", ClassInjection, "requirements.txt", 2, 2, "CWE-89")
	if classify(nv, hit, 3) != matchNone {
		t.Error("lineless findings may only match dependency entries")
	}
}

func TestMatcher_OneFindingDoesNotVouchForNeighbouringLabels(t *testing.T) {
	// Three secrets on adjacent lines; the scanner only finds the third.
	vs := []Vuln{
		vuln("S3", ClassHardcodedSecret, "s.py", 3, 3, "CWE-798"),
		vuln("S4", ClassHardcodedSecret, "s.py", 4, 4, "CWE-798"),
		vuln("S5", ClassHardcodedSecret, "s.py", 5, 5, "CWE-798"),
	}
	m := matcher{vulns: vs, tol: 3}
	f := finding("gitleaks", "generic-api-key", "s.py", 5)
	got := map[string]matchKind{}
	for _, v := range vs {
		got[v.ID] = m.classify(v, f)
	}
	if got["S5"] != matchExact || got["S3"] != matchNone || got["S4"] != matchNone {
		t.Fatalf("only the entry the finding lands on may match, got %v", got)
	}
	// With no entry directly under it, tolerance still applies.
	f2 := finding("gitleaks", "generic-api-key", "s.py", 7)
	if m.classify(vs[2], f2) != matchExact {
		t.Error("tolerance should still credit a finding two lines past the only nearby label")
	}
}

// ---------- the benchmark, end to end, with a fake scanner ----------

var allTools = []string{"gitleaks", "gosec", "opengrep", "osv-scanner", "trivy"}

func TestRun_DetectedAndPrecisionProxy(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40), "other.py": lines(10)},
		vuln("SQLI", ClassInjection, "app.py", 10, 10, "CWE-89"),
		vuln("EVAL", ClassInjection, "app.py", 30, 30, "CWE-95"))
	hit := finding("opengrep", "py.sqli", "app.py", 10, "CWE-89")
	stray := finding("opengrep", "py.other", "app.py", 20, "CWE-79")     // labeled file, no label
	unlabeled := finding("opengrep", "py.third", "other.py", 3, "CWE-1") // no labels in this file
	cands := []model.Finding{hit, stray, unlabeled}
	out := ScanOutput{
		Findings: []model.Finding{hit, stray, unlabeled},
		Records:  records([]string{"opengrep"}, []string{"opengrep"}, cands),
	}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{}, tg)

	if e := entry(t, tr, "SQLI"); !e.Detected || e.MatchedBy != "rule" || len(e.Matches) != 1 {
		t.Errorf("SQLI should be detected by rule: %+v", e)
	}
	if e := entry(t, tr, "EVAL"); e.Detected || e.Loss == nil {
		t.Errorf("EVAL should be a traced miss: %+v", e)
	}
	f := tr.Findings
	if f.Surfaced != 3 || f.Matched != 1 || f.UnmatchedInLabeledFiles != 1 || f.UnlabeledFiles != 1 {
		t.Errorf("precision proxy wrong: %+v", f)
	}
	if tr.Incomplete {
		t.Error("nothing failed; the target is complete")
	}
}

func TestTrace_NotDetectedNamesWhatRan(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)}, vuln("A", ClassSSRF, "app.py", 10, 10, "CWE-918"))
	out := ScanOutput{Records: records(allTools, []string{"opengrep", "gitleaks", "osv-scanner"}, nil)}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{
		ToolLanguages: map[string][]string{"opengrep": {"python", "generic"}, "gosec": {"go"}, "gitleaks": {"generic"}, "osv-scanner": {"generic"}, "trivy": {"generic"}},
	}, tg)
	e := entry(t, tr, "A")
	if e.Loss == nil || e.Loss.Point != LossNotDetected {
		t.Fatalf("want not-detected, got %+v", e.Loss)
	}
	for _, want := range []string{"opengrep", "gitleaks", "osv-scanner", "skipped", "gosec", "trivy"} {
		if !strings.Contains(e.Loss.Detail, want) {
			t.Errorf("detail should mention %q: %s", want, e.Loss.Detail)
		}
	}
	// gosec and trivy neither ran nor failed: they were skipped, and that is recorded.
	if got := strings.Join(tr.Tools.Skipped, ","); got != "gosec,trivy" {
		t.Errorf("skipped = %q", got)
	}
}

func TestTrace_ToolMissingMarksTargetIncomplete(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("SECRET", ClassHardcodedSecret, "app.py", 5, 5, "CWE-798"),
		vuln("SSRF", ClassSSRF, "app.py", 10, 10, "CWE-918"))
	missing := ToolFailure{Tool: "trivy", Stage: "run", Error: `trivy run: run trivy: exec: "trivy": executable file not found in $PATH`}
	out := ScanOutput{Records: records(allTools, []string{"opengrep", "gitleaks", "gosec", "osv-scanner"}, nil, missing)}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{
		ToolLanguages: map[string][]string{"opengrep": {"python"}, "trivy": {"generic"}, "gitleaks": {"generic"}},
	}, tg)

	if !tr.Incomplete {
		t.Fatal("a missing scanner makes the target incomplete")
	}
	if !tr.Tools.Failed[0].Missing {
		t.Error("the failure should be recognized as a missing binary")
	}
	// trivy covers secrets, so the secret miss may be an environment gap...
	if e := entry(t, tr, "SECRET"); e.Loss.Point != LossToolMissing || !strings.Contains(e.Loss.Detail, "trivy") {
		t.Errorf("secret miss should be tool-missing naming trivy, got %+v", e.Loss)
	}
	// ...but trivy does not cover SSRF, so that one is a genuine gap, not blamed on trivy.
	if e := entry(t, tr, "SSRF"); e.Loss.Point != LossNotDetected {
		t.Errorf("SSRF is not trivy's job; want not-detected, got %+v", e.Loss)
	}
}

func TestTrace_FailedToolThatRanIsScanIncomplete(t *testing.T) {
	tg := target(t, "t", map[string]string{"main.go": lines(40)}, vuln("A", ClassInjection, "main.go", 10, 10, "CWE-89"))
	bad := ToolFailure{Tool: "gosec", Stage: "run", Error: "gosec: reading results.sarif failed (exit 1)\nsecond line"}
	out := ScanOutput{Records: records(allTools, []string{"opengrep"}, nil, bad)}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{
		ToolLanguages: map[string][]string{"gosec": {"go"}, "opengrep": {"go"}},
	}, tg)
	e := entry(t, tr, "A")
	if e.Loss.Point != LossScanIncomplete || !strings.Contains(e.Loss.Detail, "gosec") || strings.Contains(e.Loss.Detail, "second line") {
		t.Errorf("want scan-incomplete naming gosec on one line, got %+v", e.Loss)
	}
}

func TestTrace_NoCoverage(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.rb": lines(40)}, vuln("A", ClassInjection, "app.rb", 10, 10, "CWE-89"))
	out := ScanOutput{Records: records([]string{"gosec", "gitleaks"}, []string{"gitleaks"}, nil)}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{
		ToolLanguages: map[string][]string{"gosec": {"go"}, "gitleaks": {"generic"}},
	}, tg)
	if e := entry(t, tr, "A"); e.Loss.Point != LossNoCoverage {
		t.Errorf("only a secrets scanner ran on Ruby; want no-coverage, got %+v", e.Loss)
	}
}

func TestTrace_NoiseFilterFromVaultCandidates(t *testing.T) {
	tg := target(t, "t", map[string]string{"third_party/x.py": lines(10), "app.py": lines(10)},
		vuln("VENDORED", ClassInjection, "third_party/x.py", 5, 5, "CWE-95"),
		vuln("EXCLUDED", ClassInjection, "app.py", 5, 5, "CWE-95"))
	cands := []model.Finding{
		finding("opengrep", "eval", "third_party/x.py", 5, "CWE-95"),
		finding("opengrep", "eval", "app.py", 5, "CWE-95"),
	}
	// Reported by the scanner (vault), absent from the report: dropped by the filter.
	out := ScanOutput{Records: records([]string{"opengrep"}, []string{"opengrep"}, cands)}

	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{Excludes: "app.py"}, tg)
	for _, id := range []string{"VENDORED", "EXCLUDED"} {
		e := entry(t, tr, id)
		if e.Loss == nil || e.Loss.Point != LossNoiseFilter {
			t.Errorf("%s: want noise-filter, got %+v", id, e.Loss)
		}
	}
	if d := entry(t, tr, "EXCLUDED").Loss.Detail; !strings.Contains(d, "--exclude app.py") {
		t.Errorf("the --exclude that caused the drop should be named: %s", d)
	}

	// With the default filter off and no --exclude, the same drop is unexplained.
	tr = runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{NoDefaultExcludes: true}, tg)
	if e := entry(t, tr, "VENDORED"); e.Loss.Point != LossDropped {
		t.Errorf("no filter can explain it; want dropped-unknown, got %+v", e.Loss)
	}
	// ...and attributable to the baseline or --diff when those were used.
	tr = runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{NoDefaultExcludes: true, ScanBaselineUsed: true}, tg)
	if e := entry(t, tr, "VENDORED"); e.Loss.Point != LossBaseline {
		t.Errorf("want baseline-suppressed, got %+v", e.Loss)
	}
	tr = runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{NoDefaultExcludes: true, DiffUsed: true}, tg)
	if e := entry(t, tr, "VENDORED"); e.Loss.Point != LossDiff {
		t.Errorf("want diff-filtered, got %+v", e.Loss)
	}
}

func TestRun_AIPassesAndDismissedTrace(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("KEPT", ClassInjection, "app.py", 10, 10, "CWE-89"),
		vuln("DISMISSED", ClassInjection, "app.py", 20, 20, "CWE-78"),
		vuln("NEVER", ClassSSRF, "app.py", 30, 30, "CWE-918"))
	kept := finding("opengrep", "sqli", "app.py", 10, "CWE-89")
	dismissed := finding("opengrep", "cmd", "app.py", 20, "CWE-78")
	dismissed.Fingerprint = "fp-dismissed"
	cands := []model.Finding{kept, dismissed}
	verdict := model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.93, Reasoning: "argument is a constant list; no shell is involved"}
	recs := records([]string{"opengrep"}, []string{"opengrep"}, cands)
	recs = append(recs, rec(vault.KindVerdict, "triage", "fp-dismissed", verdict))

	fs := &fakeScan{
		// Pass 1 (--keep-dismissed): nothing removed.
		unfiltered: ScanOutput{Findings: []model.Finding{kept, dismissed}, Records: recs},
		// Pass 2: the review dismissed one (SARIF carries it as suppressed).
		filtered: ScanOutput{Findings: []model.Finding{kept}, Dismissed: []model.Finding{dismissed}, Records: recs},
	}
	tr := runDetect(t, fs, DetectOptions{AI: true}, tg)

	if len(fs.calls) != 2 || !fs.calls[0].KeepDismissed || fs.calls[1].KeepDismissed || !fs.calls[0].AI || !fs.calls[1].AI {
		t.Fatalf("AI mode must run a keep-dismissed pass and a filtered pass, got %+v", fs.calls)
	}
	k := entry(t, tr, "KEPT")
	if !k.Detected || !k.DetectedUnfiltered {
		t.Errorf("KEPT survives the review: %+v", k)
	}
	d := entry(t, tr, "DISMISSED")
	if d.Detected || !d.DetectedUnfiltered {
		t.Errorf("DISMISSED was found by the scanners but lost to the AI: %+v", d)
	}
	if d.Loss.Point != LossAIDismissed || d.Loss.Verdict == nil {
		t.Fatalf("want ai-dismissed with the verdict, got %+v", d.Loss)
	}
	if !strings.Contains(d.Loss.Detail, "argument is a constant list") || d.Loss.Verdict.Confidence != 0.93 {
		t.Errorf("the verdict's reasoning must be in the trace: %+v", d.Loss)
	}
	if n := entry(t, tr, "NEVER"); n.Loss.Point != LossNotDetected {
		t.Errorf("NEVER was not found by anything: %+v", n.Loss)
	}

	rep := DetectRunner{Scan: fs, Opts: DetectOptions{AI: true, LineTolerance: 3}}.Run(context.Background(), []DetectTarget{tg})
	if rep.Overall.Detected != 1 || rep.Overall.DetectedUnfiltered != 2 {
		t.Errorf("recall must be scored on the filtered result and the unfiltered one reported beside it: %+v", rep.Overall)
	}
}

func TestRun_AIDisabledRunsOnePass(t *testing.T) {
	tg := target(t, "t", map[string]string{"a.py": lines(5)}, vuln("A", ClassInjection, "a.py", 1, 1, "CWE-89"))
	fs := &fakeScan{unfiltered: ScanOutput{}}
	runDetect(t, fs, DetectOptions{}, tg)
	if len(fs.calls) != 1 || !fs.calls[0].KeepDismissed || fs.calls[0].AI {
		t.Errorf("without --ai: one pass, keep-dismissed, no AI; got %+v", fs.calls)
	}
}

func TestTrace_ClassAndLineMismatch(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(80)},
		vuln("WRONGCLASS", ClassSSRF, "app.py", 10, 10, "CWE-918"),
		vuln("FARAWAY", ClassInjection, "app.py", 60, 60, "CWE-89"))
	cands := []model.Finding{
		finding("opengrep", "py.dangerous-call", "app.py", 10, "CWE-676"), // same place, different weakness
		finding("opengrep", "py.sqli", "app.py", 52, "CWE-89"),            // right class, 8 lines away
	}
	out := ScanOutput{Findings: cands, Records: records([]string{"opengrep"}, []string{"opengrep"}, cands)}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{}, tg)

	w := entry(t, tr, "WRONGCLASS")
	if w.Loss.Point != LossClassMismatch || !strings.Contains(w.Loss.Detail, "py.dangerous-call") || !strings.Contains(w.Loss.Detail, "--judge") {
		t.Errorf("want class-mismatch naming the rule, got %+v", w.Loss)
	}
	f := entry(t, tr, "FARAWAY")
	if f.Loss.Point != LossLineMismatch || !strings.Contains(f.Loss.Detail, "8 line") {
		t.Errorf("want line-mismatch with the distance, got %+v", f.Loss)
	}
}

func TestTrace_NearMissExplainedByAnotherLabelIsNotANearMiss(t *testing.T) {
	// The finding at line 26 belongs to CMDI; it must not be offered as a line-mismatch
	// "near miss" for the SQLI label seven lines above it.
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("SQLI", ClassInjection, "app.py", 19, 19, "CWE-89"),
		vuln("CMDI", ClassInjection, "app.py", 26, 26, "CWE-78"))
	cmd := finding("opengrep", "shell", "app.py", 26, "CWE-78")
	out := ScanOutput{Findings: []model.Finding{cmd}, Records: records([]string{"opengrep"}, []string{"opengrep"}, []model.Finding{cmd})}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{LineTolerance: 5}, tg)
	if e := entry(t, tr, "SQLI"); e.Loss.Point != LossNotDetected {
		t.Errorf("want not-detected, got %+v", e.Loss)
	}
}

type fakeJudge struct {
	same  bool
	err   error
	calls int
}

func (j *fakeJudge) SameVulnerability(context.Context, JudgeInput) (bool, string, error) {
	j.calls++
	return j.same, "judged", j.err
}

func TestRun_JudgeAdjudicatesOnlyAmbiguousMatches(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("AMBIG", ClassSSRF, "app.py", 10, 10, "CWE-918"),
		vuln("EXACT", ClassInjection, "app.py", 20, 20, "CWE-89"),
		vuln("NOTHING", ClassXSS, "app.py", 35, 35, "CWE-79"))
	fs := []model.Finding{
		finding("opengrep", "py.dangerous", "app.py", 10, "CWE-676"),
		finding("opengrep", "py.sqli", "app.py", 20, "CWE-89"),
	}
	out := ScanOutput{Findings: fs, Records: records([]string{"opengrep"}, []string{"opengrep"}, fs)}

	j := &fakeJudge{same: true}
	tr := runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{Judge: j}, tg)
	if e := entry(t, tr, "AMBIG"); !e.Detected || e.MatchedBy != "judge" || e.JudgeReason != "judged" {
		t.Errorf("the judge should rescue the ambiguous match: %+v", e)
	}
	if e := entry(t, tr, "EXACT"); e.MatchedBy != "rule" {
		t.Errorf("a deterministic match is never re-judged: %+v", e)
	}
	if e := entry(t, tr, "NOTHING"); e.Detected {
		t.Error("the judge must never invent a detection where nothing was reported")
	}
	if j.calls != 1 {
		t.Errorf("only the one ambiguous pairing should reach the judge, got %d calls", j.calls)
	}

	// A rejecting judge leaves the miss traced as class-mismatch.
	tr = runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{Judge: &fakeJudge{same: false}}, tg)
	if e := entry(t, tr, "AMBIG"); e.Detected || e.Loss.Point != LossClassMismatch {
		t.Errorf("rejected by the judge: %+v", e)
	}
	// A failing judge degrades to the deterministic result and says so.
	tr = runDetect(t, &fakeScan{unfiltered: out}, DetectOptions{Judge: &fakeJudge{err: errors.New("boom")}}, tg)
	if e := entry(t, tr, "AMBIG"); e.Detected {
		t.Error("a judge error is not a detection")
	}
	if len(tr.Notes) == 0 || !strings.Contains(tr.Notes[0], "boom") {
		t.Errorf("a judge failure should be noted: %v", tr.Notes)
	}
}

func TestRun_ScanFailureIsAMissNotASkip(t *testing.T) {
	tg := target(t, "t", map[string]string{"a.py": lines(5)},
		vuln("A", ClassInjection, "a.py", 1, 1, "CWE-89"),
		vuln("B", ClassInjection, "gone.py", 1, 1, "CWE-89"))
	tr := runDetect(t, &fakeScan{err: errors.New("achilles failed before writing a report")}, DetectOptions{}, tg)
	if !tr.Incomplete || tr.Error == "" {
		t.Fatalf("a failed scan is an incomplete target: %+v", tr)
	}
	if e := entry(t, tr, "A"); e.Status != StatusMissed || e.Loss.Point != LossScanFailed {
		t.Errorf("want a scan-failed miss (never silently dropped from the denominator): %+v", e)
	}
	if e := entry(t, tr, "B"); e.Status != StatusInvalid {
		t.Errorf("a label for a file that is not there is invalid, not a miss: %+v", e)
	}
}

func TestRun_InvalidLabelsAreNotScored(t *testing.T) {
	tg := target(t, "t", map[string]string{"a.py": lines(5)},
		vuln("GOOD", ClassInjection, "a.py", 1, 1, "CWE-89"),
		vuln("MISSING", ClassInjection, "nope.py", 1, 1, "CWE-89"),
		vuln("PASTEOF", ClassInjection, "a.py", 99, 99, "CWE-89"))
	f := finding("opengrep", "sqli", "a.py", 1, "CWE-89")
	rep := DetectRunner{Scan: &fakeScan{unfiltered: ScanOutput{Findings: []model.Finding{f}}}, Opts: DetectOptions{LineTolerance: 3}}.
		Run(context.Background(), []DetectTarget{tg})
	if rep.Overall.Invalid != 2 || rep.Overall.Detected != 1 || rep.Overall.Recall != 1 {
		t.Errorf("invalid labels must be excluded from recall: %+v", rep.Overall)
	}
}

func TestRun_FindingsWithAbsolutePathsAreNormalized(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)}, vuln("A", ClassInjection, "app.py", 10, 10, "CWE-89"))
	f := finding("opengrep", "sqli", filepath.Join(tg.Dir, "app.py"), 10, "CWE-89")
	tr := runDetect(t, &fakeScan{unfiltered: ScanOutput{Findings: []model.Finding{f}}}, DetectOptions{}, tg)
	if !entry(t, tr, "A").Detected {
		t.Error("an absolute path under the scan root should match the relative label")
	}
}

func TestReport_NeverContainsMachinePaths(t *testing.T) {
	tg := target(t, "t", map[string]string{"a.py": lines(5)}, vuln("A", ClassInjection, "a.py", 1, 1, "CWE-89"))
	home := "/" + "Users" + "/someone/Projects/x" // built at run time: this file must not itself look like a home path
	fail := ToolFailure{Tool: "gosec", Stage: "run", Error: "open " + tg.Dir + "/results.sarif: no such file; cwd " + home}
	out := ScanOutput{Records: records(allTools, []string{"opengrep"}, nil, fail)}
	rep := DetectRunner{Scan: &fakeScan{unfiltered: out}, Opts: DetectOptions{LineTolerance: 3, GroundTruthLabel: home + "/gt"}}.
		Run(context.Background(), []DetectTarget{tg})
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var md bytes.Buffer
	if err := rep.WriteMarkdown(&md); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{buf.String(), md.String()} {
		if strings.Contains(s, tg.Dir) || strings.Contains(s, "someone") {
			t.Errorf("report leaks a machine path:\n%s", s)
		}
	}
	if !strings.Contains(buf.String(), "<target>") {
		t.Error("the scan root should be rewritten to <target>")
	}
}

// ---------- scorecard ----------

func TestReport_AggregationBaselineAndRegressions(t *testing.T) {
	mk := func(detected ...bool) DetectReport {
		var es []EntryResult
		classes := []string{ClassInjection, ClassInjection, ClassXSS, ClassSSRF}
		for i, d := range detected {
			e := EntryResult{ID: string(rune('A' + i)), Class: classes[i], Status: StatusMissed}
			if d {
				e.Status, e.Detected, e.DetectedUnfiltered = StatusDetected, true, true
			} else {
				e.Loss = &LossTrace{Point: LossNotDetected, Detail: "x"}
			}
			es = append(es, e)
		}
		r := DetectReport{SchemaVersion: DetectReportVersion, Targets: []TargetResult{{ID: "t", Entries: es}}}
		r.aggregate()
		return r
	}
	base := mk(true, true, true, false) // 3/4
	cur := mk(true, false, true, false) // 2/4: injection halved
	if base.Overall.Recall != 0.75 || cur.Overall.Recall != 0.5 {
		t.Fatalf("recall: %v %v", base.Overall.Recall, cur.Overall.Recall)
	}
	if cur.LossPoints[LossNotDetected] != 2 {
		t.Errorf("histogram: %v", cur.LossPoints)
	}
	regs := DetectRegressions(base, cur, 0.02)
	if len(regs) != 2 { // overall and injection
		t.Errorf("want overall + injection regressions, got %v", regs)
	}
	if got := DetectRegressions(base, base, 0.02); len(got) != 0 {
		t.Errorf("no change, no regression: %v", got)
	}
	if got := DetectRegressions(base, cur, 0.60); len(got) != 0 {
		t.Errorf("a drop inside the tolerance is not a regression: %v", got)
	}
	if got := DetectRegressions(cur, base, 0); len(got) != 0 {
		t.Errorf("an improvement is not a regression: %v", got)
	}

	var out bytes.Buffer
	CompareDetect(base, cur, &out)
	for _, want := range []string{"75.0% -> 50.0%", "now missed:  t/B", "injection"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("comparison missing %q:\n%s", want, out.String())
		}
	}
}

func TestReport_JSONRoundTripAndMarkdown(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("HIT", ClassInjection, "app.py", 10, 10, "CWE-89"),
		vuln("MISS", ClassSSRF, "app.py", 20, 20, "CWE-918"))
	hit := finding("opengrep", "sqli", "app.py", 10, "CWE-89")
	miss := ToolFailure{Tool: "trivy", Stage: "run", Error: `exec: "trivy": executable file not found in $PATH`}
	out := ScanOutput{Findings: []model.Finding{hit}, Records: records(allTools, []string{"opengrep"}, []model.Finding{hit}, miss)}
	rep := DetectRunner{Scan: &fakeScan{unfiltered: out}, Opts: DetectOptions{LineTolerance: 3}}.Run(context.Background(), []DetectTarget{tg})

	path := filepath.Join(t.TempDir(), "r.json")
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, buf.String())
	back, err := LoadDetectReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Overall != rep.Overall || len(back.Targets) != 1 || back.Targets[0].Entries[1].Loss == nil {
		t.Errorf("round trip lost data: %+v", back.Overall)
	}

	var md bytes.Buffer
	if err := rep.WriteMarkdown(&md); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Detection benchmark", "Recall by class", "Where the misses were lost", "`t`", "not-detected", "Incomplete", "trivy", "not counted as false positives"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown missing %q:\n%s", want, md.String())
		}
	}

	var txt bytes.Buffer
	rep.Write(&txt, true)
	if !strings.Contains(txt.String(), "INCOMPLETE") || !strings.Contains(txt.String(), "lost at") {
		t.Errorf("console report should flag the incomplete target and print the trace:\n%s", txt.String())
	}

	writeFile(t, path, `{"schemaVersion": 99}`)
	if _, err := LoadDetectReport(path); err == nil {
		t.Error("a report from a different schema must be refused")
	}
}

func TestHistory_RepeatAndCarryShowStability(t *testing.T) {
	tg := target(t, "t", map[string]string{"app.py": lines(40)},
		vuln("STABLE", ClassInjection, "app.py", 10, 10, "CWE-89"),
		vuln("FLAKY", ClassInjection, "app.py", 30, 30, "CWE-89"))
	stable := finding("opengrep", "sqli", "app.py", 10, "CWE-89")
	flaky := finding("opengrep", "sqli", "app.py", 30, "CWE-89")
	// Alternate: run 1 finds both, run 2 only the stable one.
	seq := &sequenceScan{outs: []ScanOutput{
		{Findings: []model.Finding{stable, flaky}},
		{Findings: []model.Finding{stable}},
	}}
	rep := DetectRunner{Scan: seq, Opts: DetectOptions{LineTolerance: 3, Repeat: 2}}.Run(context.Background(), []DetectTarget{tg})
	if rep.Runs != 2 || len(rep.History) != 2 {
		t.Fatalf("want 2 runs of history, got %d/%d", rep.Runs, len(rep.History))
	}
	if len(rep.Unstable) != 1 || rep.Unstable[0].ID != "t/FLAKY" || rep.Unstable[0].Detected != 1 || rep.Unstable[0].Runs != 2 {
		t.Errorf("FLAKY should be reported unstable: %+v", rep.Unstable)
	}

	// A later invocation carries the earlier history forward — but only when comparable.
	next := DetectReport{Config: rep.Config, History: []RunSummary{{At: "later", ScoredIDs: []string{"t/FLAKY"}, DetectedIDs: []string{}}}}
	next.CarryHistory(rep)
	if len(next.History) != 3 {
		t.Errorf("history should accumulate: %d", len(next.History))
	}
	other := DetectReport{Config: DetectConfig{LineTolerance: 99}, History: []RunSummary{{At: "x"}}}
	other.CarryHistory(rep)
	if len(other.History) != 1 {
		t.Error("history from a different configuration must not be mixed in")
	}
}

type sequenceScan struct {
	outs []ScanOutput
	i    int
}

func (s *sequenceScan) RunScan(context.Context, ScanRequest) (ScanOutput, error) {
	o := s.outs[s.i%len(s.outs)]
	s.i++
	return o, nil
}

// ---------- artifacts: SARIF report + vault ----------

func TestParseSARIFReport_SurfacedAndSuppressed(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"achilles"}},"results":[
	 {"ruleId":"r1","message":{"text":"m1"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":7}}}],
	  "fingerprints":{"achilles/v1":"fp1"},"properties":{"cwe":["CWE-89"],"achilles/verdict":"true_positive","achilles/confidence":0.9}},
	 {"ruleId":"r2","message":{"text":"m2"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.py"},"region":{"startLine":3}}}],
	  "suppressions":[{"kind":"external","status":"accepted","justification":"constant argument"}],"properties":{"achilles/verdict":"false_positive","achilles/confidence":0.95}}
	]}]}`
	s, d, err := parseSARIFReport([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 1 || s[0].Fingerprint != "fp1" || s[0].CWE[0] != "CWE-89" || s[0].Location.Region.StartLine != 7 || s[0].Verdict.Confidence != 0.9 {
		t.Errorf("surfaced parsed wrong: %+v", s)
	}
	if len(d) != 1 || d[0].Verdict.Reasoning != "constant argument" || d[0].Verdict.Classification != model.ClassFalsePositive {
		t.Errorf("dismissed parsed wrong: %+v", d)
	}
	if _, _, err := parseSARIFReport([]byte("nope")); err == nil {
		t.Error("garbage must error")
	}
}

func TestDigest_ToolStatusFromVault(t *testing.T) {
	f := digest(records(allTools, []string{"opengrep", "gitleaks"}, nil,
		ToolFailure{Tool: "trivy", Stage: "run", Error: `exec: "trivy": executable file not found in $PATH`},
		ToolFailure{Tool: "gosec", Stage: "run", Error: "reading results.sarif failed"}))
	if got := strings.Join(f.Ran, ","); got != "gitleaks,opengrep" {
		t.Errorf("ran = %s", got)
	}
	if len(f.Failed) != 2 || !f.Failed[1].Missing || f.Failed[0].Missing {
		t.Errorf("failed = %+v", f.Failed)
	}
	if got := strings.Join(f.Skipped, ","); got != "osv-scanner" {
		t.Errorf("skipped = %q (registered but neither ran nor failed)", got)
	}
	if !f.HasVault {
		t.Error("a vault with a scan_meta record is a vault")
	}
	if digest(nil).HasVault {
		t.Error("no records: no vault")
	}
}

func TestEnrichFromVault_RestoresToolAndVerdict(t *testing.T) {
	cand := finding("opengrep", "r", "a.py", 4, "CWE-89")
	cand.Location.Region.EndLine = 6
	report := []model.Finding{{RuleID: "r", Fingerprint: cand.Fingerprint, Location: model.Location{File: "a.py", Region: model.Region{StartLine: 4}}}}
	enrichFromVault(report, []model.Finding{cand}, map[string]model.Verdict{cand.Fingerprint: {Classification: model.ClassTruePositive, Reasoning: "why"}}, nil)
	if report[0].Tool != "opengrep" || report[0].Location.Region.EndLine != 6 || report[0].Verdict == nil || report[0].Verdict.Reasoning != "why" {
		t.Errorf("not enriched: %+v", report[0])
	}
}

// ---------- the real runner, against a stand-in for the achilles binary ----------

// TestMain lets this test binary stand in for `achilles`: BinaryScanRunner execs
// os.Args[0] with the env var set, and the stand-in writes the artifacts a real
// scan would. The runner is exercised end to end with no scanners installed.
func TestMain(m *testing.M) {
	if os.Getenv("ACHILLES_DETECT_FAKE_BIN") != "" {
		os.Exit(fakeAchilles(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeAchilles(args []string) int {
	var vaultPath, sarifPath string
	var keep bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--vault":
			vaultPath = args[i+1]
			i++
		case "--sarif-report":
			sarifPath = args[i+1]
			i++
		case "--keep-dismissed":
			keep = true
		}
	}
	if os.Getenv("ACHILLES_DETECT_FAKE_BIN") == "crash" {
		return 2
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"achilles"}},"results":[
	 {"ruleId":"py.sqli","message":{"text":"sqli"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":5}}}],
	  "fingerprints":{"achilles/v1":"fp1"},"properties":{"cwe":["CWE-89"]}}]}]}`
	if err := os.WriteFile(sarifPath, []byte(doc), 0o600); err != nil {
		return 3
	}
	st, err := vault.NewFileStore(vaultPath)
	if err != nil {
		return 3
	}
	add := func(r vault.Record) { _, _ = st.Append(r) }
	add(rec(vault.KindScanMeta, "", "", map[string]any{"tools": []string{"opengrep", "trivy"}}))
	add(rec(vault.KindRawOutput, "opengrep", "", map[string]any{}))
	add(rec(vault.KindFinding, "opengrep", "fp1", finding("Opengrep OSS", "py.sqli", "app.py", 5, "CWE-89")))
	add(rec(vault.KindScanMeta, "diagnostics", "", map[string]any{"parseFailures": []ToolFailure{{Tool: "trivy", Stage: "run", Error: "executable file not found in $PATH"}}}))
	if keep {
		return 1 // a non-zero exit with a report still counts, as with --fail-on
	}
	return 0
}

func TestBinaryScanRunner_ReadsSARIFAndVault(t *testing.T) {
	t.Setenv("ACHILLES_DETECT_FAKE_BIN", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b := BinaryScanRunner{Bin: exe}
	out, err := b.RunScan(context.Background(), ScanRequest{Dir: t.TempDir(), KeepDismissed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.Findings[0].RuleID != "py.sqli" {
		t.Errorf("findings: %+v", out.Findings)
	}
	if out.ExitNote == "" {
		t.Error("a non-zero exit that still produced a report should be noted")
	}
	f := digest(out.Records)
	if !f.HasVault || len(f.Candidates) != 1 || len(f.Failed) != 1 || !f.Failed[0].Missing {
		t.Errorf("vault not read back: %+v", f)
	}
	// And the whole benchmark runs through it.
	tg := target(t, "t", map[string]string{"app.py": lines(10)}, vuln("A", ClassInjection, "app.py", 5, 5, "CWE-89"))
	tr := runDetect(t, b, DetectOptions{}, tg)
	if e := entry(t, tr, "A"); !e.Detected || !tr.Incomplete {
		t.Errorf("detected through the real runner, target incomplete (trivy missing): %+v", tr)
	}
}

func TestBinaryScanRunner_CrashIsAnError(t *testing.T) {
	t.Setenv("ACHILLES_DETECT_FAKE_BIN", "crash")
	exe, _ := os.Executable()
	_, err := BinaryScanRunner{Bin: exe}.RunScan(context.Background(), ScanRequest{Dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "before writing a report") {
		t.Errorf("want a clear failure, got %v", err)
	}
}

// ---------- the LLM judge (fake model) ----------

func TestLLMJudge_ParsesVerdictAndWithholdsSecrets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.py"), "a\nb\nc = db.execute(query)\nd\n")
	fake := &llmtest.Fake{Responses: []string{"```json\n{\"same\": true, \"reason\": \"both describe the query\"}\n```"}}
	j := LLMJudge{Client: fake}
	same, why, err := j.SameVulnerability(context.Background(), JudgeInput{
		Entry:   vuln("A", ClassInjection, "app.py", 3, 3, "CWE-89"),
		Finding: finding("opengrep", "py.dangerous", "app.py", 3, "CWE-676"),
		Root:    root,
	})
	if err != nil || !same || why != "both describe the query" {
		t.Fatalf("got %v %q %v", same, why, err)
	}
	prompt := fake.Calls[0].Messages[1].Content
	if !strings.Contains(prompt, "db.execute(query)") || !strings.Contains(prompt, "CWE-89") {
		t.Errorf("prompt should carry the label and the code:\n%s", prompt)
	}

	// Secret classes: no code is sent.
	writeFile(t, filepath.Join(root, "s.py"), "TOKEN = 'abc123def456ghi789'\n")
	fake2 := &llmtest.Fake{Responses: []string{`{"same": false, "reason": "no"}`}}
	_, _, err = LLMJudge{Client: fake2}.SameVulnerability(context.Background(), JudgeInput{
		Entry:   vuln("S", ClassHardcodedSecret, "s.py", 1, 1, "CWE-798"),
		Finding: finding("gitleaks", "generic-api-key", "s.py", 1),
		Root:    root,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := fake2.Calls[0].Messages[1].Content; strings.Contains(p, "abc123def456ghi789") || strings.Contains(p, "Code around") {
		t.Errorf("a credential must never be sent to the judge:\n%s", p)
	}

	// Bad reply and a path that escapes the root.
	_, _, err = LLMJudge{Client: &llmtest.Fake{Responses: []string{"I think so"}}}.SameVulnerability(context.Background(), JudgeInput{
		Entry: vuln("A", ClassInjection, "app.py", 3, 3), Finding: finding("t", "r", "../../etc/passwd", 1), Root: root})
	if err == nil {
		t.Error("a non-JSON reply is an error, not a default answer")
	}
	fake3 := &llmtest.Fake{Responses: []string{`{"same": false}`}}
	_, _, _ = LLMJudge{Client: fake3}.SameVulnerability(context.Background(), JudgeInput{
		Entry: vuln("A", ClassInjection, "app.py", 3, 3), Finding: finding("t", "r", "../../etc/passwd", 1), Root: root})
	if strings.Contains(fake3.Calls[0].Messages[1].Content, "Code around") {
		t.Error("a finding path outside the scan root must not be read into a prompt")
	}
}

// The committed baseline is what `make eval-detect-gate` compares against: it must
// stay loadable, cover the committed ground truth, and be free of machine paths.
func TestCommittedBaselineMatchesGroundTruth(t *testing.T) {
	base, err := LoadDetectReport(filepath.Join("..", "..", "evals", "detect", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	gts, err := LoadGroundTruth(filepath.Join("..", "..", "evals", "detect", "ground_truth"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, g := range gts {
		for _, v := range g.Vulns {
			want[g.ID+"/"+v.ID] = true
		}
	}
	for _, tr := range base.Targets {
		for _, e := range tr.Entries {
			delete(want, tr.ID+"/"+e.ID)
		}
	}
	if len(want) > 0 {
		t.Errorf("baseline lacks entries that are now in the ground truth (refresh it): %v", want)
	}
	raw, _ := os.ReadFile(filepath.Join("..", "..", "evals", "detect", "baseline.json"))
	if homePathRE.Match(raw) {
		t.Error("the committed baseline contains a home-directory path")
	}
}
