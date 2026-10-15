package verifyfix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
)

const fakeFormat = "verifyfix-test"

func init() {
	normalize.Register(fakeFormat, func(_ string, data []byte) ([]model.Finding, error) {
		var fs []model.Finding
		return fs, json.Unmarshal(data, &fs)
	})
}

// fakeScanner reports one finding per line containing a marker, per file. It reads
// the real files under the target, so a patch that removes the marker fixes it.
type fakeScanner struct {
	id    string
	tool  string            // the name it gives itself in its report; id when empty
	rules map[string]string // marker -> rule id
	runs  atomic.Int32
	fail  error
}

func (s *fakeScanner) toolName() string {
	if s.tool != "" {
		return s.tool
	}
	return s.id
}

func (s *fakeScanner) ID() string                     { return s.id }
func (s *fakeScanner) Meta() scanner.ScannerMeta      { return scanner.ScannerMeta{ID: s.id} }
func (s *fakeScanner) Applicable(scanner.Target) bool { return true }
func (s *fakeScanner) Run(_ context.Context, t scanner.Target) (scanner.RawResult, error) {
	s.runs.Add(1)
	if s.fail != nil {
		return scanner.RawResult{}, s.fail
	}
	var out []model.Finding
	_ = filepath.WalkDir(t.Path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			for marker, rule := range s.rules {
				if strings.Contains(line, marker) {
					// Absolute path on purpose: the verifier must relativize.
					out = append(out, model.Finding{
						Tool: s.toolName(), RuleID: rule,
						Location:    model.Location{File: p, Region: model.Region{StartLine: i + 1}},
						Fingerprint: model.ComputeFingerprint(s.toolName(), rule, p, strings.TrimSpace(line)),
					})
				}
			}
		}
		return nil
	})
	data, _ := json.Marshal(out)
	return scanner.RawResult{Tool: s.toolName(), Format: fakeFormat, Data: data}, nil
}

type lookup map[string]scanner.Scanner

func (l lookup) Get(id string) (scanner.Scanner, bool) { s, ok := l[id]; return s, ok }

// orig is the finding the main scan reported (paths relative, as relativizeFindings leaves them).
func orig(tool, rule, file, snippet string, line int) model.Finding {
	return model.Finding{Tool: tool, RuleID: rule,
		Location:    model.Location{File: file, Region: model.Region{StartLine: line}},
		Fingerprint: model.ComputeFingerprint(tool, rule, file, snippet)}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func newVerifier(t *testing.T, root string, sc *fakeScanner, o Options) *Verifier {
	t.Helper()
	if o.TempDir == "" {
		o.TempDir = t.TempDir()
	}
	return New(lookup{sc.id: sc}, root, o)
}

func leftovers(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("temp dir not cleaned up: %d entries left in %s", len(ents), dir)
	}
}

const fixDiff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(cmd)  # VULN\n+subprocess.run([cmd])\n print('x')\n"

func TestVerify_Fixed(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n", "other.py": "ok\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection"}}
	tmp := t.TempDir()
	v := newVerifier(t, root, sc, Options{TempDir: tmp})
	res := v.Verify(context.Background(), orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2), fixDiff)
	if res.Status != Verified {
		t.Fatalf("status = %s (%s), want verified", res.Status, res.Detail)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "app.py")); !strings.Contains(string(b), "VULN") {
		t.Error("the original target was modified by verification")
	}
	leftovers(t, tmp)
}

func TestVerify_NotFixed(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection"}}
	// The patch only edits an unrelated line; the line shifts nothing but the marker stays.
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-import os\n+import os, sys\n os.system(cmd)  # VULN\n print('x')\n"
	tmp := t.TempDir()
	res := newVerifier(t, root, sc, Options{TempDir: tmp}).Verify(context.Background(),
		orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2), diff)
	if res.Status != NotFixed {
		t.Fatalf("status = %s (%s), want not_fixed", res.Status, res.Detail)
	}
	leftovers(t, tmp)
}

// A scanner that names itself differently from its registry id (Opengrep reports
// "Opengrep OSS") must still be found and re-run, through the finding's Scanner.
func TestVerify_ScannerWhoseReportNameIsNotItsID(t *testing.T) {
	needGit(t)
	files := map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n"}
	unfixed := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-import os\n+import os, sys\n os.system(cmd)  # VULN\n print('x')\n"
	for _, c := range []struct {
		diff string
		want model.FixVerificationStatus
	}{{fixDiff, Verified}, {unfixed, NotFixed}} {
		root := writeTree(t, files)
		sc := &fakeScanner{id: "fake", tool: "Fake Scanner OSS", rules: map[string]string{"VULN": "cmd-injection"}}
		f := orig("Fake Scanner OSS", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2)
		f.Scanner = "fake"
		res := newVerifier(t, root, sc, Options{}).Verify(context.Background(), f, c.diff)
		if res.Status != c.want {
			t.Errorf("status = %s (%s), want %s", res.Status, res.Detail, c.want)
		}
	}
}

func TestVerify_NotFixed_LineShiftedWithinWindow(t *testing.T) {
	needGit(t)
	// The patch inserts 3 lines above and rewrites the flagged line so its snippet (and
	// fingerprint) changes, but the same rule still fires 3 lines lower.
	root := writeTree(t, map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection"}}
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,6 @@\n import os\n+# a\n+# b\n+# c\n-os.system(cmd)  # VULN\n+os.system(shlex.quote(cmd))  # VULN\n print('x')\n"
	res := newVerifier(t, root, sc, Options{}).Verify(context.Background(),
		orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2), diff)
	if res.Status != NotFixed {
		t.Fatalf("status = %s (%s), want not_fixed", res.Status, res.Detail)
	}
}

func TestVerify_FarAwaySameRuleIsNotTheOriginal(t *testing.T) {
	needGit(t)
	// Two findings of the same rule 40 lines apart. Fixing the first must verify even
	// though the second still fires: it is outside the +/-10 line window and has its own
	// fingerprint, and it already existed so it is not "new".
	body := "VULN one\n" + strings.Repeat("x\n", 40) + "VULN two\n"
	root := writeTree(t, map[string]string{"a.txt": body})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	diff := "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n-VULN one\n+fixed one\n x\n"
	res := newVerifier(t, root, sc, Options{}).Verify(context.Background(), orig("fake", "r", "a.txt", "VULN one", 1), diff)
	if res.Status != Verified {
		t.Fatalf("status = %s (%s), want verified", res.Status, res.Detail)
	}
}

func TestVerify_IntroducesNew(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{
		"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n",
	})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection", "EVAL": "eval-use"}}
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(cmd)  # VULN\n+eval(cmd)  # EVAL\n print('x')\n"
	tmp := t.TempDir()
	res := newVerifier(t, root, sc, Options{TempDir: tmp}).Verify(context.Background(),
		orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2), diff)
	if res.Status != IntroducesNew {
		t.Fatalf("status = %s (%s), want introduces_new", res.Status, res.Detail)
	}
	if len(res.NewFindings) != 1 || !strings.HasPrefix(res.NewFindings[0], "eval-use app.py:2") {
		t.Errorf("NewFindings = %v", res.NewFindings)
	}
	leftovers(t, tmp)
}

func TestVerify_KnownFindingsAreNotNew(t *testing.T) {
	needGit(t)
	// The main scan saw (and filtered) an eval-use finding in new.py; the baseline
	// scan sees it too, so it is not new. Known guards the case where the baseline
	// is narrower than the main scan.
	root := writeTree(t, map[string]string{"app.py": "VULN\n", "new.py": "x\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r1", "EVAL": "r2"}}
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-VULN\n+EVAL\n"
	known := []model.Finding{{Tool: "other", RuleID: "r2", Location: model.Location{File: "app.py"}, Fingerprint: "zz"}}
	res := newVerifier(t, root, sc, Options{Known: known}).Verify(context.Background(), orig("fake", "r1", "app.py", "VULN", 1), diff)
	if res.Status != Verified {
		t.Fatalf("status = %s (%s), want verified", res.Status, res.Detail)
	}
}

func TestVerify_PatchDoesNotApply(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n import os\n-this line is not in the file\n+replaced\n"
	tmp := t.TempDir()
	res := newVerifier(t, root, sc, Options{TempDir: tmp}).Verify(context.Background(), orig("fake", "r", "app.py", "x", 2), diff)
	if res.Status != PatchFailed {
		t.Fatalf("status = %s (%s), want patch_failed", res.Status, res.Detail)
	}
	if sc.runs.Load() != 0 {
		t.Error("the scanner must not run when the patch did not apply")
	}
	leftovers(t, tmp)
}

func TestVerify_UnsafeDiffsRejectedBeforeAnythingRuns(t *testing.T) {
	root := writeTree(t, map[string]string{"app.py": "VULN\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	called := false
	tmp := t.TempDir()
	v := newVerifier(t, root, sc, Options{TempDir: tmp, Apply: func(context.Context, string, string) error { called = true; return nil }})
	hdr := func(a, b string) string { return "--- " + a + "\n+++ " + b + "\n@@ -1 +1 @@\n-VULN\n+ok\n" }
	cases := map[string]string{
		"parent traversal":   hdr("a/../../etc/passwd", "b/../../etc/passwd"),
		"traversal mid path": hdr("a/x/../../y", "b/x/../../y"),
		"absolute":           hdr("/etc/passwd", "/etc/passwd"),
		"absolute after a/":  hdr("a//etc/passwd", "b//etc/passwd"),
		"dot git":            hdr("a/.git/config", "b/.git/config"),
		"nested dot git":     hdr("a/sub/.git/hooks/pre-commit", "b/sub/.git/hooks/pre-commit"),
		"quoted path":        hdr(`"a/we\nird"`, `"b/we\nird"`),
		"backslash":          hdr(`a\..\x`, `b\..\x`),
		"rename out":         "diff --git a/app.py b/app.py\nsimilarity index 100%\nrename from app.py\nrename to ../evil.py\n",
		"git header":         "diff --git a/../x b/../x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-VULN\n+ok\n",
		"symlink":            "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+/etc/passwd\n",
		"binary":             "diff --git a/b b/b\nGIT binary patch\nliteral 1\nIcmZ\n",
		"empty":              "",
		"no files":           "@@ -1 +1 @@\n-a\n+b\n",
		"oversize":           hdr("a/app.py", "b/app.py") + strings.Repeat("+x\n", DefaultMaxDiffBytes),
		"too many files":     strings.Repeat("--- a/f\n+++ b/f\n", 1) + manyFiles(DefaultMaxDiffFiles+1),
	}
	for name, diff := range cases {
		res := v.Verify(context.Background(), orig("fake", "r", "app.py", "VULN", 1), diff)
		if res.Status != PatchFailed {
			t.Errorf("%s: status = %s (%s), want patch_failed", name, res.Status, res.Detail)
		}
		if !strings.Contains(res.Detail, "rejected") {
			t.Errorf("%s: detail %q should say the diff was rejected", name, res.Detail)
		}
	}
	if called || sc.runs.Load() != 0 {
		t.Error("an unsafe diff reached the applier or the scanner")
	}
	leftovers(t, tmp)
}

func manyFiles(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("--- a/f" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n+++ b/f" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n@@ -1 +1 @@\n-a\n+b\n")
	}
	return b.String()
}

func TestVerify_OversizeTargetIsSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"a.txt": strings.Repeat("x", 4096), "b.txt": strings.Repeat("y", 4096)})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	tmp := t.TempDir()
	v := newVerifier(t, root, sc, Options{TempDir: tmp, MaxCopyBytes: 5000})
	res := v.Verify(context.Background(), orig("fake", "r", "a.txt", "x", 1), "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-x\n+y\n")
	if res.Status != Skipped || !strings.Contains(res.Detail, "target too large") {
		t.Fatalf("got %s (%s), want skipped: target too large", res.Status, res.Detail)
	}
	leftovers(t, tmp)

	v = newVerifier(t, root, sc, Options{TempDir: tmp, MaxCopyFiles: 1})
	res = v.Verify(context.Background(), orig("fake", "r", "a.txt", "x", 1), "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-x\n+y\n")
	if res.Status != Skipped {
		t.Fatalf("file-count cap: got %s (%s), want skipped", res.Status, res.Detail)
	}
	leftovers(t, tmp)
}

func TestVerify_ExcludedDirsAndSymlinksNotCopied(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app.py":                       "x\n",
		".git/config":                  "g\n",
		"node_modules/p/i.js":          "n\n",
		"vendor/v.go":                  "v\n",
		".achilles/state":              "s\n",
		"dist/out.js":                  "d\n",
		"deep/node_modules/q/index.js": "q\n",
	})
	if err := os.Symlink("/", filepath.Join(root, "rootlink")); err != nil {
		t.Skip("symlinks unsupported")
	}
	dst := t.TempDir()
	if err := copyTree(root, dst, DefaultMaxCopyBytes, DefaultMaxCopyFiles, ""); err != nil {
		t.Fatal(err)
	}
	var got []string
	_ = filepath.WalkDir(dst, func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			r, _ := filepath.Rel(dst, p)
			got = append(got, filepath.ToSlash(r))
		}
		return nil
	})
	if len(got) != 1 || got[0] != "app.py" {
		t.Errorf("copied %v, want only app.py", got)
	}
}

func TestVerify_UnknownScannerIsSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"a": "x\n"})
	v := New(lookup{}, root, Options{TempDir: t.TempDir()})
	res := v.Verify(context.Background(), orig("opengrep-shadow", "r", "a", "x", 1), "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n")
	if res.Status != Skipped {
		t.Fatalf("got %s (%s), want skipped", res.Status, res.Detail)
	}
}

func TestVerify_ScannerFailureIsErrorNotVerified(t *testing.T) {
	root := writeTree(t, map[string]string{"app.py": "VULN\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}, fail: errors.New("tool crashed")}
	tmp := t.TempDir()
	apply := func(context.Context, string, string) error { return nil }
	res := newVerifier(t, root, sc, Options{TempDir: tmp, Apply: apply}).Verify(context.Background(), orig("fake", "r", "app.py", "VULN", 1),
		"--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-VULN\n+ok\n")
	if res.Status != Error || !strings.Contains(res.Detail, "tool crashed") {
		t.Fatalf("got %s (%s), want error", res.Status, res.Detail)
	}
	leftovers(t, tmp)
}

func TestVerify_BaselineRunsOncePerTool(t *testing.T) {
	root := writeTree(t, map[string]string{"app.py": "VULN\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	apply := func(_ context.Context, dir, _ string) error { // pretend patch: remove the marker
		return os.WriteFile(filepath.Join(dir, "app.py"), []byte("ok\n"), 0o644)
	}
	v := newVerifier(t, root, sc, Options{Apply: apply})
	d := "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-VULN\n+ok\n"
	for i := 0; i < 3; i++ {
		if res := v.Verify(context.Background(), orig("fake", "r", "app.py", "VULN", 1), d); res.Status != Verified {
			t.Fatalf("run %d: %s (%s)", i, res.Status, res.Detail)
		}
	}
	if got := sc.runs.Load(); got != 4 { // 1 baseline + 3 patched copies
		t.Errorf("scanner ran %d times, want 4 (one shared baseline)", got)
	}
}

func TestCheckDiff_AcceptsOrdinaryDiffs(t *testing.T) {
	ok := []string{
		fixDiff,
		"diff --git a/src/a b.go b/src/a b.go\n--- a/src/a b.go\n+++ b/src/a b.go\n@@ -1 +1 @@\n-x\n+y\n",
		"--- a/f.txt\t2024-01-01 00:00:00\n+++ b/f.txt\t2024-01-01 00:00:00\n@@ -1 +1 @@\n-x\n+y\n",
		"--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+hello\n",
		"--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-x\n+y\n",
		"--- a/..data/f\n+++ b/..data/f\n@@ -1 +1 @@\n-x\n+y\n", // "..data" is a name, not a parent reference
	}
	for i, d := range ok {
		if err := checkDiff(d, DefaultMaxDiffBytes, DefaultMaxDiffFiles); err != nil {
			t.Errorf("case %d rejected: %v", i, err)
		}
	}
}

func TestRelTo(t *testing.T) {
	root := t.TempDir()
	if got := relTo(root, filepath.Join(root, "a", "b.go")); got != "a/b.go" {
		t.Errorf("got %q", got)
	}
	if got := relTo(root, "./a//b.go"); got != "a/b.go" {
		t.Errorf("got %q", got)
	}
	if got := relTo(root, "file://"+filepath.Join(root, "x.go")); got != "x.go" {
		t.Errorf("got %q", got)
	}
}
