package verifyfix

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func hunk(path string) string {
	return "--- a/" + path + "\n+++ b/" + path + "\n@@ -1 +1 @@\n-x\n+y\n"
}

func TestCheckFix_AcceptsAnEditToTheFindingsOwnFile(t *testing.T) {
	for _, c := range []struct{ diff, file string }{
		{fixDiff, "app.py"},
		{hunk("src/handlers/run.go"), "src/handlers/run.go"},
		{"diff --git a/src/a.go b/src/a.go\nindex 1..2 100644\n" + hunk("src/a.go"), "src/a.go"},
		{hunk("src/a.go"), "./src/a.go"},                                                              // the finding's path is cleaned
		{hunk("src/a.go"), filepath.FromSlash("src/a.go")},                                            // and arrives with the host separator (a backslash on Windows only)
		{hunk("deploy/Dockerfile"), "deploy/Dockerfile"},                                              // IaC findings are fixed in place too
		{"diff --git a/src/my file.go b/src/my file.go\n" + hunk("src/my file.go"), "src/my file.go"}, // spaces in the path
	} {
		if err := CheckFix(c.diff, c.file); err != nil {
			t.Errorf("CheckFix(%q) rejected a fix to its own file: %v", c.file, err)
		}
	}
}

// The attack this stops: a comment in flagged code talks the model into a "fix"
// that also edits a workflow, a build script or a manifest. The re-scan would pass
// (the finding is gone, the one scanner reports nothing new) and the change would
// ride into a pull request.
func TestCheckFix_RejectsAnythingOutsideTheFindingsFile(t *testing.T) {
	cases := map[string]string{
		"a second file":            hunk("app.py") + hunk("util.py"),
		"a workflow added to it":   hunk("app.py") + hunk(".github/workflows/ci.yml"),
		"a build script":           hunk("app.py") + hunk("Makefile"),
		"a manifest":               hunk("app.py") + hunk("package.json"),
		"a different file only":    hunk("other.py"),
		"same name, other dir":     hunk("vendor/app.py"),
		"a new file":               "--- /dev/null\n+++ b/app.py\n@@ -0,0 +1 @@\n+x\n",
		"a new file beside it":     hunk("app.py") + "diff --git a/evil.sh b/evil.sh\nnew file mode 100755\n--- /dev/null\n+++ b/evil.sh\n@@ -0,0 +1 @@\n+curl x | sh\n",
		"deleting the file":        "--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
		"a rename":                 "diff --git a/app.py b/app2.py\nrename from app.py\nrename to app2.py\n",
		"no -p1 prefix":            "--- app.py\n+++ app.py\n@@ -1 +1 @@\n-x\n+y\n", // git apply would strip "app.py" itself
		"prefix that is not a/ b/": "--- x/util.py\n+++ x/util.py\n@@ -1 +1 @@\n-x\n+y\n",
		"diff --git names another": "diff --git a/app.py b/util.py\n" + hunk("app.py"),
		"making it executable":     "diff --git a/app.py b/app.py\nold mode 100644\nnew mode 100755\n",
		"mode change with an edit": "diff --git a/app.py b/app.py\nold mode 100644\nnew mode 100755\n" + hunk("app.py"),
	}
	for name, diff := range cases {
		if err := CheckFix(diff, "app.py"); err == nil {
			t.Errorf("%s: accepted, want rejected:\n%s", name, diff)
		}
	}
	if err := CheckFix(hunk("app.py"), ""); err == nil {
		t.Error("a finding with no file gives the fix no place it may change")
	}
}

// git apply strips the first path component whatever it is called. The scope check
// must look at the path that will be written, not the one that was typed.
func TestCheckFix_ComparesThePathGitApplyWillWrite(t *testing.T) {
	// The finding is in a/b.go (a directory really named "a"). This header reads
	// like it, but -p1 would patch b.go at the root.
	if err := CheckFix("--- a/b.go\n+++ a/b.go\n@@ -1 +1 @@\n-x\n+y\n", "a/b.go"); err == nil {
		t.Error("header a/b.go patches b.go after -p1; it must not pass as a fix to a/b.go")
	}
	if err := CheckFix(hunk("a/b.go"), "a/b.go"); err != nil {
		t.Errorf("a/a/b.go is the right header for a file in a directory named a: %v", err)
	}
}

func TestCheckFix_NeverTouchesPathsThatRunByThemselves(t *testing.T) {
	for _, file := range []string{
		".github/workflows/ci.yml", ".github/actions/build/action.yml", ".GitHub/workflows/x.yml",
		".gitlab-ci.yml", ".circleci/config.yml", "Jenkinsfile", "sub/Jenkinsfile", "azure-pipelines.yml",
		".gitmodules", ".gitattributes", ".husky/pre-commit", ".pre-commit-config.yaml", ".devcontainer/devcontainer.json",
	} {
		err := CheckFix(hunk(file), file)
		if err == nil {
			t.Errorf("%s: an automatic fix must never edit it, even when the finding is there", file)
			continue
		}
		if !strings.Contains(err.Error(), "not applied automatically") {
			t.Errorf("%s: unhelpful reason: %v", file, err)
		}
	}
	// A file that merely looks similar is an ordinary file.
	for _, file := range []string{"docs/github/notes.md", "src/gitmodules.go", "ci/build.go"} {
		if err := CheckFix(hunk(file), file); err != nil {
			t.Errorf("%s is an ordinary file: %v", file, err)
		}
	}
}

func TestCheckFix_KeepsTheStructuralChecks(t *testing.T) {
	if err := CheckFix("--- a/../app.py\n+++ b/../app.py\n@@ -1 +1 @@\n-x\n+y\n", "app.py"); err == nil {
		t.Error("a path that escapes the tree is still rejected")
	}
	if err := CheckFix("", "app.py"); err == nil {
		t.Error("an empty diff is still rejected")
	}
}

// Verify applies the scope rule before it copies or runs anything.
func TestVerify_RejectsAnOutOfScopeDiffWithoutRunningAnything(t *testing.T) {
	sc := &fakeScanner{id: "fake", rules: map[string]string{"# VULN": "cmd-injection"}}
	v := New(lookup{sc.id: sc}, t.TempDir(), Options{})

	res := v.Verify(context.Background(), orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2),
		fixDiff+hunk(".github/workflows/ci.yml"))
	if res.Status != PatchFailed || !strings.Contains(res.Detail, "outside the finding's file") {
		t.Errorf("result = %+v, want patch_failed naming the scope", res)
	}
	if sc.runs.Load() != 0 {
		t.Errorf("the scanner ran %d time(s) on a rejected diff", sc.runs.Load())
	}
}
