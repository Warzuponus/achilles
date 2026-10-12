package gitops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// recordingRunner captures the git command sequence without shelling out.
func recordingRunner(log *[]string) Runner {
	return func(ctx context.Context, dir, stdinFile string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if stdinFile != "" {
			// Prove Apply fed the diff via stdin by echoing the file's contents.
			b, _ := os.ReadFile(stdinFile)
			line += " <" + strings.TrimSpace(string(b))
		}
		*log = append(*log, line)
		if len(args) > 0 && args[0] == "rev-parse" {
			return "main\n", nil
		}
		return "", nil
	}
}

func TestBranchApplyCommitPush_Sequence(t *testing.T) {
	var log []string
	r := &Repo{Dir: "/repo", Run: recordingRunner(&log)}
	ctx := context.Background()

	base, err := r.CurrentBranch(ctx)
	if err != nil || base != "main" {
		t.Fatalf("CurrentBranch=%q err=%v", base, err)
	}
	if err := r.AddWorktree(ctx, "/tmp/wt", "achilles/autofix-abc", base); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(ctx, "PATCH-BODY"); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(ctx, "fix: auto", "src/a.go", "src/b.go"); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(ctx, "origin", "achilles/autofix-abc"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"rev-parse --abbrev-ref HEAD",
		"worktree add -B achilles/autofix-abc /tmp/wt main",
		"apply -p1 --recount --whitespace=nowarn <PATCH-BODY",
		"add -- src/a.go src/b.go",
		"commit -m fix: auto -- src/a.go src/b.go",
		"push -u origin achilles/autofix-abc",
	}
	if len(log) != len(want) {
		t.Fatalf("got %d steps %v, want %d", len(log), log, len(want))
	}
	for i := range want {
		if log[i] != want[i] {
			t.Errorf("step %d = %q, want %q", i, log[i], want[i])
		}
	}
}

// There is no way to commit "everything": this package pushes what it commits.
func TestCommit_NeverStagesAWholeTree(t *testing.T) {
	var log []string
	r := &Repo{Dir: "/repo", Run: recordingRunner(&log)}
	ctx := context.Background()

	if err := r.Commit(ctx, "msg"); err == nil {
		t.Error("Commit with no paths must refuse, not fall back to staging everything")
	}
	for _, bad := range []string{"", " ", "-A", "--all", ":/", ":(glob)**"} {
		if err := r.Commit(ctx, "msg", "src/a.go", bad); err == nil {
			t.Errorf("Commit must refuse the path %q", bad)
		}
	}
	if len(log) != 0 {
		t.Errorf("a refused commit must run no git command, ran %v", log)
	}
	for _, line := range log {
		if strings.Contains(line, "add -A") || strings.Contains(line, "add .") {
			t.Errorf("staged wholesale: %q", line)
		}
	}
}

// A model writes the changed lines right far more often than it counts them. git
// refuses a hunk whose header disagrees with its body unless told to recount.
func TestApply_ToleratesWrongHunkLineCounts(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\nprint('x')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The header claims 9 lines before and after; the hunk has 3.
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,9 +1,9 @@\n import os\n-os.system(cmd)\n+subprocess.run([cmd])\n print('x')\n"
	if err := (&Repo{Dir: dir}).Apply(context.Background(), diff); err != nil {
		t.Fatalf("a correct change with miscounted hunk lines must apply: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "app.py"))
	// A Windows git configured with core.autocrlf may write CRLF line endings.
	if got := strings.ReplaceAll(string(b), "\r\n", "\n"); got != "import os\nsubprocess.run([cmd])\nprint('x')\n" {
		t.Errorf("file after apply:\n%q", got)
	}

	// The context still has to match: recounting does not make a wrong patch apply.
	wrong := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import sys\n-os.system(cmd)\n+x\n print('x')\n"
	if err := (&Repo{Dir: dir}).Apply(context.Background(), wrong); err == nil {
		t.Error("a patch whose context does not match the file must still be refused")
	}
}
