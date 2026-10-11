package gitops

import (
	"context"
	"os"
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
		"apply -p1 --whitespace=nowarn <PATCH-BODY",
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
