package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestFilterFindings(t *testing.T) {
	findings := []model.Finding{
		{Location: model.Location{File: "app/handlers.py"}},
		{Location: model.Location{File: "app/untouched.py"}},
		{Location: model.Location{File: "/abs/root/app/handlers.py"}}, // absolute variant
	}
	got := FilterFindings(findings, []string{"app/handlers.py"})
	if len(got) != 2 {
		t.Fatalf("want 2 (relative + abs suffix), got %d", len(got))
	}
	if FilterFindings(findings, nil) != nil {
		t.Error("empty changed set should yield no findings")
	}
}

func TestChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.com",
			"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, c string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q")
	write("a.py", "x=1\n")
	write("b.py", "y=1\n")
	git("add", ".")
	git("commit", "-q", "-m", "base")

	// Modify a.py, add a new untracked file.
	write("a.py", "x=2\n")
	write("c.py", "z=1\n")

	changed, err := ChangedFiles(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, f := range changed {
		set[f] = true
	}
	if !set["a.py"] {
		t.Error("modified a.py should be reported changed")
	}
	if !set["c.py"] {
		t.Error("untracked c.py should be reported changed")
	}
	if set["b.py"] {
		t.Error("unchanged b.py should NOT be reported")
	}
}
