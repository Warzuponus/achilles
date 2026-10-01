package enrich

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestGitBlame(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Ada Lovelace", "GIT_AUTHOR_EMAIL=ada@example.com",
			"GIT_COMMITTER_NAME=Ada Lovelace", "GIT_COMMITTER_EMAIL=ada@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("l1\neval(x)\nl3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "a.py")
	git("commit", "-q", "-m", "add a.py")

	f := model.Finding{Location: model.Location{File: "a.py", Region: model.Region{StartLine: 2}}}
	b, ok := New(0).GitBlame(f, dir)
	if !ok {
		t.Fatal("expected blame to succeed in a git repo")
	}
	if b.Author != "Ada Lovelace" {
		t.Errorf("author: got %q", b.Author)
	}
	if len(b.Commit) < 8 || b.Date == "" {
		t.Errorf("commit/date not parsed: %+v", b)
	}
}

func TestGitBlame_NotARepo(t *testing.T) {
	f := model.Finding{Location: model.Location{File: "x.py", Region: model.Region{StartLine: 1}}}
	if _, ok := New(0).GitBlame(f, t.TempDir()); ok {
		t.Error("blame should fail (ok=false) outside a git repo")
	}
}

func TestContext_AppendsBlameWhenEnabled(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Grace Hopper", "GIT_AUTHOR_EMAIL=g@example.com",
			"GIT_COMMITTER_NAME=Grace Hopper", "GIT_COMMITTER_EMAIL=g@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	os.WriteFile(filepath.Join(dir, "a.py"), []byte("l1\neval(x)\n"), 0o644)
	run("add", "a.py")
	run("commit", "-q", "-m", "x")

	e := New(0)
	e.IncludeBlame = true
	ctx := e.Context(model.Finding{Location: model.Location{File: "a.py", Region: model.Region{StartLine: 2}}}, dir)
	if !strings.Contains(ctx, "Grace Hopper") {
		t.Errorf("context should include blame attribution:\n%s", ctx)
	}
}
