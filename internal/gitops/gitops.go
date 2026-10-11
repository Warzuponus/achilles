// Package gitops performs the local git steps for Achilles's auto-fix PRs:
// branch from a base, apply unified diffs, commit, and push to a remote. It is
// deliberately thin — every git invocation goes through an injectable Runner so
// the command sequence is unit-testable without a real repository, and the real
// path is just os/exec. Nothing here opens a PR or merges anything; that is the
// github client's job, gated behind an explicit flag.
package gitops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner runs one git subcommand in dir and returns its combined output. When
// stdinFile is non-empty it is fed to the command's stdin (used for `git apply`).
type Runner func(ctx context.Context, dir, stdinFile string, args ...string) (string, error)

// Repo is a working tree that auto-fix operates on.
type Repo struct {
	Dir string
	Run Runner // defaults to ExecRunner
}

// ExecRunner is the production Runner: it shells out to git.
func ExecRunner(ctx context.Context, dir, stdinFile string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	if stdinFile != "" {
		f, err := os.Open(stdinFile) // #nosec G304 -- operator-controlled temp file we just wrote
		if err != nil {
			return "", err
		}
		defer f.Close()
		cmd.Stdin = f
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (r *Repo) run(ctx context.Context, stdinFile string, args ...string) (string, error) {
	if r.Run == nil {
		r.Run = ExecRunner
	}
	return r.Run(ctx, r.Dir, stdinFile, args...)
}

// CurrentBranch returns the checked-out branch (or a detached-HEAD sha).
func (r *Repo) CurrentBranch(ctx context.Context) (string, error) {
	out, err := r.run(ctx, "", "rev-parse", "--abbrev-ref", "HEAD")
	return strings.TrimSpace(out), err
}

// AddWorktree creates a new working tree at path with branch created (or reset)
// at base and checked out there. The repository's own working tree — the user's
// checkout, with whatever is uncommitted or untracked in it — is not touched.
// Git refuses if branch is already checked out somewhere, which is the right
// answer: we must not move a branch someone is standing on.
func (r *Repo) AddWorktree(ctx context.Context, path, branch, base string) error {
	_, err := r.run(ctx, "", "worktree", "add", "-B", branch, path, base)
	return err
}

// RemoveWorktree removes a working tree made by AddWorktree. The branch stays.
func (r *Repo) RemoveWorktree(ctx context.Context, path string) error {
	_, err := r.run(ctx, "", "worktree", "remove", "--force", path)
	return err
}

// Dirty reports whether the working tree has uncommitted or untracked changes.
func (r *Repo) Dirty(ctx context.Context) (bool, error) {
	out, err := r.run(ctx, "", "status", "--porcelain")
	return strings.TrimSpace(out) != "", err
}

// Prefix returns r.Dir's path relative to the top of its working tree, with
// forward slashes and no trailing slash ("" at the top).
func (r *Repo) Prefix(ctx context.Context) (string, error) {
	out, err := r.run(ctx, "", "rev-parse", "--show-prefix")
	return strings.TrimSuffix(strings.TrimSpace(out), "/"), err
}

// Apply applies a unified diff via `git apply`. It writes the diff to a temp file
// (git reads it from stdin) and returns an error if the patch does not apply
// cleanly — the caller treats that as a skip, not a hard failure.
func (r *Repo) Apply(ctx context.Context, diff string) error {
	f, err := os.CreateTemp("", "achilles-fix-*.diff")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(diff); err != nil {
		f.Close()
		return err
	}
	f.Close()
	// -p1 is explicit: without it git guesses how many leading path components
	// to strip from a plain (non "diff --git") patch by looking at the files on
	// disk, so the path a caller validated would not be the path git writes.
	_, err = r.run(ctx, f.Name(), "apply", "-p1", "--whitespace=nowarn")
	return err
}

// Commit commits exactly the named paths (relative to r.Dir) with msg, and nothing
// else (identity via env if unset).
//
// There is deliberately no way to commit "everything": this package pushes what
// it commits, and a working tree holds things that were never meant to leave the
// machine (an untracked .env, a scan's own vault and reports). The pathspec is
// passed to `git commit` as well as `git add`, so anything else that happens to be
// staged stays out of the commit.
func (r *Repo) Commit(ctx context.Context, msg string, paths ...string) error {
	if len(paths) == 0 {
		return fmt.Errorf("gitops: Commit needs the paths to commit; it never stages a whole tree")
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" || strings.HasPrefix(p, "-") || strings.HasPrefix(p, ":") {
			return fmt.Errorf("gitops: refusing to commit path %q", p)
		}
	}
	if _, err := r.run(ctx, "", append([]string{"add", "--"}, paths...)...); err != nil {
		return err
	}
	_, err := r.run(ctx, "", append([]string{"commit", "-m", msg, "--"}, paths...)...)
	return err
}

// Push pushes branch to remote, setting upstream.
func (r *Repo) Push(ctx context.Context, remote, branch string) error {
	_, err := r.run(ctx, "", "push", "-u", remote, branch)
	return err
}

// TopLevel returns the git working-tree root that contains path.
func TopLevel(ctx context.Context, path string) (string, error) {
	dir := path
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		dir = filepath.Dir(path)
	}
	out, err := ExecRunner(ctx, dir, "", "rev-parse", "--show-toplevel")
	return strings.TrimSpace(out), err
}
