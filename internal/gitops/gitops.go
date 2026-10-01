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

// CreateBranch creates (or resets) branch at base and checks it out.
func (r *Repo) CreateBranch(ctx context.Context, name, base string) error {
	_, err := r.run(ctx, "", "checkout", "-B", name, base)
	return err
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
	_, err = r.run(ctx, f.Name(), "apply", "--whitespace=nowarn")
	return err
}

// Commit stages everything and commits with msg (identity via env if unset).
func (r *Repo) Commit(ctx context.Context, msg string) error {
	if _, err := r.run(ctx, "", "add", "-A"); err != nil {
		return err
	}
	_, err := r.run(ctx, "", "commit", "-m", msg)
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
