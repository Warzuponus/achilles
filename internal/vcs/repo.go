package vcs

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Repo is what a scan of the git history needs to know about its target.
type Repo struct {
	// InWorkTree is false when the directory is not inside a git work tree, when
	// git is not installed, and when git refuses to read the repository (a
	// checkout owned by another user, which git calls dubious ownership).
	InWorkTree bool
	// Shallow is true for a clone made with a depth limit: commits older than the
	// limit are not there to be scanned.
	Shallow bool
	// Prefix is the directory's path below the top of the repository, empty at
	// the top. Commits name files relative to the top.
	Prefix string
	// Reason is git's own message when InWorkTree is false.
	Reason string
}

// RepoState describes dir as a git checkout.
func RepoState(dir string) Repo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommand and flags; dir is passed to -C, not parsed as an option
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--is-inside-work-tree", "--is-shallow-repository", "--show-prefix")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		reason := strings.TrimSpace(stderr.String())
		if reason == "" {
			reason = err.Error()
		}
		if i := strings.IndexByte(reason, '\n'); i >= 0 {
			reason = reason[:i]
		}
		return Repo{Reason: reason}
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	for len(lines) < 3 {
		lines = append(lines, "")
	}
	return Repo{
		InWorkTree: strings.TrimSpace(lines[0]) == "true",
		Shallow:    strings.TrimSpace(lines[1]) == "true",
		Prefix:     strings.Trim(strings.TrimSpace(lines[2]), "/"),
	}
}

// HasCommit reports whether ref names a commit in the repository at dir.
func HasCommit(dir, ref string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommand; --end-of-options keeps ref from being read as an option
	return exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}").Run() == nil
}
