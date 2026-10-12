package vcs

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Tracked reports whether path (relative to root) is a file git tracks in root.
// It is false when root is not a git repository or git is not installed.
func Tracked(root, path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommand; path follows "--" and is never parsed as an option
	return exec.CommandContext(ctx, "git", "-C", root, "ls-files", "--error-unmatch", "--", path).Run() == nil
}

// CommittedChanges returns the tracked files at or under path (relative to root)
// that differ between ref and HEAD.
//
// Unlike ChangedFiles it leaves the working tree out: it answers "did the commits
// under review change this", not "is this file different right now". The
// difference matters for files a scan itself writes, such as the Evidence Vault,
// which are modified in the working tree by the very run that asks.
func CommittedChanges(root, ref, path string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommand; ref is the operator's --diff value and path follows "--"
	out, err := exec.CommandContext(ctx, "git", "-C", root, "diff", "--name-only", ref, "HEAD", "--", path).Output()
	if err != nil {
		return nil
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files
}
