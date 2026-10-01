// Package vcs provides git helpers for diff-aware scanning (DESIGN.md §11):
// restrict findings to files changed versus a base ref, so PR scans are fast and
// focused on what the change introduced.
package vcs

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
)

// ChangedFiles returns files changed in root relative to a git ref (e.g. the PR
// base branch). Paths are relative to root. Includes tracked changes vs the ref
// plus untracked files.
func ChangedFiles(root, ref string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	set := map[string]bool{}
	add := func(out []byte) {
		for _, line := range strings.Split(string(out), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				set[line] = true
			}
		}
	}

	// Changed vs the ref (staged + unstaged).
	out, err := exec.CommandContext(ctx, "git", "-C", root, "diff", "--name-only", ref).Output()
	if err != nil {
		return nil, err
	}
	add(out)

	// Untracked files (new, not yet committed).
	if unt, err := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "--others", "--exclude-standard").Output(); err == nil {
		add(unt)
	}

	files := make([]string, 0, len(set))
	for fpth := range set {
		files = append(files, fpth)
	}
	return files, nil
}

// FilterFindings keeps only findings whose file is in the changed set. Matching
// is by cleaned relative path or basename suffix (SARIF URIs vary by tool).
func FilterFindings(findings []model.Finding, changed []string) []model.Finding {
	if len(changed) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, c := range changed {
		want[filepath.Clean(c)] = true
	}

	var out []model.Finding
	for _, f := range findings {
		file := filepath.Clean(f.Location.File)
		if want[file] || matchesSuffix(want, file) {
			out = append(out, f)
		}
	}
	return out
}

// matchesSuffix handles absolute or prefixed finding paths by checking whether
// any changed (relative) path is a suffix of the finding's path.
func matchesSuffix(want map[string]bool, file string) bool {
	for c := range want {
		if strings.HasSuffix(file, string(filepath.Separator)+c) {
			return true
		}
	}
	return false
}
