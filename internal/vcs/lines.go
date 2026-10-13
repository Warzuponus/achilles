package vcs

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var hunkNew = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// AddedLines returns the lines of file (relative to root) that differ from ref:
// the lines the change under review added or edited, by their numbers in the file
// as it is now. whole is true when every line is new, which is the case for a file
// git does not track yet. A file that did not change yields an empty set.
func AddedLines(root, ref, file string) (lines map[int]bool, whole bool) {
	if !Tracked(root, file) {
		return nil, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommand; ref is the operator's --diff value and file follows "--"
	out, err := exec.CommandContext(ctx, "git", "-C", root, "diff", "--no-ext-diff", "-U0", ref, "--", file).Output()
	if err != nil {
		return nil, false
	}
	lines = map[int]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		m := hunkNew.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		for i := 0; i < count; i++ {
			lines[start+i] = true
		}
	}
	return lines, false
}
