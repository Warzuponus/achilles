package triage

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Citation checking (Cloudflare security-audit skill, "independent record
// verification"): a verdict's prose ends up in reports, issues and pull requests,
// and a reader trusts a line number more than a paragraph. A model that cites
// "line 42" when it was shown lines 10-30, or names another file's line it never
// saw, has made that reference up. The pipeline cannot tell whether the claim is
// right, but it can tell whether the model could have seen the line, and flags
// the ones it could not.

// maxCitations bounds how many unverified references are kept on a verdict.
const maxCitations = 10

var (
	// gutterLine matches a source line of enrich.Context: ">>   12 | code" or "   12 | code".
	gutterLine = regexp.MustCompile(`^\s*(?:>>)?\s*(\d+)\s*\|`)
	// fileLineRef matches "path/to/file.go:42" and "file.go:42-48".
	fileLineRef = regexp.MustCompile(`([A-Za-z0-9_./\\-]+\.[A-Za-z0-9]{1,8}):(\d+)(?:\s*[-–]\s*(\d+))?`)
	// bareLineRef matches "line 42", "lines 42-48", "L42" and "lines 42 and 48".
	bareLineRef = regexp.MustCompile(`(?i)\b(?:lines?\s+|L)(\d+)(?:\s*(?:[-–]|to|and|,)\s*(\d+))?\b`)
)

// shownLines returns the line numbers that appear in the code context.
func shownLines(codeContext string) map[int]bool {
	shown := map[int]bool{}
	for _, line := range strings.Split(codeContext, "\n") {
		if m := gutterLine.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				shown[n] = true
			}
		}
	}
	return shown
}

// unverifiedCitations returns the line references in texts that point at a line
// of file that is not in codeContext, or at a line of another file (only file's
// own code is ever shown in triage). Sorted and deduplicated.
func unverifiedCitations(file, codeContext string, texts ...string) []string {
	shown := shownLines(codeContext)
	own := strings.ToLower(path.Base(strings.ReplaceAll(file, "\\", "/")))
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	inRange := func(a, b string) bool {
		lo, err := strconv.Atoi(a)
		if err != nil || lo <= 0 {
			return true // not a line number we can judge
		}
		hi := lo
		if b != "" {
			if n, err := strconv.Atoi(b); err == nil && n >= lo && n-lo <= 500 {
				hi = n
			}
		}
		return shown[lo] && shown[hi]
	}
	for _, t := range texts {
		if t == "" {
			continue
		}
		// File-qualified references first; blank them out so "app.py:12" is not
		// read again as a bare "12".
		rest := fileLineRef.ReplaceAllStringFunc(t, func(m string) string {
			sm := fileLineRef.FindStringSubmatch(m)
			name := strings.ToLower(path.Base(strings.ReplaceAll(sm[1], "\\", "/")))
			if name != own || !inRange(sm[2], sm[3]) {
				add(strings.TrimSpace(m))
			}
			return strings.Repeat(" ", len(m))
		})
		for _, sm := range bareLineRef.FindAllStringSubmatch(rest, -1) {
			if !inRange(sm[1], sm[2]) {
				ref := "line " + sm[1]
				if sm[2] != "" {
					ref = fmt.Sprintf("lines %s-%s", sm[1], sm[2])
				}
				add(ref)
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxCitations {
		out = out[:maxCitations]
	}
	return out
}
