// Package suppress honours suppressions written in the code being scanned:
//
//	subprocess.run(cmd, shell=True)  # achilles:ignore B602 -- cmd is a constant, see build.py
//
//	// achilles:ignore gosec:G204 -- the binary path is validated by resolveTool
//	out, err := exec.Command(bin, args...).Output()
//
// A marker names the rule or rules it is about and says why, after " -- ". It
// applies to a finding on its own line, or on the line directly below when the
// marker stands alone in a comment.
//
// This is configuration that arrives with the code under review, so it follows the
// rules the rest of Achilles sets for that: a suppression is never silent (the
// finding moves to its own list in every report, with the reason), a marker with no
// rule or no reason is not honoured, credential findings cannot be suppressed this
// way, and the caller decides whether markers are honoured at all
// (--no-repo-config) and which of them the change under review itself added.
package suppress

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Warzuponus/achilles/internal/model"
)

// Token is the text that makes a comment a suppression.
const Token = "achilles:ignore"

const (
	maxFileBytes = 8 << 20 // a source file larger than this is not read for markers
	maxReason    = 300
)

// Marker is one suppression comment.
type Marker struct {
	Line   int      // 1-based line it was written on
	Rules  []string // the rules it names, as written
	Reason string
	// Alone is true when nothing but comment punctuation precedes the marker on its
	// line, so it may speak for the line below.
	Alone bool
}

// Problem is a marker that sits where it would apply to a finding but cannot be
// honoured, and why. The finding it was aimed at stays a finding.
type Problem struct {
	File string
	Line int
	Why  string
}

var (
	markerRE = regexp.MustCompile(`(?i)achilles:ignore\b[ \t]*(.*)$`)
	// Closers of block comments, so a reason does not end in "*/".
	closers = []string{"*/", "-->", "%>", "#}", "--}}", "}}"}
)

// Parse reads the marker on one line of source. ok is false when the line has
// none. A marker that is there but unusable is returned with why set.
func Parse(line string) (m Marker, why string, ok bool) {
	loc := markerRE.FindStringSubmatchIndex(line)
	if loc == nil {
		return Marker{}, "", false
	}
	m.Alone = !strings.ContainsFunc(line[:loc[0]], func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
	rest := strings.TrimSpace(line[loc[2]:loc[3]])
	for _, c := range closers {
		rest = strings.TrimSpace(strings.TrimSuffix(rest, c))
	}
	rules, reason, hasReason := strings.Cut(rest, "--")
	m.Rules = strings.FieldsFunc(rules, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	m.Reason = strings.TrimSpace(reason)
	if len(m.Reason) > maxReason {
		m.Reason = strings.TrimSpace(m.Reason[:maxReason]) + " ..."
	}
	switch {
	case len(m.Rules) == 0:
		return m, "it names no rule (write `" + Token + " RULE -- reason`)", true
	case !hasReason || m.Reason == "":
		return m, "it gives no reason (write `" + Token + " RULE -- reason`)", true
	}
	return m, "", true
}

// Covers reports whether the marker names the finding's rule: the rule id, the
// rule id qualified by its tool ("gosec:G204"), or the last dotted segment of a
// long rule id ("dangerous-system-call" for "python.lang.security.dangerous-system-call",
// "template-injection" for "zizmor/template-injection"), alone or with the tool.
func (m Marker) Covers(f model.Finding) bool {
	id := strings.ToLower(f.RuleID)
	if id == "" {
		return false
	}
	// The last segment of a long id: after the last "." (Opengrep's
	// "python.lang.security.dangerous-system-call") or "/" (zizmor's
	// "zizmor/template-injection").
	last := id
	if i := strings.LastIndexAny(id, "./"); i >= 0 && i < len(id)-1 {
		last = id[i+1:]
	}
	tool := strings.ToLower(f.Tool) + ":"
	for _, r := range m.Rules {
		r = strings.ToLower(r)
		if r == id || r == last || r == tool+id || r == tool+last {
			return true
		}
	}
	return false
}

// Suppressible reports whether a finding of this kind may be suppressed by a
// comment. A credential is not made safe by a comment beside it, a dependency
// advisory points at a manifest that usually cannot hold one, and a finding made
// in the git history has no line in the files.
func Suppressible(f model.Finding) bool {
	return !f.IsSecret() && !f.IsDependencyAdvisory() && f.Commit == "" && f.Location.File != "" && f.Location.Region.StartLine > 0
}

// Result is what Find found.
type Result struct {
	// Markers maps the index of a finding (in the slice given to Find) to the
	// marker that suppresses it.
	Markers  map[int]Marker
	Problems []Problem
}

// Find looks, for every suppressible finding, for a marker that covers it: on the
// finding's first line, or alone on the line above. Files are read from inside
// root only. It does not change the findings.
func Find(root string, findings []model.Finding) Result {
	res := Result{Markers: map[int]Marker{}}
	fsRoot, err := os.OpenRoot(root)
	if err != nil {
		return res
	}
	defer fsRoot.Close()

	lines := map[string][]string{} // file -> its lines; nil when it could not be read
	read := func(file string) []string {
		if l, ok := lines[file]; ok {
			return l
		}
		var out []string
		rel := filepath.FromSlash(file)
		if filepath.IsLocal(rel) {
			if st, err := fsRoot.Stat(rel); err == nil && st.Mode().IsRegular() && st.Size() <= maxFileBytes {
				if b, err := fsRoot.ReadFile(rel); err == nil {
					out = strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
				}
			}
		}
		lines[file] = out
		return out
	}

	reported := map[string]bool{}
	for i, f := range findings {
		if !Suppressible(f) {
			continue
		}
		src := read(f.Location.File)
		at := f.Location.Region.StartLine
		if at > len(src) {
			continue
		}
		// The finding's own line first, then a marker standing alone above it.
		for _, n := range []int{at, at - 1} {
			if n < 1 {
				continue
			}
			m, why, ok := Parse(src[n-1])
			if !ok || (n != at && !m.Alone) {
				continue
			}
			m.Line = n
			if why != "" {
				key := f.Location.File + ":" + strconv.Itoa(n)
				if !reported[key] {
					reported[key] = true
					res.Problems = append(res.Problems, Problem{File: f.Location.File, Line: n, Why: why})
				}
				continue
			}
			if m.Covers(f) {
				res.Markers[i] = m
				break
			}
		}
	}
	return res
}
