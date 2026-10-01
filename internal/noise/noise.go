// Package noise filters out findings in files that are almost never worth
// triaging — vendored dependencies, generated code, and minified assets — so a
// scan's signal isn't drowned by third-party or machine-written code
// (DESIGN.md §11).
package noise

import (
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// Matcher decides whether a file path is "noise". A pattern is matched two ways:
//   - no "*": a path SEGMENT (e.g. "vendor" matches any .../vendor/... path)
//   - has "*": a glob against the BASENAME (e.g. "*.min.js")
type Matcher struct {
	segments map[string]bool
	globs    []string
}

// NewMatcher returns an empty matcher (no patterns).
func NewMatcher() *Matcher { return &Matcher{segments: map[string]bool{}} }

// DefaultMatcher returns the built-in noise patterns: vendored dependency
// directories, minified assets, and common generated files. It deliberately
// does NOT exclude test code by default — security issues in tests can be real;
// add test patterns explicitly with Add if you want them dropped.
func DefaultMatcher() *Matcher {
	m := NewMatcher()
	for _, seg := range []string{
		"vendor", "node_modules", "third_party", "bower_components",
		".venv", "venv", "site-packages", ".tox",
	} {
		m.segments[seg] = true
	}
	m.globs = []string{"*.min.js", "*.min.css", "*.pb.go", "*_pb2.py"}
	return m
}

// Add registers a pattern (a bare path segment, or a "*" glob for basenames).
func (m *Matcher) Add(pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	if strings.Contains(pattern, "*") {
		m.globs = append(m.globs, pattern)
		return
	}
	// A trailing slash (e.g. "vendor/") is a convenience for a directory segment.
	m.segments[strings.Trim(pattern, "/")] = true
}

// Matches reports whether path is considered noise.
func (m *Matcher) Matches(path string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg != "" && m.segments[seg] {
			return true
		}
	}
	base := filepath.Base(path)
	for _, g := range m.globs {
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
	}
	return false
}

// Filter partitions findings into those to keep and those excluded as noise.
func (m *Matcher) Filter(findings []model.Finding) (kept, excluded []model.Finding) {
	for _, f := range findings {
		if m.Matches(f.Location.File) {
			excluded = append(excluded, f)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, excluded
}
