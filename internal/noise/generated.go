package noise

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// goGenerated is Go's marker for a generated file (https://go.dev/s/generatedcode):
// a line of exactly this shape, before the package clause.
var goGenerated = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

const (
	// headerBytes and headerLines bound how much of a file is read for its marker.
	// A licence block can come first, so it is more than a line or two.
	headerBytes = 16 << 10
	headerLines = 60
	// atGeneratedLines is how near the top "@generated" must be: further down, the
	// word is more likely prose (a doc comment about generated code) than a marker.
	atGeneratedLines = 10
)

// IsGenerated reports whether a file's header says a tool wrote it: Go's
// "// Code generated ... DO NOT EDIT." line, or an "@generated" marker in a
// comment near the top, which many other generators write.
func IsGenerated(r io.Reader) bool {
	sc := bufio.NewScanner(io.LimitReader(r, headerBytes))
	sc.Buffer(make([]byte, 0, 4096), headerBytes)
	for n := 1; n <= headerLines && sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if goGenerated.MatchString(line) {
			return true
		}
		if n <= atGeneratedLines && strings.Contains(line, "@generated") && isComment(line) {
			return true
		}
		if strings.HasPrefix(line, "package ") {
			return false // Go: the marker must come before the package clause
		}
	}
	return false
}

func isComment(line string) bool {
	for _, p := range []string{"//", "#", "/*", "*", "<!--", "--", ";"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

// Generated drops findings in files whose header marks them as generated, under
// root (the scanned directory; finding paths are relative to it).
//
// The header is part of the scanned repository, so a repository could mark a
// file as generated to hide what is in it. Findings that must not be hidden that
// way are always kept: credentials (a secret is just as exposed in generated
// code), dependency advisories, and findings in commit history. A file that
// cannot be opened inside root is kept.
func Generated(root string, findings []model.Finding) (kept, excluded []model.Finding) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return findings, nil
	}
	defer func() { _ = r.Close() }()
	cache := map[string]bool{}
	generated := func(file string) bool {
		if v, ok := cache[file]; ok {
			return v
		}
		v := false
		if rel := filepath.FromSlash(file); !filepath.IsAbs(rel) {
			if f, err := r.Open(rel); err == nil {
				v = IsGenerated(f)
				_ = f.Close() // read-only; nothing to flush
			}
		}
		cache[file] = v
		return v
	}
	for _, f := range findings {
		if f.IsSecret() || f.IsDependencyAdvisory() || f.Commit != "" || !generated(f.Location.File) {
			kept = append(kept, f)
			continue
		}
		excluded = append(excluded, f)
	}
	return kept, excluded
}
