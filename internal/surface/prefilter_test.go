package surface

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRequiredLiterals(t *testing.T) {
	for expr, want := range map[string][]string{
		`\bexec\.Command\(`:               {"exec.command("},
		`(?i)\b(eval|exec)\(`:             {"val", "xec"}, // the parser factors out the "e"
		`\b(os\.system|subprocess)\b`:     {"os.system", "subprocess"},
		`(?i)login_required|require_auth`: {"login_required", "require_auth"},
		`\w+\s*=\s*\d+`:                   {"="},
		`\w+\s*\d+`:                       nil, // nothing literal to require
		`(foo)?bar`:                       {"bar"},
	} {
		got := requiredLiterals(expr)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("requiredLiterals(%q) = %q, want %q", expr, got, want)
		}
	}
}

// The prefilter may only ever skip a line the regexp would not match. Checked on
// every line of this repository's own source and fixtures, for every pattern.
func TestPrefilter_NeverSkipsAMatch(t *testing.T) {
	var all []pattern
	all = append(all, common...)
	for _, ps := range sinks {
		all = append(all, ps...)
	}
	withLits := 0
	for _, pt := range all {
		if pt.lits != nil {
			withLits++
		}
	}
	if withLits < len(all)*3/4 {
		t.Errorf("only %d of %d patterns have a prefilter", withLits, len(all))
	}
	lines, matched := 0, 0
	for _, dir := range []string{"../../evals/detect/fixtures", "../../internal/inventory", "../../internal/surface"} {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || langOf(p) == "" {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, raw := range bytes.Split(src, []byte("\n")) {
				lines++
				low := bytes.ToLower(raw)
				for _, pt := range all {
					if pt.re.Match(raw) {
						matched++
						if !pt.mayMatch(low) {
							t.Errorf("%s: pattern %s/%s matches %q but the prefilter skips it (literals %q)", p, pt.kind, pt.class, raw, pt.lits)
						}
					}
				}
			}
			return nil
		})
	}
	if lines < 1000 || matched < 100 {
		t.Errorf("corpus too small: %d lines, %d matches", lines, matched)
	}
}
