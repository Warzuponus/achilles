package surface

import (
	"bytes"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// requiredLiterals returns strings, lowercased, at least one of which every match
// of the expression contains. It returns nil when it cannot tell, and then the
// expression is always run. It lets a pattern be skipped on a line (or a whole
// file) with a substring search instead of a regexp match, which on this many
// patterns was nearly all the cost of building the map.
func requiredLiterals(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := required(re.Simplify())
	for _, l := range lits {
		if l == "" {
			return nil
		}
	}
	return lits
}

func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
	case syntax.OpCharClass:
		// A small class of single characters: each is a literal ([sS], [.:]).
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] > 3 || len(out) > 8 {
				return nil
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				out = append(out, strings.ToLower(string(r)))
			}
		}
		return dedup(out)
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			l := required(sub)
			if l == nil {
				return nil
			}
			out = append(out, l...)
		}
		return dedup(out)
	case syntax.OpConcat:
		// Adjacent literal runs join into longer literals; otherwise the most
		// selective child decides.
		var best []string
		bestLen := 0
		var run strings.Builder
		flush := func() {
			if s := run.String(); utf8.RuneCountInString(s) > bestLen {
				best, bestLen = []string{s}, utf8.RuneCountInString(s)
			}
			run.Reset()
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run.WriteString(strings.ToLower(string(sub.Rune)))
				continue
			}
			flush()
			if l := required(sub); l != nil {
				if n := minLen(l); n > bestLen {
					best, bestLen = l, n
				}
			}
		}
		flush()
		return best
	}
	return nil
}

func minLen(ls []string) int {
	n := -1
	for _, l := range ls {
		if c := utf8.RuneCountInString(l); n < 0 || c < n {
			n = c
		}
	}
	return n
}

func dedup(ls []string) []string {
	seen := map[string]bool{}
	out := ls[:0]
	for _, l := range ls {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// mayMatch reports whether lowered (already lowercased) can hold a match of the
// pattern: false only when it contains none of the pattern's required literals.
func (pt pattern) mayMatch(lowered []byte) bool {
	if pt.lits == nil {
		return true
	}
	for _, l := range pt.lits {
		if bytes.Contains(lowered, []byte(l)) {
			return true
		}
	}
	return false
}
