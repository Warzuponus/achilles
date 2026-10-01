package enrich

import (
	"path/filepath"
	"strings"
)

// A fixed radius around a finding often cuts off the very thing triage needs —
// the function signature, the parameter the tainted value arrived in, the guard
// clause that makes the finding a false positive. This file widens the window to
// the *enclosing scope* instead (DESIGN.md §2: "the LLM never sees a finding
// without code context").
//
// It is a heuristic, not a parser: Achilles normalizes 15+ languages and
// carrying a real parser for each is not worth it here. Two strategies cover
// most of what we scan, and everything else keeps the old fixed-radius window:
//
//   - braces, for C-family syntax (Go, Java, JS/TS, C/C++, C#, PHP, Rust, Swift,
//     Kotlin, Scala, and HCL/Terraform blocks);
//   - indentation, for Python.
//
// Because it is a heuristic, three things bound the damage: the result must
// actually contain the flagged line, it is capped at MaxScopeLines, and any
// failure falls back to the fixed radius. The window is also unioned with the
// radius window, so scope-awareness can never show LESS than before.

type scopeStyle int

const (
	styleNone scopeStyle = iota
	styleBrace
	styleIndent
)

// defaultMaxScopeLines caps how much enclosing scope is included. Big enough for
// a normal function, small enough that one enormous one cannot dominate a prompt
// (and the cost estimate shows the difference either way — see internal/cost).
const defaultMaxScopeLines = 120

var braceExts = map[string]bool{
	".go": true, ".java": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true,
	".cs": true, ".php": true, ".rs": true, ".kt": true, ".kts": true, ".swift": true,
	".scala": true, ".m": true, ".mm": true, ".tf": true, ".hcl": true,
}

// styleFor picks a strategy from the file extension. Anything unrecognized gets
// styleNone, which means "keep the fixed-radius window" — deliberately, since a
// wrong guess costs prompt quality on every finding in that file.
func styleFor(path string) scopeStyle {
	switch ext := strings.ToLower(filepath.Ext(path)); {
	case braceExts[ext]:
		return styleBrace
	case ext == ".py":
		return styleIndent
	default:
		return styleNone
	}
}

// scope is a resolved line range, 1-indexed and inclusive.
type scope struct {
	lo, hi    int
	truncated bool // the real scope was larger than maxLines and got clamped
}

// enclosingScope finds the smallest block enclosing lines [start,end]. ok is
// false when no scope could be resolved confidently, in which case the caller
// keeps its fixed-radius window.
func enclosingScope(lines []string, start, end, maxLines int, st scopeStyle) (scope, bool) {
	if st == styleNone || start <= 0 || start > len(lines) || maxLines <= 0 {
		return scope{}, false
	}
	if end < start {
		end = start
	}

	var s scope
	var ok bool
	switch st {
	case styleBrace:
		s, ok = braceScope(lines, start, end)
	case styleIndent:
		s, ok = indentScope(lines, start, end)
	}
	if !ok {
		return scope{}, false
	}
	// A heuristic that lost the flagged line is a heuristic that failed.
	if s.lo > start || s.hi < end {
		return scope{}, false
	}
	return clampScope(s, start, end, maxLines, len(lines)), true
}

// clampScope keeps a scope within maxLines, preferring to keep the flagged span
// centred rather than dropping the scope entirely — a truncated function is far
// more context than three lines.
func clampScope(s scope, start, end, maxLines, total int) scope {
	if s.hi-s.lo+1 <= maxLines {
		return s
	}
	span := end - start + 1
	if span >= maxLines {
		return scope{lo: start, hi: min(total, start+maxLines-1), truncated: true}
	}
	pad := (maxLines - span) / 2
	lo := max(s.lo, start-pad)
	hi := min(s.hi, lo+maxLines-1)
	// Pull lo back up if hi hit the scope end first, so the full budget is used.
	if hi-lo+1 < maxLines {
		lo = max(s.lo, hi-maxLines+1)
	}
	return scope{lo: lo, hi: hi, truncated: true}
}

// braceScope walks back to the unmatched "{" that opens the enclosing block,
// then forward to its match.
func braceScope(lines []string, start, end int) (scope, bool) {
	// Walk backward from the line above the flagged span, tracking how deep we
	// are: a "}" seen going up means we passed a nested block, a "{" closes it,
	// and the first "{" with nothing left to close is our opener.
	depth := 0
	opener := 0
	for i := start; i >= 1; i-- {
		code := stripNonCode(lines[i-1])
		// Right-to-left within the line, since we are travelling upward. Skip the
		// flagged line's own braces on the first iteration only if it opens a
		// block we are not inside yet — handled naturally by the depth counter.
		for j := len(code) - 1; j >= 0; j-- {
			switch code[j] {
			case '}':
				depth++
			case '{':
				if depth == 0 {
					opener = i
				} else {
					depth--
				}
			}
			if opener != 0 {
				break
			}
		}
		if opener != 0 {
			break
		}
	}
	if opener == 0 {
		return scope{}, false
	}

	lo := opener
	// A brace on its own line means the signature is above it (Java/C style).
	if strings.TrimSpace(stripNonCode(lines[opener-1])) == "{" {
		for i := opener - 1; i >= 1 && i >= opener-3; i-- {
			if strings.TrimSpace(lines[i-1]) != "" {
				lo = i
				break
			}
		}
	}

	// Forward to the matching close brace.
	depth = 0
	hi := 0
	for i := opener; i <= len(lines); i++ {
		code := stripNonCode(lines[i-1])
		for j := 0; j < len(code); j++ {
			switch code[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					hi = i
				}
			}
			if hi != 0 {
				break
			}
		}
		if hi != 0 {
			break
		}
	}
	if hi == 0 {
		// Unbalanced (or the span runs past EOF); end at the file's end so the
		// caller still gets the body rather than nothing.
		hi = len(lines)
	}
	if hi < end {
		return scope{}, false
	}
	return scope{lo: lo, hi: hi}, true
}

// indentScope finds the nearest enclosing def/class by indentation (Python).
func indentScope(lines []string, start, end int) (scope, bool) {
	own, okIndent := indentOf(lines, start)
	if !okIndent {
		return scope{}, false
	}

	lo := 0
	loIndent := 0
	for i := start; i >= 1; i-- {
		text := lines[i-1]
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentWidth(text)
		if ind >= own && i != start {
			continue
		}
		if isPythonBlockOpener(trimmed) && (ind < own || i == start) {
			lo, loIndent = i, ind
			break
		}
	}
	if lo == 0 {
		return scope{}, false
	}

	hi := len(lines)
	for i := lo + 1; i <= len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i-1])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indentWidth(lines[i-1]) <= loIndent {
			hi = i - 1
			break
		}
	}
	// Trim trailing blank lines the loop may have swept in.
	for hi > lo && strings.TrimSpace(lines[hi-1]) == "" {
		hi--
	}
	if hi < end {
		return scope{}, false
	}
	return scope{lo: lo, hi: hi}, true
}

func isPythonBlockOpener(trimmed string) bool {
	for _, kw := range []string{"def ", "async def ", "class "} {
		if strings.HasPrefix(trimmed, kw) {
			return true
		}
	}
	return false
}

// indentOf returns the indentation of the nearest non-blank line at or above n.
func indentOf(lines []string, n int) (int, bool) {
	for i := n; i >= 1; i-- {
		if strings.TrimSpace(lines[i-1]) != "" {
			return indentWidth(lines[i-1]), true
		}
	}
	return 0, false
}

// indentWidth counts leading whitespace, expanding tabs to 4 columns.
func indentWidth(s string) int {
	n := 0
	for _, r := range s {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// stripNonCode blanks out string/char literals and line comments so braces
// inside them don't confuse the matcher. It is intentionally simple — no
// multi-line comment or raw-string tracking — which is why every caller can fall
// back to a fixed radius.
func stripNonCode(line string) string {
	out := make([]byte, 0, len(line))
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' { // skip the escaped character
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue // characters inside a literal contribute nothing
		}
		switch c {
		case '"', '\'', '`':
			quote = c
			continue
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return string(out)
			}
		case '#':
			return string(out)
		}
		out = append(out, c)
	}
	return string(out)
}
