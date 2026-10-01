package enrich

import (
	"regexp"
	"sort"
	"strings"
)

// Enclosing-scope context still loses the two kinds of evidence that most often
// decide a verdict:
//
//   - the FILE-SCOPE DECLARATION of something the flagged code uses. Whether
//     `reportTable` is a compile-time constant or a request parameter is the whole
//     question, and the answer is usually above the function.
//   - the CALL SITE of the enclosing function. MD5 inside a function named
//     `cacheKey` looks benign until you see `cacheKey(password) == storedDigest`
//     one function below.
//
// The eval corpus measured the cost of omitting them: `go-trap-md5-auth-compare`
// was answered false_positive at 0.95 confidence, consistently — a missed true
// positive — because the call site was not in the prompt (see evals/README.md).
//
// This resolves both WITHIN THE SAME FILE only. Cross-file resolution needs a
// build/index and is a different feature; single-file already covers the common
// shape, where a helper and its caller live together.
//
// It is still a heuristic, matched to scope.go's two strategies. It is bounded by
// budgets and it only ever ADDS lines that exist in the file, so the failure mode
// is a little wasted prompt, never a wrong quotation.

const (
	// defaultMaxRefLines caps file-scope declaration lines pulled in.
	defaultMaxRefLines = 12
	// defaultMaxCallSites caps how many callers of the enclosing function are
	// shown. One or two are usually enough to establish intent.
	defaultMaxCallSites = 3
)

var identRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// skipIdents are keywords and builtins that can never be the interesting
// file-scope declaration, so they never trigger a lookup.
var skipIdents = map[string]bool{
	// Go keywords + common builtins/types.
	"break": true, "case": true, "chan": true, "const": true, "continue": true,
	"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
	"func": true, "go": true, "goto": true, "if": true, "import": true,
	"interface": true, "map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true, "var": true,
	"append": true, "cap": true, "copy": true, "delete": true, "len": true,
	"make": true, "new": true, "nil": true, "panic": true, "print": true,
	"recover": true, "string": true, "int": true, "int64": true, "byte": true,
	"bool": true, "error": true, "true": true, "false": true, "rune": true,
	"float64": true, "any": true,
	// Python keywords + builtins.
	"and": true, "as": true, "assert": true, "async": true, "await": true,
	"class": true, "def": true, "del": true, "elif": true, "except": true,
	"finally": true, "from": true, "global": true, "in": true, "is": true,
	"lambda": true, "None": true, "nonlocal": true, "not": true, "or": true,
	"pass": true, "raise": true, "try": true, "while": true, "with": true,
	"yield": true, "self": true, "True": true, "False": true, "str": true,
	"dict": true, "list": true, "set": true, "tuple": true, "print_function": true,
}

// reference is one extra line worth showing, with why it was pulled in.
type reference struct {
	line int
	kind string // "decl" | "call"
}

// declRE matchers, applied only to lines at file scope.
var (
	goDeclRE     = regexp.MustCompile(`^(?:func|var|const|type)\s+\(?\s*([A-Za-z_][A-Za-z0-9_]*)`)
	goMethodRE   = regexp.MustCompile(`^func\s+\([^)]*\)\s*([A-Za-z_][A-Za-z0-9_]*)`)
	goGroupItem  = regexp.MustCompile(`^\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:[A-Za-z_*\[\]]+\s*)?=`)
	goGroupOpen  = regexp.MustCompile(`^(?:var|const)\s*\($`)
	pyAssignRE   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=`)
	pyDefRE      = regexp.MustCompile(`^(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	funcHeaderRE = regexp.MustCompile(`^\s*(?:func|def)\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)`)
)

// fileScopeDecls maps each file-scope-declared identifier to the line that
// declares it. Only declarations at column 0 (plus members of a Go `var (`/
// `const (` group) count, which is what makes this cheap and predictable.
func fileScopeDecls(lines []string, st scopeStyle) map[string]int {
	out := map[string]int{}
	inGroup := false
	for i, raw := range lines {
		line := stripNonCode(raw)
		trimmed := strings.TrimRight(line, " \t")
		if trimmed == "" {
			continue
		}
		if inGroup {
			if strings.HasPrefix(strings.TrimSpace(trimmed), ")") {
				inGroup = false
				continue
			}
			if m := goGroupItem.FindStringSubmatch(trimmed); m != nil {
				setIfAbsent(out, m[1], i+1)
			}
			continue
		}
		if indentWidth(raw) != 0 {
			continue // not file scope
		}
		switch st {
		case styleBrace:
			if goGroupOpen.MatchString(trimmed) {
				inGroup = true
				continue
			}
			if m := goMethodRE.FindStringSubmatch(trimmed); m != nil {
				setIfAbsent(out, m[1], i+1)
				continue
			}
			if m := goDeclRE.FindStringSubmatch(trimmed); m != nil {
				setIfAbsent(out, m[1], i+1)
			}
		case styleIndent:
			if m := pyDefRE.FindStringSubmatch(trimmed); m != nil {
				setIfAbsent(out, m[1], i+1)
				continue
			}
			if m := pyAssignRE.FindStringSubmatch(trimmed); m != nil {
				setIfAbsent(out, m[1], i+1)
			}
		}
	}
	return out
}

func setIfAbsent(m map[string]int, k string, v int) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// identsIn returns the distinct identifiers appearing in lines [lo,hi], with
// string literals and comments stripped so prose cannot pull in a declaration.
func identsIn(lines []string, lo, hi int) []string {
	seen := map[string]bool{}
	var out []string
	for i := lo; i <= hi && i <= len(lines); i++ {
		if i < 1 {
			continue
		}
		for _, id := range identRE.FindAllString(stripNonCode(lines[i-1]), -1) {
			if skipIdents[id] || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// enclosingFuncName returns the name declared by the scope's opening line, or ""
// when the scope is not a function (an `if` block, say).
func enclosingFuncName(lines []string, lo int) string {
	if lo < 1 || lo > len(lines) {
		return ""
	}
	if m := funcHeaderRE.FindStringSubmatch(stripNonCode(lines[lo-1])); m != nil {
		return m[1]
	}
	return ""
}

// callSites finds lines that call name, excluding the declaration's own scope
// [lo,hi] — a recursive call inside the function proves nothing about intent.
func callSites(lines []string, name string, lo, hi, max int) []int {
	if name == "" || max <= 0 {
		return nil
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
	var out []int
	for i, raw := range lines {
		n := i + 1
		if n >= lo && n <= hi {
			continue
		}
		code := stripNonCode(raw)
		if !re.MatchString(code) {
			continue
		}
		// The declaration line itself is not a call site.
		if funcHeaderRE.MatchString(code) {
			continue
		}
		out = append(out, n)
		if len(out) >= max {
			break
		}
	}
	return out
}

// refRequest describes what a finding already shows and what it might be
// missing. The window and the scope are deliberately SEPARATE fields: the window
// is the scope unioned with the fixed radius, so its first line is often a blank
// line or an import above the function. Resolving the enclosing function's name
// from the window start therefore finds nothing — which silently disabled call
// sites for exactly the case that motivated this file.
type refRequest struct {
	lines          []string
	spanLo, spanHi int // the flagged span
	winLo, winHi   int // what the prompt already shows
	scopeLo        int // opening line of the enclosing scope (declares the name)
	maxRefs        int
	maxCalls       int
	style          scopeStyle
}

// gatherReferences collects the out-of-window lines worth adding.
//
// Ordering is deliberate: identifiers in the FLAGGED SPAN are resolved before
// ones merely elsewhere in the function, because when the budget runs out the
// span's own operands are what matter. Call sites get their own budget so a
// declaration-heavy function cannot crowd them out.
func gatherReferences(r refRequest) []reference {
	if r.style == styleNone {
		return nil
	}
	decls := fileScopeDecls(r.lines, r.style)
	visible := func(n int) bool { return n >= r.winLo && n <= r.winHi }

	var refs []reference
	added := map[int]bool{}
	addDecl := func(ids []string) {
		for _, id := range ids {
			if len(refs) >= r.maxRefs {
				return
			}
			n, ok := decls[id]
			if !ok || visible(n) || added[n] {
				continue
			}
			added[n] = true
			refs = append(refs, reference{line: n, kind: "decl"})
		}
	}
	addDecl(identsIn(r.lines, r.spanLo, r.spanHi))
	addDecl(identsIn(r.lines, r.winLo, r.winHi))

	name := enclosingFuncName(r.lines, r.scopeLo)
	for _, n := range callSites(r.lines, name, r.winLo, r.winHi, r.maxCalls) {
		if added[n] {
			continue
		}
		added[n] = true
		refs = append(refs, reference{line: n, kind: "call"})
	}

	sort.Slice(refs, func(i, j int) bool { return refs[i].line < refs[j].line })
	return refs
}
