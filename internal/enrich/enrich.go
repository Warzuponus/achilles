// Package enrich expands a finding with the surrounding source context the LLM
// needs to triage it well (DESIGN.md §7 step 1). Phase 2 provides file-context
// (lines around the span); git blame and data-flow come later.
package enrich

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
)

// Enricher builds the source context around a finding's span. It prefers the
// enclosing function/block (see scope.go) and falls back to a fixed radius when
// the scope can't be resolved — the radius is also a floor, so the window is
// never smaller than Radius lines either side.
type Enricher struct {
	Radius int // minimum lines of context on each side
	// MaxScopeLines caps how much enclosing scope is included; 0 disables
	// scope-awareness entirely (and with it references), restoring pure
	// fixed-radius behaviour.
	MaxScopeLines int
	// MaxRefLines caps file-scope declaration lines pulled in for identifiers the
	// flagged code references; MaxCallSites caps callers of the enclosing
	// function. Both 0 disables that half. See references.go for why they exist.
	MaxRefLines  int
	MaxCallSites int
	// IncludeBlame appends git-blame attribution to Context (best-effort).
	IncludeBlame bool
}

// New returns an enricher with the given minimum context radius (min 0) and the
// default enclosing-scope cap.
func New(radius int) *Enricher {
	if radius < 0 {
		radius = 0
	}
	return &Enricher{
		Radius:        radius,
		MaxScopeLines: defaultMaxScopeLines,
		MaxRefLines:   defaultMaxRefLines,
		MaxCallSites:  defaultMaxCallSites,
	}
}

// writeRefSection renders the references of one kind under a heading, keeping
// real line numbers so the model can see the lines are not contiguous with the
// finding. It writes nothing when there are none of that kind.
func writeRefSection(b *strings.Builder, lines []string, refs []reference, kind, heading string) {
	first := true
	for _, r := range refs {
		if r.kind != kind || r.line < 1 || r.line > len(lines) {
			continue
		}
		if first {
			fmt.Fprintf(b, "// %s:\n", heading)
			first = false
		}
		fmt.Fprintf(b, "   %4d | %s\n", r.line, lines[r.line-1])
	}
}

// Blame is git-blame attribution for the finding's line.
type Blame struct {
	Commit string
	Author string
	Date   string // YYYY-MM-DD
}

// GitBlame returns attribution for the finding's start line, or ok=false when
// the file isn't in a git repo (or git is unavailable). Best-effort by design.
func (e *Enricher) GitBlame(f model.Finding, root string) (Blame, bool) {
	line := f.Location.Region.StartLine
	if line <= 0 || f.Location.File == "" {
		return Blame{}, false
	}
	if _, err := exec.LookPath("git"); err != nil {
		return Blame{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []string{"-C", root, "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--line-porcelain", "--", f.Location.File}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return Blame{}, false
	}

	var b Blame
	for _, ln := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(ln, "author "):
			b.Author = strings.TrimPrefix(ln, "author ")
		case strings.HasPrefix(ln, "author-time "):
			if ts, err := strconv.ParseInt(strings.TrimPrefix(ln, "author-time "), 10, 64); err == nil {
				b.Date = time.Unix(ts, 0).UTC().Format("2006-01-02")
			}
		}
	}
	// The first porcelain line starts with the commit SHA.
	if fields := strings.Fields(string(out)); len(fields) > 0 && len(fields[0]) >= 8 {
		b.Commit = fields[0][:8]
	}
	if b.Author == "" {
		return Blame{}, false
	}
	return b, true
}

// Context returns numbered source lines around the finding. root is the scanned
// tree root; the finding's file may be relative to it or absolute. If the file
// cannot be read, it falls back to any snippet the tool already provided.
func (e *Enricher) Context(f model.Finding, root string) string {
	path := f.Location.File
	if !filepath.IsAbs(path) && root != "" {
		path = filepath.Join(root, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return f.CodeContext // fall back to the tool's snippet
	}
	lines := strings.Split(string(data), "\n")

	start := f.Location.Region.StartLine
	end := f.Location.Region.EndLine
	if end < start {
		end = start
	}
	if start <= 0 {
		return f.CodeContext
	}

	lo := max(1, start-e.Radius)
	hi := min(len(lines), end+e.Radius)

	// Prefer the enclosing function/block, unioned with the radius window so the
	// context can only ever grow relative to the radius-only behaviour.
	truncated := false
	style := styleFor(f.Location.File)
	var refs []reference
	if s, ok := enclosingScope(lines, start, end, e.MaxScopeLines, style); ok {
		lo = max(1, min(lo, s.lo))
		hi = min(len(lines), max(hi, s.hi))
		truncated = s.truncated
		// Referenced declarations and callers live outside this window; without
		// them the model cannot tell a constant from a request parameter, or a
		// cache key from a credential check. scopeLo is s.lo, NOT lo: the window
		// may start above the function, where there is no name to resolve.
		refs = gatherReferences(refRequest{
			lines: lines, spanLo: start, spanHi: end,
			winLo: lo, winHi: hi, scopeLo: s.lo,
			maxRefs: e.MaxRefLines, maxCalls: e.MaxCallSites, style: style,
		})
	}

	var b strings.Builder
	// Declarations first: they establish what the flagged code's operands are
	// before the model reads the code that uses them.
	writeRefSection(&b, lines, refs, "decl", "referenced at file scope")
	if truncated {
		// Tell the model the body is incomplete rather than letting it reason as
		// if it had seen the whole function.
		fmt.Fprintf(&b, "// enclosing scope truncated to %d lines\n", hi-lo+1)
	}
	if len(refs) > 0 {
		// The window is no longer the whole of what follows, so label it. Without
		// this the sections read as one contiguous block.
		fmt.Fprintf(&b, "// the finding:\n")
	}
	for i := lo; i <= hi; i++ {
		marker := "   "
		if i >= start && i <= end {
			marker = ">> " // the flagged span
		}
		fmt.Fprintf(&b, "%s%4d | %s\n", marker, i, lines[i-1])
	}
	writeRefSection(&b, lines, refs, "call", "callers of this function, elsewhere in the file")
	out := strings.TrimRight(b.String(), "\n")

	if e.IncludeBlame {
		if bl, ok := e.GitBlame(f, root); ok {
			out += fmt.Sprintf("\n// last changed by %s on %s (%s)", bl.Author, bl.Date, bl.Commit)
		}
	}
	return out
}
