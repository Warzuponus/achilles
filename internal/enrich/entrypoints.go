package enrich

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/inventory"
)

// defaultMaxEntryHints bounds the entry-point block: enough to name a file's
// handful of routes, small enough that a router file with dozens does not bury
// the code it sits above.
const defaultMaxEntryHints = 8

// writeEntryHints renders the entry points the finding's own file exposes, nearest
// the flagged line first when there are more than max. It writes nothing when
// there are none or max is 0.
//
// The wording is part of the contract with the model: these come from a
// line-level pattern match on THIS file alone, so a missing hint says nothing
// about reachability (a handler is often registered in a different file), and a
// present one says the file takes input, not that the flagged line is on that path.
func writeEntryHints(b *strings.Builder, hints []inventory.EntryPoint, at, max int) {
	if len(hints) == 0 || max <= 0 {
		return
	}
	if len(hints) > max {
		sort.SliceStable(hints, func(i, j int) bool { return dist(hints[i].Line, at) < dist(hints[j].Line, at) })
		hints = hints[:max]
		sort.SliceStable(hints, func(i, j int) bool { return hints[i].Line < hints[j].Line })
	}
	fmt.Fprintf(b, "// This file exposes (pattern match on this file only; no hint is NOT evidence of unreachability):\n")
	for _, h := range hints {
		fmt.Fprintf(b, "//   %s (line %d)\n", h.Summary, h.Line)
	}
}

func dist(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
