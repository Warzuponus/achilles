package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/surface"
	"github.com/Warzuponus/achilles/internal/vault"
)

// Values of --prioritize.
const (
	prioritizeSeverity = "severity"
	prioritizeSurface  = "surface"
)

func validPrioritize(s string) error {
	switch s {
	case prioritizeSeverity, prioritizeSurface:
		return nil
	}
	return fmt.Errorf("--prioritize %q: want %s or %s", s, prioritizeSeverity, prioritizeSurface)
}

// planWanted reports whether this run builds the attack-surface map.
func (o *options) planWanted() bool {
	return o.prioritize == prioritizeSurface || o.planOut != ""
}

// reviewPriority is the order the AI review and --deep-verify take findings in
// when the budget may not reach them all. nil means by severity.
func (o *options) reviewPriority() func(*model.Finding) float64 {
	if o.prioritize != prioritizeSurface || o.surface == nil {
		return nil
	}
	return o.surface.Priority
}

// buildPlan is the Model phase: it maps the target's attack surface before the
// scanners run, writes it to --plan-out, records it in the vault and, under
// --prioritize surface, keeps it for ordering the review.
//
// The map only orders work. If it cannot be built, the review falls back to
// severity order and says so; only an explicitly requested --plan-out file that
// cannot be produced is an error.
func buildPlan(o *options, ev vault.Store, runID, absTarget string, w io.Writer) error {
	if !o.planWanted() {
		return nil
	}
	m, err := surface.Build(absTarget, surface.Options{})
	if err != nil {
		if o.planOut != "" {
			return fmt.Errorf("--plan-out: map the attack surface: %w", err)
		}
		fmt.Fprintf(w, "achilles: surface map failed (%v); the AI review keeps severity order\n", err)
		return nil
	}
	o.surface = m
	fmt.Fprintln(w, planSummary(m))
	if m.Truncated {
		fmt.Fprintf(w, "achilles: surface map is INCOMPLETE: the walk stopped after %d file(s) / %d MiB; files past that score 0 and are reviewed in severity order\n",
			m.FilesRead, m.BytesRead>>20)
	}
	if o.prioritize == prioritizeSurface {
		fmt.Fprintln(w, "achilles: review order: by risk (severity weighted by file exposure, --prioritize surface); unreached findings are still reported as unreached")
	}
	recordJSON(ev, vault.Record{RunID: runID, Phase: "plan", Kind: vault.KindScanPlan, Source: "surface"}, m)
	if o.planOut != "" {
		err := writeToFile(o.planOut, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(m)
		})
		if err != nil {
			return fmt.Errorf("--plan-out: %w", err)
		}
		fmt.Fprintf(w, "achilles: wrote the scan plan to %s\n", o.planOut)
	}
	return nil
}

// planSummary is the one stderr line that says what the map found.
func planSummary(m *surface.Map) string {
	var b strings.Builder
	fmt.Fprintf(&b, "achilles: surface — %d file(s) read: %d entry point(s), %d dangerous operation(s), %d guard(s), %d asset hint(s)",
		m.FilesRead, m.Summary.Entries, m.Summary.Sinks, m.Summary.Controls, m.Summary.Assets)
	if len(m.AIFiles) > 0 {
		fmt.Fprintf(&b, ", %d file(s) calling an LLM or exposing tools", len(m.AIFiles))
	}
	if len(m.Hotspots) > 0 {
		h := m.Hotspots[0]
		fmt.Fprintf(&b, "; top hotspot %s (%.2f)", h.File, h.Score)
	}
	return b.String()
}
