package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/triage"
)

// ContextResult is the per-case outcome of the hermetic context check.
type ContextResult struct {
	CaseID          string `json:"caseId"`
	Fixture         string `json:"fixture"`
	Label           Label  `json:"label"`
	ContextLines    int    `json:"contextLines"`
	PromptTokens    int    `json:"promptTokens"`
	EvidenceTotal   int    `json:"evidenceTotal"`
	EvidenceVisible int    `json:"evidenceVisible"`
	MissingLines    []int  `json:"missingLines,omitempty"`
	Truncated       bool   `json:"truncated,omitempty"`
}

// Complete reports whether every line this case needs is in the prompt.
func (r ContextResult) Complete() bool { return r.EvidenceVisible == r.EvidenceTotal }

// ContextReport aggregates the hermetic context check over a corpus.
type ContextReport struct {
	Mode            string          `json:"mode"`
	Cases           int             `json:"cases"`
	CasesComplete   int             `json:"casesComplete"`
	EvidenceTotal   int             `json:"evidenceTotal"`
	EvidenceVisible int             `json:"evidenceVisible"`
	MeanContextLine float64         `json:"meanContextLines"`
	TotalTokens     int             `json:"totalPromptTokens"`
	Results         []ContextResult `json:"results"`
}

// CoverageRate is the fraction of individual evidence lines that made it into a
// prompt. It moves more smoothly than CasesComplete, which is all-or-nothing.
func (r ContextReport) CoverageRate() float64 {
	if r.EvidenceTotal == 0 {
		return 0
	}
	return float64(r.EvidenceVisible) / float64(r.EvidenceTotal)
}

// CompleteRate is the fraction of cases where the model would see ALL the
// deciding evidence. This is the number to move.
func (r ContextReport) CompleteRate() float64 {
	if r.Cases == 0 {
		return 0
	}
	return float64(r.CasesComplete) / float64(r.Cases)
}

// lineNumRE pulls the line numbers back out of a rendered context block, which
// the enricher formats as ">>  12 | code" / "    13 | code". Reading them back is
// deliberate: it measures the prompt that would really be sent, rather than
// re-deriving the window from the same arithmetic the enricher used and thereby
// testing nothing.
var lineNumRE = regexp.MustCompile(`(?m)^(?:>> |   )\s*(\d+) \|`)

// visibleLines returns the source line numbers present in a rendered context.
func visibleLines(rendered string) map[int]bool {
	out := map[int]bool{}
	for _, m := range lineNumRE.FindAllStringSubmatch(rendered, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil {
			out[n] = true
		}
	}
	return out
}

// ScoreContext runs the hermetic check: for every case, build the context the
// enricher would attach and the prompt the triage layer would send, then verify
// the case's declared evidence lines are actually in it. No model is called.
func ScoreContext(c Corpus, en *enrich.Enricher) ContextReport {
	rep := ContextReport{Mode: "context", Cases: len(c.Cases)}
	totalLines := 0

	for _, cs := range c.SortedCases() {
		f := cs.ToFinding()
		rendered := en.Context(f, c.Root)
		visible := visibleLines(rendered)

		res := ContextResult{
			CaseID:        cs.ID,
			Fixture:       cs.Fixture,
			Label:         cs.Label,
			ContextLines:  len(visible),
			PromptTokens:  triage.TriagePromptTokens(f, rendered),
			EvidenceTotal: len(cs.EvidenceLines),
			Truncated:     hasTruncationNotice(rendered),
		}
		for _, l := range cs.EvidenceLines {
			if visible[l] {
				res.EvidenceVisible++
			} else {
				res.MissingLines = append(res.MissingLines, l)
			}
		}
		sort.Ints(res.MissingLines)

		if res.Complete() {
			rep.CasesComplete++
		}
		rep.EvidenceTotal += res.EvidenceTotal
		rep.EvidenceVisible += res.EvidenceVisible
		rep.TotalTokens += res.PromptTokens
		totalLines += res.ContextLines
		rep.Results = append(rep.Results, res)
	}
	if rep.Cases > 0 {
		rep.MeanContextLine = float64(totalLines) / float64(rep.Cases)
	}
	return rep
}

func hasTruncationNotice(rendered string) bool {
	return strings.Contains(rendered, "enclosing scope truncated")
}

// Write renders the context report for a terminal.
func (r ContextReport) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "Context adequacy (hermetic — no model called)\n\n")
	fmt.Fprintf(w, "  cases with ALL deciding evidence visible: %d/%d (%.1f%%)\n",
		r.CasesComplete, r.Cases, 100*r.CompleteRate())
	fmt.Fprintf(w, "  evidence lines visible:                   %d/%d (%.1f%%)\n",
		r.EvidenceVisible, r.EvidenceTotal, 100*r.CoverageRate())
	fmt.Fprintf(w, "  mean context lines per finding:           %.1f\n", r.MeanContextLine)
	fmt.Fprintf(w, "  total triage prompt tokens:               %d\n", r.TotalTokens)

	var incomplete []ContextResult
	for _, res := range r.Results {
		if !res.Complete() {
			incomplete = append(incomplete, res)
		}
	}
	if len(incomplete) > 0 {
		fmt.Fprintf(w, "\n  cases still missing evidence:\n")
		for _, res := range incomplete {
			fmt.Fprintf(w, "    %-28s missing line(s) %v  (%d/%d visible)\n",
				res.CaseID, res.MissingLines, res.EvidenceVisible, res.EvidenceTotal)
		}
	}
	if verbose {
		fmt.Fprintf(w, "\n  %-28s %-6s %8s %8s %10s\n", "CASE", "LABEL", "LINES", "TOKENS", "EVIDENCE")
		for _, res := range r.Results {
			fmt.Fprintf(w, "  %-28s %-6s %8d %8d %6d/%d\n",
				res.CaseID, res.Label, res.ContextLines, res.PromptTokens,
				res.EvidenceVisible, res.EvidenceTotal)
		}
	}
}

// WriteJSON persists the report so a later run can diff against it.
func (r ContextReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// LoadContextReport reads a persisted context report.
func LoadContextReport(path string) (ContextReport, error) {
	data, err := readFile(path)
	if err != nil {
		return ContextReport{}, err
	}
	var r ContextReport
	if err := json.Unmarshal(data, &r); err != nil {
		return ContextReport{}, fmt.Errorf("parse context report %s: %w", path, err)
	}
	return r, nil
}

// CompareContext prints what changed between two context runs — the point of the
// harness, since a metric with no baseline proves nothing.
func CompareContext(base, cur ContextReport, w io.Writer) {
	fmt.Fprintf(w, "\nvs baseline:\n")
	fmt.Fprintf(w, "  cases complete:  %d/%d -> %d/%d  (%+.1f pp)\n",
		base.CasesComplete, base.Cases, cur.CasesComplete, cur.Cases,
		100*(cur.CompleteRate()-base.CompleteRate()))
	fmt.Fprintf(w, "  evidence lines:  %.1f%% -> %.1f%%  (%+.1f pp)\n",
		100*base.CoverageRate(), 100*cur.CoverageRate(),
		100*(cur.CoverageRate()-base.CoverageRate()))
	fmt.Fprintf(w, "  mean ctx lines:  %.1f -> %.1f  (%+.1f)\n",
		base.MeanContextLine, cur.MeanContextLine, cur.MeanContextLine-base.MeanContextLine)
	fmt.Fprintf(w, "  prompt tokens:   %d -> %d  (%+d, %+.1f%%)\n",
		base.TotalTokens, cur.TotalTokens, cur.TotalTokens-base.TotalTokens,
		pctChange(base.TotalTokens, cur.TotalTokens))

	byID := map[string]ContextResult{}
	for _, res := range base.Results {
		byID[res.CaseID] = res
	}
	var completed, improved, lost []string
	for _, res := range cur.Results {
		b, ok := byID[res.CaseID]
		if !ok {
			completed = append(completed, res.CaseID+" (new)")
			continue
		}
		switch {
		case res.EvidenceVisible < b.EvidenceVisible:
			lost = append(lost, fmt.Sprintf("%s (%d->%d lines)", res.CaseID, b.EvidenceVisible, res.EvidenceVisible))
		case !b.Complete() && res.Complete():
			completed = append(completed, res.CaseID)
		case res.EvidenceVisible > b.EvidenceVisible:
			// Worth printing even when the case is still incomplete: partial
			// progress is how a multi-step context fix shows up. But this branch is
			// also reached when a case was ALREADY complete and the corpus simply
			// declared more evidence lines — the denominator moved, not the coverage
			// — so the note has to be earned rather than assumed.
			note := ""
			if !res.Complete() {
				note = ", still incomplete"
			}
			improved = append(improved, fmt.Sprintf("%s (%d->%d lines%s)",
				res.CaseID, b.EvidenceVisible, res.EvidenceVisible, note))
		}
	}
	if len(completed) > 0 {
		fmt.Fprintf(w, "  now complete:    %v\n", completed)
	}
	if len(improved) > 0 {
		fmt.Fprintf(w, "  more evidence:   %v\n", improved)
	}
	if len(lost) > 0 {
		fmt.Fprintf(w, "  REGRESSED:       %v\n", lost)
	}
	if len(completed) == 0 && len(improved) == 0 && len(lost) == 0 {
		fmt.Fprintf(w, "  no per-case coverage changes\n")
	}
}

// ContextRegressions returns the case ids whose evidence coverage got worse, so
// CI can fail on a prompt change that quietly took context away.
func ContextRegressions(base, cur ContextReport) []string {
	byID := map[string]ContextResult{}
	for _, res := range base.Results {
		byID[res.CaseID] = res
	}
	var lost []string
	for _, res := range cur.Results {
		b, ok := byID[res.CaseID]
		if !ok {
			continue
		}
		// Per-case, not aggregate: a change that fixes one case and breaks another
		// can leave the totals flat while losing real coverage.
		if res.EvidenceVisible < b.EvidenceVisible {
			lost = append(lost, res.CaseID)
		}
	}
	sort.Strings(lost)
	return lost
}

func pctChange(from, to int) float64 {
	if from == 0 {
		return 0
	}
	return 100 * float64(to-from) / float64(from)
}
