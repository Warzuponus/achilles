package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// DetectReportVersion is the JSON schema version of DetectReport.
const DetectReportVersion = 1

// Entry statuses.
const (
	StatusDetected = "detected"
	StatusMissed   = "missed"
	// StatusInvalid: the label points at a file or line that does not exist in the
	// checkout (wrong commit, stale subdir). Not scored: a broken label is not a miss.
	StatusInvalid = "invalid"
)

// maxHistory bounds the run history carried between invocations.
const maxHistory = 20

// FindingRef is a compact reference to a scanner finding.
type FindingRef struct {
	Tool   string   `json:"tool,omitempty"`
	RuleID string   `json:"ruleId"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
	CWE    []string `json:"cwe,omitempty"`
}

// VerdictRef is the AI verdict behind an ai-dismissed loss.
type VerdictRef struct {
	Classification string  `json:"classification,omitempty"`
	Confidence     float64 `json:"confidence,omitempty"`
	Reasoning      string  `json:"reasoning,omitempty"`
	Refuted        bool    `json:"refuted,omitempty"`
	RefuteReason   string  `json:"refuteReason,omitempty"`
}

// LossTrace says where a missed entry was lost.
type LossTrace struct {
	Point    string       `json:"point"`
	Detail   string       `json:"detail"`
	Findings []FindingRef `json:"findings,omitempty"`
	Verdict  *VerdictRef  `json:"verdict,omitempty"`
}

// EntryResult is the outcome for one ground-truth entry.
type EntryResult struct {
	ID          string   `json:"id"`
	Class       string   `json:"class"`
	CWE         []string `json:"cwe,omitempty"`
	File        string   `json:"file"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Detected    bool     `json:"detected"`
	// DetectedUnfiltered is detection before the AI review filtered anything; equal
	// to Detected unless the run used --ai.
	DetectedUnfiltered bool         `json:"detectedUnfiltered"`
	MatchedBy          string       `json:"matchedBy,omitempty"` // rule | judge
	JudgeReason        string       `json:"judgeReason,omitempty"`
	Matches            []FindingRef `json:"matches,omitempty"`
	Loss               *LossTrace   `json:"loss,omitempty"`
	Invalid            string       `json:"invalid,omitempty"`
}

// ToolStatus is how the scanners fared on a target.
type ToolStatus struct {
	// KnownToVault is false when the scan left no vault, so ran/failed/skipped are unknown.
	KnownToVault bool          `json:"knownToVault"`
	Registered   []string      `json:"registered,omitempty"`
	Ran          []string      `json:"ran,omitempty"`
	Failed       []ToolFailure `json:"failed,omitempty"`
	Skipped      []string      `json:"skipped,omitempty"`
}

// FindingStats is the precision proxy for one target. Findings in files with no
// ground truth are "unlabeled", never "false positives": the benchmark labels
// known vulnerabilities, not every line of code, so it cannot tell a false alarm
// from a real bug nobody listed.
type FindingStats struct {
	Surfaced                int          `json:"surfaced"`
	Matched                 int          `json:"matched"`
	UnmatchedInLabeledFiles int          `json:"unmatchedInLabeledFiles"`
	UnlabeledFiles          int          `json:"unlabeledFiles"`
	Dismissed               int          `json:"dismissedByAI,omitempty"`
	Samples                 []FindingRef `json:"unmatchedSamples,omitempty"`
}

// TargetResult is one target's outcome.
type TargetResult struct {
	ID          string        `json:"id"`
	Description string        `json:"description,omitempty"`
	Source      string        `json:"source"`
	Entries     []EntryResult `json:"entries"`
	Tools       ToolStatus    `json:"tools"`
	Findings    FindingStats  `json:"findings"`
	// Incomplete is true when a scanner failed or the scan did not complete: the
	// result is a lower bound, not a measurement of the scanners' reach.
	Incomplete bool     `json:"incomplete"`
	Error      string   `json:"error,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Score is recall over a set of entries.
type Score struct {
	Entries  int `json:"entries"`
	Invalid  int `json:"invalid,omitempty"`
	Detected int `json:"detected"`
	Missed   int `json:"missed"`
	// Recall is Detected / (Entries - Invalid).
	Recall float64 `json:"recall"`
	// DetectedUnfiltered/RecallUnfiltered are before AI review; with --ai the gap is
	// the AI review's cost in recall.
	DetectedUnfiltered int     `json:"detectedUnfiltered"`
	RecallUnfiltered   float64 `json:"recallUnfiltered"`
	// JudgeAssisted counts detections the deterministic rule did not make.
	JudgeAssisted int `json:"judgeAssisted,omitempty"`
}

func (s *Score) add(e EntryResult) {
	s.Entries++
	switch e.Status {
	case StatusInvalid:
		s.Invalid++
		return
	case StatusDetected:
		s.Detected++
		if e.MatchedBy == "judge" {
			s.JudgeAssisted++
		}
	default:
		s.Missed++
	}
	if e.DetectedUnfiltered {
		s.DetectedUnfiltered++
	}
}

func (s *Score) finish() {
	if n := s.Entries - s.Invalid; n > 0 {
		s.Recall = float64(s.Detected) / float64(n)
		s.RecallUnfiltered = float64(s.DetectedUnfiltered) / float64(n)
	}
}

// ClassScore is recall for one class.
type ClassScore struct {
	Class string `json:"class"`
	Score
}

// DetectConfig records how the run was configured, so a baseline comparison can
// tell a real change from a different setup.
type DetectConfig struct {
	LineTolerance     int    `json:"lineTolerance"`
	AI                bool   `json:"ai"`
	Judge             bool   `json:"judge"`
	Exclude           string `json:"exclude,omitempty"`
	NoDefaultExcludes bool   `json:"noDefaultExcludes,omitempty"`
	GroundTruth       string `json:"groundTruth,omitempty"`
	// MatcherVersion changes when the matching rule does, so results measured under
	// different rules are never compared as if they were the same experiment.
	MatcherVersion int `json:"matcherVersion"`
}

// RunSummary is one run in the history. IDs are "target/entry".
type RunSummary struct {
	At          string   `json:"at"`
	Recall      float64  `json:"recall"`
	Detected    int      `json:"detected"`
	Scored      int      `json:"scored"`
	Incomplete  bool     `json:"incomplete,omitempty"`
	ScoredIDs   []string `json:"scoredIds"`
	DetectedIDs []string `json:"detectedIds"`
}

// Unstable is an entry detected in some runs and missed in others.
type Unstable struct {
	ID       string `json:"id"`
	Runs     int    `json:"runs"`
	Detected int    `json:"detected"`
}

// FindingTotals sums FindingStats over targets.
type FindingTotals struct {
	Surfaced                int `json:"surfaced"`
	Matched                 int `json:"matched"`
	UnmatchedInLabeledFiles int `json:"unmatchedInLabeledFiles"`
	UnlabeledFiles          int `json:"unlabeledFiles"`
}

// DetectReport is the scorecard.
type DetectReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	GeneratedAt   string         `json:"generatedAt"`
	Config        DetectConfig   `json:"config"`
	Targets       []TargetResult `json:"targets"`
	Overall       Score          `json:"overall"`
	ByClass       []ClassScore   `json:"byClass"`
	// LossPoints is the histogram of where misses were lost.
	LossPoints map[string]int `json:"lossPoints"`
	Findings   FindingTotals  `json:"findings"`
	// IncompleteTargets lists targets where a scanner failed or the scan did not finish.
	IncompleteTargets []string `json:"incompleteTargets,omitempty"`
	// Runs is how many times this invocation ran the benchmark; History holds each
	// (plus earlier invocations when carried forward with CarryHistory).
	Runs     int          `json:"runs"`
	History  []RunSummary `json:"history,omitempty"`
	Unstable []Unstable   `json:"unstable,omitempty"`
}

func (r *DetectReport) aggregate() {
	byClass := map[string]*ClassScore{}
	r.LossPoints = map[string]int{}
	r.Overall = Score{}
	r.Findings = FindingTotals{}
	r.IncompleteTargets = nil
	for _, t := range r.Targets {
		for _, e := range t.Entries {
			r.Overall.add(e)
			key := strings.ToLower(e.Class)
			cs := byClass[key]
			if cs == nil {
				cs = &ClassScore{Class: key}
				byClass[key] = cs
			}
			cs.add(e)
			if e.Status == StatusMissed && e.Loss != nil {
				r.LossPoints[e.Loss.Point]++
			}
		}
		r.Findings.Surfaced += t.Findings.Surfaced
		r.Findings.Matched += t.Findings.Matched
		r.Findings.UnmatchedInLabeledFiles += t.Findings.UnmatchedInLabeledFiles
		r.Findings.UnlabeledFiles += t.Findings.UnlabeledFiles
		if t.Incomplete {
			r.IncompleteTargets = append(r.IncompleteTargets, t.ID)
		}
	}
	r.Overall.finish()
	r.ByClass = nil
	for _, cs := range byClass {
		cs.finish()
		r.ByClass = append(r.ByClass, *cs)
	}
	sort.Slice(r.ByClass, func(i, j int) bool { return classOrder(r.ByClass[i].Class) < classOrder(r.ByClass[j].Class) })
}

func classOrder(c string) string {
	for i, k := range KnownClasses {
		if k == c {
			return fmt.Sprintf("0%02d", i)
		}
	}
	return "1" + c
}

func (r DetectReport) summary() RunSummary {
	s := RunSummary{
		At: r.GeneratedAt, Recall: r.Overall.Recall, Detected: r.Overall.Detected,
		Scored: r.Overall.Entries - r.Overall.Invalid, Incomplete: len(r.IncompleteTargets) > 0,
		ScoredIDs: []string{}, DetectedIDs: []string{},
	}
	for _, t := range r.Targets {
		for _, e := range t.Entries {
			if e.Status == StatusInvalid {
				continue
			}
			s.ScoredIDs = append(s.ScoredIDs, t.ID+"/"+e.ID)
			if e.Detected {
				s.DetectedIDs = append(s.DetectedIDs, t.ID+"/"+e.ID)
			}
		}
	}
	sort.Strings(s.ScoredIDs)
	sort.Strings(s.DetectedIDs)
	return s
}

// CarryHistory prepends the history of a previous report (typically the file about
// to be overwritten by --out), so repeated invocations accumulate a stability
// record, and recomputes which entries flapped across all of it.
func (r *DetectReport) CarryHistory(prev DetectReport) {
	// Runs made under another configuration or matching rule measured something
	// else; mixing them in would show "instability" that is really a change.
	if len(prev.History) == 0 || prev.Config != r.Config {
		return
	}
	all := append(append([]RunSummary{}, prev.History...), r.History...)
	if len(all) > maxHistory {
		all = all[len(all)-maxHistory:]
	}
	r.History = all
	r.Unstable = unstableEntries(all)
}

// WriteJSON persists the report.
func (r DetectReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // "<target>" and "&" stay readable in a committed baseline
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// LoadDetectReport reads a persisted report.
func LoadDetectReport(path string) (DetectReport, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return DetectReport{}, fmt.Errorf("read %s: %w", path, err)
	}
	var r DetectReport
	if err := json.Unmarshal(data, &r); err != nil {
		return DetectReport{}, fmt.Errorf("parse detect report %s: %w", path, err)
	}
	if r.SchemaVersion != DetectReportVersion {
		return DetectReport{}, fmt.Errorf("%s: detect report schemaVersion %d, this build reads %d", path, r.SchemaVersion, DetectReportVersion)
	}
	return r, nil
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", 100*f) }

// Write prints the scorecard. verbose adds every entry.
func (r DetectReport) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "\nDetection benchmark — %d target(s), %d known vulnerabilit(ies)\n", len(r.Targets), r.Overall.Entries)
	fmt.Fprintf(w, "  recall:            %s  (%d/%d detected, %d missed",
		pct(r.Overall.Recall), r.Overall.Detected, r.Overall.Entries-r.Overall.Invalid, r.Overall.Missed)
	if r.Overall.Invalid > 0 {
		fmt.Fprintf(w, ", %d INVALID label(s) not scored", r.Overall.Invalid)
	}
	fmt.Fprintln(w, ")")
	if r.Config.AI {
		fmt.Fprintf(w, "  recall pre-AI:     %s  (the AI review cost %d detection(s))\n",
			pct(r.Overall.RecallUnfiltered), r.Overall.DetectedUnfiltered-r.Overall.Detected)
	}
	if r.Overall.JudgeAssisted > 0 {
		fmt.Fprintf(w, "  judge-assisted:    %d of the detections needed --judge\n", r.Overall.JudgeAssisted)
	}
	fmt.Fprintf(w, "  findings:          %d surfaced — %d matched a label, %d more in labeled files, %d in unlabeled files\n",
		r.Findings.Surfaced, r.Findings.Matched, r.Findings.UnmatchedInLabeledFiles, r.Findings.UnlabeledFiles)
	fmt.Fprintf(w, "                     (unlabeled is NOT false-positive: the benchmark only labels known bugs)\n")
	if len(r.IncompleteTargets) > 0 {
		fmt.Fprintf(w, "  INCOMPLETE:        %s — a scanner failed or was missing; recall there is a lower bound\n",
			strings.Join(r.IncompleteTargets, ", "))
	}

	fmt.Fprintf(w, "\n  %-24s %8s %9s %8s\n", "CLASS", "ENTRIES", "DETECTED", "RECALL")
	for _, c := range r.ByClass {
		fmt.Fprintf(w, "  %-24s %8d %9d %8s\n", c.Class, c.Entries-c.Invalid, c.Detected, pct(c.Recall))
	}

	if len(r.LossPoints) > 0 {
		fmt.Fprintf(w, "\n  where the misses were lost:\n")
		for _, p := range lossOrder(r.LossPoints) {
			fmt.Fprintf(w, "    %-22s %d\n", p, r.LossPoints[p])
		}
	}

	fmt.Fprintf(w, "\n  %-18s %8s %9s %8s  %s\n", "TARGET", "ENTRIES", "DETECTED", "RECALL", "STATUS")
	for _, t := range r.Targets {
		var s Score
		for _, e := range t.Entries {
			s.add(e)
		}
		s.finish()
		status := "ok"
		switch {
		case t.Error != "":
			status = "SCAN FAILED"
		case t.Incomplete:
			status = "incomplete: " + failedNames(t.Tools.Failed)
		}
		fmt.Fprintf(w, "  %-18s %8d %9d %8s  %s\n", t.ID, s.Entries-s.Invalid, s.Detected, pct(s.Recall), status)
	}

	if verbose {
		for _, t := range r.Targets {
			fmt.Fprintf(w, "\n  %s  (%s)\n", t.ID, t.Source)
			for _, n := range t.Notes {
				fmt.Fprintf(w, "    note: %s\n", n)
			}
			for _, e := range t.Entries {
				fmt.Fprintf(w, "    %-9s %-20s %-16s %s:%d-%d\n", strings.ToUpper(e.Status), e.ID, e.Class, e.File, e.StartLine, e.EndLine)
				if e.Loss != nil {
					fmt.Fprintf(w, "              lost at %s: %s\n", e.Loss.Point, e.Loss.Detail)
				}
				if e.Invalid != "" {
					fmt.Fprintf(w, "              %s\n", e.Invalid)
				}
			}
		}
	}
	if len(r.Unstable) > 0 {
		fmt.Fprintf(w, "\n  UNSTABLE across %d run(s):", len(r.History))
		for _, u := range r.Unstable {
			fmt.Fprintf(w, " %s (%d/%d)", u.ID, u.Detected, u.Runs)
		}
		fmt.Fprintln(w)
	}
}

func lossOrder(m map[string]int) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range AllLossPoints {
		if m[p] > 0 {
			out = append(out, p)
			seen[p] = true
		}
	}
	var rest []string
	for p := range m {
		if !seen[p] {
			rest = append(rest, p)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func failedNames(fs []ToolFailure) string {
	var n []string
	for _, f := range fs {
		s := f.Tool
		if f.Missing {
			s += " (missing)"
		}
		n = append(n, s)
	}
	if len(n) == 0 {
		return "scan did not complete"
	}
	return strings.Join(n, ", ")
}

// WriteMarkdown renders the scorecard as a document with the full per-target tables
// and the loss trace of every miss.
func (r DetectReport) WriteMarkdown(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("# Detection benchmark\n\n")
	p("Generated %s. Line tolerance +/-%d; AI review %s; judge %s.\n\n",
		r.GeneratedAt, r.Config.LineTolerance, onOff(r.Config.AI), onOff(r.Config.Judge))
	p("## Summary\n\n")
	p("| Metric | Value |\n|---|---|\n")
	p("| Recall | **%s** (%d of %d known vulnerabilities detected) |\n", pct(r.Overall.Recall), r.Overall.Detected, r.Overall.Entries-r.Overall.Invalid)
	if r.Config.AI {
		p("| Recall before AI review | %s |\n", pct(r.Overall.RecallUnfiltered))
	}
	if r.Overall.Invalid > 0 {
		p("| Invalid labels (not scored) | %d |\n", r.Overall.Invalid)
	}
	if r.Overall.JudgeAssisted > 0 {
		p("| Detections that needed the judge | %d |\n", r.Overall.JudgeAssisted)
	}
	p("| Findings surfaced | %d |\n", r.Findings.Surfaced)
	p("| ...matching a label | %d |\n", r.Findings.Matched)
	p("| ...in labeled files, no label | %d |\n", r.Findings.UnmatchedInLabeledFiles)
	p("| ...in unlabeled files | %d |\n\n", r.Findings.UnlabeledFiles)
	p("Unlabeled findings are not counted as false positives: this benchmark labels known vulnerabilities only, so a finding outside the labels is unclassified, not wrong.\n\n")
	if len(r.IncompleteTargets) > 0 {
		p("> **Incomplete:** %s. A scanner failed or was not installed on these targets, so their recall is a lower bound.\n\n", strings.Join(r.IncompleteTargets, ", "))
	}

	p("## Recall by class\n\n| Class | Entries | Detected | Recall |\n|---|---:|---:|---:|\n")
	for _, c := range r.ByClass {
		p("| %s | %d | %d | %s |\n", c.Class, c.Entries-c.Invalid, c.Detected, pct(c.Recall))
	}

	p("\n## Where the misses were lost\n\n")
	if len(r.LossPoints) == 0 {
		p("No misses.\n")
	} else {
		p("| Loss point | Misses | Meaning |\n|---|---:|---|\n")
		for _, lp := range lossOrder(r.LossPoints) {
			p("| %s | %d | %s |\n", lp, r.LossPoints[lp], lossMeaning[lp])
		}
	}

	for _, t := range r.Targets {
		p("\n## Target `%s`\n\n%s\n\nSource: `%s`\n\n", t.ID, t.Description, t.Source)
		if t.Error != "" {
			p("**Scan failed:** %s\n\n", oneLineMD(t.Error))
		}
		p("Scanners ran: %s.", listOrNone(t.Tools.Ran))
		if len(t.Tools.Failed) > 0 {
			p(" Failed: %s.", failedNames(t.Tools.Failed))
		}
		if len(t.Tools.Skipped) > 0 {
			p(" Skipped (not applicable): %s.", strings.Join(t.Tools.Skipped, ", "))
		}
		p("\n\n")
		for _, n := range t.Notes {
			p("- note: %s\n", oneLineMD(n))
		}
		p("| Entry | Class | Location | Result | Loss point |\n|---|---|---|---|---|\n")
		for _, e := range t.Entries {
			loss := ""
			if e.Loss != nil {
				loss = e.Loss.Point
			}
			p("| %s | %s | `%s:%d-%d` | %s | %s |\n", e.ID, e.Class, e.File, e.StartLine, e.EndLine, e.Status, loss)
		}
		var traced []EntryResult
		for _, e := range t.Entries {
			if e.Loss != nil {
				traced = append(traced, e)
			}
		}
		if len(traced) > 0 {
			p("\nMiss traces:\n\n")
			for _, e := range traced {
				p("- **%s** (%s): %s\n", e.ID, e.Loss.Point, oneLineMD(e.Loss.Detail))
			}
		}
		p("\nFindings: %d surfaced, %d matched, %d unmatched in labeled files, %d in unlabeled files.\n",
			t.Findings.Surfaced, t.Findings.Matched, t.Findings.UnmatchedInLabeledFiles, t.Findings.UnlabeledFiles)
	}

	if len(r.History) > 1 || len(r.Unstable) > 0 {
		p("\n## Stability\n\n%d run(s) recorded.\n\n", len(r.History))
		p("| Run | Recall | Detected | Incomplete |\n|---|---:|---:|---|\n")
		for _, h := range r.History {
			p("| %s | %s | %d/%d | %v |\n", h.At, pct(h.Recall), h.Detected, h.Scored, h.Incomplete)
		}
		if len(r.Unstable) > 0 {
			p("\nEntries whose result changed between runs:\n\n")
			for _, u := range r.Unstable {
				p("- `%s`: detected in %d of %d runs\n", u.ID, u.Detected, u.Runs)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

var lossMeaning = map[string]string{
	LossNotDetected:    "Scanners that cover it ran cleanly and reported nothing nearby: a detection gap (add or widen a rule).",
	LossNoCoverage:     "No scanner that ran claims this language/class.",
	LossToolMissing:    "A scanner that covers it is not installed; the miss may be environmental.",
	LossScanIncomplete: "A scanner that covers it failed to run or its output was unreadable.",
	LossScanFailed:     "The whole scan failed; nothing was learned.",
	LossClassMismatch:  "Flagged at the right place but as a different class or CWE (the judge can adjudicate).",
	LossLineMismatch:   "A compatible finding exists in the file but outside the line tolerance.",
	LossNoiseFilter:    "Reported, then dropped by the vendored/generated/minified filter or --exclude.",
	LossBaseline:       "Reported, then suppressed by the --baseline file.",
	LossDiff:           "Reported, then dropped by --diff.",
	LossAIDismissed:    "Reported, then dismissed as a false positive by the AI review.",
	LossDropped:        "Reported but absent from the final report; no known filter explains it.",
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func oneLineMD(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}

// CompareDetect prints how cur differs from base.
func CompareDetect(base, cur DetectReport, w io.Writer) {
	fmt.Fprintf(w, "\nvs baseline:\n")
	fmt.Fprintf(w, "  recall:      %s -> %s  (%+.1f pp)\n", pct(base.Overall.Recall), pct(cur.Overall.Recall),
		100*(cur.Overall.Recall-base.Overall.Recall))
	baseClass := map[string]ClassScore{}
	for _, c := range base.ByClass {
		baseClass[c.Class] = c
	}
	for _, c := range cur.ByClass {
		if b, ok := baseClass[c.Class]; ok && (b.Recall != c.Recall) {
			fmt.Fprintf(w, "  %-22s %s -> %s  (%+.1f pp)\n", c.Class, pct(b.Recall), pct(c.Recall), 100*(c.Recall-b.Recall))
		}
	}
	flipped := flips(base, cur)
	if len(flipped.lost) > 0 {
		fmt.Fprintf(w, "  now missed:  %s\n", strings.Join(flipped.lost, ", "))
	}
	if len(flipped.gained) > 0 {
		fmt.Fprintf(w, "  now found:   %s\n", strings.Join(flipped.gained, ", "))
	}
	var moved []string
	for _, p := range lossOrder(unionKeys(base.LossPoints, cur.LossPoints)) {
		if base.LossPoints[p] != cur.LossPoints[p] {
			moved = append(moved, fmt.Sprintf("%s %d->%d", p, base.LossPoints[p], cur.LossPoints[p]))
		}
	}
	if len(moved) > 0 {
		fmt.Fprintf(w, "  loss points: %s\n", strings.Join(moved, ", "))
	}
	if len(cur.IncompleteTargets) > len(base.IncompleteTargets) {
		fmt.Fprintf(w, "  INCOMPLETE:  %v (baseline: %v)\n", cur.IncompleteTargets, base.IncompleteTargets)
	}
	if len(flipped.lost) == 0 && len(flipped.gained) == 0 && base.Overall.Recall == cur.Overall.Recall {
		fmt.Fprintf(w, "  no per-entry changes\n")
	}
}

type flipSet struct{ lost, gained []string }

func flips(base, cur DetectReport) flipSet {
	was := map[string]bool{}
	for _, t := range base.Targets {
		for _, e := range t.Entries {
			was[t.ID+"/"+e.ID] = e.Detected
		}
	}
	var fs flipSet
	for _, t := range cur.Targets {
		for _, e := range t.Entries {
			id := t.ID + "/" + e.ID
			b, known := was[id]
			switch {
			case known && b && !e.Detected && e.Status != StatusInvalid:
				fs.lost = append(fs.lost, id)
			case known && !b && e.Detected:
				fs.gained = append(fs.gained, id)
			}
		}
	}
	sort.Strings(fs.lost)
	sort.Strings(fs.gained)
	return fs
}

func unionKeys(a, b map[string]int) map[string]int {
	out := map[string]int{}
	for k := range a {
		out[k] = 1
	}
	for k := range b {
		out[k] = 1
	}
	return out
}

// DetectRegressions returns what got worse beyond tol (a fraction: 0.02 = 2 pp):
// overall recall, and any class's recall. Entry flips alone are not regressions —
// scanners and advisory databases move — but they are printed by CompareDetect.
func DetectRegressions(base, cur DetectReport, tol float64) []string {
	var out []string
	if d := base.Overall.Recall - cur.Overall.Recall; d > tol+1e-9 {
		out = append(out, fmt.Sprintf("overall recall %s -> %s", pct(base.Overall.Recall), pct(cur.Overall.Recall)))
	}
	baseClass := map[string]ClassScore{}
	for _, c := range base.ByClass {
		baseClass[c.Class] = c
	}
	for _, c := range cur.ByClass {
		if b, ok := baseClass[c.Class]; ok && b.Recall-c.Recall > tol+1e-9 {
			out = append(out, fmt.Sprintf("%s recall %s -> %s", c.Class, pct(b.Recall), pct(c.Recall)))
		}
	}
	sort.Strings(out)
	return out
}
