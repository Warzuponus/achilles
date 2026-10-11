// Package report renders a Scan for humans and passes SARIF through for
// machine consumers. In Phase 0 the SARIF output is the tool's own document;
// later phases re-emit a unified SARIF across all tools.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

var severityOrder = []model.Severity{
	model.SeverityCritical,
	model.SeverityHigh,
	model.SeverityMedium,
	model.SeverityLow,
	model.SeverityInfo,
	model.SeverityUnknown,
}

// WriteHuman renders a readable summary + per-finding detail to w.
func WriteHuman(w io.Writer, s model.Scan) {
	fmt.Fprintf(w, "Achilles scan: %s\n", s.Target)
	if len(s.Tools) > 0 {
		fmt.Fprintf(w, "Tools: %v\n", s.Tools)
	}

	counts := s.CountsBySeverity()
	fmt.Fprintf(w, "\n%d finding(s):\n", len(s.Findings))
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "  %-8s %d\n", sev, n)
		}
	}

	if len(s.FailedTools) > 0 {
		fmt.Fprintf(w, "\nWARNING: %d tool(s) FAILED to run (%s) — results are incomplete. "+
			"Install the missing tool(s) or see --diagnostics; this is NOT a clean scan.\n",
			len(s.FailedTools), strings.Join(s.FailedTools, ", "))
	}
	if t := s.Triage; t != nil {
		fmt.Fprintf(w, "\nAI review (%s): verdict on %d of %d finding(s)", t.Model, t.Triaged, t.Total)
		if t.Failed+t.Skipped > 0 {
			fmt.Fprintf(w, " — %d failed, %d not reached; those are UNVERIFIED", t.Failed, t.Skipped)
		}
		fmt.Fprintln(w)
	}
	if n := len(s.Dismissed); n > 0 {
		fmt.Fprintf(w, "%d more finding(s) ruled out as false positives by the AI review (not counted above; see the HTML/Markdown report, or --keep-dismissed to include them)\n", n)
	}
	if len(s.Findings) == 0 {
		if len(s.FailedTools) == 0 {
			fmt.Fprintln(w, "\nNo findings. Clean scan.")
		}
		return
	}

	// Most severe first, then by file/line for stable output.
	sorted := make([]model.Finding, len(s.Findings))
	copy(sorted, s.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if a, b := sorted[i].Severity.Rank(), sorted[j].Severity.Rank(); a != b {
			return a > b
		}
		if sorted[i].Location.File != sorted[j].Location.File {
			return sorted[i].Location.File < sorted[j].Location.File
		}
		return sorted[i].Location.Region.StartLine < sorted[j].Location.Region.StartLine
	})

	fmt.Fprintln(w, "\nDetail:")
	for _, f := range sorted {
		loc := f.Location.File
		if f.Location.Region.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
		}
		shadow := ""
		if f.Shadow {
			shadow = "  (shadow — report-only, not gating)"
		}
		fmt.Fprintf(w, "\n  [%s] %s%s\n", f.Severity, f.RuleID, shadow)
		fmt.Fprintf(w, "    %s\n", f.Message)
		fmt.Fprintf(w, "    at %s  (%s)\n", loc, f.Tool)
		if len(f.CWE) > 0 {
			fmt.Fprintf(w, "    %v\n", f.CWE)
		}
		if len(f.Correlated) > 0 {
			fmt.Fprintf(w, "    also reported by: %s\n", strings.Join(f.Correlated, ", "))
		}
		if v := f.Verdict; v != nil {
			status := string(v.Classification)
			switch {
			case v.Disputed():
				// The judge disagreed but did not back it well enough to dismiss the
				// finding, so it is still here on purpose.
				status += " (DISPUTED by judge — kept for review)"
			case v.Refuted:
				status += " (refuted by judge)"
			case v.Overturned:
				// Surfaced despite the triage verdict, so say whose call it was and
				// that the two passes disagree — the confidence figure below belongs
				// to the verdict that was overturned, not to the decision to show it.
				status += " (OVERTURNED by judge — surfaced for review)"
			}
			fmt.Fprintf(w, "    triage: %s  confidence=%.2f  exploitability=%s\n", status, v.Confidence, v.Exploitability)
			if (v.Overturned || v.Disputed()) && v.RefuteReason != "" {
				fmt.Fprintf(w, "    judge: %s\n", v.RefuteReason)
			}
			if p := f.Provenance; p != nil && p.CorrelatedFrom != "" {
				fmt.Fprintf(w, "    (verdict inherited from correlated finding %s)\n", p.CorrelatedFrom)
			}
			if v.SuggestedFix != "" {
				fmt.Fprintf(w, "    fix: %s\n", v.SuggestedFix)
			}
		}
		if d := f.Deep; d != nil {
			if d.Aborted != "" {
				fmt.Fprintf(w, "    deep check stopped after %d step(s): %s\n", d.Steps, d.Aborted)
			} else {
				fmt.Fprintf(w, "    deep check (%d step(s)): %s, confidence=%.2f\n", d.Steps, d.Conclusion, d.Confidence)
			}
		}
		if v := f.Verdict; v != nil && v.Stability != nil && v.Stability.Samples > 1 && !v.Stability.Unanimous() {
			fmt.Fprintf(w, "    the model's %d answers disagreed; not dismissed automatically\n", v.Stability.Samples)
		}
		if r := f.Remediation; r != nil {
			fmt.Fprintf(w, "    remediation: %s\n", r.Summary)
			if vf := r.Verification; vf != nil {
				if vf.Status == model.FixVerified {
					fmt.Fprintln(w, "    fix verified by re-scan (the finding is gone, nothing new appeared)")
				} else {
					fmt.Fprintf(w, "    fix NOT verified: %s\n", vf.Status)
				}
			}
			if r.Diff != "" {
				fmt.Fprintln(w, "    (patch available in the Evidence Vault)")
			}
		}
	}
}

// WriteSARIF passes SARIF bytes through to w.
func WriteSARIF(w io.Writer, sarif []byte) error {
	_, err := w.Write(sarif)
	return err
}

// MaxSeverity returns the highest severity present, or SeverityUnknown if none.
func MaxSeverity(s model.Scan) model.Severity {
	best := model.SeverityUnknown
	for _, f := range s.Findings {
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}

// GatingSeverity is MaxSeverity over findings that may affect the CI gate —
// i.e. excluding shadow findings from generated rules still in their shadow
// window. Use this (not MaxSeverity) for --fail-on decisions.
func GatingSeverity(s model.Scan) model.Severity {
	best := model.SeverityUnknown
	for _, f := range s.Findings {
		if f.Shadow {
			continue
		}
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}
