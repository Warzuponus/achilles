// Package report renders a Scan for humans and passes SARIF through for
// machine consumers: one unified SARIF document across all tools, plus HTML,
// Markdown and JUnit.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
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
			"`achilles doctor` shows what is missing and how to fix it (or see --diagnostics); this is NOT a clean scan.\n",
			len(s.FailedTools), strings.Join(s.FailedTools, ", "))
	}
	if len(s.UncoveredLanguages) > 0 {
		fmt.Fprintf(w, "\nNOTE: no scanner that ran covers %s. Code in those languages was not analyzed, so no findings there is not evidence of safety.\n",
			strings.Join(s.UncoveredLanguages, ", "))
	}
	if len(s.RepoConfigChanged) > 0 {
		fmt.Fprintf(w, "\nWARNING: the change under review modifies scanner configuration (%s). "+
			"It can hide findings in the same change; review it as part of this scan.\n", strings.Join(s.RepoConfigChanged, "; "))
	}
	if len(s.RepoConfig) > 0 {
		fmt.Fprintf(w, "\nScanner configuration from the scanned repository was in effect (%s). "+
			"It can remove findings before Achilles sees them.\n", strings.Join(s.RepoConfig, "; "))
	}
	if t := s.Triage; t != nil && t.Aborted != "" {
		fmt.Fprintf(w, "\nWARNING: the AI review did NOT complete (%s). The findings below are scanner output that was not reviewed.\n", t.Aborted)
	}
	if t := s.Triage; t != nil {
		fmt.Fprintf(w, "\nAI review (%s): verdict on %d of %d finding(s)", t.Model, t.Triaged, t.Total)
		if t.Failed+t.Skipped > 0 {
			fmt.Fprintf(w, " — %d failed, %d not reached; those are UNVERIFIED", t.Failed, t.Skipped)
		}
		fmt.Fprintln(w)
		if t.Advisories > 0 {
			fmt.Fprintf(w, "%d dependency advisory finding(s) are listed as reported: the AI review does not judge known CVEs in dependencies\n", t.Advisories)
		}
		if t.AutoResolved > 0 {
			fmt.Fprintf(w, "%d of those verdict(s) came from analyst feedback on the rule (--calibrate), not from a model review\n", t.AutoResolved)
		}
		if t.Reused > 0 {
			fmt.Fprintf(w, "%d of those verdict(s) were reused from earlier runs: the same code, reviewed with the same prompt and models\n", t.Reused)
		}
	}
	if ruledOut, hardening := splitDismissed(s.Dismissed); len(ruledOut)+len(hardening) > 0 {
		if n := len(ruledOut); n > 0 {
			fmt.Fprintf(w, "%d more finding(s) ruled out as false positives by the AI review (not counted above; see the HTML/Markdown report, or --keep-dismissed to include them)\n", n)
		}
		if n := len(hardening); n > 0 {
			fmt.Fprintf(w, "%d hardening note(s): real weaknesses the AI review found already stopped by another control (not counted above; listed in the HTML/Markdown report)\n", n)
		}
	}
	if n := len(s.Suppressed); n > 0 {
		fmt.Fprintf(w, "\n%d more finding(s) suppressed by comments in the scanned code (achilles:ignore; not counted above; --no-repo-config to refuse them):\n", n)
		for _, f := range s.Suppressed {
			sup := f.Suppression
			if sup == nil {
				continue
			}
			added := ""
			if sup.New {
				added = "  [ADDED BY THE CHANGE UNDER REVIEW]"
			}
			fmt.Fprintf(w, "  [%s] %s at %s:%d — %s%s\n", f.Severity, f.RuleID, f.Location.File, f.Location.Region.StartLine,
				redact.Secrets(sup.Reason), added)
		}
	}
	if n := len(s.Hunted); n > 0 {
		fmt.Fprintf(w, "\n%d hunt candidate(s) the AI review did not confirm (--hunt; not counted above, never gate the build):\n", n)
		for _, f := range s.Hunted {
			fmt.Fprintf(w, "  [%s] %s at %s:%d — %s\n", f.Severity, f.RuleID, f.Location.File, f.Location.Region.StartLine,
				redact.Secrets(firstSentence(f.Message)))
		}
	}
	if len(s.Findings) == 0 {
		switch {
		case len(s.FailedTools) > 0:
		case len(s.Suppressed) > 0:
			fmt.Fprintf(w, "\nNo findings besides the %d suppressed in the code.\n", len(s.Suppressed))
		default:
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

	writeByRule(w, sorted)

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
			if v.Classification == model.ClassUncertain {
				status = "needs validation (uncertain)" + strings.TrimPrefix(status, string(model.ClassUncertain))
			}
			fmt.Fprintf(w, "    triage: %s  confidence=%.2f  exploitability=%s\n", status, v.Confidence, v.Exploitability)
			if !f.IsSecret() {
				for _, d := range v.Details() {
					fmt.Fprintf(w, "    %s: %s\n", strings.ToLower(d.Label), redact.Secrets(d.Text))
				}
			}
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
		if steps, from := f.SourcePath(); len(steps) > 0 {
			fmt.Fprintf(w, "    path (traced by %s):\n", from)
			for i, s := range steps {
				fmt.Fprintf(w, "      %d. %s\n", i+1, redact.Secrets(s.String()))
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
			if t := r.RegressionTest; t != nil && !f.IsSecret() {
				where := ""
				if t.File != "" {
					where = " for " + t.File
				}
				fmt.Fprintf(w, "    regression test proposed%s (not run): %s\n", where, redact.Secrets(t.Description))
			}
		}
	}
}

// splitDismissed separates hardening notes from findings ruled out as false
// positives; both are out of the gate, but they mean different things to a team.
func splitDismissed(fs []model.Finding) (ruledOut, hardening []model.Finding) {
	for _, f := range fs {
		if f.Verdict != nil && f.Verdict.Hardening() {
			hardening = append(hardening, f)
		} else {
			ruledOut = append(ruledOut, f)
		}
	}
	return ruledOut, hardening
}

// byRuleThreshold is the number of findings above which the human report
// summarizes them by rule before listing each one; byRuleMax is how many rules
// that summary shows.
const (
	byRuleThreshold = 10
	byRuleMax       = 15
)

// writeByRule prints how many findings each rule produced, most severe and
// most frequent first, so a long report can be read at a glance: a few rules
// usually account for most of it. sorted is most severe first.
func writeByRule(w io.Writer, sorted []model.Finding) {
	if len(sorted) <= byRuleThreshold {
		return
	}
	type row struct {
		tool, rule string
		sev        model.Severity
		n          int
		files      map[string]bool
		first      int // index in sorted, for a stable order
	}
	idx := map[string]*row{}
	var rows []*row
	for i, f := range sorted {
		k := f.Tool + "\x00" + f.RuleID
		r := idx[k]
		if r == nil {
			r = &row{tool: f.Tool, rule: f.RuleID, sev: f.Severity, files: map[string]bool{}, first: i}
			idx[k] = r
			rows = append(rows, r)
		}
		r.n++
		r.files[f.Location.File] = true
		if f.Severity.Rank() > r.sev.Rank() {
			r.sev = f.Severity
		}
	}
	if len(rows) == len(sorted) {
		return // one finding per rule: the summary would repeat the detail
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if a, b := rows[i].sev.Rank(), rows[j].sev.Rank(); a != b {
			return a > b
		}
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].first < rows[j].first
	})
	fmt.Fprintf(w, "\nBy rule (%d rules):\n", len(rows))
	for i, r := range rows {
		if i == byRuleMax {
			fmt.Fprintf(w, "  ... and %d more rule(s)\n", len(rows)-byRuleMax)
			break
		}
		where := "1 file"
		if len(r.files) != 1 {
			where = fmt.Sprintf("%d files", len(r.files))
		}
		fmt.Fprintf(w, "  %-8s %4d  %s (%s, %s)\n", r.sev, r.n, r.rule, r.tool, where)
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

// firstSentence is the text up to its first ". ", for a one-line listing.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i]
	}
	return s
}
