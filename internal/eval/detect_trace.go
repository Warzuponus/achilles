package eval

import (
	"fmt"
	"path"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/noise"
)

// Loss points: WHERE in the pipeline a known vulnerability was lost. Every missed
// ground-truth entry gets exactly one. "Not detected" alone says nothing about what
// to fix; these say whether the fix is a rule, a missing tool, a filter, or the AI
// review.
const (
	// LossToolMissing: a scanner that covers this entry was not installed. The
	// target is incomplete; the miss may be an environment gap, not a rule gap.
	LossToolMissing = "tool-missing"
	// LossScanIncomplete: a scanner that covers this entry failed to run or its
	// output could not be read.
	LossScanIncomplete = "scan-incomplete"
	// LossScanFailed: the whole scan failed; nothing was learned about the entry.
	LossScanFailed = "scan-failed"
	// LossNoCoverage: no scanner that ran claims this language/class at all.
	LossNoCoverage = "no-coverage"
	// LossNotDetected: scanners that cover the entry ran cleanly and reported nothing
	// near it — a genuine detection gap (missing or too-narrow rule).
	LossNotDetected = "not-detected"
	// LossClassMismatch: a scanner flagged the right place but as a different class
	// or CWE, so it was not counted (the optional judge can adjudicate).
	LossClassMismatch = "class-mismatch"
	// LossLineMismatch: a compatible finding exists in the right file but outside
	// the line tolerance.
	LossLineMismatch = "line-mismatch"
	// LossNoiseFilter: reported by a scanner, then dropped by the vendored/generated/
	// minified filter or an --exclude pattern.
	LossNoiseFilter = "noise-filter"
	// LossBaseline: reported, then removed because it was in the --baseline file.
	LossBaseline = "baseline-suppressed"
	// LossDiff: reported, then removed by --diff.
	LossDiff = "diff-filtered"
	// LossDropped: reported by a scanner but absent from the final report, and no
	// known filter explains it.
	LossDropped = "dropped-unknown"
	// LossAIDismissed: reported, then dismissed as a false positive by the AI review.
	LossAIDismissed = "ai-dismissed"
)

// AllLossPoints is the report order of the histogram.
var AllLossPoints = []string{
	LossNotDetected, LossNoCoverage, LossToolMissing, LossScanIncomplete, LossScanFailed,
	LossClassMismatch, LossLineMismatch, LossNoiseFilter, LossBaseline, LossDiff,
	LossAIDismissed, LossDropped,
}

// toolClasses lists, for the tools whose scope is narrower than "any weakness", the
// classes they can find. Tools absent from the table are assumed to cover every
// class (opengrep, gosec, ...).
var toolClasses = map[string][]string{
	"gitleaks":       {ClassHardcodedSecret},
	"trufflehog":     {ClassHardcodedSecret},
	"detect-secrets": {ClassHardcodedSecret},
	"osv-scanner":    {ClassVulnDependency},
	"govulncheck":    {ClassVulnDependency},
	"trivy":          {ClassVulnDependency, ClassHardcodedSecret, "misconfiguration"},
	"syft":           {},
}

var extLanguage = map[string]string{
	".go": "go", ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".rb": "ruby", ".java": "java", ".kt": "kotlin",
	".php": "php", ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".rs": "rust", ".sh": "shell",
}

func languageOf(file string) string { return extLanguage[strings.ToLower(path.Ext(file))] }

// traceContext is everything the loss-point analysis may look at.
type traceContext struct {
	m              matcher
	opts           DetectOptions
	facts          scanFacts
	unfiltered     []model.Finding // pass-1 surfaced (before AI review)
	finalSurfaced  []model.Finding
	finalDismissed []model.Finding
	noise          *noise.Matcher
}

// toolCovers reports whether a tool could plausibly report an entry of this class
// in a file of this language.
func (tc traceContext) toolCovers(tool, lang, class string) bool {
	if classes, limited := toolClasses[tool]; limited {
		ok := false
		for _, c := range classes {
			if strings.EqualFold(c, class) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	langs, known := tc.opts.ToolLanguages[tool]
	if !known || len(langs) == 0 {
		return true
	}
	for _, l := range langs {
		if l == "generic" || (lang != "" && strings.EqualFold(l, lang)) {
			return true
		}
	}
	return false
}

// trace explains one missed entry.
func (tc traceContext) trace(v Vuln) LossTrace {
	tol := tc.opts.LineTolerance
	m := tc.m

	// (c) Reported, then dismissed by the AI review.
	for _, f := range tc.finalDismissed {
		if m.classify(v, f) == matchExact {
			lt := LossTrace{Point: LossAIDismissed, Findings: []FindingRef{refOf(f)}}
			verdict := &VerdictRef{}
			if f.Verdict != nil {
				verdict = &VerdictRef{
					Classification: string(f.Verdict.Classification), Confidence: f.Verdict.Confidence,
					Reasoning: clip(f.Verdict.Reasoning, 600), Refuted: f.Verdict.Refuted,
					RefuteReason: clip(f.Verdict.RefuteReason, 600),
				}
			}
			lt.Verdict = verdict
			why := verdict.Reasoning
			if verdict.RefuteReason != "" {
				why = "judge refuted: " + verdict.RefuteReason
			}
			if why == "" {
				why = "no reasoning recorded"
			}
			lt.Detail = fmt.Sprintf("%s at %s:%d was reported, then the AI review dismissed it (%s, confidence %.2f): %s",
				f.RuleID, f.Location.File, f.Location.Region.StartLine, orDash(verdict.Classification), verdict.Confidence, why)
			return lt
		}
	}

	// Reported by a scanner (the vault records findings BEFORE any filter) but not in
	// the final report.
	var reported []model.Finding
	for _, f := range tc.facts.Candidates {
		if m.classify(v, f) == matchExact {
			reported = append(reported, f)
		}
	}
	if len(reported) == 0 {
		// Without a vault the surfaced sets are all we can see.
		for _, f := range append(append([]model.Finding{}, tc.unfiltered...), tc.finalSurfaced...) {
			if m.classify(v, f) == matchExact {
				reported = append(reported, f)
				break
			}
		}
	}
	if len(reported) > 0 {
		f := reported[0]
		lt := LossTrace{Findings: []FindingRef{refOf(f)}}
		where := fmt.Sprintf("%s reported %s at %s:%d", f.Tool, f.RuleID, f.Location.File, f.Location.Region.StartLine)
		inUnfiltered := false
		for _, u := range tc.unfiltered {
			if m.classify(v, u) == matchExact {
				inUnfiltered = true
			}
		}
		switch {
		case inUnfiltered:
			lt.Point = LossDropped
			lt.Detail = where + ", and it was in the unfiltered report, but it is absent from the AI-filtered report and not listed as dismissed " +
				"(run-to-run variance in the AI pass, or its triage failed)"
		case tc.noise != nil && tc.noise.Matches(f.Location.File):
			lt.Point = LossNoiseFilter
			lt.Detail = where + ", but the path matches the noise filter (vendored/generated/minified defaults" +
				excludeNote(tc.opts) + ") and the finding was dropped before reporting"
		case tc.opts.ScanBaselineUsed || tc.facts.BaselineUsed:
			lt.Point = LossBaseline
			lt.Detail = where + ", but it was suppressed because it is in the --baseline file"
		case tc.opts.DiffUsed:
			lt.Point = LossDiff
			lt.Detail = where + ", but it was dropped by --diff (the file is not among the changed files)"
		default:
			lt.Point = LossDropped
			lt.Detail = where + ", but it is absent from the final report and no known filter (noise, baseline, diff) explains it" +
				"; check the scan's own flags"
		}
		return lt
	}

	// Near misses: right place, wrong class — or right class, wrong place.
	pool := tc.facts.Candidates
	if len(pool) == 0 {
		pool = append(append([]model.Finding{}, tc.unfiltered...), tc.finalSurfaced...)
	}
	var wrongClass []model.Finding
	nearest, nearestRef := -1, FindingRef{}
	for _, f := range pool {
		if m.classify(v, f) == matchAmbiguous {
			wrongClass = append(wrongClass, f)
		}
		if m.landsOnAnother(v, f) {
			continue // that finding is explained by a different label, not a near miss for this one
		}
		if d := nearestLineDistance(v, f); d > tol && (nearest < 0 || d < nearest) {
			nearest, nearestRef = d, refOf(f)
		}
	}
	if len(wrongClass) > 0 {
		var refs []FindingRef
		var names []string
		for _, f := range firstFindings(wrongClass, 3) {
			refs = append(refs, refOf(f))
			names = append(names, fmt.Sprintf("%s %s %s", f.Tool, f.RuleID, cweList(f.CWE)))
		}
		return LossTrace{Point: LossClassMismatch, Findings: refs,
			Detail: fmt.Sprintf("scanner(s) flagged %s:%d-%d but not as %s (%s) — reported: %s. "+
				"Not counted; run with --judge to adjudicate such matches",
				v.File, v.StartLine, v.EndLine, v.Class, orDash(strings.Join(v.CWE, ",")), strings.Join(names, "; "))}
	}
	if nearest > tol {
		return LossTrace{Point: LossLineMismatch, Findings: []FindingRef{nearestRef},
			Detail: fmt.Sprintf("%s reported a compatible finding in %s %d line(s) from the labeled range %d-%d (tolerance %d)",
				nearestRef.Tool, v.File, nearest, v.StartLine, v.EndLine, tol)}
	}

	// Nothing reported anywhere near it. Was the scan able to?
	lang := languageOf(v.File)
	var failedRelevant []ToolFailure
	missing := false
	for _, tf := range tc.facts.Failed {
		if tc.toolCovers(tf.Tool, lang, v.Class) {
			failedRelevant = append(failedRelevant, tf)
			missing = missing || tf.Missing
		}
	}
	if len(failedRelevant) > 0 {
		var parts []string
		for _, tf := range failedRelevant {
			if tf.Missing {
				parts = append(parts, tf.Tool+" (not installed or not on PATH)")
			} else {
				parts = append(parts, fmt.Sprintf("%s (%s failed: %s)", tf.Tool, tf.Stage, clip(detectFirstLine(tf.Error), 160)))
			}
		}
		point := LossScanIncomplete
		if missing {
			point = LossToolMissing
		}
		return LossTrace{Point: point,
			Detail: fmt.Sprintf("nothing was reported near %s:%d-%d, and a scanner that covers %s was unavailable: %s. %s",
				v.File, v.StartLine, v.EndLine, orDash(coverLabel(lang, v.Class)), strings.Join(parts, "; "), tc.scanSummary())}
	}
	if !tc.facts.HasVault {
		return LossTrace{Point: LossNotDetected,
			Detail: fmt.Sprintf("nothing was reported near %s:%d-%d (no scan vault was available, so which scanners ran is unknown)",
				v.File, v.StartLine, v.EndLine)}
	}
	var covering []string
	for _, t := range tc.facts.Ran {
		if tc.toolCovers(t, lang, v.Class) {
			covering = append(covering, t)
		}
	}
	if len(covering) == 0 {
		return LossTrace{Point: LossNoCoverage,
			Detail: fmt.Sprintf("no scanner that ran covers %s. %s", coverLabel(lang, v.Class), tc.scanSummary())}
	}
	return LossTrace{Point: LossNotDetected,
		Detail: fmt.Sprintf("%s ran cleanly on %s and reported nothing within %d line(s) of %d-%d — a detection gap (no rule matched). %s",
			strings.Join(covering, ", "), v.File, tol, v.StartLine, v.EndLine, tc.scanSummary())}
}

// scanSummary states which scanners ran, failed, or were skipped.
func (tc traceContext) scanSummary() string {
	f := tc.facts
	var parts []string
	parts = append(parts, "Scanners ran: "+listOrNone(f.Ran))
	if len(f.Failed) > 0 {
		var fs []string
		for _, t := range f.Failed {
			s := t.Tool
			if t.Missing {
				s += " (not installed)"
			} else {
				s += " (" + t.Stage + " error)"
			}
			fs = append(fs, s)
		}
		parts = append(parts, "failed: "+strings.Join(fs, ", "))
	}
	if len(f.Skipped) > 0 {
		parts = append(parts, "skipped as not applicable to the target's languages: "+strings.Join(f.Skipped, ", "))
	}
	return strings.Join(parts, "; ") + "."
}

func excludeNote(o DetectOptions) string {
	if o.Excludes == "" {
		return ""
	}
	return " plus --exclude " + o.Excludes
}

func coverLabel(lang, class string) string {
	if lang == "" {
		return class + " findings in this file type"
	}
	return class + " findings in " + lang
}

func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}

func cweList(c []string) string {
	if len(c) == 0 {
		return "(no CWE)"
	}
	return "(" + strings.Join(c, ",") + ")"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstFindings(fs []model.Finding, n int) []model.Finding {
	if len(fs) > n {
		return fs[:n]
	}
	return fs
}
