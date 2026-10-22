package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
)

// sarifLevel maps our severity onto SARIF result levels.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIFReport emits one unified SARIF 2.1.0 document across all tools —
// the format GitHub code scanning and other consumers ingest.
func WriteSARIFReport(w io.Writer, s model.Scan) error {
	// Results must be a non-nil array: SARIF requires `results` to be an array,
	// and GitHub code scanning rejects `"results": null` (which a nil slice emits).
	rules, ruleIndex := sarifRules(s.Findings, s.Dismissed, s.Suppressed)
	run := model.SarifRun{
		Tool:    model.SarifTool{Driver: model.SarifDriver{Name: "achilles", Rules: rules}},
		Results: []model.SarifResult{},
	}
	all := append(append(append([]model.Finding{}, s.Findings...), s.Dismissed...), s.Suppressed...)
	hashes := lineHashes(all)
	for i, f := range all {
		// Findings the AI review ruled out are still emitted, marked suppressed, so
		// code scanning shows them as dismissed (with the reason) and does not
		// re-open them as new alerts on the next run.
		// Findings suppressed by a comment in the code are emitted too, with the
		// suppression kind SARIF has for exactly that ("inSource").
		r := sarifResult(f, i >= len(s.Findings) && f.Suppression == nil)
		if sup := f.Suppression; sup != nil {
			r.Suppressions = []model.SarifSuppression{{Kind: "inSource", Status: "accepted", Justification: redact.Secrets(sup.Reason)}}
		}
		if idx, ok := ruleIndex[f.RuleID]; ok {
			r.RuleIndex = &idx
		}
		if hashes[i] != "" {
			r.PartialFingerprints = map[string]string{"primaryLocationLineHash": hashes[i]}
		}
		if s.BaselineApplied {
			r.BaselineState = "new"
		}
		r.Fixes = sarifFix(f)
		run.Results = append(run.Results, r)
	}
	if len(s.FailedTools) > 0 {
		inv := model.SarifInvocation{ExecutionSuccessful: false}
		for _, t := range s.FailedTools {
			inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, model.SarifNotification{
				Level: "error", Message: model.SarifMessage{Text: t + " failed to run or its output could not be read; results are incomplete"},
			})
		}
		run.Invocations = []model.SarifInvocation{inv}
	}
	log := model.SarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []model.SarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifResult(f model.Finding, suppressed bool) model.SarifResult {
	msg := f.Message
	if f.IsSecret() {
		msg = redact.Secrets(msg) // code scanning alerts are readable by everyone with repo access
	}
	r := model.SarifResult{
		RuleID:  f.RuleID,
		Level:   sarifLevel(f.Severity),
		Message: model.SarifMessage{Text: msg},
		Locations: []model.SarifLocation{{
			PhysicalLocation: model.SarifPhysicalLocation{
				ArtifactLocation: model.SarifArtifactLocation{URI: f.Location.File},
				Region:           model.SarifRegion{StartLine: f.Location.Region.StartLine},
			},
		}},
		Fingerprints: map[string]string{"achilles/v1": f.Fingerprint},
	}
	props := map[string]any{}
	if len(f.CWE) > 0 {
		props["cwe"] = f.CWE
	}
	if v := f.Verdict; v != nil {
		props["achilles/verdict"] = string(v.Classification)
		props["achilles/confidence"] = v.Confidence
		props["achilles/exploitability"] = string(v.Exploitability)
		if v.SuggestedFix != "" && !f.IsSecret() {
			props["achilles/suggestedFix"] = v.SuggestedFix
		}
		if v.Gates != nil {
			props["achilles/gates"] = v.Gates
		}
		if !f.IsSecret() {
			if v.AssessedSeverity != "" {
				props["achilles/assessedSeverity"] = string(v.AssessedSeverity)
			}
			if v.Attacker != "" {
				props["achilles/attacker"] = v.Attacker
			}
			if v.Impact != "" {
				props["achilles/impact"] = v.Impact
			}
			if len(v.Blockers) > 0 {
				props["achilles/blockers"] = v.Blockers
			}
			if v.ValidationPlan != nil {
				props["achilles/validationPlan"] = v.ValidationPlan
			}
			if len(v.UnverifiedCitations) > 0 {
				props["achilles/unverifiedCitations"] = v.UnverifiedCitations
			}
		}
		if v.Stability != nil && v.Stability.Samples > 1 {
			props["achilles/stability"] = map[string]any{
				"samples": v.Stability.Samples, "agreeing": v.Stability.Agreeing, "unanimous": v.Stability.Unanimous(),
			}
		}
	}
	if r := f.Remediation; r != nil && r.Verification != nil {
		props["achilles/fixVerification"] = string(r.Verification.Status)
	}
	if d := f.Deep; d != nil && d.Aborted == "" {
		props["achilles/deepVerdict"] = map[string]any{
			"conclusion": string(d.Conclusion), "confidence": d.Confidence, "steps": d.Steps,
		}
	}
	if len(props) > 0 {
		r.Properties = props
	}
	if suppressed {
		why := "Ruled out by the Achilles AI review."
		if v := f.Verdict; v != nil {
			switch {
			case v.RefuteReason != "":
				why = v.RefuteReason
			case v.Reasoning != "":
				why = v.Reasoning
			}
		}
		if v := f.Verdict; v != nil && v.Hardening() {
			why = "Hardening note (a real weakness another control already stops): " + why
		}
		r.Suppressions = []model.SarifSuppression{{Kind: "external", Status: "accepted", Justification: why}}
	}
	return r
}

// --- JUnit ---

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitFailure `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit emits JUnit XML for CI systems that render test reports. Each
// finding is a failing test case. Each scanner that failed, or could not analyze
// everything, is a test case in error: a JUnit report with no failures is rendered
// as a green run, and a scan whose scanners did not run is not one.
func WriteJUnit(w io.Writer, s model.Scan) error {
	suite := junitSuite{Name: "achilles"}
	for _, tool := range s.FailedTools {
		suite.Errors++
		suite.Cases = append(suite.Cases, junitCase{
			Name:      fmt.Sprintf("scanner %s completed", tool),
			Classname: "achilles.scan",
			Error: &junitFailure{
				Message: fmt.Sprintf("%s failed to run or could not analyze everything; the scan is incomplete", tool),
				Text:    "A missing result from this scanner is not evidence of safety. See the run log, --diagnostics, or `achilles doctor`.",
			},
		})
	}
	if t := s.Triage; t != nil && t.Aborted != "" {
		suite.Errors++
		suite.Cases = append(suite.Cases, junitCase{
			Name:      "AI review completed",
			Classname: "achilles.review",
			Error:     &junitFailure{Message: "the AI review did not complete: " + t.Aborted, Text: "The findings in this report were not reviewed."},
		})
	}
	for _, f := range s.Findings {
		loc := f.Location.File
		if f.Location.Region.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
		}
		msg := f.Message
		if f.IsSecret() {
			msg = redact.Secrets(msg) // a test report is a CI artifact many people can open
		}
		suite.Failures++
		suite.Cases = append(suite.Cases, junitCase{
			Name:      fmt.Sprintf("%s (%s)", f.RuleID, loc),
			Classname: f.Tool,
			Failure:   &junitFailure{Message: msg, Text: fmt.Sprintf("[%s] %s at %s", f.Severity, f.RuleID, loc)},
		})
	}
	suite.Tests = len(suite.Cases)
	doc := junitSuites{Tests: suite.Tests, Failures: suite.Failures, Errors: suite.Errors, Suites: []junitSuite{suite}}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(doc)
}

// --- Markdown (PR comment) ---

// WriteMarkdown emits a Markdown summary suitable for a PR comment.
func WriteMarkdown(w io.Writer, s model.Scan) error {
	fmt.Fprintf(w, "## Achilles scan — %d finding(s)\n\n", len(s.Findings))
	if len(s.FailedTools) > 0 {
		fmt.Fprintf(w, "> **Incomplete scan:** %s failed to run, so missing results are not evidence of safety.\n\n",
			strings.Join(s.FailedTools, ", "))
	}
	if len(s.UncoveredLanguages) > 0 {
		fmt.Fprintf(w, "> **Not covered by any scanner that ran:** %s. Code in these languages was not analyzed, so no findings there is not evidence of safety.\n\n",
			MarkdownText(strings.Join(s.UncoveredLanguages, ", ")))
	}
	if len(s.RepoConfigChanged) > 0 {
		fmt.Fprintf(w, "> **This change modifies scanner configuration:** %s. It can hide findings in the same change; review it as part of this scan.\n\n",
			MarkdownText(strings.Join(s.RepoConfigChanged, "; ")))
	}
	if len(s.RepoConfig) > 0 {
		fmt.Fprintf(w, "Scanner configuration from the scanned repository was in effect (%s). It can remove findings before Achilles sees them.\n\n",
			MarkdownText(strings.Join(s.RepoConfig, "; ")))
	}
	if t := s.Triage; t != nil && t.Aborted != "" {
		fmt.Fprintf(w, "> **The AI review did not complete:** %s. The findings below are scanner output that was not reviewed.\n\n", MarkdownText(t.Aborted))
	}
	if t := s.Triage; t != nil {
		fmt.Fprintf(w, "AI review (`%s`) gave a verdict on %d of %d findings", t.Model, t.Triaged, t.Total)
		if t.Failed+t.Skipped > 0 {
			fmt.Fprintf(w, " (%d failed, %d not reached)", t.Failed, t.Skipped)
		}
		if t.AutoResolved > 0 {
			fmt.Fprintf(w, "; %d of those came from analyst feedback on the rule (`--calibrate`), not from a model review", t.AutoResolved)
		}
		if t.Reused > 0 {
			fmt.Fprintf(w, "; %d were reused from earlier runs (same code, prompt and models)", t.Reused)
		}
		fmt.Fprint(w, ".")
		if t.Advisories > 0 {
			fmt.Fprintf(w, " %d dependency advisories are listed as reported: the AI review does not judge known CVEs in dependencies.", t.Advisories)
		}
		fmt.Fprint(w, "\n\n")
	}
	if len(s.Findings) == 0 {
		msg := "No findings. ✅\n"
		if len(s.FailedTools) > 0 {
			msg = "No findings from the tools that ran.\n"
		}
		if _, err := io.WriteString(w, msg); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(w, "| Severity | Rule | Location | Verdict | Message |")
		fmt.Fprintln(w, "|----------|------|----------|---------|---------|")
		for _, f := range s.Findings {
			loc := f.Location.File
			if f.Location.Region.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
			}
			verdict := "—"
			if f.Verdict != nil {
				verdict = string(f.Verdict.Classification)
				if f.Verdict.Classification == model.ClassUncertain {
					verdict = "needs validation"
					if bs := f.Verdict.Blockers; len(bs) > 0 && !f.IsSecret() {
						verdict += ": " + MarkdownText(bs[0])
					}
				}
				if a := f.Verdict.AssessedSeverity; a != "" {
					verdict += " (assessed " + string(a) + ")"
				}
				switch {
				case f.Verdict.Disputed():
					verdict += " (**disputed by judge**)"
				case f.Verdict.Refuted:
					verdict += " (refuted)"
				case f.Verdict.Overturned:
					verdict += " (**overturned by judge**)"
				}
			}
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n",
				f.Severity, markdownCode(f.RuleID), MarkdownText(loc), verdict, FindingMessage(f))
		}
	}
	if len(s.Suppressed) > 0 {
		added := 0
		for _, f := range s.Suppressed {
			if f.Suppression != nil && f.Suppression.New {
				added++
			}
		}
		note := ""
		if added > 0 {
			note = fmt.Sprintf(", **%d of them added by this change**", added)
		}
		fmt.Fprintf(w, "\n<details><summary>%d finding(s) suppressed by comments in the code%s</summary>\n\n", len(s.Suppressed), note)
		fmt.Fprintln(w, "| Rule | Location | Reason given | |")
		fmt.Fprintln(w, "|------|----------|--------------|---|")
		for _, f := range s.Suppressed {
			sup := f.Suppression
			if sup == nil {
				continue
			}
			loc := fmt.Sprintf("%s:%d", f.Location.File, f.Location.Region.StartLine)
			flag := ""
			if sup.New {
				flag = "added by this change"
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", markdownCode(f.RuleID), MarkdownText(loc), MarkdownText(sup.Reason), flag)
		}
		fmt.Fprint(w, "\n</details>\n")
	}
	ruledOut, hardening := splitDismissed(s.Dismissed)
	if len(hardening) > 0 {
		fmt.Fprintf(w, "\n<details><summary>%d hardening note(s): real weaknesses already stopped by another control</summary>\n\n", len(hardening))
		fmt.Fprintln(w, "| Rule | Location | What already stops it |")
		fmt.Fprintln(w, "|------|----------|-----------------------|")
		for _, f := range hardening {
			loc := f.Location.File
			if f.Location.Region.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
			}
			fmt.Fprintf(w, "| `%s` | %s | %s |\n", markdownCode(f.RuleID), MarkdownText(loc), MarkdownText(f.Verdict.Reasoning))
		}
		fmt.Fprint(w, "\n</details>\n")
	}
	if len(ruledOut) > 0 {
		fmt.Fprintf(w, "\n<details><summary>%d finding(s) ruled out by the AI review</summary>\n\n", len(ruledOut))
		fmt.Fprintln(w, "| Rule | Location | Why |")
		fmt.Fprintln(w, "|------|----------|-----|")
		for _, f := range ruledOut {
			loc := f.Location.File
			if f.Location.Region.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
			}
			why := ""
			if f.Verdict != nil {
				why = f.Verdict.Reasoning
				if f.Verdict.RefuteReason != "" {
					why = f.Verdict.RefuteReason
				}
			}
			fmt.Fprintf(w, "| `%s` | %s | %s |\n", markdownCode(f.RuleID), MarkdownText(loc), MarkdownText(why))
		}
		fmt.Fprint(w, "\n</details>\n")
	}
	return nil
}

var mentionRE = regexp.MustCompile(`@([A-Za-z0-9])`)

// maxMarkdownText bounds one piece of untrusted text in a comment or table cell.
const maxMarkdownText = 1000

// MarkdownText prepares untrusted text for a Markdown comment or table cell. A
// scanner's message, a file name and a model's reasoning all derive from the code
// being scanned, which may be hostile, and this text is posted where the whole
// repository reads it. So: credentials are masked, it is put on one line, HTML
// (including comments, which could forge Achilles' own hidden markers) is shown
// as text, @mentions notify nobody, a pipe cannot break out of a table cell, and
// the length is bounded.
func MarkdownText(s string) string {
	s = redact.Prompt(strings.Join(strings.Fields(s), " "))
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, "-->", "--&gt;")
	s = mentionRE.ReplaceAllString(s, "@\u200b$1")
	s = strings.ReplaceAll(s, "|", `\|`)
	if len(s) > maxMarkdownText {
		cut := maxMarkdownText
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + " ... (truncated)"
	}
	return s
}

// FindingMessage is a finding's message made safe for Markdown. A credential
// finding's message gets the stronger mask first: the message may quote the secret.
func FindingMessage(f model.Finding) string {
	msg := f.Message
	if f.IsSecret() {
		msg = redact.Secrets(msg)
	}
	return MarkdownText(msg)
}

// markdownCode prepares a short untrusted value (a rule id) for a code span: a
// backtick in it would close the span.
func markdownCode(s string) string {
	return MarkdownText(strings.ReplaceAll(s, "`", "'"))
}

// --- GitHub Actions annotations ---

// WriteGitHubAnnotations emits GitHub Actions workflow commands so findings show
// up as inline annotations on the PR diff (no API calls required).
func WriteGitHubAnnotations(w io.Writer, s model.Scan) error {
	for _, f := range s.Findings {
		level := "warning"
		if f.Severity.Rank() >= model.SeverityHigh.Rank() {
			level = "error"
		}
		_, err := fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			level, ghProp(f.Location.File), f.Location.Region.StartLine,
			ghProp(f.RuleID), ghData(f.Message))
		if err != nil {
			return err
		}
	}
	return nil
}

func ghData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

func ghProp(s string) string {
	s = ghData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	return strings.ReplaceAll(s, ",", "%2C")
}
