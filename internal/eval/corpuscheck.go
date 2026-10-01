package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// The corpus makes claims about external tools — "gosec reports G201 on this file" —
// and nothing checked them. Three of the SQL cases claimed G201 while gosec 2.27
// actually emits G701, and that survived four merged changes because verdict mode
// only passes the rule id through as prompt text: a wrong id still produces a
// plausible prompt and a plausible score. It surfaced only when the scanner-based
// fix check started reporting "unknown" for a third of runs.
//
// This mode closes that class: run each case's tool on each case's fixture and
// compare what it emits against what the case claims. Two further claims get checked
// while the tool is running:
//
//   - the declared `tool` must be the one we would actually run for that file type,
//     since the scanner is chosen by extension — a case claiming `trivy` on a .go
//     file would silently be validated with gosec;
//   - an FP case must be something a scanner genuinely flags. An "fp" fixture nothing
//     reports is not a false positive, it is a hypothetical, and it measures nothing
//     when the pipeline never sees it.
//
// It cannot live in LoadCorpus: that runs on every invocation including the hermetic
// `--mode context` used in CI, where no scanners are installed. So it is its own
// mode, and it degrades to SKIPPED rather than failing when a tool is absent.

// expectedTool is the scanner scanSource would actually invoke for a fixture, keyed
// by extension. Keep this in step with scanSource.
func expectedTool(fixture string) string {
	switch strings.ToLower(filepath.Ext(fixture)) {
	case ".go":
		return "gosec"
	case ".py":
		return "bandit"
	default:
		return ""
	}
}

// CorpusIssue is one problem found, or one case that could not be checked.
type CorpusIssue struct {
	CaseID      string   `json:"caseId"`
	Fixture     string   `json:"fixture"`
	Label       Label    `json:"label"`
	ClaimedTool string   `json:"claimedTool"`
	ClaimedRule string   `json:"claimedRule"`
	Emitted     []string `json:"emitted,omitempty"`
	Problem     string   `json:"problem"`
	// Skipped marks "we could not check this" — a missing toolchain is our gap, not
	// a corpus defect, and must not fail the check.
	Skipped bool `json:"skipped,omitempty"`
}

// CorpusCheckReport is the result of validating the corpus against the real tools.
type CorpusCheckReport struct {
	Cases    int           `json:"cases"`
	Checked  int           `json:"checked"`
	OK       int           `json:"ok"`
	Mismatch int           `json:"mismatch"`
	Skipped  int           `json:"skipped"`
	Issues   []CorpusIssue `json:"issues,omitempty"`
}

// Sound reports whether every checkable case's claims held.
func (r CorpusCheckReport) Sound() bool { return r.Mismatch == 0 }

// ValidateCorpusAgainstTools runs each case's scanner on its fixture and compares
// the emitted rule ids against what the case claims. progress may be nil.
func ValidateCorpusAgainstTools(c Corpus, progress func(id string, done, total int)) CorpusCheckReport {
	rep := CorpusCheckReport{Cases: len(c.Cases)}

	cases := c.SortedCases()
	for i, cs := range cases {
		if progress != nil {
			progress(cs.ID, i+1, len(cases))
		}
		issue := CorpusIssue{
			CaseID: cs.ID, Fixture: cs.Fixture, Label: cs.Label,
			ClaimedTool: cs.Finding.Tool, ClaimedRule: cs.Finding.RuleID,
		}

		want := expectedTool(cs.Fixture)
		if want == "" {
			issue.Skipped = true
			issue.Problem = fmt.Sprintf("no scanner wired for %q — this case's claims cannot be checked", filepath.Ext(cs.Fixture))
			rep.Skipped++
			rep.Issues = append(rep.Issues, issue)
			continue
		}
		// A declared tool we would never run makes every other claim untestable, and
		// silently validates against the wrong scanner. That is a corpus defect, not
		// a skip.
		if !strings.EqualFold(cs.Finding.Tool, want) {
			issue.Problem = fmt.Sprintf("declares tool %q but %s is what runs for this file type", cs.Finding.Tool, want)
			rep.Mismatch++
			rep.Checked++
			rep.Issues = append(rep.Issues, issue)
			continue
		}

		body, err := cs.fixtureBody(c.Root)
		if err != nil {
			issue.Skipped = true
			issue.Problem = fmt.Sprintf("cannot read fixture: %v", err)
			rep.Skipped++
			rep.Issues = append(rep.Issues, issue)
			continue
		}

		out := scanSource(cs, []byte(body))
		if !out.trusted {
			// The tool's silence proves nothing here — the same rule the fix check
			// follows. Say WHICH kind of silence: "not installed" is an environment
			// gap, "ran but could not analyze" is a fixture that needs looking at.
			issue.Skipped = true
			if out.absent {
				issue.Problem = fmt.Sprintf("%s is not installed", want)
			} else {
				issue.Problem = fmt.Sprintf("%s ran but could not analyze the fixture", want)
			}
			rep.Skipped++
			rep.Issues = append(rep.Issues, issue)
			continue
		}

		rep.Checked++
		for rule := range out.rules {
			issue.Emitted = append(issue.Emitted, rule)
		}
		sort.Strings(issue.Emitted)

		switch {
		case out.rules[strings.ToUpper(cs.Finding.RuleID)]:
			// The rule fired. Its line, message and severity are declared by the
			// corpus too, and all three go straight into the triage prompt — a case
			// that names the right rule but the wrong line measures a prompt no real
			// scan would produce. Checking only tool/ruleId left these drifting: one
			// case pointed at the Sprintf when gosec reports the Query sink a line
			// later, and an fp case claimed HIGH severity where bandit says LOW and
			// "seems safe", which made the fp half look scarier than it is.
			if problems := fieldMismatches(cs, out.hits[strings.ToUpper(cs.Finding.RuleID)]); len(problems) > 0 {
				issue.Problem = strings.Join(problems, "; ")
				rep.Mismatch++
				rep.Issues = append(rep.Issues, issue)
				continue
			}
			rep.OK++
		case len(out.rules) == 0:
			// Nothing fired at all, so the case describes a finding this tool does not
			// produce. That is fatal to either label: a tp the scanner never reports
			// never reaches triage, and an fp the scanner never reports is not a false
			// positive, it is a hypothetical.
			issue.Problem = fmt.Sprintf("%s reports NOTHING on this fixture — the case describes a finding the tool does not produce", want)
			rep.Mismatch++
			rep.Issues = append(rep.Issues, issue)
		default:
			issue.Problem = fmt.Sprintf("claims %s but %s emits %s",
				cs.Finding.RuleID, want, strings.Join(issue.Emitted, ", "))
			rep.Mismatch++
			rep.Issues = append(rep.Issues, issue)
		}
	}
	return rep
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// fieldMismatches compares the corpus's declared finding metadata against what the
// scanner actually reported. A zero line means we could not read the tool's, which
// is our gap and not a claim to contradict.
func fieldMismatches(cs Case, hit ruleHit) []string {
	var problems []string
	if hit.line > 0 && cs.Finding.Line != hit.line {
		problems = append(problems, fmt.Sprintf("declares line %d but %s reports line %d",
			cs.Finding.Line, cs.Finding.Tool, hit.line))
	}
	if hit.severity != "" && !strings.EqualFold(cs.Finding.Severity, hit.severity) {
		problems = append(problems, fmt.Sprintf("declares severity %q but %s reports %q",
			cs.Finding.Severity, cs.Finding.Tool, hit.severity))
	}
	if hit.message != "" && strings.TrimSpace(cs.Finding.Message) != strings.TrimSpace(hit.message) {
		problems = append(problems, fmt.Sprintf("declares message %q but %s reports %q",
			cs.Finding.Message, cs.Finding.Tool, hit.message))
	}
	return problems
}

// Write renders the corpus check for a terminal.
func (r CorpusCheckReport) Write(w io.Writer) {
	fmt.Fprintf(w, "Corpus claims vs the real tools\n\n")
	fmt.Fprintf(w, "  cases:      %d\n", r.Cases)
	fmt.Fprintf(w, "  checked:    %d  (%d claims held, %d MISMATCHED)\n", r.Checked, r.OK, r.Mismatch)
	fmt.Fprintf(w, "  skipped:    %d  (tool absent or fixture unanalyzable — not corpus defects)\n", r.Skipped)

	var bad, skipped []CorpusIssue
	for _, i := range r.Issues {
		if i.Skipped {
			skipped = append(skipped, i)
		} else {
			bad = append(bad, i)
		}
	}
	if len(bad) > 0 {
		fmt.Fprintf(w, "\n  MISMATCHES — the corpus says something the tool contradicts:\n")
		for _, i := range bad {
			fmt.Fprintf(w, "    %-30s %s\n", i.CaseID, i.Problem)
			// Only suggest a rule id when the declared one is the thing that is
			// wrong. When the rule fired and a field drifted, the problem line
			// already names the fix, and "set ruleId" would send the reader after
			// a value that is already correct.
			if len(i.Emitted) > 0 && !contains(i.Emitted, i.ClaimedRule) {
				fmt.Fprintf(w, "    %-30s   (fix: set ruleId to one of %s)\n", "", strings.Join(i.Emitted, ", "))
			}
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "\n  not checked:\n")
		for _, i := range skipped {
			fmt.Fprintf(w, "    %-30s %s\n", i.CaseID, i.Problem)
		}
	}
	if r.Sound() && r.Checked > 0 {
		fmt.Fprintf(w, "\n  every checkable claim held.\n")
	}
	fmt.Fprintf(w, "\n  Why this mode exists: three cases claimed gosec G201 while gosec emits G701,\n")
	fmt.Fprintf(w, "  and it survived four merged changes because verdict mode only passes the rule\n")
	fmt.Fprintf(w, "  id through as prompt text — a wrong id still yields a plausible score.\n")
}

// WriteJSON persists the check.
func (r CorpusCheckReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
