package report

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// This file holds what makes the SARIF report useful to the systems that read it,
// beyond a list of results: a rule table with severities, fingerprints a consumer
// can track a finding by, whether a finding is new, and the verified fix.

// securitySeverity is the score GitHub code scanning reads (as
// properties."security-severity" on the rule) to file an alert under critical,
// high, medium or low. Without it every alert lands by SARIF level alone, where
// "error" is the top and critical does not exist. The value is the middle of the
// band our severity maps to; it is a bucket, not a measured CVSS score.
func securitySeverity(s model.Severity) model.SarifScore {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "2.0"
	}
	return ""
}

// sarifRules builds the driver's rule table from the findings: one entry per rule
// id, carrying the highest severity any of its findings has, and its CWEs as tags
// in the form code scanning recognizes. It returns the table and each rule's index.
func sarifRules(findings ...[]model.Finding) ([]model.SarifRule, map[string]int) {
	type agg struct {
		sev  model.Severity
		cwes map[string]bool
		tool string
	}
	byID := map[string]*agg{}
	var ids []string
	for _, group := range findings {
		for _, f := range group {
			a := byID[f.RuleID]
			if a == nil {
				a = &agg{sev: f.Severity, cwes: map[string]bool{}, tool: f.Tool}
				byID[f.RuleID] = a
				ids = append(ids, f.RuleID)
			}
			if f.Severity.Rank() > a.sev.Rank() {
				a.sev = f.Severity
			}
			for _, c := range f.CWE {
				if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
					a.cwes[c] = true
				}
			}
		}
	}
	sort.Strings(ids)

	rules := make([]model.SarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		a := byID[id]
		tags := []string{"security"}
		cwes := make([]string, 0, len(a.cwes))
		for c := range a.cwes {
			cwes = append(cwes, c)
		}
		sort.Strings(cwes)
		for _, c := range cwes {
			tags = append(tags, "external/cwe/"+c)
		}
		rules = append(rules, model.SarifRule{
			ID:                   id,
			Name:                 id,
			ShortDescription:     &model.SarifMessage{Text: id + " (reported by " + a.tool + ")"},
			DefaultConfiguration: model.SarifRuleConfig{Level: sarifLevel(a.sev)},
			Properties:           model.SarifRuleProps{Tags: tags, SecuritySeverity: securitySeverity(a.sev)},
		})
		index[id] = i
	}
	return rules, index
}

// lineHashes assigns each finding the value for partialFingerprints.
// primaryLocationLineHash, the fingerprint code scanning uses to recognize the same
// alert across commits. Achilles' own fingerprint already ignores line numbers; the
// suffix numbers repeats of one fingerprint within a file, as the convention is.
func lineHashes(findings []model.Finding) []string {
	seen := map[string]int{}
	out := make([]string, len(findings))
	for i, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		k := f.Location.File + "\x00" + f.Fingerprint
		seen[k]++
		out[i] = f.Fingerprint + ":" + strconv.Itoa(seen[k])
	}
	return out
}

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@`)

// sarifFix turns a verified patch into a SARIF fix: for each hunk, the lines it
// replaces and the text that replaces them. It returns nil when there is no
// verified patch or the diff cannot be read as plain hunks against one file. Only a
// patch that passed re-scan verification is offered: a consumer may apply a SARIF
// fix with one click.
func sarifFix(f model.Finding) []model.SarifFix {
	r := f.Remediation
	if r == nil || r.Verification == nil || r.Verification.Status != model.FixVerified || f.IsSecret() {
		return nil
	}
	var reps []model.SarifReplacement
	var (
		inHunk   bool
		oldStart int
		oldLines int
		newText  []string
	)
	flush := func() {
		if !inHunk {
			return
		}
		rep := model.SarifReplacement{InsertedContent: &model.SarifArtifactContent{Text: strings.Join(newText, "\n")}}
		if oldLines > 0 {
			// A region given by lines alone runs to the end of its last line, not
			// past the line break, so the inserted text carries no final newline.
			rep.DeletedRegion = model.SarifRegion{StartLine: oldStart, EndLine: oldStart + oldLines - 1}
		} else {
			// A pure insertion: an empty region at the start of the following line.
			rep.DeletedRegion = model.SarifRegion{StartLine: oldStart + 1, StartColumn: 1, EndColumn: 1}
			rep.InsertedContent.Text += "\n"
		}
		reps = append(reps, rep)
		inHunk, oldLines, newText = false, 0, nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(r.Diff, "\r\n", "\n"), "\n") {
		if m := hunkHeader.FindStringSubmatch(line); m != nil {
			flush()
			inHunk = true
			oldStart, _ = strconv.Atoi(m[1])
			continue
		}
		if !inHunk || line == "" {
			continue
		}
		switch line[0] {
		case ' ':
			oldLines++
			newText = append(newText, line[1:])
		case '-':
			oldLines++
		case '+':
			newText = append(newText, line[1:])
		case '\\': // "\ No newline at end of file"
		default:
			flush()
		}
	}
	flush()
	if len(reps) == 0 {
		return nil
	}
	desc := strings.TrimSpace(r.Summary)
	if desc == "" {
		desc = "Fix suggested by Achilles"
	}
	desc += " (verified: after this change the scanner no longer reports the finding, and reports nothing new)"
	return []model.SarifFix{{
		Description: model.SarifMessage{Text: MarkdownText(desc)},
		ArtifactChanges: []model.SarifArtifactChange{{
			ArtifactLocation: model.SarifArtifactLocation{URI: f.Location.File},
			Replacements:     reps,
		}},
	}}
}
