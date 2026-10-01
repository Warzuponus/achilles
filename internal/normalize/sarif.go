// Package normalize converts a tool's native output into Achilles's Finding
// model. SARIF is the common path: any tool that emits SARIF 2.1.0 flows
// through FromSARIF with no tool-specific code.
package normalize

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

var (
	cweRE = regexp.MustCompile(`CWE-\d+`)
	// A taxonomy relationship's target.id is a bare CWE number; require it to be
	// numeric so a non-CWE taxonomy id can't be relabelled as one.
	cweNumRE = regexp.MustCompile(`^\d+$`)
)

// FromSARIF parses a SARIF 2.1.0 document and returns normalized findings.
// The tool name is taken from the SARIF driver when present, else from the
// provided fallback.
func FromSARIF(fallbackTool string, data []byte) ([]model.Finding, error) {
	var log model.SarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	var findings []model.Finding
	for _, run := range log.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = fallbackTool
		}
		rules := indexRules(run.Tool.Driver.Rules)

		for _, res := range run.Results {
			loc := firstLocation(res.Locations)
			snippet := ""
			if len(res.Locations) > 0 {
				snippet = res.Locations[0].PhysicalLocation.Region.Snippet.Text
			}

			f := model.Finding{
				Tool:        tool,
				RuleID:      res.RuleID,
				Message:     strings.TrimSpace(res.Message.Text),
				Location:    loc,
				CodeContext: snippet,
				Severity:    severityFor(res, rules[res.RuleID]),
				CWE:         cweFor(res, rules[res.RuleID]),
			}
			f.ID = model.ComputeID(tool, res.RuleID, loc)
			f.Fingerprint = fingerprintFor(res, tool, loc.File, snippet)
			if raw, err := json.Marshal(res); err == nil {
				f.Raw = raw
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func indexRules(rules []model.SarifRule) map[string]model.SarifRule {
	out := make(map[string]model.SarifRule, len(rules))
	for _, r := range rules {
		out[r.ID] = r
	}
	return out
}

func firstLocation(locs []model.SarifLocation) model.Location {
	if len(locs) == 0 {
		return model.Location{}
	}
	p := locs[0].PhysicalLocation
	return model.Location{
		File: p.ArtifactLocation.URI,
		Region: model.Region{
			StartLine: p.Region.StartLine,
			StartCol:  p.Region.StartColumn,
			EndLine:   p.Region.EndLine,
			EndCol:    p.Region.EndColumn,
		},
	}
}

// severityFor maps SARIF level to our normalized severity. SARIF levels are
// error/warning/note/none. A result with no explicit level inherits the rule's
// defaultConfiguration.level (this is how Opengrep encodes severity).
func severityFor(res model.SarifResult, rule model.SarifRule) model.Severity {
	level := res.Level
	if level == "" {
		level = rule.DefaultConfiguration.Level
	}
	switch strings.ToLower(level) {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "note":
		return model.SeverityLow
	case "none":
		return model.SeverityInfo
	}
	// Last resort: infer from the rule's tags if it carries a severity-ish one.
	for _, t := range rule.Properties.Tags {
		switch strings.ToLower(t) {
		case "error", "high", "critical":
			return model.SeverityHigh
		case "warning", "medium":
			return model.SeverityMedium
		case "note", "low", "info":
			return model.SeverityLow
		}
	}
	return model.SeverityUnknown
}

// cweFor collects CWE identifiers from the result and its rule metadata. Tools
// publish CWEs two different ways and we read both:
//
//   - inline as "CWE-89" in a tag or the message text (Opengrep, Trivy, Bandit);
//   - as a SARIF taxonomy relationship, where target.toolComponent.name is "CWE"
//     and target.id is the BARE number ("89") — this is what gosec emits, and
//     reading only the inline form silently dropped the CWE from every gosec
//     finding.
func cweFor(res model.SarifResult, rule model.SarifRule) []string {
	seen := map[string]bool{}
	var out []string
	addID := func(id string) {
		id = "CWE-" + strings.TrimPrefix(strings.TrimSpace(id), "CWE-")
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add := func(s string) {
		for _, m := range cweRE.FindAllString(s, -1) {
			addID(m)
		}
	}
	for _, t := range rule.Properties.Tags {
		add(t)
	}
	add(res.Message.Text)
	for _, rel := range rule.Relationships {
		if !strings.EqualFold(rel.Target.ToolComponent.Name, "CWE") {
			continue
		}
		if id := strings.TrimSpace(rel.Target.ID); cweNumRE.MatchString(id) {
			addID(id)
		}
	}
	return out
}

// fingerprintFor prefers the tool's own fingerprint (Semgrep/Opengrep emit
// matchBasedId), then any partial fingerprint, else a snippet-based fallback.
func fingerprintFor(res model.SarifResult, tool, file, snippet string) string {
	for _, k := range []string{"matchBasedId/v1", "primaryLocationLineHash"} {
		if v := res.Fingerprints[k]; v != "" {
			return v
		}
		if v := res.PartialFingerprints[k]; v != "" {
			return v
		}
	}
	// Any fingerprint the tool provided is better than recomputing.
	for _, v := range res.Fingerprints {
		if v != "" {
			return v
		}
	}
	return model.ComputeFingerprint(tool, res.RuleID, file, snippet)
}
