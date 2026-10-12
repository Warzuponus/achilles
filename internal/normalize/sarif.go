// Package normalize converts a tool's native output into Achilles's Finding
// model. SARIF is the common path: any tool that emits SARIF 2.1.0 flows
// through FromSARIF with no tool-specific code.
package normalize

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
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
			res.RuleID = ruleIDFor(res, run.Tool.Driver.Rules)
			loc := firstLocation(res.Locations, run.OriginalURIBaseIDs)
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
				CWE:         cweFor(res, rules[res.RuleID]),
				Category:    categoryFor(tool, res, rules[res.RuleID]),
			}
			f.Severity = severityFor(res, rules[res.RuleID], f.IsSecret())
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

// ruleIDFor returns the id of the rule a result is about. Most tools set ruleId;
// the specification also allows naming the rule only by its index in the driver's
// rule list, or through a rule reference. Such a result used to get an empty rule
// id, and with it no severity from the rule, no CWE and no category.
func ruleIDFor(res model.SarifResult, rules []model.SarifRule) string {
	if res.RuleID != "" {
		return res.RuleID
	}
	if res.Rule != nil && res.Rule.ID != "" {
		return res.Rule.ID
	}
	index := res.RuleIndex
	if index == nil && res.Rule != nil {
		index = res.Rule.Index
	}
	if index != nil && *index >= 0 && *index < len(rules) {
		return rules[*index].ID
	}
	return ""
}

// artifactPath turns a SARIF artifact location into a file path.
//
// The uri field is a URI reference, not a path: it may be percent-encoded
// ("src/my%20file.py"), an absolute file URI ("file:///repo/src/a.py"), and
// relative to a named base that is itself relative ("SRC" -> "src/", relative to
// "ROOT"). Taken literally, such a value names a file that does not exist: the
// code around the finding cannot be read, diff and baseline matching miss it,
// and a fix cannot be applied.
//
// A base whose own URI is absolute is deliberately NOT applied: scanners point it
// at wherever the tree was mounted for them (file:///mnt/src/), and the path
// relative to that is the path relative to the scanned tree, which is what the
// rest of Achilles works with.
func artifactPath(a model.SarifArtifactLocation, bases map[string]model.SarifArtifactLocation) string {
	p := decodeURIPath(a.URI)
	if p == "" || path.IsAbs(p) || isWindowsAbs(p) {
		return p
	}
	seen := map[string]bool{}
	for id := a.URIBaseID; id != "" && !seen[id]; {
		seen[id] = true
		base, ok := bases[id]
		if !ok {
			break
		}
		b := decodeURIPath(base.URI)
		if b == "" || path.IsAbs(b) || isWindowsAbs(b) || strings.Contains(base.URI, "://") {
			break // an absolute base: the mount point, not part of the path
		}
		p = path.Join(b, p)
		id = base.URIBaseID
	}
	return p
}

// decodeURIPath returns the path a URI reference names: the scheme and host of a
// file: URI removed, percent-escapes decoded. Anything it cannot parse is
// returned unchanged rather than guessed at.
func decodeURIPath(uri string) string {
	if strings.HasPrefix(strings.ToLower(uri), "file:") {
		if u, err := url.Parse(uri); err == nil && u.Path != "" {
			p := u.Path
			// file:///C:/repo/a.go parses to "/C:/repo/a.go".
			if len(p) >= 3 && p[0] == '/' && isWindowsAbs(p[1:]) {
				p = p[1:]
			}
			return p
		}
		return uri
	}
	if strings.Contains(uri, "%") {
		if p, err := url.PathUnescape(uri); err == nil {
			return p
		}
	}
	return uri
}

func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\') &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

func firstLocation(locs []model.SarifLocation, bases map[string]model.SarifArtifactLocation) model.Location {
	if len(locs) == 0 {
		return model.Location{}
	}
	p := locs[0].PhysicalLocation
	return model.Location{
		File: artifactPath(p.ArtifactLocation, bases),
		Region: model.Region{
			StartLine: p.Region.StartLine,
			StartCol:  p.Region.StartColumn,
			EndLine:   p.Region.EndLine,
			EndCol:    p.Region.EndColumn,
		},
	}
}

// severityFor derives our normalized severity from the two things a SARIF result
// can say about it, and takes the MORE severe of the two:
//
//   - the level (error/warning/note/none), on the result or inherited from the
//     rule's defaultConfiguration (this is how Opengrep encodes severity). SARIF
//     has only three real levels, so on its own it can never say "critical";
//   - the security-severity score (CVSS-style, 0..10) on the result or the rule,
//     which is how Trivy, osv-scanner and others carry critical vs. high.
//
// Taking the maximum means a score can raise a finding (an "error" with a 9.8
// becomes critical) but never quietly lower what the tool's own level said.
//
// A result with neither gets the SARIF default level, "warning" (§3.27.10), unless
// it is a credential finding: a secret scanner that states no severity (Gitleaks)
// is reporting a leaked credential, and that must be able to fail a gate.
func severityFor(res model.SarifResult, rule model.SarifRule, secret bool) model.Severity {
	sev := levelSeverity(res, rule)
	if s := scoreSeverity(res, rule); s.Rank() > sev.Rank() {
		sev = s
	}
	if sev != model.SeverityUnknown {
		return sev
	}
	if secret {
		return model.SeverityHigh
	}
	return model.SeverityMedium
}

func levelSeverity(res model.SarifResult, rule model.SarifRule) model.Severity {
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
	// No level: infer from the rule's tags if it carries a severity-ish one.
	for _, t := range rule.Properties.Tags {
		switch strings.ToLower(t) {
		case "critical":
			return model.SeverityCritical
		case "error", "high":
			return model.SeverityHigh
		case "warning", "medium":
			return model.SeverityMedium
		case "note", "low", "info":
			return model.SeverityLow
		}
	}
	return model.SeverityUnknown
}

// scoreSeverity reads a security-severity from the result's own properties (more
// specific) or else the rule's.
func scoreSeverity(res model.SarifResult, rule model.SarifRule) model.Severity {
	if raw, ok := res.Properties["security-severity"]; ok {
		var s model.SarifScore
		switch v := raw.(type) {
		case string:
			s = model.SarifScore(v)
		case float64:
			s = model.SarifScore(strconv.FormatFloat(v, 'f', -1, 64))
		}
		if score, ok := s.Value(); ok {
			return model.SeverityFromScore(score)
		}
	}
	if score, ok := rule.Properties.SecuritySeverity.Value(); ok {
		return model.SeverityFromScore(score)
	}
	return model.SeverityUnknown
}

// categoryFor reads the scanner's own statement of what kind of finding this is.
//
// Trivy is the case that needs it: one tool, three kinds of result, and rule ids
// such as "github-pat" or "slack-web-hook" that no keyword list reliably marks as
// credentials. Trivy tags every rule with its class ("secret", "vulnerability",
// "misconfiguration") and labels a secret result in its message. Missing this
// sends the line holding the credential to the model and lets a verdict dismiss it.
func categoryFor(tool string, res model.SarifResult, rule model.SarifRule) string {
	tags := append([]string(nil), rule.Properties.Tags...)
	if raw, ok := res.Properties["tags"].([]any); ok {
		for _, t := range raw {
			if s, ok := t.(string); ok {
				tags = append(tags, s)
			}
		}
	}
	trivy := strings.EqualFold(tool, "trivy")
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "secret", "secrets":
			return model.CategorySecret
		case "vulnerability":
			// Only Trivy's use of the word is known to mean "vulnerable package";
			// another tool may tag a code finding this way.
			if trivy {
				return model.CategoryDependency
			}
		}
	}
	if trivy && (strings.HasPrefix(res.Message.Text, "Secret ") || strings.Contains(res.Message.Text, "\nSecret ")) {
		return model.CategorySecret
	}
	return ""
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
	// Any fingerprint the tool provided is better than recomputing. Keys are taken
	// in sorted order: a tool that emits two fingerprints must yield the same one
	// on every run, or baselines, issue de-duplication and feedback all break at
	// random (Go randomizes map iteration).
	keys := make([]string, 0, len(res.Fingerprints))
	for k := range res.Fingerprints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := res.Fingerprints[k]; v != "" {
			return v
		}
	}
	return model.ComputeFingerprint(tool, res.RuleID, file, snippet)
}
