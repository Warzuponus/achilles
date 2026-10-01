package normalize

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// shellcheckComment is one entry of ShellCheck's `-f json` output (a flat array).
type shellcheckComment struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"` // error | warning | info | style
	Code    int    `json:"code"`  // the numeric SC code, e.g. 2086
	Message string `json:"message"`
}

// FromShellCheck normalizes ShellCheck `-f json` output. ShellCheck is GPL-3.0,
// so it's invoked strictly as a separate-process container (never linked), and
// it has no SARIF formatter — hence this per-tool JSON normalizer.
func FromShellCheck(fallbackTool string, data []byte) ([]model.Finding, error) {
	var comments []shellcheckComment
	if err := json.Unmarshal(data, &comments); err != nil {
		return nil, fmt.Errorf("parse shellcheck json: %w", err)
	}
	tool := fallbackTool
	if tool == "" {
		tool = "shellcheck"
	}

	findings := make([]model.Finding, 0, len(comments))
	for _, c := range comments {
		ruleID := fmt.Sprintf("SC%d", c.Code)
		loc := model.Location{File: c.File, Region: model.Region{StartLine: c.Line, StartCol: c.Column}}
		f := model.Finding{
			Tool:     tool,
			RuleID:   ruleID,
			Message:  strings.TrimSpace(c.Message),
			Location: loc,
			Severity: shellcheckSeverity(c.Level),
		}
		f.ID = model.ComputeID(tool, ruleID, loc)
		// ShellCheck carries no source snippet, so anchor the fingerprint on the
		// precise location (keeps two same-rule findings in one file distinct).
		f.Fingerprint = model.ComputeFingerprint(tool, ruleID, c.File, fmt.Sprintf("L%dC%d", c.Line, c.Column))
		if raw, err := json.Marshal(c); err == nil {
			f.Raw = raw
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// shellcheckSeverity maps ShellCheck's level to our scale.
func shellcheckSeverity(level string) model.Severity {
	switch strings.ToLower(level) {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "info", "style":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}
