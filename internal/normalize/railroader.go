package normalize

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// railroaderReport is the subset of Railroader/Brakeman `-f json` we consume.
type railroaderReport struct {
	Warnings []railroaderWarning `json:"warnings"`
}

type railroaderWarning struct {
	WarningType string `json:"warning_type"`
	CheckName   string `json:"check_name"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"` // may be null in JSON → 0
	Code        string `json:"code"`
	Confidence  string `json:"confidence"` // High | Medium | Weak
	CWEID       []int  `json:"cwe_id"`     // present in newer versions; optional
}

// FromRailroader normalizes Railroader/Brakeman `-f json` output. Railroader is
// the MIT-licensed Brakeman fork (commercial-safe); it shares Brakeman's JSON
// schema and has no SARIF formatter, so it flows through this per-tool JSON
// normalizer.
func FromRailroader(fallbackTool string, data []byte) ([]model.Finding, error) {
	var rep railroaderReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse railroader json: %w", err)
	}
	tool := fallbackTool
	if tool == "" {
		tool = "railroader"
	}

	findings := make([]model.Finding, 0, len(rep.Warnings))
	for _, w := range rep.Warnings {
		ruleID := w.CheckName
		if ruleID == "" {
			ruleID = w.WarningType
		}
		// Prefix the human warning type so the message always names the class
		// (e.g. "SQL Injection: ...") — the reader and downstream matching rely
		// on it, and Railroader's `message` alone is sometimes terse.
		msg := strings.TrimSpace(w.Message)
		if w.WarningType != "" {
			msg = strings.TrimSpace(w.WarningType + ": " + msg)
		}
		loc := model.Location{File: w.File, Region: model.Region{StartLine: w.Line}}

		var cwe []string
		for _, id := range w.CWEID {
			if id > 0 {
				cwe = append(cwe, "CWE-"+strconv.Itoa(id))
			}
		}

		f := model.Finding{
			Tool:        tool,
			RuleID:      ruleID,
			Message:     msg,
			Location:    loc,
			CodeContext: w.Code,
			Severity:    railroaderSeverity(w.Confidence),
			CWE:         cwe,
		}
		f.ID = model.ComputeID(tool, ruleID, loc)
		f.Fingerprint = model.ComputeFingerprint(tool, ruleID, w.File, w.Code)
		if raw, err := json.Marshal(w); err == nil {
			f.Raw = raw
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// railroaderSeverity maps Brakeman/Railroader confidence to our scale. Confidence
// isn't strictly severity, but it's the tool's own signal of how sure it is.
func railroaderSeverity(c string) model.Severity {
	switch strings.ToLower(c) {
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "weak", "low":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}
