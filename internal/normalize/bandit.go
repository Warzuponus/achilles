package normalize

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// banditReport is the subset of `bandit -f json` we consume.
type banditReport struct {
	Results []banditResult `json:"results"`
}

type banditResult struct {
	Filename      string `json:"filename"`
	LineNumber    int    `json:"line_number"`
	ColOffset     int    `json:"col_offset"`
	TestID        string `json:"test_id"`
	TestName      string `json:"test_name"`
	IssueText     string `json:"issue_text"`
	IssueSeverity string `json:"issue_severity"`
	Code          string `json:"code"`
	IssueCWE      *struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
}

// FromBandit normalizes `bandit -f json` output (Bandit is the Python SAST tool,
// Apache-2.0). Bandit has no clean SARIF formatter, so it flows through a
// per-tool JSON normalizer rather than a SARIF-converter wrapper.
func FromBandit(fallbackTool string, data []byte) ([]model.Finding, error) {
	var rep banditReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse bandit json: %w", err)
	}
	tool := fallbackTool
	if tool == "" {
		tool = "bandit"
	}

	findings := make([]model.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		loc := model.Location{
			File:   r.Filename,
			Region: model.Region{StartLine: r.LineNumber, StartCol: r.ColOffset},
		}
		var cwe []string
		if r.IssueCWE != nil && r.IssueCWE.ID > 0 {
			cwe = []string{"CWE-" + strconv.Itoa(r.IssueCWE.ID)}
		}
		f := model.Finding{
			Tool:        tool,
			RuleID:      r.TestID,
			Message:     strings.TrimSpace(r.IssueText),
			Location:    loc,
			CodeContext: r.Code,
			Severity:    banditSeverity(r.IssueSeverity),
			CWE:         cwe,
		}
		f.ID = model.ComputeID(tool, r.TestID, loc)
		// Fingerprint off the matched code (like SARIF's snippet path) so it
		// survives line drift; falls back to file when the code is absent.
		f.Fingerprint = model.ComputeFingerprint(tool, r.TestID, r.Filename, r.Code)
		if raw, err := json.Marshal(r); err == nil {
			f.Raw = raw
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// banditSeverity maps Bandit's issue_severity to our normalized scale (Bandit
// has no "critical").
func banditSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}
