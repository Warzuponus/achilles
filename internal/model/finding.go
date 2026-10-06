// Package model defines Achilles's normalized data model. Findings are
// deliberately SARIF-shaped so we can import and export SARIF without loss.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// Severity is the normalized severity of a finding, prior to LLM triage.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// Rank returns a sortable weight (higher = more severe). Used for reporting
// order and for the --fail-on gate.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Region is a source span (1-indexed, matching SARIF).
type Region struct {
	StartLine int `json:"startLine"`
	StartCol  int `json:"startColumn,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	EndCol    int `json:"endColumn,omitempty"`
}

// Location points at a source span within a file.
type Location struct {
	File   string `json:"file"`
	Region Region `json:"region"`
}

// Finding is one normalized result from one tool. Triage fields (Verdict,
// Explanation, SuggestedFix) are added by later phases and are absent in
// Phase 0.
type Finding struct {
	ID          string          `json:"id"`
	Tool        string          `json:"tool"`
	RuleID      string          `json:"ruleId"`
	CWE         []string        `json:"cwe,omitempty"`
	Message     string          `json:"message"`
	Location    Location        `json:"location"`
	CodeContext string          `json:"codeContext,omitempty"`
	Severity    Severity        `json:"severity"`
	Fingerprint string          `json:"fingerprint"`
	Raw         json.RawMessage `json:"-"`

	// Shadow marks a finding produced by a generated rule still inside its
	// shadow window (§9.4 rule flywheel): it is reported for observation but
	// does NOT affect the --fail-on gate, issue filing, or a written baseline.
	Shadow bool `json:"shadow,omitempty"`

	// Correlated lists the "tool:ruleId" of other findings that describe the
	// same defect at the same location and CWE (see internal/correlate). It is
	// descriptive only: correlated findings keep their own ID, fingerprint,
	// severity, and gating behaviour. It is NOT part of ID or Fingerprint.
	Correlated []string `json:"correlated,omitempty"`

	// Populated by the triage layer (Phase 2); nil before triage.
	Verdict     *Verdict     `json:"verdict,omitempty"`
	Provenance  *Provenance  `json:"provenance,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"` // Phase 2.1; nil unless remediated

	// Deep is set when --deep-verify let the model read the repository to settle this
	// finding; nil otherwise.
	Deep *DeepVerification `json:"deep,omitempty"`
}

// Scan is the result of running one or more tools against a target.
type Scan struct {
	Target   string    `json:"target"`
	Tools    []string  `json:"tools"`
	Findings []Finding `json:"findings"`
	// Dismissed holds findings the AI review confidently ruled out (see
	// Verdict.Dismissed). They are not in Findings, so they do not gate, file
	// issues, or inflate counts, but reports list them so the call can be audited.
	Dismissed []Finding `json:"dismissed,omitempty"`
	// FailedTools are tools that could not run or whose output could not be
	// normalized. A scan with failures is incomplete, so "no findings" must never
	// be presented as a clean result.
	FailedTools []string `json:"failedTools,omitempty"`
	// Triage summarizes how much of the scan the AI review actually covered; nil
	// when no triage was requested.
	Triage *TriageStats `json:"triage,omitempty"`
}

// TriageStats is the coverage of the AI review over a scan. A report that shows
// verdicts must also show how many findings never got one.
type TriageStats struct {
	Model     string `json:"model,omitempty"`
	Total     int    `json:"total"`     // findings considered
	Triaged   int    `json:"triaged"`   // findings that ended with a verdict
	Failed    int    `json:"failed"`    // triage was attempted and errored
	Withheld  int    `json:"withheld"`  // not sent to the model on purpose (credential findings)
	Skipped   int    `json:"skipped"`   // not attempted (timeout, budget, aborted)
	Dismissed int    `json:"dismissed"` // moved to Scan.Dismissed
}

// Dismissed reports whether this finding's verdict rules it out.
func (f Finding) Dismissed() bool {
	// A credential finding is never dismissed: the model was never shown it, and a
	// leaked secret is not something a verdict can make safe.
	return f.Verdict != nil && !f.IsSecret() && f.Verdict.Dismissed()
}

// PartitionDismissed moves every dismissed finding out of Findings into Dismissed and
// returns how many moved. Order is preserved on both sides.
func (s *Scan) PartitionDismissed() int {
	kept := s.Findings[:0:0]
	n := 0
	for _, f := range s.Findings {
		if f.Dismissed() {
			s.Dismissed = append(s.Dismissed, f)
			n++
			continue
		}
		kept = append(kept, f)
	}
	s.Findings = kept
	return n
}

// CountsBySeverity tallies findings per severity for summary reporting.
func (s Scan) CountsBySeverity() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range s.Findings {
		out[f.Severity]++
	}
	return out
}

// ComputeID derives a stable identity for a finding from its precise location.
// Two runs over the same unchanged code produce the same ID.
func ComputeID(tool, ruleID string, loc Location) string {
	key := strings.Join([]string{
		tool, ruleID, loc.File,
		strconv.Itoa(loc.Region.StartLine),
		strconv.Itoa(loc.Region.StartCol),
	}, "|")
	return shortHash(key)
}

// ComputeFingerprint derives a location-drift-resistant fingerprint. It prefers
// a hash of the matched code snippet (so the finding survives reformatting and
// line shifts); it falls back to file+rule when no snippet is available.
func ComputeFingerprint(tool, ruleID, file, snippet string) string {
	basis := snippet
	if strings.TrimSpace(basis) == "" {
		basis = file
	}
	return shortHash(strings.Join([]string{tool, ruleID, normalizeWS(basis)}, "|"))
}

func normalizeWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// IsSecret reports whether this finding is about a credential or key. Such a
// finding's matched text IS the secret, so its code and message must never be
// copied into an LLM prompt, a shared report, or an issue. The test is
// deliberately broad: wrongly withholding a snippet costs a little context,
// wrongly including one leaks a credential.
func (f Finding) IsSecret() bool {
	switch strings.ToLower(f.Tool) {
	case "gitleaks", "trufflehog", "detect-secrets":
		return true
	}
	rule := strings.ToLower(f.RuleID)
	for _, w := range []string{"secret", "password", "passwd", "credential", "api-key", "apikey", "api_key",
		"private-key", "private_key", "access-key", "access_key", "hardcoded-key", "hardcoded_key"} {
		if strings.Contains(rule, w) {
			return true
		}
	}
	for _, c := range f.CWE {
		switch strings.ToUpper(strings.TrimSpace(c)) {
		case "CWE-798", "CWE-259", "CWE-321":
			return true
		}
	}
	return false
}
