// Package model defines Achilles's normalized data model. Findings are
// deliberately SARIF-shaped so we can import and export SARIF without loss.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
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

// ParseSeverity reads a severity name as a user types it (--fail-on high). It
// reports false for anything that is not one of the five real severities, so a
// typo is an error at the flag instead of a threshold that silently means "any".
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if sev.Rank() == 0 {
		return "", false
	}
	return sev, true
}

// SeverityFromScore maps a CVSS-style 0..10 score onto a severity using the CVSS
// v3 qualitative bands, which are also what GitHub code scanning applies to a
// SARIF security-severity: 9.0+ critical, 7.0+ high, 4.0+ medium, above 0 low.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

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

// Finding is one normalized result from one tool. The triage fields (Verdict,
// Explanation, SuggestedFix) are filled in by the model review and are absent
// on a scanner-only run.
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

	// Category is what KIND of finding the scanner said this is, when it said so
	// (CategorySecret, CategoryDependency, or empty). A multi-purpose scanner such
	// as Trivy reports vulnerable packages, misconfigurations and leaked secrets
	// under one tool name with opaque rule ids, so the tool and rule alone cannot
	// tell them apart; its own classification can. IsSecret and
	// IsDependencyAdvisory consult it first.
	Category string `json:"category,omitempty"`

	// Commit is set on a finding made in the git history rather than in the files
	// as they are now (--secrets-history): the commit that added the reported line.
	// Location is then that commit's file and line, which may no longer exist.
	// CommitDate is when it was committed, as the scanner gave it.
	Commit     string `json:"commit,omitempty"`
	CommitDate string `json:"commitDate,omitempty"`

	// Shadow marks a finding produced by a generated rule still inside its
	// shadow window (§9.4 rule flywheel): it is reported for observation but
	// does NOT affect the --fail-on gate, issue filing, or a written baseline.
	Shadow bool `json:"shadow,omitempty"`

	// Correlated lists the "tool:ruleId" of other findings that describe the
	// same defect at the same location and CWE (see internal/correlate). It is
	// descriptive only: correlated findings keep their own ID, fingerprint,
	// severity, and gating behaviour. It is NOT part of ID or Fingerprint.
	Correlated []string `json:"correlated,omitempty"`

	// Suppression is set on a finding that a comment in the scanned code
	// (`achilles:ignore RULE -- reason`) suppressed. Such a finding is in
	// Scan.Suppressed, not Scan.Findings.
	Suppression *Suppression `json:"suppression,omitempty"`

	// Populated by the triage layer; nil before triage.
	Verdict     *Verdict     `json:"verdict,omitempty"`
	Provenance  *Provenance  `json:"provenance,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"` // nil unless remediated

	// Deep is set when --deep-verify let the model read the repository to settle this
	// finding; nil otherwise.
	Deep *DeepVerification `json:"deep,omitempty"`
}

// Suppression is a comment in the scanned code that says a finding is to be
// ignored, and why. It is the repository speaking about its own findings, so it is
// reported wherever findings are, never applied silently.
type Suppression struct {
	File   string `json:"file"`   // where the comment is
	Line   int    `json:"line"`   // its line
	Reason string `json:"reason"` // what it gives as the reason
	// New is true when the change under review (--diff) added or edited the line
	// the comment is on: the change is suppressing a finding in itself.
	New bool `json:"new,omitempty"`
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
	// Suppressed holds findings that a comment in the scanned code suppressed (see
	// Suppression). Like Dismissed they are not in Findings and do not gate or file
	// issues, and every report lists them with the reason given.
	Suppressed []Finding `json:"suppressed,omitempty"`
	// FailedTools are tools that could not run or whose output could not be
	// normalized. A scan with failures is incomplete, so "no findings" must never
	// be presented as a clean result.
	FailedTools []string `json:"failedTools,omitempty"`
	// RepoConfig names the scanner configuration files found in the scanned
	// repository that were in effect ("gitleaks: .gitleaks.toml"). Such a file can
	// remove findings before Achilles sees them, so reports say when one was used.
	RepoConfig []string `json:"repoConfig,omitempty"`
	// RepoConfigChanged is the subset of RepoConfig that the diff under review
	// (--diff) itself modifies.
	RepoConfigChanged []string `json:"repoConfigChanged,omitempty"`
	// BaselineApplied is true when the scan was compared with a baseline, so
	// Findings holds only what is new relative to it.
	BaselineApplied bool `json:"baselineApplied,omitempty"`
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
	// AutoResolved counts verdicts that came from analyst feedback on the rule
	// (--calibrate), not from a model reading the finding. They are included in
	// Triaged; reports name them so "a verdict" is never mistaken for "a review".
	AutoResolved int `json:"autoResolved,omitempty"`
	// Reused counts verdicts taken from the verdict cache: an earlier run reviewed
	// the same code with the same prompt and models. They are included in Triaged.
	Reused int `json:"reused,omitempty"`
	// Advisories counts dependency advisories (known CVEs in dependencies). They
	// are kept exactly as the scanner reported them and are never sent to the
	// model: there is no code context to judge, and a verdict could only mislead.
	Advisories int `json:"advisories,omitempty"`
	// Aborted is why the AI review stopped early (a rejected key, no credits, an
	// endpoint failing every call); empty when it ran to the end. Reports must say
	// so: the findings are then scanner output that nobody reviewed.
	Aborted string `json:"aborted,omitempty"`
}

// Dismissed reports whether this finding's verdict rules it out.
func (f Finding) Dismissed() bool {
	// A credential finding is never dismissed: the model was never shown it, and a
	// leaked secret is not something a verdict can make safe.
	//
	// Neither is a dependency advisory: a published CVE in a package the project
	// depends on is a fact about a version, not a judgment about code, and nothing a
	// model (or a verdict inherited from another finding, or feedback history) says
	// can make the vulnerable version safe. It is resolved by upgrading.
	return f.Verdict != nil && !f.IsSecret() && !f.IsDependencyAdvisory() && f.Verdict.Dismissed()
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

// Finding categories, as declared by the scanner (see Finding.Category).
const (
	CategorySecret     = "secret"
	CategoryDependency = "dependency"
)

// IsSecret reports whether this finding is about a credential or key. Such a
// finding's matched text IS the secret, so its code and message must never be
// copied into an LLM prompt, a shared report, or an issue. The test is
// deliberately broad: wrongly withholding a snippet costs a little context,
// wrongly including one leaks a credential.
func (f Finding) IsSecret() bool {
	if f.Category == CategorySecret {
		return true // the scanner itself says so
	}
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

// scaTools are scanners whose every finding is a dependency advisory.
var scaTools = map[string]bool{
	"osv-scanner": true, "govulncheck": true, "grype": true, "dependency-check": true,
	"pip-audit": true, "npm-audit": true, "cargo-audit": true, "bundler-audit": true,
}

// advisoryID matches the identifier of a published vulnerability advisory. The
// patterns are exact on purpose: a hand-written rule called "go-sqli-concat" must
// not look like a Go advisory ("GO-2024-1234").
var advisoryID = regexp.MustCompile(`(?i)^(?:` +
	`CVE-\d{4}-\d{4,}` +
	`|GHSA(?:-[0-9a-z]{4}){3}` +
	`|GO-\d{4}-\d{3,}` +
	`|PYSEC-\d{4}-\d+` +
	`|RUSTSEC-\d{4}-\d{4}` +
	`|OSV-\d{4}-\d+` +
	`|MAL-\d{4}-\d+` +
	`)$`)

// IsDependencyAdvisory reports whether this finding is a known vulnerability in a
// third-party dependency (software composition analysis) rather than a defect in
// the project's own code: it comes from a dependency scanner, or its rule id is an
// advisory identifier (which is how Trivy reports a vulnerable package).
//
// Such a finding points at a manifest or lockfile, not at code, so the per-finding
// AI review has nothing to read and its verdict would be a guess. The pipeline
// therefore never sends one to the model and never dismisses one.
func (f Finding) IsDependencyAdvisory() bool {
	if f.Category == CategoryDependency {
		return true // the scanner itself says so
	}
	if scaTools[strings.ToLower(strings.TrimSpace(f.Tool))] {
		return true
	}
	return advisoryID.MatchString(strings.TrimSpace(f.RuleID))
}
