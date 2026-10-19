package report

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
)

// GitLab reads scan results from job artifacts in its own formats. Three are
// written here:
//
//   - the SAST security report (gl-sast-report.json), for findings in code;
//   - the secret detection security report (gl-secret-detection-report.json);
//   - the Code Quality report (gl-code-quality-report.json), which every GitLab
//     tier shows in the merge request widget and which carries every finding.
//
// Dependency advisories are not written as a GitLab dependency scanning report:
// that format describes each affected package and the lockfile it came from, and a
// Finding does not keep them apart from the scanner's message. They appear in the
// Code Quality report.
//
// Only findings that count are written: Scan.Findings without the shadow ones
// (generated rules still under observation). A finding the AI review dismissed is
// in Scan.Findings only under --keep-dismissed, and is then flagged as a likely
// false positive, which is GitLab's own vocabulary for it.

// GitLabSchemaVersion is the security report schema version the SAST and secret
// detection reports declare. It is the oldest 15.x schema on purpose: every field
// written here exists in it, and a GitLab instance validates a report against the
// version the report names, which it must know.
const GitLabSchemaVersion = "15.0.0"

const (
	gitlabSchemaBase = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v" + GitLabSchemaVersion + "/dist/"
	gitlabProjectURL = "https://github.com/Warzuponus/achilles"

	// Limits from the schema (name, solution) and from GitLab's ingestion
	// (identifiers per finding). Text beyond them is cut, never rejected.
	gitlabMaxName        = 255
	gitlabMaxSolution    = 7000
	gitlabMaxDescription = 4000
	gitlabMaxIdentifiers = 20

	// gitlabNoCommit stands in for the commit of a secret found in the working
	// tree. The secret detection schema requires a commit sha; GitLab's own
	// analyzer writes this value when it scans files rather than history.
	gitlabNoCommit = "0000000"
)

// GitLabMeta is what a GitLab security report says about the scan itself.
type GitLabMeta struct {
	Version string    // the Achilles version; empty is written as 0.0.0
	Start   time.Time // when the scan started
	End     time.Time // when it finished
	// Commit is the commit that was scanned, when known. The secret detection
	// format requires one per finding.
	Commit string
}

type glReport struct {
	Version         string          `json:"version"`
	Schema          string          `json:"schema"`
	Scan            glScan          `json:"scan"`
	Vulnerabilities []glVuln        `json:"vulnerabilities"`
	Remediations    []glRemediation `json:"remediations,omitempty"`
}

type glScan struct {
	Analyzer  glTool      `json:"analyzer"`
	Scanner   glTool      `json:"scanner"`
	Type      string      `json:"type"`
	StartTime string      `json:"start_time"`
	EndTime   string      `json:"end_time"`
	Status    string      `json:"status"`
	Messages  []glMessage `json:"messages,omitempty"`
}

type glTool struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Version string   `json:"version"`
	Vendor  glVendor `json:"vendor"`
}

type glVendor struct {
	Name string `json:"name"`
}

type glMessage struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

type glVuln struct {
	ID          string              `json:"id"`
	Name        string              `json:"name,omitempty"`
	Description string              `json:"description,omitempty"`
	Severity    string              `json:"severity"`
	Solution    string              `json:"solution,omitempty"`
	Location    glLocation          `json:"location"`
	Identifiers []glIdentifier      `json:"identifiers"`
	Tracking    *glTracking         `json:"tracking,omitempty"`
	Flags       []glFlag            `json:"flags,omitempty"`
	Details     map[string]glDetail `json:"details,omitempty"`
}

// glTracking lets GitLab follow a vulnerability as the code around it moves, so a
// finding that shifts lines keeps its history (status, comments, issue) instead of
// being closed and reported again. GitLab uses it on Ultimate, where the
// vulnerability report lives.
type glTracking struct {
	Type  string           `json:"type"`
	Items []glTrackingItem `json:"items"`
}

type glTrackingItem struct {
	File       string        `json:"file,omitempty"`
	StartLine  int           `json:"start_line,omitempty"`
	EndLine    int           `json:"end_line,omitempty"`
	Signatures []glSignature `json:"signatures"`
}

type glSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type glLocation struct {
	File      string    `json:"file,omitempty"`
	StartLine int       `json:"start_line,omitempty"`
	EndLine   int       `json:"end_line,omitempty"`
	Commit    *glCommit `json:"commit,omitempty"`
}

type glCommit struct {
	SHA string `json:"sha"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type glFlag struct {
	Type        string `json:"type"`
	Origin      string `json:"origin"`
	Description string `json:"description"`
}

// glDetail is one named text field of a vulnerability's details.
type glDetail struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type glRemediation struct {
	Fixes   []glFixRef `json:"fixes"`
	Summary string     `json:"summary"`
	Diff    string     `json:"diff"`
}

type glFixRef struct {
	ID string `json:"id"`
}

// gitlabScanHeader is the scan object every GitLab security report starts with.
func gitlabScanHeader(s model.Scan, meta GitLabMeta, scanType string) glScan {
	version := strings.TrimPrefix(strings.TrimSpace(meta.Version), "v")
	if version == "" {
		version = "0.0.0"
	}
	tool := glTool{ID: "achilles", Name: "Achilles", URL: gitlabProjectURL, Version: version, Vendor: glVendor{Name: "Achilles"}}
	start, end := meta.Start, meta.End
	if end.IsZero() {
		end = time.Now()
	}
	if start.IsZero() || start.After(end) {
		start = end
	}
	scan := glScan{
		Analyzer: tool, Scanner: tool, Type: scanType,
		StartTime: start.UTC().Format("2006-01-02T15:04:05"),
		EndTime:   end.UTC().Format("2006-01-02T15:04:05"),
		Status:    "success",
	}
	// A scanner that did not run leaves the report incomplete, and the report says
	// so in the two places the format has for it.
	for _, t := range s.FailedTools {
		scan.Status = "failure"
		scan.Messages = append(scan.Messages, glMessage{
			Level: "warn", Value: gitlabText(t, 200) + " failed to run or its output could not be read; results are incomplete",
		})
	}
	return scan
}

// WriteGitLabSAST writes the findings in code as a GitLab SAST report. Credential
// findings and dependency advisories are left out: they belong to other reports.
func WriteGitLabSAST(w io.Writer, s model.Scan, meta GitLabMeta) error {
	return writeGitLabSecurity(w, s, meta, "sast", func(f model.Finding) bool {
		return !f.IsSecret() && !f.IsDependencyAdvisory()
	})
}

// WriteGitLabSecretDetection writes the credential findings as a GitLab secret
// detection report. The matched text is never included.
func WriteGitLabSecretDetection(w io.Writer, s model.Scan, meta GitLabMeta) error {
	return writeGitLabSecurity(w, s, meta, "secret_detection", model.Finding.IsSecret)
}

func writeGitLabSecurity(w io.Writer, s model.Scan, meta GitLabMeta, scanType string, include func(model.Finding) bool) error {
	schemaFile := "sast-report-format.json"
	if scanType == "secret_detection" {
		schemaFile = "secret-detection-report-format.json"
	}
	doc := glReport{
		Version:         GitLabSchemaVersion,
		Schema:          gitlabSchemaBase + schemaFile,
		Scan:            gitlabScanHeader(s, meta, scanType),
		Vulnerabilities: []glVuln{}, // an array even when empty: null does not validate
	}

	seen := map[string]int{}
	tracked := map[string]int{}
	for _, f := range s.Findings {
		if f.Shadow || !include(f) {
			continue
		}
		v := gitlabVuln(f, seen)
		v.Tracking = gitlabTracking(f, v.Location, tracked)
		if scanType == "secret_detection" {
			// A finding made in the history names its own commit; one made in the
			// files names the commit that was scanned.
			sha := strings.TrimSpace(f.Commit)
			if sha == "" {
				sha = strings.TrimSpace(meta.Commit)
			}
			if sha == "" {
				sha = gitlabNoCommit
			}
			v.Location.Commit = &glCommit{SHA: sha}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
		if rem, ok := gitlabRemediation(f, v.ID); ok {
			doc.Remediations = append(doc.Remediations, rem)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func gitlabVuln(f model.Finding, seen map[string]int) glVuln {
	secret := f.IsSecret()
	message := f.Message
	if secret {
		message = redact.Secrets(message)
	}
	v := glVuln{
		ID:          gitlabID(f, seen),
		Name:        gitlabName(f, message),
		Description: gitlabText(message, gitlabMaxDescription),
		Severity:    gitlabSeverity(f.Severity),
		Location:    glLocation{File: gitlabPath(f.Location.File)},
		Identifiers: gitlabIdentifiers(f),
		Details:     map[string]glDetail{},
	}
	if line := f.Location.Region.StartLine; line > 0 {
		v.Location.StartLine = line
		if end := f.Location.Region.EndLine; end >= line {
			v.Location.EndLine = end
		}
	}

	detail := func(key, name, value string) {
		if value = gitlabText(value, gitlabMaxDescription); value != "" {
			v.Details[key] = glDetail{Type: "text", Name: name, Value: value}
		}
	}
	detail("reported_by", "Reported by", strings.TrimSpace(f.Tool+" "+f.RuleID))
	detail("fingerprint", "Achilles fingerprint", f.Fingerprint)
	if len(f.Correlated) > 0 {
		detail("also_reported_by", "Also reported by", strings.Join(f.Correlated, ", "))
	}
	if vd := f.Verdict; vd != nil {
		detail("ai_review", "AI review", gitlabVerdict(vd))
		if !secret {
			why := vd.Reasoning
			if vd.Refuted && vd.RefuteReason != "" {
				why = vd.RefuteReason
			}
			detail("ai_reasoning", "AI reasoning", why)
		}
	}
	if r := f.Remediation; r != nil && !secret {
		v.Solution = gitlabText(strings.TrimSpace(r.Summary+"\n\n"+r.Guidance), gitlabMaxSolution)
		if r.Verification != nil {
			detail("fix_verification", "Suggested fix, re-scanned", string(r.Verification.Status))
		}
	}
	if f.Dismissed() {
		why := "Ruled out by the Achilles AI review."
		if vd := f.Verdict; vd != nil {
			switch {
			case vd.RefuteReason != "":
				why = vd.RefuteReason
			case vd.Reasoning != "":
				why = vd.Reasoning
			}
		}
		v.Flags = []glFlag{{Type: "flagged-as-likely-false-positive", Origin: "achilles", Description: gitlabText(why, gitlabMaxDescription)}}
	}
	if len(v.Details) == 0 {
		v.Details = nil
	}
	return v
}

// gitlabVerdict is the AI review's call in a few words.
func gitlabVerdict(v *model.Verdict) string {
	out := strings.ReplaceAll(string(v.Classification), "_", " ")
	out += fmt.Sprintf(", confidence %.2f", v.Confidence)
	if v.Exploitability != "" {
		out += ", " + string(v.Exploitability)
	}
	switch {
	case v.Overturned:
		out += "; the second reviewer disagreed and found evidence that it is real"
	case v.Refuted && v.RefuteSupported:
		out += "; refuted by the second reviewer"
	case v.Refuted:
		out += "; the second reviewer disagreed without enough evidence to dismiss it"
	}
	return out
}

// gitlabRemediation offers a patch only when re-scanning verified it, as the SARIF
// report does: GitLab can turn a remediation into a merge request with one click.
func gitlabRemediation(f model.Finding, id string) (glRemediation, bool) {
	r := f.Remediation
	if r == nil || r.Verification == nil || r.Verification.Status != model.FixVerified || f.IsSecret() || strings.TrimSpace(r.Diff) == "" {
		return glRemediation{}, false
	}
	summary := gitlabText(r.Summary, gitlabMaxName)
	if summary == "" {
		summary = "Fix suggested by Achilles and verified by re-scanning"
	}
	return glRemediation{
		Fixes:   []glFixRef{{ID: id}},
		Summary: summary,
		Diff:    base64.StdEncoding.EncodeToString([]byte(r.Diff)),
	}, true
}

// gitlabID returns an identifier that is unique within one report and the same on
// every run over unchanged code. It has the shape of a UUID, as the schema
// recommends, in the custom (version 8) layout: the bits are a SHA-256, not a
// timestamp or a namespace hash.
// gitlabTracking gives the vulnerability a signature that does not depend on its
// line: Achilles' fingerprint, which hashes the matched code (see
// model.ComputeFingerprint, or the scanner's own line-independent fingerprint),
// with the tool, rule and file. A second identical match in the same file gets
// its own signature by occurrence, so the two are never merged. Without a
// fingerprint there is nothing line-independent to offer, and no tracking.
func gitlabTracking(f model.Finding, loc glLocation, seen map[string]int) *glTracking {
	if strings.TrimSpace(f.Fingerprint) == "" {
		return nil
	}
	basis := strings.Join([]string{f.Tool, f.RuleID, loc.File, f.Fingerprint}, "\x00")
	n := seen[basis]
	seen[basis] = n + 1
	if n > 0 {
		basis += "\x00" + strconv.Itoa(n)
	}
	sum := sha256.Sum256([]byte("achilles/gitlab-tracking/v1\x00" + basis))
	return &glTracking{Type: "source", Items: []glTrackingItem{{
		File:       loc.File,
		StartLine:  loc.StartLine,
		EndLine:    loc.EndLine,
		Signatures: []glSignature{{Algorithm: "hash", Value: hex.EncodeToString(sum[:])}},
	}}}
}

func gitlabID(f model.Finding, seen map[string]int) string {
	basis := strings.Join([]string{f.ID, f.Fingerprint, f.Tool, f.RuleID, f.Location.File, strconv.Itoa(f.Location.Region.StartLine)}, "\x00")
	n := seen[basis]
	seen[basis] = n + 1
	if n > 0 {
		basis += "\x00" + strconv.Itoa(n)
	}
	sum := sha256.Sum256([]byte("achilles/gitlab/v1\x00" + basis))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x80 // version 8
	b[8] = b[8]&0x3f | 0x80 // RFC 9562 variant
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

var sentenceEnd = regexp.MustCompile(`[.!?](\s|$)`)

// gitlabName is the title GitLab lists the vulnerability under: the first sentence
// of the scanner's message, or the rule when there is no message. A credential
// finding is titled by its rule alone, so nothing from the match can reach a title.
func gitlabName(f model.Finding, message string) string {
	rule := strings.TrimSpace(f.Tool + " " + f.RuleID)
	if rule == "" {
		rule = "Achilles finding"
	}
	if f.IsSecret() {
		return gitlabText("Possible credential ("+rule+")", gitlabMaxName)
	}
	name := gitlabText(message, 0)
	if loc := sentenceEnd.FindStringIndex(name); loc != nil && loc[0] >= 12 {
		name = name[:loc[0]]
	}
	if name == "" {
		name = rule
	}
	const comfortable = 150
	if len(name) > comfortable {
		name = strings.TrimSpace(cutUTF8(name, comfortable)) + "..."
	}
	return name
}

func gitlabSeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "Critical"
	case model.SeverityHigh:
		return "High"
	case model.SeverityMedium:
		return "Medium"
	case model.SeverityLow:
		return "Low"
	case model.SeverityInfo:
		return "Info"
	}
	return "Unknown"
}

var (
	cweNumber      = regexp.MustCompile(`(?i)^(?:CWE[-_ ]?)?(\d{1,6})\b`)
	identifierType = regexp.MustCompile(`[^a-z0-9]+`)
)

// gitlabIdentifiers lists what identifies the finding. The first entry is the
// primary identifier, which GitLab uses with the location to recognize the same
// vulnerability from one pipeline to the next: it is the reporting tool's rule.
func gitlabIdentifiers(f model.Finding) []glIdentifier {
	tool := strings.Trim(identifierType.ReplaceAllString(strings.ToLower(f.Tool), "_"), "_")
	if tool == "" {
		tool = "achilles"
	}
	rule := gitlabText(f.RuleID, gitlabMaxName)
	if rule == "" {
		rule = "unknown"
	}
	ids := []glIdentifier{{
		Type:  tool + "_rule_id",
		Name:  gitlabText(strings.TrimSpace(f.Tool+" "+rule), gitlabMaxName),
		Value: rule,
	}}
	seen := map[string]bool{}
	for _, c := range f.CWE {
		m := cweNumber.FindStringSubmatch(strings.TrimSpace(c))
		if m == nil {
			continue
		}
		n := strings.TrimLeft(m[1], "0")
		if n == "" || seen[n] || len(ids) >= gitlabMaxIdentifiers {
			continue
		}
		seen[n] = true
		ids = append(ids, glIdentifier{
			Type: "cwe", Name: "CWE-" + n, Value: n,
			URL: "https://cwe.mitre.org/data/definitions/" + n + ".html",
		})
	}
	return ids
}

// gitlabPath is a finding's file as GitLab expects it: relative to the repository
// root, with forward slashes.
func gitlabPath(file string) string {
	p := path.Clean(filepath.ToSlash(strings.TrimSpace(file)))
	p = strings.TrimPrefix(p, "./")
	if p == "." {
		return ""
	}
	return p
}

// gitlabText prepares untrusted text (a scanner's message, a model's reasoning)
// for a GitLab report: credentials are masked, control characters are dropped,
// runs of blank space within a line are collapsed, and the length is bounded
// (max 0 means one line, unbounded). Nothing is escaped: the document is JSON, and
// GitLab renders these fields itself.
func gitlabText(s string, max int) string {
	s = redact.Prompt(s)
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.Join(strings.FieldsFunc(line, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}), " ")
		if line != "" || (len(lines) > 0 && lines[len(lines)-1] != "") {
			lines = append(lines, line)
		}
	}
	sep := "\n"
	if max == 0 {
		sep = " "
	}
	s = strings.TrimSpace(strings.Join(lines, sep))
	if max > 0 && len(s) > max {
		const tail = " ... (truncated)"
		s = strings.TrimSpace(cutUTF8(s, max-len(tail))) + tail
	}
	return s
}

// cutUTF8 returns at most n bytes of s without splitting a character.
func cutUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// --- Code Quality ---

// cqIssue is one entry of a GitLab Code Quality report (a subset of the Code
// Climate format). All five fields are required by GitLab.
type cqIssue struct {
	Description string     `json:"description"`
	CheckName   string     `json:"check_name"`
	Fingerprint string     `json:"fingerprint"`
	Severity    string     `json:"severity"`
	Location    cqLocation `json:"location"`
}

type cqLocation struct {
	Path  string  `json:"path"`
	Lines cqLines `json:"lines"`
}

type cqLines struct {
	Begin int `json:"begin"`
}

// WriteGitLabCodeQuality writes every finding that counts as a GitLab Code Quality
// report. Unlike the security reports, GitLab shows this one in the merge request
// widget on every tier, so it is the way to see Achilles' findings on a merge
// request without GitLab Ultimate. Credential findings are included with their
// message masked.
func WriteGitLabCodeQuality(w io.Writer, s model.Scan) error {
	issues := []cqIssue{}
	seen := map[string]int{}
	for _, f := range s.Findings {
		if f.Shadow {
			continue
		}
		message := f.Message
		if f.IsSecret() {
			message = redact.Secrets(message)
		}
		rule := strings.TrimSpace(f.Tool + " " + f.RuleID)
		desc := gitlabText(message, 0)
		switch {
		case desc == "":
			desc = rule
		case rule != "":
			desc += " [" + gitlabText(rule, 0) + "]"
		}
		if len(desc) > maxMarkdownText {
			desc = strings.TrimSpace(cutUTF8(desc, maxMarkdownText)) + " ... (truncated)"
		}
		check := gitlabText(f.RuleID, gitlabMaxName)
		if check == "" {
			check = "achilles"
		}
		file := gitlabPath(f.Location.File)
		line := f.Location.Region.StartLine
		if line < 1 {
			line = 1 // the format has no "whole file": the first line is the convention
		}
		// The fingerprint is how GitLab tells a finding that is still there from a
		// new one. It is built from Achilles' own fingerprint, which ignores line
		// numbers, plus the file; repeats within a file are numbered in order.
		basis := f.Fingerprint + "\x00" + f.Tool + "\x00" + f.RuleID + "\x00" + file
		n := seen[basis]
		seen[basis] = n + 1
		sum := sha256.Sum256([]byte("achilles/codequality/v1\x00" + basis + "\x00" + strconv.Itoa(n)))
		issues = append(issues, cqIssue{
			Description: desc,
			CheckName:   check,
			Fingerprint: hex.EncodeToString(sum[:16]),
			Severity:    codeQualitySeverity(f.Severity),
			Location:    cqLocation{Path: file, Lines: cqLines{Begin: line}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(issues)
}

// codeQualitySeverity maps onto the five Code Climate severities GitLab accepts.
func codeQualitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "blocker"
	case model.SeverityHigh:
		return "critical"
	case model.SeverityMedium:
		return "major"
	case model.SeverityLow:
		return "minor"
	}
	return "info"
}
