// Package research implements the research-agent loop (DESIGN.md §9): from a
// codebase inventory, spawn grounded research agents that turn threat intel into
// candidate detections, synthesize Opengrep rules, and admit them ONLY if they
// pass a validation gate — building a self-growing, self-curating rule corpus.
package research

// Target is a technology to research (a dependency or a language/framework).
type Target struct {
	Tech      string
	Version   string
	Ecosystem string // "go" | "pypi" | "npm" | "lang"
}

// Key uniquely identifies a target for dedup/caching (DESIGN.md §9.2 step 2).
func (t Target) Key() string { return t.Ecosystem + "|" + t.Tech + "@" + t.Version }

// Issue is a candidate security issue found by a research agent. Citation is
// mandatory — an issue with no resolvable source is discarded (anti-hallucination
// rule #1, DESIGN.md §9.2 step 3).
type Issue struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Citation    string `json:"citation"`
	CWE         string `json:"cwe,omitempty"`
	Language    string `json:"language"`
	// Origin says what the issue was derived from, when that matters for how a
	// rule built from it may be used (see OriginExternalRule). It is set by
	// Achilles, never read from a model's reply.
	Origin string `json:"-"`
}

// OriginExternalRule marks an issue (and a rule synthesized from it) that came
// from a finding reported by a rule Achilles did not author: in practice the
// community Opengrep rule pack, whose licence adds a Commons Clause. A rule
// derived from such a finding is not loaded under --mode commercial, where the
// pack itself is not allowed.
const OriginExternalRule = "external-rule"

// GeneratedRule is a synthesized detection plus the test fixtures the validation
// gate uses to prove it (DESIGN.md §9.3).
type GeneratedRule struct {
	ID                string
	Language          string
	RuleYAML          string
	VulnerableSnippet string
	PatchedSnippet    string
	Provenance        Provenance
}

// Provenance records where a generated rule came from (DESIGN.md §9.4).
type Provenance struct {
	SourceCitation string `json:"sourceCitation"`
	Origin         string `json:"origin,omitempty"`
	IssueTitle     string `json:"issueTitle"`
	Model          string `json:"model,omitempty"`
	PromptVersion  string `json:"promptVersion"`
	Created        string `json:"created,omitempty"`
}

// ValidationResult is the outcome of running a generated rule against its own
// vulnerable and patched fixtures.
type ValidationResult struct {
	Parses            bool `json:"parses"`
	MatchesVulnerable bool `json:"matchesVulnerable"`
	MatchesPatched    bool `json:"matchesPatched"`
	// MatchesControl: the rule also fires on ordinary code that has nothing to do
	// with the issue, so it is too broad to be a detection.
	MatchesControl bool   `json:"matchesControl,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// Summary is the tally of a research run.
type Summary struct {
	TargetsResearched int
	IssuesFound       int
	RulesGenerated    int
	Admitted          int
	Quarantined       int
}
