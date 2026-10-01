package model

// Classification is the triage layer's call on whether a finding is real.
type Classification string

const (
	ClassTruePositive  Classification = "true_positive"
	ClassFalsePositive Classification = "false_positive"
	ClassUncertain     Classification = "uncertain"
)

// Exploitability is whether the issue is actually reachable/attacker-triggerable.
type Exploitability string

const (
	ExploitReachable    Exploitability = "reachable"
	ExploitNotReachable Exploitability = "not-reachable"
	ExploitUnknown      Exploitability = "unknown"
)

// Verdict is the LLM triage result for a finding, refined by the judge pass.
type Verdict struct {
	Classification Classification `json:"classification"`
	Confidence     float64        `json:"confidence"` // 0.0–1.0
	Exploitability Exploitability `json:"exploitability"`
	Reasoning      string         `json:"reasoning"`
	SuggestedFix   string         `json:"suggestedFix,omitempty"`

	// Set by the adversarial judge (§7 step 3). Refuted means the judge knocked
	// DOWN a true-positive verdict.
	Refuted      bool   `json:"refuted"`
	RefuteReason string `json:"refuteReason,omitempty"`

	// Overturned means the judge knocked a verdict UP: triage called the finding
	// not-a-problem, and the adversarial pass found concrete evidence that it is.
	//
	// This is deliberately a separate field rather than a rewrite of
	// Classification/Confidence. Those record what the triage pass actually said,
	// and a 0.95 "false_positive" confidence is not evidence for the opposite
	// claim — reusing it as a true-positive confidence would be dishonest
	// provenance. Two models disagreeing is its own state, and the report says so.
	Overturned bool `json:"overturned,omitempty"`
}

// HighConfidence reports whether a verdict is trustworthy enough to act on
// automatically: a true-positive the judge could not refute, above a confidence
// floor. Remediation gates on this, so an overturned verdict deliberately does
// NOT qualify — when two models disagree we do not write a patch.
func (v Verdict) HighConfidence() bool {
	return v.Classification == ClassTruePositive && !v.Refuted && v.Confidence >= 0.7
}

// Surfaced reports whether a human should see this finding. It is the union of
// "we believe it" and "our own adversarial pass disagreed with suppressing it".
//
// The distinction from HighConfidence exists because the judge used to be
// one-directional: it could only ever downgrade a true positive, so a cheap
// triage model's false negative was unrecoverable even though the stronger judge
// model already ran on every finding. The eval corpus measured that as a missed
// vulnerability (see evals/README.md), which is the costlier direction to get
// wrong — a false alarm wastes analyst time, a miss ships the bug.
func (v Verdict) Surfaced() bool {
	return v.HighConfidence() || v.Overturned
}

// Provenance records how a verdict was produced (for the Evidence Vault).
type Provenance struct {
	TriageModel   string `json:"triageModel,omitempty"`
	JudgeModel    string `json:"judgeModel,omitempty"`
	PromptVersion string `json:"promptVersion,omitempty"`

	// CorrelatedFrom is the fingerprint of the cluster representative this
	// verdict was inherited from, when the finding was not triaged directly
	// (see internal/correlate). Empty for a directly-triaged finding.
	CorrelatedFrom string `json:"correlatedFrom,omitempty"`
}
