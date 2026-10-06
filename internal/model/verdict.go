package model

import (
	"encoding/json"
	"strings"
)

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

	// Gates are the attacker-first questions behind the classification, answered
	// separately so a report can show WHY a finding was kept or dismissed. Nil when
	// the model did not supply them (older prompt versions, or a loose model).
	Gates *Gates `json:"gates,omitempty"`

	// Stability is set only when self-consistency sampling re-asked a borderline
	// finding (triage.Engine.SetSamples): how many answers were collected and how
	// they split. Nil means the verdict is a single answer.
	Stability *Stability `json:"stability,omitempty"`
}

// GateAnswer is one gate's answer. For every gate but Sanitized the vocabulary is
// yes/no/unknown; Sanitized uses none/partial/effective/unknown.
type GateAnswer string

const (
	GateYes     GateAnswer = "yes"
	GateNo      GateAnswer = "no"
	GateUnknown GateAnswer = "unknown"

	SanitizedNone      GateAnswer = "none"
	SanitizedPartial   GateAnswer = "partial"
	SanitizedEffective GateAnswer = "effective"
)

// Gate is one answered question plus the one-line evidence the model gave for it
// (for Sanitized, where the control sits).
type Gate struct {
	Answer   GateAnswer `json:"answer"`
	Evidence string     `json:"evidence,omitempty"`
}

// maxGateEvidence bounds model-written evidence kept on a verdict.
const maxGateEvidence = 300

// UnmarshalJSON accepts the object form {"answer":..,"evidence":..} and, because
// loose models flatten things, a bare string ("yes") or boolean (true/false).
// Anything else decodes to an empty Gate rather than an error: gates are advisory
// and must never make an otherwise usable verdict unparseable.
func (g *Gate) UnmarshalJSON(b []byte) error {
	*g = Gate{}
	var s string
	if json.Unmarshal(b, &s) == nil {
		g.Answer = GateAnswer(s)
		return nil
	}
	var flag bool
	if json.Unmarshal(b, &flag) == nil {
		g.Answer = GateNo
		if flag {
			g.Answer = GateYes
		}
		return nil
	}
	var o struct {
		Answer   any    `json:"answer"`
		Evidence string `json:"evidence"`
		Where    string `json:"where"`
		Reason   string `json:"reason"`
	}
	if json.Unmarshal(b, &o) != nil {
		return nil
	}
	switch a := o.Answer.(type) {
	case string:
		g.Answer = GateAnswer(a)
	case bool:
		g.Answer = GateNo
		if a {
			g.Answer = GateYes
		}
	}
	for _, e := range []string{o.Evidence, o.Where, o.Reason} {
		if e != "" {
			g.Evidence = e
			break
		}
	}
	return nil
}

// Gates are the five questions an attacker-first analyst asks of a finding.
type Gates struct {
	// DesignedBehavior: is this the application doing what it is designed to do
	// (an admin feature, a CLI running a user's own command) rather than a flaw?
	DesignedBehavior Gate `json:"designedBehavior"`
	// Reachable: can production code reach the flagged code?
	Reachable Gate `json:"reachable"`
	// AttackerControlled: does attacker-influenced data reach it?
	AttackerControlled Gate `json:"attackerControlled"`
	// Sanitized: is there an effective control between source and sink?
	// (none / partial / effective / unknown)
	Sanitized Gate `json:"sanitized"`
	// NewCapability: would exploiting it give the attacker something they did not
	// already have?
	NewCapability Gate `json:"newCapability"`
}

// Normalize lowercases and validates every answer in place: an empty or
// unrecognised answer becomes "unknown", and evidence is trimmed and bounded. It
// reports whether the model actually answered at least one gate, so the caller
// can drop a Gates the model left entirely blank.
func (g *Gates) Normalize() (answered bool) {
	yn := func(a *Gate) {
		a.Answer, answered = normalizeAnswer(a.Answer, answered, GateYes, GateNo)
		a.Evidence = boundEvidence(a.Evidence)
	}
	yn(&g.DesignedBehavior)
	yn(&g.Reachable)
	yn(&g.AttackerControlled)
	yn(&g.NewCapability)
	g.Sanitized.Answer, answered = normalizeAnswer(g.Sanitized.Answer, answered, SanitizedNone, SanitizedPartial, SanitizedEffective)
	g.Sanitized.Evidence = boundEvidence(g.Sanitized.Evidence)
	return answered
}

// normalizeAnswer returns the canonical form of a (or "unknown"), and the caller's
// running "answered" flag, now true if a was one of the allowed answers.
func normalizeAnswer(a GateAnswer, answered bool, allowed ...GateAnswer) (GateAnswer, bool) {
	n := GateAnswer(strings.ToLower(strings.TrimSpace(string(a))))
	for _, ok := range allowed {
		if n == ok {
			return n, true
		}
	}
	return GateUnknown, answered
}

func boundEvidence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxGateEvidence {
		return string(r[:maxGateEvidence]) + "..."
	}
	return s
}

// OpenPath reports whether the gates describe a wide-open, new-capability path:
// reachable, attacker-controlled, with no effective control, and giving the
// attacker something new. Every answer must be an explicit positive — "unknown"
// never counts — so this is deliberately narrow. It exists to stop a verdict from
// being dismissed when its own gates contradict it.
func (g *Gates) OpenPath() bool {
	if g == nil {
		return false
	}
	return g.Reachable.Answer == GateYes &&
		g.AttackerControlled.Answer == GateYes &&
		(g.Sanitized.Answer == SanitizedNone || g.Sanitized.Answer == SanitizedPartial) &&
		g.NewCapability.Answer == GateYes
}

// Stability records the outcome of self-consistency sampling for one finding.
type Stability struct {
	// Samples is how many triage answers were collected (the first plus any extra
	// that succeeded).
	Samples int `json:"samples"`
	// Agreeing is how many of them share the final classification. It can be 0
	// when the samples tied and the verdict fell back to "uncertain".
	Agreeing int `json:"agreeing"`
	// Classifications is the full split, so a report can show "2 true_positive /
	// 1 false_positive".
	Classifications map[Classification]int `json:"classifications"`
}

// Unanimous reports whether every sample gave the same classification. A nil
// Stability (a single answer) is trivially unanimous.
func (s *Stability) Unanimous() bool {
	return s == nil || len(s.Classifications) <= 1
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

// DismissFloor is the confidence a false-positive verdict needs before the
// finding is dismissed rather than kept for a human. It matches the floor
// HighConfidence uses for true positives: a shaky "probably fine" must not hide a
// finding.
const DismissFloor = 0.7

// Dismissed reports whether the AI review is confident enough that this finding is
// not a real issue to take it out of the actionable set (gate, issues, headline
// counts). Dismissed findings are still reported, in their own section, so the
// call is auditable.
//
// A verdict the adversarial judge overturned is never dismissed: two models
// disagreeing is a reason for a human to look. "uncertain" and low-confidence
// verdicts are never dismissed either. Neither is a verdict whose repeated samples
// disagreed (Stability), or whose own gates describe an open path to a new
// capability (Gates.OpenPath): both are the verdict contradicting itself.
func (v Verdict) Dismissed() bool {
	if v.Overturned {
		return false
	}
	if !v.Stability.Unanimous() || v.Gates.OpenPath() {
		return false
	}
	if v.Refuted {
		return true // the judge knocked down the only claim that it was real
	}
	return v.Classification == ClassFalsePositive && v.Confidence >= DismissFloor
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
