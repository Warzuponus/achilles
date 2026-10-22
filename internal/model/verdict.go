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
	// ClassHardening is a real weakness that another control in the code already
	// stops: a missing extra layer of defense, not a vulnerability. A confident
	// hardening verdict leaves the gate like a false positive, but reports list it
	// on its own so the note is not lost or mistaken for "nothing here".
	ClassHardening Classification = "hardening"
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

	// JudgeConfidence and RefuteEvidence are what the judge offered in support of a
	// refutation: how sure it said it was, and the line(s) it quoted from the
	// context it was shown. RefuteSupported is the pipeline's own check of that
	// support (the judge was confident AND the quote really appears in the
	// context); a model can never set it. A refutation that is not supported is
	// recorded as a disagreement and the finding stays in front of a human: see
	// Dismissed.
	JudgeConfidence float64 `json:"judgeConfidence,omitempty"`
	RefuteEvidence  string  `json:"refuteEvidence,omitempty"`
	RefuteSupported bool    `json:"refuteSupported,omitempty"`

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

	// Blockers and ValidationPlan turn an "uncertain" verdict into something a
	// person can act on: the exact facts the code shown does not settle, and how to
	// settle them. Kept only on uncertain verdicts; reports call those "needs
	// validation".
	Blockers       []string        `json:"blockers,omitempty"`
	ValidationPlan *ValidationPlan `json:"validationPlan,omitempty"`

	// Attacker, Impact and AssessedSeverity describe a true positive in terms a
	// team prioritizes by: who can exploit it, what they gain, and how bad that
	// is on fixed anchors. AssessedSeverity is advisory: it is shown beside the
	// scanner's severity and never changes the gate. Kept only on true positives.
	Attacker         string   `json:"attacker,omitempty"`
	Impact           string   `json:"impact,omitempty"`
	AssessedSeverity Severity `json:"assessedSeverity,omitempty"`

	// UnverifiedCitations are line references in the model-written text
	// (reasoning, fix idea, judge's reason) that point at lines the model was
	// never shown. The pipeline sets it; a model can never clear it. Reports flag
	// them so a reader does not go looking for a line the model made up.
	UnverifiedCitations []string `json:"unverifiedCitations,omitempty"`
}

// ValidationPlan is how to settle an uncertain verdict. Local is a check a
// developer can run against the code (a unit test, a grep, reading a named
// caller). Owner is a fact only someone who runs the system can observe (a proxy
// rule, an IAM policy, whether a route is exposed). Either may be empty.
type ValidationPlan struct {
	Local string `json:"local,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// NeedsValidation reports whether this is an undecided verdict that names what
// would decide it. Such a finding stays in the gate like any uncertain one;
// reports put the open questions in front of the reader.
func (v Verdict) NeedsValidation() bool {
	return v.Classification == ClassUncertain && (len(v.Blockers) > 0 || v.ValidationPlan != nil)
}

// Hardening reports whether this verdict was dismissed as a hardening note rather
// than as a false positive.
func (v Verdict) Hardening() bool {
	return v.Classification == ClassHardening && v.Dismissed()
}

// maxDetail bounds one model-written detail string kept on a verdict, and
// maxBlockers how many open questions are kept.
const (
	maxDetail   = 400
	maxBlockers = 5
)

// NormalizeDetail bounds the model-written detail fields and keeps each only on
// the classification it belongs to: blockers and a validation plan on an
// uncertain verdict, attacker, impact and assessed severity on a true positive.
// An assessed severity outside the scale is dropped rather than guessed.
func (v *Verdict) NormalizeDetail() {
	if v.Classification == ClassUncertain {
		var bs []string
		for _, b := range v.Blockers {
			if b = boundDetail(b); b != "" && len(bs) < maxBlockers {
				bs = append(bs, b)
			}
		}
		v.Blockers = bs
		if p := v.ValidationPlan; p != nil {
			p.Local, p.Owner = boundDetail(p.Local), boundDetail(p.Owner)
			if p.Local == "" && p.Owner == "" {
				v.ValidationPlan = nil
			}
		}
	} else {
		v.Blockers, v.ValidationPlan = nil, nil
	}
	if v.Classification == ClassTruePositive {
		v.Attacker, v.Impact = boundDetail(v.Attacker), boundDetail(v.Impact)
		switch s := Severity(strings.ToLower(strings.TrimSpace(string(v.AssessedSeverity)))); s {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
			v.AssessedSeverity = s
		default:
			v.AssessedSeverity = ""
		}
	} else {
		v.Attacker, v.Impact, v.AssessedSeverity = "", "", ""
	}
}

func boundDetail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxDetail {
		return string(r[:maxDetail]) + "..."
	}
	return s
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

// SureFloor is the triage confidence at and above which the adversarial judge
// alone cannot dismiss a true positive. The deep-verification merge follows the
// same principle (internal/deep): a review that was sure is not overruled by a
// second opinion, it is escalated to a person.
const SureFloor = 0.9

// NormalizeConfidence maps a model-reported confidence onto 0..1. Loose models
// answer in percent ("85"), so anything in (1, 100] is read that way. NaN,
// negative and absurd values become 0, which every threshold treats as "not
// confident": an out-of-range number must never clear a floor by accident.
func NormalizeConfidence(c float64) float64 {
	switch {
	case c != c, c < 0, c > 100: // c != c is NaN
		return 0
	case c > 1:
		return c / 100
	}
	return c
}

// Dismissed reports whether the AI review is confident enough that this finding is
// not a real issue to take it out of the actionable set (gate, issues, headline
// counts). Dismissed findings are still reported, in their own section, so the
// call is auditable.
//
// A true positive the judge refuted is dismissed only when that refutation was
// verified and the triage pass was not sure (the Refuted branch below).
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
		// The judge's bare word is not enough to take a finding out of the gate. A
		// refutation dismisses only a true-positive call (refuting "uncertain" says
		// nothing about which way the truth lies), only when the pipeline verified
		// the judge's support for it, and only when the triage pass was not itself
		// sure. Anything else is two reviews disagreeing, which a human settles.
		return v.Classification == ClassTruePositive && v.RefuteSupported && v.Confidence < SureFloor
	}
	// A hardening note leaves the gate on the same terms as a false positive: the
	// review is confident the attack is already stopped. Reports list it apart.
	return (v.Classification == ClassFalsePositive || v.Classification == ClassHardening) && v.Confidence >= DismissFloor
}

// Disputed reports whether the judge refuted this verdict without that refutation
// being strong enough to dismiss the finding. Reports label it so a reader knows
// the two passes disagreed and the finding was kept on purpose.
func (v Verdict) Disputed() bool {
	return v.Refuted && !v.Dismissed()
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

	// ReusedFrom is the run whose review produced this verdict, when it was taken
	// from the verdict cache instead of asking the model again: the rule, the code
	// shown, the prompt and the models were all unchanged. Empty for a verdict
	// produced in this run.
	ReusedFrom string `json:"reusedFrom,omitempty"`
}

// DetailLine is one labeled piece of a verdict's detail for display.
type DetailLine struct{ Label, Text string }

// Details lists the parts of a verdict a team acts on beyond the classification:
// for a true positive who can exploit it, what they gain and the assessed
// severity; for an uncertain verdict the open questions and how to settle them;
// and any line reference the model made to code it was not shown. The text is
// model-written: every renderer must still escape and redact it.
func (v Verdict) Details() []DetailLine {
	var out []DetailLine
	if v.Attacker != "" {
		out = append(out, DetailLine{"Attacker", v.Attacker})
	}
	if v.Impact != "" {
		out = append(out, DetailLine{"Impact", v.Impact})
	}
	if v.AssessedSeverity != "" {
		out = append(out, DetailLine{"AI-assessed severity", string(v.AssessedSeverity) + " (advisory; the gate uses the scanner's severity)"})
	}
	for _, b := range v.Blockers {
		out = append(out, DetailLine{"Open question", b})
	}
	if p := v.ValidationPlan; p != nil {
		if p.Local != "" {
			out = append(out, DetailLine{"Check in the code", p.Local})
		}
		if p.Owner != "" {
			out = append(out, DetailLine{"Ask whoever runs it", p.Owner})
		}
	}
	if len(v.UnverifiedCitations) > 0 {
		out = append(out, DetailLine{"Unchecked references", "the review cites " + strings.Join(v.UnverifiedCitations, ", ") +
			", which it was not shown; do not rely on those references"})
	}
	return out
}
