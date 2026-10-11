package knowledge

import (
	"fmt"
	"sort"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
)

// RuleHealth summarizes how a (tool, rule) pair has performed against analyst
// feedback. TP and FP count DISTINCT findings (by fingerprint), each by its most
// recent label, so labelling one finding five times is one sample, not five.
type RuleHealth struct {
	Tool   string
	RuleID string
	TP     int
	FP     int
}

// Samples is the number of distinct labeled findings for this rule.
func (h RuleHealth) Samples() int { return h.TP + h.FP }

// FPRate is the confirmed false-positive rate (0 when no samples).
func (h RuleHealth) FPRate() float64 {
	if h.Samples() == 0 {
		return 0
	}
	return float64(h.FP) / float64(h.Samples())
}

// Policy is how much feedback it takes before a rule's findings are resolved
// without a model looking at them. Auto-resolution removes findings from the gate
// on the strength of past labels alone, so the bar is deliberately high and the
// decision is bounded in time and in severity.
type Policy struct {
	// MinFindings is how many distinct labeled findings a rule needs.
	MinFindings int
	// FPThreshold is the share of those that must be labeled false positive.
	FPThreshold float64
	// MaxAge ignores labels older than this, so a rule is re-examined when its
	// evidence goes stale (the code and the rule both change). 0 keeps labels forever.
	MaxAge time.Duration
	// MaxSeverity is the most severe finding that may be auto-resolved. Anything
	// above it always gets a real review, however noisy its rule has been.
	MaxSeverity model.Severity
}

// DefaultPolicy is the shipped calibration policy: ten distinct findings, nine in
// ten of them false positives, labeled within the last 180 days, and never a
// finding above medium severity.
var DefaultPolicy = Policy{
	MinFindings: 10,
	FPThreshold: 0.9,
	MaxAge:      180 * 24 * time.Hour,
	MaxSeverity: model.SeverityMedium,
}

// Calibrator uses accumulated feedback to auto-resolve findings from
// chronically false-positive rules without spending an LLM call (DESIGN.md §8).
type Calibrator struct {
	health map[string]RuleHealth
	policy Policy
}

// NewCalibrator builds calibration from feedback history under p, as of now.
// Labels older than p.MaxAge are ignored, labels with no rule attached are
// ignored, and each finding counts once, by its latest label.
func NewCalibrator(fb *FeedbackStore, p Policy, now time.Time) *Calibrator {
	c := &Calibrator{health: map[string]RuleHealth{}, policy: p}

	type latest struct {
		tool, rule string
		label      Label
	}
	byFinding := map[string]latest{} // rule key + fingerprint -> its latest label
	var order []string               // first-seen order, for deterministic totals
	for _, f := range fb.All() {     // insertion order: a later record overrides an earlier one
		if f.Tool == "" && f.RuleID == "" {
			continue // the fingerprint was not found in the vault when it was labeled
		}
		if p.MaxAge > 0 && !f.At.IsZero() && now.Sub(f.At) > p.MaxAge {
			continue
		}
		if f.Label != LabelTP && f.Label != LabelFP {
			continue
		}
		k := ruleKey(f.Tool, f.RuleID) + "|" + f.Fingerprint
		if _, seen := byFinding[k]; !seen {
			order = append(order, k)
		}
		byFinding[k] = latest{tool: f.Tool, rule: f.RuleID, label: f.Label}
	}
	for _, k := range order {
		l := byFinding[k]
		rk := ruleKey(l.tool, l.rule)
		h := c.health[rk]
		h.Tool, h.RuleID = l.tool, l.rule
		if l.label == LabelTP {
			h.TP++
		} else {
			h.FP++
		}
		c.health[rk] = h
	}
	return c
}

// Health returns the accumulated health for a rule.
func (c *Calibrator) Health(tool, ruleID string) (RuleHealth, bool) {
	h, ok := c.health[ruleKey(tool, ruleID)]
	return h, ok
}

// Rules returns every rule's health, noisiest first (highest FP rate, then most
// samples, then rule key) — the data behind the rule-health report.
func (c *Calibrator) Rules() []RuleHealth {
	out := make([]RuleHealth, 0, len(c.health))
	for _, h := range c.health {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].FPRate(), out[j].FPRate(); a != b {
			return a > b
		}
		if out[i].Samples() != out[j].Samples() {
			return out[i].Samples() > out[j].Samples()
		}
		return ruleKey(out[i].Tool, out[i].RuleID) < ruleKey(out[j].Tool, out[j].RuleID)
	})
	return out
}

// Suppresses reports whether a rule has enough false-positive history that
// AutoResolve would resolve its findings (severity permitting).
func (c *Calibrator) Suppresses(h RuleHealth) bool {
	return c.policy.MinFindings > 0 && h.Samples() >= c.policy.MinFindings && h.FPRate() >= c.policy.FPThreshold
}

// Policy returns the policy this calibrator applies (for reporting).
func (c *Calibrator) Policy() Policy { return c.policy }

// AutoResolve returns a false-positive verdict (and true) when the finding's
// rule is chronically noisy enough to resolve without an LLM. Otherwise false.
//
// It never resolves a finding above the policy's severity cap, and never a
// credential finding: those always get whatever review the pipeline gives them.
func (c *Calibrator) AutoResolve(f model.Finding) (model.Verdict, bool) {
	h, ok := c.health[ruleKey(f.Tool, f.RuleID)]
	if !ok || !c.Suppresses(h) {
		return model.Verdict{}, false
	}
	if f.Severity.Rank() > c.policy.MaxSeverity.Rank() || f.IsSecret() {
		return model.Verdict{}, false
	}
	return model.Verdict{
		Classification: model.ClassFalsePositive,
		Confidence:     h.FPRate(),
		Exploitability: model.ExploitUnknown,
		Reasoning: fmt.Sprintf("auto-resolved by calibration, not reviewed by a model: analysts labeled %d of %d distinct findings of rule %s false positive",
			h.FP, h.Samples(), f.RuleID),
	}, true
}

func ruleKey(tool, ruleID string) string { return tool + "|" + ruleID }
