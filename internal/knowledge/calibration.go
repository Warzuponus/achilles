package knowledge

import (
	"fmt"
	"sort"

	"github.com/Warzuponus/achilles/internal/model"
)

// RuleHealth summarizes how a (tool, rule) pair has performed against analyst
// feedback. A high FP rate over enough samples means the rule is noisy.
type RuleHealth struct {
	Tool   string
	RuleID string
	TP     int
	FP     int
}

// Samples is the total labeled findings for this rule.
func (h RuleHealth) Samples() int { return h.TP + h.FP }

// FPRate is the confirmed false-positive rate (0 when no samples).
func (h RuleHealth) FPRate() float64 {
	if h.Samples() == 0 {
		return 0
	}
	return float64(h.FP) / float64(h.Samples())
}

// Calibrator uses accumulated feedback to auto-resolve findings from
// chronically false-positive rules without spending an LLM call (DESIGN.md §8).
type Calibrator struct {
	health      map[string]RuleHealth
	minSamples  int
	fpThreshold float64
}

// NewCalibrator builds calibration from feedback history. A rule is eligible for
// auto-suppression once it has >= minSamples labels and an FP rate >= fpThreshold.
func NewCalibrator(fb *FeedbackStore, minSamples int, fpThreshold float64) *Calibrator {
	c := &Calibrator{health: map[string]RuleHealth{}, minSamples: minSamples, fpThreshold: fpThreshold}
	for _, f := range fb.All() {
		k := ruleKey(f.Tool, f.RuleID)
		h := c.health[k]
		h.Tool, h.RuleID = f.Tool, f.RuleID
		switch f.Label {
		case LabelTP:
			h.TP++
		case LabelFP:
			h.FP++
		}
		c.health[k] = h
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

// Suppresses reports whether a rule is noisy enough that AutoResolve would
// suppress its findings (>= minSamples labels and FP rate >= fpThreshold).
func (c *Calibrator) Suppresses(h RuleHealth) bool {
	return h.Samples() >= c.minSamples && h.FPRate() >= c.fpThreshold
}

// MinSamples and FPThreshold expose the calibration thresholds (for reporting).
func (c *Calibrator) MinSamples() int      { return c.minSamples }
func (c *Calibrator) FPThreshold() float64 { return c.fpThreshold }

// AutoResolve returns a false-positive verdict (and true) when the finding's
// rule is chronically noisy enough to resolve without an LLM. Otherwise false.
func (c *Calibrator) AutoResolve(f model.Finding) (model.Verdict, bool) {
	h, ok := c.health[ruleKey(f.Tool, f.RuleID)]
	if !ok || h.Samples() < c.minSamples || h.FPRate() < c.fpThreshold {
		return model.Verdict{}, false
	}
	return model.Verdict{
		Classification: model.ClassFalsePositive,
		Confidence:     h.FPRate(),
		Exploitability: model.ExploitUnknown,
		Reasoning: fmt.Sprintf("auto-resolved by calibration: rule %s ruled false-positive in %d/%d prior reviews",
			f.RuleID, h.FP, h.Samples()),
	}, true
}

func ruleKey(tool, ruleID string) string { return tool + "|" + ruleID }
