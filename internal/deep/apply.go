package deep

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// Apply folds a deep verification into a finding. It always records the outcome on
// f.Deep and only ever touches f.Verdict; it never changes f.Severity.
//
// The merge is asymmetric on purpose, because the two mistakes cost differently: a
// confirmed finding that is not real wastes an analyst's time, a dismissed finding
// that is real ships the bug, and the deep pass is still one model's judgment
// reading text an attacker may have written.
//
//   - Aborted or uncertain: the verdict is left alone.
//   - true_positive: confirms, freely. The finding becomes a true positive (an
//     earlier dismissal, refutation or "not reachable" call is lifted) and the
//     confidence never drops below an earlier true-positive's.
//   - false_positive: supports dismissal only if ALL of these hold: confidence is at
//     least model.DismissFloor; at least one evidence reference survived the check
//     that a tool showed the model that file; at least one tool call was made; and
//     the finding is not a credential finding. Even then:
//   - an earlier high-confidence true positive is not overruled. The verdict
//     becomes "uncertain" (never dismissed), and the disagreement is stated in
//     Reasoning;
//   - an earlier verdict the adversarial judge overturned stays surfaced;
//   - otherwise the verdict becomes a confident false positive, which is what
//     PartitionDismissed acts on.
func Apply(f *model.Finding, d model.DeepVerification) {
	rec := d
	rec.Evidence = append([]string(nil), d.Evidence...)
	rec.Trace = append([]string(nil), d.Trace...)
	f.Deep = &rec

	if d.Aborted != "" {
		return
	}
	switch d.Conclusion {
	case model.ClassTruePositive:
		confirm(f, d)
	case model.ClassFalsePositive:
		if !supportsDismissal(f, d) {
			return
		}
		dismiss(f, d)
	}
}

// supportsDismissal reports whether d is strong enough to count as a reason to
// dismiss at all.
func supportsDismissal(f *model.Finding, d model.DeepVerification) bool {
	return d.Conclusion == model.ClassFalsePositive &&
		!f.IsSecret() &&
		!f.IsDependencyAdvisory() &&
		d.Aborted == "" &&
		d.Confidence >= model.DismissFloor &&
		len(d.Evidence) > 0 &&
		d.Steps >= 1
}

func confirm(f *model.Finding, d model.DeepVerification) {
	v := model.Verdict{Exploitability: model.ExploitUnknown}
	prior := f.Verdict
	if prior != nil {
		v = *prior
	}
	if prior != nil && prior.Classification == model.ClassTruePositive && prior.Confidence > d.Confidence {
		v.Confidence = prior.Confidence
	} else {
		v.Confidence = d.Confidence
	}
	v.Classification = model.ClassTruePositive
	v.Refuted, v.RefuteSupported = false, false // the deep pass read the code the judge only reasoned about
	if v.Exploitability == model.ExploitNotReachable {
		v.Exploitability = model.ExploitUnknown
	}
	v.Reasoning = deepNote("confirms", d) + priorNote(prior)
	v.NormalizeDetail() // an earlier uncertain verdict's open questions no longer apply
	f.Verdict = &v
}

func dismiss(f *model.Finding, d model.DeepVerification) {
	prior := f.Verdict
	if prior == nil {
		f.Verdict = &model.Verdict{
			Classification: model.ClassFalsePositive, Confidence: d.Confidence,
			Exploitability: model.ExploitNotReachable, Reasoning: deepNote("finds a false positive", d),
		}
		return
	}
	v := *prior
	switch {
	case prior.HighConfidence():
		// Two reviews disagree and the earlier one was sure: a human decides.
		v.Classification = model.ClassUncertain
		v.Confidence = min(prior.Confidence, d.Confidence)
		v.Exploitability = model.ExploitUnknown
		v.Reasoning = deepNote("DISAGREES with the earlier true-positive verdict and argues false positive", d) +
			priorNote(prior) + " | Left uncertain and surfaced for a human."
	case prior.Overturned:
		// The judge already argued this finding is real; the deep pass does not
		// outvote it. Stays surfaced.
		v.Reasoning = deepNote("argues false positive but the adversarial judge had overturned that call", d) + priorNote(prior)
	default:
		v.Classification = model.ClassFalsePositive
		if prior.Classification == model.ClassFalsePositive && prior.Confidence > d.Confidence {
			v.Confidence = prior.Confidence
		} else {
			v.Confidence = d.Confidence
		}
		v.Refuted, v.RefuteSupported = false, false
		v.Exploitability = model.ExploitNotReachable
		v.Reasoning = deepNote("finds a false positive", d) + priorNote(prior)
	}
	v.NormalizeDetail() // keep only the detail that fits the merged classification
	f.Verdict = &v
}

func deepNote(what string, d model.DeepVerification) string {
	s := fmt.Sprintf("Deep verification (%d tool call(s), confidence %.2f) %s: %s", d.Steps, d.Confidence, what, strings.TrimSpace(d.Reasoning))
	if len(d.Evidence) > 0 {
		s += " [evidence: " + strings.Join(d.Evidence, ", ") + "]"
	}
	return s
}

func priorNote(prior *model.Verdict) string {
	if prior == nil {
		return ""
	}
	r := strings.TrimSpace(prior.Reasoning)
	if len(r) > 400 {
		r = capBytes(r, 400, " …")
	}
	return fmt.Sprintf(" | Earlier review: %s (confidence %.2f): %s", prior.Classification, prior.Confidence, r)
}

// needsAttention reports whether an existing verdict is the kind a deep look can
// improve: undecided, shaky, or contested by the adversarial judge.
func needsAttention(v *model.Verdict) bool {
	return v == nil || v.Classification == model.ClassUncertain || v.Confidence < model.DismissFloor ||
		v.Overturned || v.Refuted
}

// Select returns the indices of up to n findings worth a deep look, in the order
// they should be verified. Priority, highest first:
//
//  1. critical and high severity, most severe first (within a severity, findings
//     whose verdict is missing or contested come before settled ones);
//  2. any other finding whose verdict is uncertain, low-confidence, refuted or
//     overturned by the judge;
//  3. any other finding with no verdict.
//
// Never selected: credential findings (their content must not reach a model),
// dependency advisories (a known CVE is not settled by reading the project's code
// for a sink, and they would otherwise take every slot: they are often the most
// severe findings in a scan),
// shadow-rule findings (they do not gate), findings already deep-verified, and
// settled medium/low findings. The order is stable: ties keep scan order.
func Select(findings []model.Finding, n int) []int {
	return SelectBy(findings, n, nil)
}

// SelectBy is Select with a review priority: within each tier, findings are taken
// highest priority first, then most severe. priority(f) must be the severity rank
// when it knows nothing more about f (see surface.Risk), so a nil priority, or one
// that adds nothing, gives exactly Select's order. It never changes which findings
// qualify or which tier they fall in.
func SelectBy(findings []model.Finding, n int, priority func(*model.Finding) float64) []int {
	if n <= 0 {
		return nil
	}
	type cand struct {
		idx, tier, sev, attn int
		prio                 float64
	}
	var cs []cand
	for i := range findings {
		f := &findings[i]
		if f.IsSecret() || f.IsDependencyAdvisory() || f.Shadow || f.Deep != nil {
			continue
		}
		c := cand{idx: i, sev: f.Severity.Rank(), prio: float64(f.Severity.Rank())}
		if priority != nil {
			c.prio = priority(f)
		}
		switch {
		case c.sev >= model.SeverityHigh.Rank():
			c.tier = 0
			if !needsAttention(f.Verdict) {
				c.attn = 1
			}
		case f.Verdict != nil && needsAttention(f.Verdict):
			c.tier = 1
		case f.Verdict == nil:
			c.tier = 2
		default:
			continue
		}
		cs = append(cs, c)
	}
	if len(cs) == 0 {
		return nil
	}
	sort.SliceStable(cs, func(a, b int) bool {
		x, y := cs[a], cs[b]
		if x.tier != y.tier {
			return x.tier < y.tier
		}
		if x.prio != y.prio {
			return x.prio > y.prio
		}
		if x.sev != y.sev {
			return x.sev > y.sev
		}
		return x.attn < y.attn
	})
	if len(cs) > n {
		cs = cs[:n]
	}
	out := make([]int, len(cs))
	for i, c := range cs {
		out[i] = c.idx
	}
	return out
}
