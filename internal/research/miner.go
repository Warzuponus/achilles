package research

import "context"

// MineSummary tallies a mining run.
type MineSummary struct {
	Seeds       int
	Admitted    int
	Quarantined int
}

// Miner distills durable Opengrep rules from confirmed (analyst-labeled true
// positive) findings — the same synthesize → §9.3 validation-gate → RuleRepo
// pipeline as the research agents (§9), but sourced from OUR own confirmed
// findings instead of external threat intel. Admitted rules then flow into
// future scans via the rule flywheel + shadow window (§9.4).
//
// The validation gate is the shared safety net: a mined rule is admitted only if
// it parses, matches its vulnerable fixture, and does NOT match the patched one —
// so a bad mine is quarantined, never auto-run.
type Miner struct {
	synth     Synthesizer
	validator Validator
	repo      *RuleRepo
	max       int
}

// NewMiner wires a miner. max caps how many seeds are processed per run (budget).
func NewMiner(s Synthesizer, v Validator, r *RuleRepo, max int) *Miner {
	return &Miner{synth: s, validator: v, repo: r, max: max}
}

// Mine synthesizes and gate-validates a rule for each seed (an Issue derived from
// a confirmed finding), admitting passers and quarantining the rest.
func (m *Miner) Mine(ctx context.Context, runID string, seeds []Issue) (MineSummary, error) {
	var sum MineSummary
	for i, iss := range seeds {
		if i >= m.max {
			break
		}
		sum.Seeds++
		rule, err := m.synth.Synthesize(ctx, iss)
		if err != nil {
			continue
		}
		if res, ok, reason := Judge(ctx, m.validator, rule); ok {
			if err := m.repo.Admit(runID, rule, res); err == nil {
				sum.Admitted++
			}
		} else {
			if err := m.repo.Quarantine(runID, rule, res, reason); err == nil {
				sum.Quarantined++
			}
		}
	}
	return sum, nil
}
