package research

import (
	"context"
	"fmt"
)

// Engine orchestrates the research loop: dedup targets, research each, synthesize
// rules, gate them, and admit or quarantine. Research is best-effort — a failing
// target or issue is skipped, never fatal (DESIGN.md §9.5).
type Engine struct {
	agent      Agent
	synth      Synthesizer
	validator  Validator
	repo       *RuleRepo
	maxTargets int // budget cap; 0 = unlimited
}

func NewEngine(agent Agent, synth Synthesizer, validator Validator, repo *RuleRepo, maxTargets int) *Engine {
	return &Engine{agent: agent, synth: synth, validator: validator, repo: repo, maxTargets: maxTargets}
}

// Run researches the given targets and returns a tally. Targets are deduped by
// Key() so the same tech@version isn't researched twice in one run.
func (e *Engine) Run(ctx context.Context, runID string, targets []Target) (Summary, error) {
	var sum Summary
	seen := map[string]bool{}

	for _, t := range targets {
		if e.maxTargets > 0 && sum.TargetsResearched >= e.maxTargets {
			break // budget cap
		}
		if seen[t.Key()] {
			continue
		}
		seen[t.Key()] = true
		sum.TargetsResearched++

		issues, err := e.agent.Research(ctx, t)
		if err != nil {
			continue
		}
		sum.IssuesFound += len(issues)

		for _, iss := range issues {
			rule, err := e.synth.Synthesize(ctx, iss)
			if err != nil {
				continue
			}
			sum.RulesGenerated++

			res, err := e.validator.Validate(ctx, rule)
			if err != nil {
				_ = e.repo.Quarantine(runID, rule, res, fmt.Sprintf("validation error: %v", err))
				sum.Quarantined++
				continue
			}
			if ok, reason := Admit(res); ok {
				_ = e.repo.Admit(runID, rule, res)
				sum.Admitted++
			} else {
				_ = e.repo.Quarantine(runID, rule, res, reason)
				sum.Quarantined++
			}
		}
	}
	return sum, nil
}
