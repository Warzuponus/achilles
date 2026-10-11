// Package metrics rolls up the Evidence Vault into a fleet-level summary
// (DESIGN §11): findings by severity/tool/rule/target, the analyst
// feedback FP rate, and LLM token spend. It's a pure read over the vault — the
// read-side of fleet aggregation — so it works on a single file-backed vault or
// a shared PostgreSQL vault holding many targets/projects alike.
package metrics

import (
	"encoding/json"
	"sort"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// RuleCount is a rule id and how many findings it produced.
type RuleCount struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// Summary is the aggregated view of a vault.
type Summary struct {
	Runs           int            `json:"runs"`
	Targets        int            `json:"targets"`
	TotalFindings  int            `json:"totalFindings"`  // finding records (across all runs)
	UniqueFindings int            `json:"uniqueFindings"` // distinct fingerprints
	BySeverity     map[string]int `json:"bySeverity"`
	ByTool         map[string]int `json:"byTool"`
	ByTarget       map[string]int `json:"byTarget"`
	TopRules       []RuleCount    `json:"topRules"`
	TP             int            `json:"truePositives"`
	FP             int            `json:"falsePositives"`
	LLMTokens      int            `json:"llmTokens"`
}

// FPRate is the confirmed false-positive rate over labeled findings (0 if none).
func (s Summary) FPRate() float64 {
	if s.TP+s.FP == 0 {
		return 0
	}
	return float64(s.FP) / float64(s.TP+s.FP)
}

// FPPercent is FPRate as a rounded whole percent (for display/templates).
func (s Summary) FPPercent() int { return int(s.FPRate()*100 + 0.5) }

// Compute aggregates vault records into a Summary. topRules caps the TopRules list.
func Compute(recs []vault.Record, topRulesN int) Summary {
	s := Summary{BySeverity: map[string]int{}, ByTool: map[string]int{}, ByTarget: map[string]int{}}

	// Pass 1: run -> target (from scan-meta), and count distinct scan runs. Only
	// scan-meta-bearing run IDs count as "runs" — a scan always writes scan-meta,
	// while standalone actions (e.g. --feedback) get a run ID but no scan-meta and
	// must not inflate the count.
	runTarget := map[string]string{}
	runs := map[string]bool{}
	for _, r := range recs {
		if r.Kind != vault.KindScanMeta || r.RunID == "" {
			continue
		}
		runs[r.RunID] = true
		var m struct {
			Target string `json:"target"`
		}
		if json.Unmarshal(r.Payload, &m) == nil && m.Target != "" {
			runTarget[r.RunID] = m.Target
		}
	}

	// Pass 2: findings, feedback, LLM usage.
	rules := map[string]int{}
	fps := map[string]bool{}
	for _, r := range recs {
		switch r.Kind {
		case vault.KindFinding:
			var f model.Finding
			if json.Unmarshal(r.Payload, &f) != nil {
				continue
			}
			s.TotalFindings++
			s.BySeverity[string(f.Severity)]++
			if f.Tool != "" {
				s.ByTool[f.Tool]++
			}
			rules[f.RuleID]++
			if r.Fingerprint != "" {
				fps[r.Fingerprint] = true
			}
			if t := runTarget[r.RunID]; t != "" {
				s.ByTarget[t]++
			}
		case vault.KindFeedback:
			var fb knowledge.Feedback
			if json.Unmarshal(r.Payload, &fb) == nil {
				switch fb.Label {
				case knowledge.LabelTP:
					s.TP++
				case knowledge.LabelFP:
					s.FP++
				}
			}
		case vault.KindScanMeta:
			if r.Source == "llm-usage" {
				var u struct {
					Total int `json:"totalTokens"`
				}
				if json.Unmarshal(r.Payload, &u) == nil {
					s.LLMTokens += u.Total
				}
			}
		}
	}

	s.Runs = len(runs)
	s.UniqueFindings = len(fps)
	targets := map[string]bool{}
	for _, t := range runTarget {
		targets[t] = true
	}
	s.Targets = len(targets)
	s.TopRules = topN(rules, topRulesN)
	return s
}

// TenantSummary is one tenant's rollup within a fleet.
type TenantSummary struct {
	Tenant  string  `json:"tenant"`
	Summary Summary `json:"summary"`
}

// FleetSummary is the cross-tenant rollup: fleet-wide totals plus a per-tenant
// breakdown. It's the read-side of fleet scanning.
type FleetSummary struct {
	Tenants  int             `json:"tenants"`
	Totals   Summary         `json:"totals"`
	ByTenant []TenantSummary `json:"byTenant"`
}

// ComputeFleet rolls up per-tenant vault records into fleet-wide totals plus a
// per-tenant breakdown. perTenant maps tenant id -> that tenant's records
// (the caller fetches them via the tenant registry + per-tenant vaults, so
// isolation is preserved — this just aggregates the reads).
func ComputeFleet(perTenant map[string][]vault.Record, topRulesN int) FleetSummary {
	fs := FleetSummary{Tenants: len(perTenant)}
	var all []vault.Record
	for id, recs := range perTenant {
		fs.ByTenant = append(fs.ByTenant, TenantSummary{Tenant: id, Summary: Compute(recs, topRulesN)})
		all = append(all, recs...)
	}
	fs.Totals = Compute(all, topRulesN)
	sort.Slice(fs.ByTenant, func(i, j int) bool { return fs.ByTenant[i].Tenant < fs.ByTenant[j].Tenant })
	return fs
}

func topN(m map[string]int, n int) []RuleCount {
	out := make([]RuleCount, 0, len(m))
	for k, v := range m {
		out = append(out, RuleCount{Rule: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Rule < out[j].Rule
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
