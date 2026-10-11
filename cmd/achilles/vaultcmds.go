package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/metrics"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// runRuleHealth prints per-rule TP/FP health accumulated from analyst feedback,
// so you can see which rules are noisy (auto-suppressed) vs. high-yield. No scan.
func runRuleHealth(ctx context.Context, opts vault.Options) error {
	ev, err := vault.Open(ctx, opts)
	if err != nil {
		return err
	}
	pol := knowledge.DefaultPolicy
	cal := knowledge.NewCalibrator(knowledge.NewFeedbackStore(ev), pol, time.Now())
	rules := cal.Rules()
	if len(rules) == 0 {
		fmt.Println("No analyst feedback recorded yet — rule health builds up as findings are labeled (--feedback).")
		return nil
	}

	labeled := 0
	for _, h := range rules {
		labeled += h.Samples()
	}
	fmt.Printf("Rule health (%d distinct labeled finding(s) across %d rule(s), labels from the last %d days).\n"+
		"With --calibrate, a rule with >=%d labeled findings and >=%.0f%% of them false positive has its findings\n"+
		"ruled out without a model review (never above %s severity). Without --calibrate nothing is auto-dismissed.\n\n",
		labeled, len(rules), int(pol.MaxAge.Hours()/24), pol.MinFindings, pol.FPThreshold*100, pol.MaxSeverity)
	fmt.Printf("  %-40s %4s %4s %8s %8s  %s\n", "TOOL/RULE", "TP", "FP", "SAMPLES", "FP-RATE", "STATUS")
	for _, h := range rules {
		status := "healthy"
		switch {
		case cal.Suppresses(h):
			status = "noisy: --calibrate would rule it out"
		case h.FP > 0:
			status = "watch"
		}
		fmt.Printf("  %-40s %4d %4d %8d %7.0f%%  %s\n",
			truncate(h.Tool+"/"+h.RuleID, 40), h.TP, h.FP, h.Samples(), h.FPRate()*100, status)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

// runMetrics prints a fleet rollup over the whole Evidence Vault (findings by
// severity/tool/rule/target, feedback FP rate, LLM spend). Pure read — the
// read-side of fleet aggregation; no scan.
func runMetrics(ctx context.Context, opts vault.Options) error {
	ev, err := vault.Open(ctx, opts)
	if err != nil {
		return err
	}
	s := metrics.Compute(ev.All(), 10)
	if s.Runs == 0 {
		fmt.Println("No scans recorded in the vault yet.")
		return nil
	}

	fmt.Printf("Fleet metrics (%d run(s) across %d target(s)):\n\n", s.Runs, s.Targets)
	fmt.Printf("  Findings: %d (%d unique)\n", s.TotalFindings, s.UniqueFindings)
	fmt.Printf("  By severity: %s\n", kvLine(s.BySeverity, []string{"critical", "high", "medium", "low", "unknown"}))
	fmt.Printf("  By tool:     %s\n", kvLineSorted(s.ByTool))
	if len(s.ByTarget) > 1 {
		fmt.Printf("  By target:   %s\n", kvLineSorted(s.ByTarget))
	}
	if len(s.TopRules) > 0 {
		fmt.Printf("  Top rules:   ")
		for i, rc := range s.TopRules {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s(%d)", rc.Rule, rc.Count)
		}
		fmt.Println()
	}
	if s.TP+s.FP > 0 {
		fmt.Printf("  Feedback:    %d TP, %d FP (%.0f%% FP rate)\n", s.TP, s.FP, s.FPRate()*100)
	}
	if s.LLMTokens > 0 {
		fmt.Printf("  LLM tokens:  %d\n", s.LLMTokens)
	}
	return nil
}

// kvLine formats selected keys (in the given order) as "k=v" for present keys.
func kvLine(m map[string]int, order []string) string {
	var parts []string
	for _, k := range order {
		if v := m[k]; v > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

// kvLineSorted formats a map as "k=v" sorted by descending value.
func kvLineSorted(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprintf("%s=%d", it.k, it.v)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

// runFeedback records an analyst's ground-truth label for a finding, looking up
// its tool/rule from the vault so calibration can group by rule.
func runFeedback(ctx context.Context, opts vault.Options, runID, fingerprint, label, note string) error {
	var lbl knowledge.Label
	switch label {
	case "tp", "true_positive":
		lbl = knowledge.LabelTP
	case "fp", "false_positive":
		lbl = knowledge.LabelFP
	default:
		return fmt.Errorf("--label must be tp or fp (got %q)", label)
	}

	ev, err := vault.Open(ctx, opts)
	if err != nil {
		return err
	}

	tool, rule := "", ""
	for _, r := range ev.ByFingerprint(fingerprint) {
		if r.Kind == vault.KindFinding {
			var f model.Finding
			if json.Unmarshal(r.Payload, &f) == nil {
				tool, rule = f.Tool, f.RuleID
			}
			break
		}
	}

	fb := knowledge.NewFeedbackStore(ev)
	if err := fb.Record(runID, knowledge.Feedback{Fingerprint: fingerprint, Tool: tool, RuleID: rule, Label: lbl, Note: note}); err != nil {
		return err
	}
	fmt.Printf("recorded %s feedback for %s (%s/%s)\n", lbl, fingerprint, tool, rule)
	return nil
}
