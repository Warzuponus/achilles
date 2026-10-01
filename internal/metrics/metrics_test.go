package metrics

import (
	"encoding/json"
	"testing"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

func rec(kind vault.Kind, runID, source, fp string, payload any) vault.Record {
	b, _ := json.Marshal(payload)
	return vault.Record{Kind: kind, RunID: runID, Source: source, Fingerprint: fp, Payload: b}
}

func TestCompute(t *testing.T) {
	recs := []vault.Record{
		// Two runs over two targets.
		rec(vault.KindScanMeta, "r1", "", "", map[string]any{"target": "/repo/a"}),
		rec(vault.KindScanMeta, "r2", "", "", map[string]any{"target": "/repo/b"}),
		// r1 (target a): 2 findings, gosec.
		rec(vault.KindFinding, "r1", "gosec", "fp1", model.Finding{Tool: "gosec", RuleID: "G201", Severity: model.SeverityHigh}),
		rec(vault.KindFinding, "r1", "gosec", "fp2", model.Finding{Tool: "gosec", RuleID: "G404", Severity: model.SeverityMedium}),
		// r2 (target b): 1 finding, opengrep; same rule G201 as r1 to test aggregation.
		rec(vault.KindFinding, "r2", "opengrep", "fp3", model.Finding{Tool: "opengrep", RuleID: "G201", Severity: model.SeverityHigh}),
		// Feedback: 1 TP, 1 FP.
		rec(vault.KindFeedback, "r1", "", "fp1", knowledge.Feedback{Fingerprint: "fp1", Label: knowledge.LabelTP}),
		rec(vault.KindFeedback, "r1", "", "fp2", knowledge.Feedback{Fingerprint: "fp2", Label: knowledge.LabelFP}),
		// LLM usage across two runs.
		rec(vault.KindScanMeta, "r1", "llm-usage", "", map[string]any{"totalTokens": 1000}),
		rec(vault.KindScanMeta, "r2", "llm-usage", "", map[string]any{"totalTokens": 500}),
		// A standalone action gets its own run ID but writes no scan-meta; it must
		// NOT count as a run (only scan-meta-bearing run IDs are scans).
		rec(vault.KindLLMCall, "standalone-run", "", "", map[string]any{}),
	}

	s := Compute(recs, 5)

	if s.Runs != 2 || s.Targets != 2 {
		t.Errorf("runs/targets: got %d/%d want 2/2 (feedback-only run must not count)", s.Runs, s.Targets)
	}
	if s.TotalFindings != 3 || s.UniqueFindings != 3 {
		t.Errorf("findings: got total=%d unique=%d want 3/3", s.TotalFindings, s.UniqueFindings)
	}
	if s.BySeverity["high"] != 2 || s.BySeverity["medium"] != 1 {
		t.Errorf("bySeverity wrong: %+v", s.BySeverity)
	}
	if s.ByTool["gosec"] != 2 || s.ByTool["opengrep"] != 1 {
		t.Errorf("byTool wrong: %+v", s.ByTool)
	}
	if s.ByTarget["/repo/a"] != 2 || s.ByTarget["/repo/b"] != 1 {
		t.Errorf("byTarget wrong: %+v", s.ByTarget)
	}
	// G201 (2) should rank above G404 (1).
	if len(s.TopRules) != 2 || s.TopRules[0].Rule != "G201" || s.TopRules[0].Count != 2 {
		t.Errorf("topRules wrong: %+v", s.TopRules)
	}
	if s.TP != 1 || s.FP != 1 || s.FPRate() != 0.5 {
		t.Errorf("feedback wrong: tp=%d fp=%d rate=%.2f", s.TP, s.FP, s.FPRate())
	}
	if s.LLMTokens != 1500 {
		t.Errorf("llm tokens: got %d want 1500", s.LLMTokens)
	}
}

func TestCompute_Empty(t *testing.T) {
	s := Compute(nil, 5)
	if s.Runs != 0 || s.TotalFindings != 0 || s.FPRate() != 0 {
		t.Errorf("empty vault should be all-zero, got %+v", s)
	}
}

func TestComputeFleet(t *testing.T) {
	acme := []vault.Record{
		rec(vault.KindScanMeta, "r1", "", "", map[string]any{"target": "/acme/api"}),
		rec(vault.KindFinding, "r1", "gosec", "fp1", model.Finding{Tool: "gosec", RuleID: "G201", Severity: model.SeverityHigh}),
		rec(vault.KindFinding, "r1", "gosec", "fp2", model.Finding{Tool: "gosec", RuleID: "G404", Severity: model.SeverityLow}),
	}
	globex := []vault.Record{
		rec(vault.KindScanMeta, "r2", "", "", map[string]any{"target": "/globex/svc"}),
		rec(vault.KindFinding, "r2", "opengrep", "fp3", model.Finding{Tool: "opengrep", RuleID: "X1", Severity: model.SeverityHigh}),
	}
	fs := ComputeFleet(map[string][]vault.Record{"acme": acme, "globex": globex}, 5)

	if fs.Tenants != 2 {
		t.Fatalf("tenants: got %d want 2", fs.Tenants)
	}
	// Totals aggregate across tenants.
	if fs.Totals.TotalFindings != 3 || fs.Totals.Targets != 2 || fs.Totals.BySeverity["high"] != 2 {
		t.Errorf("totals wrong: %+v", fs.Totals)
	}
	// Per-tenant breakdown, sorted by tenant id (acme before globex).
	if len(fs.ByTenant) != 2 || fs.ByTenant[0].Tenant != "acme" || fs.ByTenant[1].Tenant != "globex" {
		t.Fatalf("byTenant order/keys wrong: %+v", fs.ByTenant)
	}
	if fs.ByTenant[0].Summary.TotalFindings != 2 || fs.ByTenant[1].Summary.TotalFindings != 1 {
		t.Errorf("per-tenant counts wrong: %+v", fs.ByTenant)
	}
}
