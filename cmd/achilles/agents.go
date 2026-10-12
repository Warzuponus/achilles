package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/research"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/generic"
	"github.com/Warzuponus/achilles/internal/threatmodel"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// runSBOM generates a CycloneDX SBOM of the target with Syft and writes it to
// outPath. Syft produces an inventory artifact, not findings, so it runs outside
// the scan/normalize pipeline; it reuses the generic runner (mounts + output
// file) and its raw output IS the SBOM. The SBOM is also recorded to the vault.
func runSBOM(ctx context.Context, runner xexec.Runner, cfg *config.Config, gate policy.Gate, target, outPath string, ev vault.Store, runID string) error {
	var tc config.ToolConfig
	found := false
	for _, t := range cfg.Tools {
		if t.ID == "syft" {
			tc, found = t, true
			break
		}
	}
	if !found {
		return fmt.Errorf("--sbom needs a 'syft' entry in the tool config")
	}
	if err := gate.Allow(tc.ToLicense()); err != nil {
		return fmt.Errorf("syft: %w", err)
	}

	raw, err := generic.New(runner, tc, "").Run(ctx, scanner.Target{Path: target})
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, raw.Data, 0o600); err != nil {
		return err
	}
	recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindSBOM, Source: "syft"},
		map[string]any{"format": "cyclonedx-json", "sbom": json.RawMessage(raw.Data)})
	fmt.Fprintf(os.Stderr, "achilles: SBOM — %d component(s) (cyclonedx-json) -> %s\n", sbomComponentCount(raw.Data), outPath)
	return nil
}

// runReview runs the holistic full-repo security review agent over the codebase
// profile + surfaced findings and prints its assessment (also recorded to the
// vault). It uses the "review" router task, so --model-config can point it at a
// stronger model than triage.
func runReview(ctx context.Context, ev vault.Store, runID, target string, scan model.Scan, baseURL, llmModel string, tasks map[string]llm.TaskModel) (*review.Review, error) {
	if llmModel == "" {
		return nil, fmt.Errorf("--review requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return nil, err
	}
	router := llm.BuildRouter(factory(baseURL, llmModel), tasks, baseURL, factory)

	inv, err := inventoryOf(target)
	if err != nil {
		return nil, err
	}
	r, err := review.NewEngine(router, ev).Review(ctx, runID, inv, scan)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\nSecurity review:\n  %s\n", r.Summary)
	for _, risk := range r.Risks {
		fmt.Printf("\n  [%s] %s (%s)\n    %s\n    -> %s\n",
			risk.Severity, risk.Title, risk.Area, risk.Rationale, risk.Recommendation)
	}
	fmt.Fprintf(os.Stderr, "achilles: review — %d systemic risk(s)\n", len(r.Risks))
	return r, nil
}

// runAdvisor runs the SCA dependency-upgrade advisor over the inventory + SCA
// findings and prints a merge-safety-scored upgrade plan (also recorded to the
// vault). Uses the "sca" router task.
func runAdvisor(ctx context.Context, ev vault.Store, runID, target string, scan model.Scan, baseURL, llmModel string, tasks map[string]llm.TaskModel) (*advisor.Advice, error) {
	if llmModel == "" {
		return nil, fmt.Errorf("--sca-advice requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return nil, err
	}
	router := llm.BuildRouter(factory(baseURL, llmModel), tasks, baseURL, factory)

	inv, err := inventoryOf(target)
	if err != nil {
		return nil, err
	}
	a, err := advisor.NewEngine(router, ev).Advise(ctx, runID, inv, scan)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\nDependency upgrade advice:\n  %s\n", a.Summary)
	for _, u := range a.Upgrades {
		sec := ""
		if u.SecurityDriven {
			sec = " [security]"
		}
		target := u.CurrentVersion
		if u.RecommendedVersion != "" {
			target = u.CurrentVersion + " -> " + u.RecommendedVersion
		}
		fmt.Printf("\n  %s (%s)%s\n    %s | merge-risk: %s\n    %s\n",
			u.Package, target, sec, u.UpgradeType, u.MergeRisk, u.Rationale)
	}
	fmt.Fprintf(os.Stderr, "achilles: sca-advice — %d upgrade(s) advised\n", len(a.Upgrades))
	return a, nil
}

// runThreatModel infers an OTM threat model over the codebase profile + findings
// and writes it to outPath (also recorded to the vault). Uses the "threat-model"
// router task.
func runThreatModel(ctx context.Context, ev vault.Store, runID, target string, scan model.Scan, outPath, baseURL, llmModel string, tasks map[string]llm.TaskModel) (*threatmodel.ThreatModel, error) {
	if llmModel == "" {
		return nil, fmt.Errorf("--threat-model requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return nil, err
	}
	router := llm.BuildRouter(factory(baseURL, llmModel), tasks, baseURL, factory)

	inv, err := inventoryOf(target)
	if err != nil {
		return nil, err
	}
	tm, err := threatmodel.NewEngine(router, ev).Generate(ctx, runID, target, inv, scan)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "achilles: threat-model — %d component(s), %d threat(s) (OTM) -> %s\n",
		len(tm.Components), len(tm.Threats), outPath)
	return tm, nil
}

// sbomComponentCount reports how many components a CycloneDX SBOM lists.
func sbomComponentCount(data []byte) int {
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(data, &doc)
	return len(doc.Components)
}

// runResearch runs the §9 research loop: inventory the target, research each
// dependency, synthesize Opengrep rules, and admit only those that pass the
// validation gate — growing the generated-rule repository.
func runResearch(ctx context.Context, ev vault.Store, runID, target, repoDir string, maxTargets int, runner xexec.Runner, baseURL, model string, tasks map[string]llm.TaskModel) error {
	if model == "" {
		return fmt.Errorf("--research requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	inv, err := inventoryOf(target)
	if err != nil {
		return err
	}
	targets := make([]research.Target, 0, len(inv.Dependencies))
	for _, d := range inv.Dependencies {
		targets = append(targets, research.Target{Tech: d.Name, Version: d.Version, Ecosystem: d.Ecosystem})
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "achilles: research: no dependencies discovered")
		return nil
	}

	factory, err := newLLMFactory()
	if err != nil {
		return err
	}
	client := llm.BuildRouter(factory(baseURL, model), tasks, baseURL, factory).For("research")
	now := func() string { return time.Now().UTC().Format("2006-01-02") }

	eng := research.NewEngine(
		research.NewLLMAgent(client),
		research.NewLLMSynthesizer(client, now),
		research.NewOpengrepValidator(runner),
		research.NewRuleRepo(repoDir, ev),
		maxTargets,
	)
	sum, err := eng.Run(ctx, runID, targets)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"achilles: research — %d target(s), %d issue(s), %d rule(s): %d admitted, %d quarantined (repo: %s)\n",
		sum.TargetsResearched, sum.IssuesFound, sum.RulesGenerated, sum.Admitted, sum.Quarantined, repoDir)
	return nil
}

// runMiner distills durable Opengrep rules from analyst-confirmed (true-positive)
// findings in the vault: synthesize → §9.3 validation gate → RuleRepo. Admitted
// rules then flow into future scans via the flywheel + shadow window. Same
// safety net as research; the source is our own confirmed findings, not intel.
func runMiner(ctx context.Context, ev vault.Store, runID, repoDir string, max int, runner xexec.Runner, baseURL, model string, tasks map[string]llm.TaskModel) error {
	if model == "" {
		return fmt.Errorf("--mine-rules requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	seeds := confirmedIssues(ev)
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "achilles: mine-rules — no analyst-confirmed findings to mine yet (label true positives via --feedback)")
		return nil
	}

	factory, err := newLLMFactory()
	if err != nil {
		return err
	}
	client := llm.BuildRouter(factory(baseURL, model), tasks, baseURL, factory).For("mine-rules")
	now := func() string { return time.Now().UTC().Format("2006-01-02") }
	miner := research.NewMiner(
		research.NewLLMSynthesizer(client, now),
		research.NewOpengrepValidator(runner),
		research.NewRuleRepo(repoDir, ev),
		max,
	)
	sum, err := miner.Mine(ctx, runID, seeds)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "achilles: mine-rules — %d seed(s): %d admitted, %d quarantined (repo: %s)\n",
		sum.Seeds, sum.Admitted, sum.Quarantined, repoDir)
	return nil
}

// confirmedIssues turns the vault's analyst-confirmed (TP) findings into mining
// seeds. It skips findings from already-generated rules (gen.*) and those whose
// language can't be inferred (the synthesizer + validator need a language).
func confirmedIssues(ev vault.Store) []research.Issue {
	fb := knowledge.NewFeedbackStore(ev)
	seen := map[string]bool{}
	var issues []research.Issue
	for _, f := range fb.All() {
		if f.Label != knowledge.LabelTP || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		finding, ok := findingByFingerprint(ev, f.Fingerprint)
		if !ok {
			continue
		}
		lang := langForFile(finding.Location.File)
		if lang == "" || strings.HasPrefix(finding.RuleID, "gen.") {
			continue
		}
		desc := strings.TrimSpace(finding.Message)
		if finding.CodeContext != "" {
			desc += "\n\nConfirmed vulnerable code:\n" + finding.CodeContext
		}
		cwe := ""
		if len(finding.CWE) > 0 {
			cwe = finding.CWE[0]
		}
		issues = append(issues, research.Issue{
			Title:       finding.RuleID + ": analyst-confirmed vulnerability",
			Description: desc,
			Citation:    "internal: analyst-confirmed finding " + f.Fingerprint,
			CWE:         cwe,
			Language:    lang,
		})
	}
	return issues
}

func findingByFingerprint(ev vault.Store, fp string) (model.Finding, bool) {
	for _, rec := range ev.ByFingerprint(fp) {
		if rec.Kind == vault.KindFinding {
			var f model.Finding
			if json.Unmarshal(rec.Payload, &f) == nil {
				return f, true
			}
		}
	}
	return model.Finding{}, false
}

// langForFile infers the source language from a file extension (for rule
// synthesis). "" when unknown.
func langForFile(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".php":
		return "php"
	default:
		return ""
	}
}
