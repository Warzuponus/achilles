// Command achilles orchestrates open-source SAST tools, normalizes their SARIF
// to Findings, records provenance to the Evidence Vault, and prints a report.
//
// Phase 1: config-driven tool registry (configs/tools.yaml) + license-mode
// policy gate + Evidence Vault. A --from-sarif mode ingests existing SARIF,
// exercising the normalize→report spine without running any scanner.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "achilles: "+err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	o, err := parseFlags(argv)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	runID := newRunID()

	vaultOpts := vault.Options{Backend: o.vaultBackend, Path: o.vaultPath, Tenant: o.vaultTenant, DSN: os.Getenv(vault.EnvPostgresDSN)}

	if o.feedbackFP != "" {
		return runFeedback(ctx, vaultOpts, runID, o.feedbackFP, o.feedbackLbl, o.feedbackNote)
	}

	if o.ruleHealth {
		return runRuleHealth(ctx, vaultOpts)
	}

	if o.metricsOn {
		return runMetrics(ctx, vaultOpts)
	}

	if o.fromSarif != "" {
		return runFromSARIF(o.fromSarif, o.failOn)
	}

	if err := llm.ValidateAuthMode(o.llmAuth); err != nil {
		return err
	}
	llmAuthMode = o.llmAuth

	// --- resolve target + config ---
	absTarget, err := filepath.Abs(o.target)
	if err != nil {
		return err
	}

	cfg, err := config.Load(o.configPath)
	if err != nil {
		return err
	}
	m, err := policy.ParseMode(o.mode)
	if err != nil {
		return err
	}
	gate := policy.Gate{Mode: m, Attested: parseAttest(o.attest)}

	runner, err := buildRunner(o.runnerKind)
	if err != nil {
		return err
	}

	opengrepRules, shadowRules, cleanupRules := provisionGeneratedRules(o, cfg)
	defer cleanupRules()

	reg, shadow, err := buildRegistry(o, cfg, gate, runner, opengrepRules, shadowRules)
	if err != nil {
		return err
	}

	// --- Evidence Vault ---
	ev, err := vault.Open(ctx, vaultOpts)
	if err != nil {
		return err
	}
	recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta},
		scanMetaPayload(absTarget, o.targetLabel, o.sourceCommit, string(m), o.profile, toolIDs(reg)))

	scan, diags, err := scanTarget(ctx, o, ev, runID, absTarget, reg, shadow)
	if err != nil {
		return err
	}
	if err := filterFindings(o, ev, runID, absTarget, &scan); err != nil {
		return err
	}
	seedMode, err := applyPRMini(o)
	if err != nil {
		return err
	}
	inScope := inScopeFindings(scan.Findings)
	if err := applyBaseline(o, ev, runID, &scan); err != nil {
		return err
	}
	clusters := correlateFindings(o, ev, runID, &scan)

	tasks, err := loadTaskRouting(o.modelConfig)
	if err != nil {
		return err
	}
	llmUsage, err := triageScan(ctx, o, ev, runID, &scan, clusters, tasks)
	if err != nil {
		return err
	}

	for _, d := range diags {
		scan.FailedTools = append(scan.FailedTools, d.Tool)
	}
	report.WriteHuman(os.Stdout, scan)
	fmt.Fprintf(os.Stderr, "\nEvidence Vault: %s (run %s)\n", vaultOpts.Backend, runID)

	if err := writeReports(ctx, o, absTarget, scan, inScope); err != nil {
		return err
	}

	if o.researchOn {
		if err := runResearch(ctx, ev, runID, absTarget, o.ruleRepoDir, o.maxTargets, runner, o.llmBaseURL, o.llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: research: %v\n", err)
		}
	}

	if o.mineRules {
		if err := runMiner(ctx, ev, runID, o.ruleRepoDir, o.maxTargets, runner, o.llmBaseURL, o.llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: mine-rules: %v\n", err)
		}
	}

	if err := writeDiagnostics(o, ev, runID, diags, llmUsage); err != nil {
		return err
	}

	// --- SBOM (supply-chain artifact, independent of findings) ---
	if o.sbomOut != "" {
		if err := runSBOM(ctx, runner, cfg, gate, absTarget, o.sbomOut, ev, runID); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: sbom: %v\n", err)
		}
	}

	if err := runAgents(ctx, o, ev, runID, absTarget, scan, tasks); err != nil {
		return err
	}

	// A scan whose evidence didn't persist must not look like a clean success —
	// checked before the severity gate so a vault outage is never masked by a
	// passing gate.
	if err := reportVaultFailures(); err != nil {
		return err
	}

	// Fail closed on request: a partial scan is not evidence of safety. Exit 2
	// (an error) rather than 1 (findings gated) so callers can tell them apart.
	// Checked before the severity gate so a passing gate cannot mask it.
	if o.strictTools && len(diags) > 0 {
		return fmt.Errorf("--strict-tools: %d tool(s) failed to run or normalize (%s); the scan is incomplete",
			len(diags), strings.Join(scan.FailedTools, ", "))
	}

	if seedMode {
		return nil // pr-mini seed run: baseline established, nothing to gate yet
	}
	return applyFailOn(o.failOn, scan)
}

// llmAuthMode is set once from --llm-auth before any scan work begins, and read
// by newLLMFactory. It's package-level because every LLM entry point needs it
// and the alternative is threading an extra parameter through six call sites.
var llmAuthMode = "key"

// newLLMFactory builds the client constructor for this run from --llm-auth and
// the ACHILLES_LLM_* environment (see llm.NewFactory for the modes).
func newLLMFactory() (func(string, string) llm.Client, error) {
	return llm.NewFactory(llmAuthMode)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeToFile(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

func parseAttest(s string) map[string]bool {
	out := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}

// scanMetaPayload builds the scan_meta record payload. A label overrides the
// scanned path as the run's "target" (so a fetched checkout in a throwaway dir
// is recorded under its stable repo URL, keeping `--metrics` target counts
// meaningful), and a commit adds the resolved source sha.
func scanMetaPayload(absTarget, label, commit, mode, profile string, tools []string) map[string]any {
	meta := map[string]any{"target": absTarget, "mode": mode, "profile": profile, "tools": tools}
	if label != "" {
		meta["target"] = label
	}
	if commit != "" {
		meta["commit"] = commit
	}
	return meta
}

func toolIDs(reg *scanner.Registry) []string {
	var ids []string
	for _, s := range reg.All() {
		ids = append(ids, s.ID())
	}
	return ids
}

func newRunID() string {
	return fmt.Sprintf("%s-%d", time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
}
