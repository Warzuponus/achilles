// Command achilles orchestrates open-source SAST tools, normalizes their SARIF
// to Findings, records provenance to the Evidence Vault, and prints a report.
//
// Phase 1: config-driven tool registry (configs/tools.yaml) + license-mode
// policy gate + Evidence Vault. A --from-sarif mode ingests existing SARIF,
// exercising the normalize→report spine without running any scanner.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/baseline"
	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/correlate"
	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/enrich"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/gitops"
	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/metrics"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/noise"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/research"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/generic"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
	"github.com/Warzuponus/achilles/internal/threatmodel"
	"github.com/Warzuponus/achilles/internal/triage"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/vcs"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "achilles: "+err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("achilles", flag.ContinueOnError)
	var (
		configPath        = fs.String("config", "configs/tools.yaml", "tool registry file")
		profile           = fs.String("profile", "default", "scan profile: default (baseline tools) | full (also the heavy per-language tools)")
		mode              = fs.String("mode", "oss", "license mode: oss | commercial")
		attest            = fs.String("attest", "", "comma-separated tool IDs with a supplied license attestation")
		runnerKind        = fs.String("runner", "local", "how to run tools: local | docker")
		vaultPath         = fs.String("vault", ".achilles/vault.jsonl", "Evidence Vault path (file backend)")
		vaultBackend      = fs.String("vault-backend", "file", "Evidence Vault backend: file | postgres (DSN from $"+vault.EnvPostgresDSN+")")
		vaultTenant       = fs.String("vault-tenant", "default", "project this scan belongs to; the War Room lists results per project (postgres backend; the file backend is addressed by --vault)")
		sarifOut          = fs.String("sarif-out", "", "write each tool's SARIF into this directory")
		fromSarif         = fs.String("from-sarif", "", "skip scanning; normalize this existing SARIF file")
		failOn            = fs.String("fail-on", "", "exit non-zero if a finding at/above this severity exists: critical|high|medium|low")
		timeout           = fs.Duration("timeout", 5*time.Minute, "scan timeout")
		triageOn          = fs.Bool("triage", false, "run LLM triage + adversarial judge on findings")
		remediateOn       = fs.Bool("remediate", false, "propose fixes for high-confidence findings (implies --triage)")
		ragOn             = fs.Bool("rag", false, "use RAG few-shot from past feedback (needs --llm-embed-model)")
		llmBaseURL        = fs.String("llm-base-url", envOr("ACHILLES_LLM_BASE_URL", "https://api.openai.com/v1"), "OpenAI-compatible base URL")
		llmModel          = fs.String("llm-model", os.Getenv("ACHILLES_LLM_MODEL"), "model for triage (API key from ACHILLES_LLM_API_KEY or OPENAI_API_KEY)")
		llmJudge          = fs.String("llm-judge-model", "", "model for the judge pass (default: same as --llm-model)")
		llmEmbed          = fs.String("llm-embed-model", os.Getenv("ACHILLES_LLM_EMBED_MODEL"), "embeddings model for --rag")
		llmAuth           = fs.String("llm-auth", envOr("ACHILLES_LLM_AUTH", "key"), "LLM credential: key (Bearer, from ACHILLES_LLM_API_KEY) | api-key (same key as an `api-key:` header, for Azure OpenAI) | none (no credential header; local runtimes) . Extra headers/query/timeout: see docs/llm-and-agents.md")
		modelConfig       = fs.String("model-config", "", "YAML routing per pipeline step to a model/endpoint (tasks: triage|judge|remediation|review|sca|threat-model|research|mine-rules)")
		feedbackFP        = fs.String("feedback", "", "record analyst feedback for a finding fingerprint, then exit")
		ruleHealth        = fs.Bool("rule-health", false, "print per-rule TP/FP health from accumulated feedback, then exit")
		metricsOn         = fs.Bool("metrics", false, "print a fleet metrics rollup over the Evidence Vault, then exit")
		feedbackLbl       = fs.String("label", "", "feedback label with --feedback: tp | fp")
		feedbackNote      = fs.String("note", "", "optional note with --feedback")
		researchOn        = fs.Bool("research", false, "run research agents over the inventory to synthesize + validate new rules")
		mineRules         = fs.Bool("mine-rules", false, "mine Opengrep rules from analyst-confirmed findings (validated + admitted; needs --llm-model)")
		ruleRepoDir       = fs.String("rule-repo", ".achilles/generated-rules", "generated-rule repository directory")
		ruleShadow        = fs.Int("rule-shadow-days", 7, "admitted generated rules are report-only (do not gate) until this many days old")
		maxTargets        = fs.Int("research-max", 20, "max dependencies to research per run (budget cap)")
		diffRef           = fs.String("diff", "", "diff-aware: keep only findings in files changed vs this git ref")
		excludePaths      = fs.String("exclude", "", "comma-separated extra noise patterns (path segment like 'tests' or glob like '*.gen.go')")
		noDefaultExcludes = fs.Bool("no-default-excludes", false, "disable the built-in vendored/generated/minified noise filter")
		noCorrelate       = fs.Bool("no-correlate", false, "disable cross-tool finding correlation (triage every duplicate report separately)")
		dryRun            = fs.Bool("dry-run", false, "run the scan, print the LLM cost estimate, and stop before any model call or outward-facing action")
		maxCost           = fs.Float64("max-cost", 0, "refuse to start LLM work if the estimated spend exceeds this many USD (needs --price-config)")
		priceConfig       = fs.String("price-config", "", "YAML per-model token prices for cost estimation (see configs/prices.example.yaml)")
		baselinePath      = fs.String("baseline", "", "suppress findings present in this baseline file")
		writeBl           = fs.String("write-baseline", "", "write current findings' fingerprints as a baseline to this file")
		prMini            = fs.String("pr-mini", "", "auto baseline: if this file is absent, seed it (full scan, no gate); if present, delta-scan against it")
		sarifReport       = fs.String("sarif-report", "", "write a unified SARIF report to this file")
		junitOut          = fs.String("junit", "", "write a JUnit XML report to this file")
		markdownOut       = fs.String("markdown", "", "write a Markdown summary to this file")
		htmlReport        = fs.String("html-report", "", "write a self-contained HTML report (findings + AI review/advice/threat-model) to this file")
		githubAnn         = fs.Bool("github", false, "emit GitHub Actions annotations to stdout")
		prComment         = fs.Int("pr-comment", 0, "post/update a sticky summary comment on this PR number (needs GITHUB_TOKEN + --repo/$GITHUB_REPOSITORY)")
		prReview          = fs.Int("pr-review", 0, "post findings as inline review comments on this PR number (needs --pr-head-sha)")
		prHeadSHA         = fs.String("pr-head-sha", "", "the PR head commit SHA for --pr-review (github.event.pull_request.head.sha)")
		fileIssues        = fs.Bool("file-issues", false, "file/reconcile GitHub issues for kept findings (dedupe by fingerprint; closed issues suppress; auto-close resolved). Intended for full-repo scans; skips auto-close under --diff")
		fixPR             = fs.Bool("fix-pr", false, "open a review PR with high-confidence auto-fixes (needs --remediate; applies each remediation diff, pushes a branch, opens a PR — NEVER merges)")
		fixRemote         = fs.String("fix-remote", "origin", "git remote to push the auto-fix branch to (with --fix-pr)")
		fixBase           = fs.String("fix-base", "", "base branch for the auto-fix PR (with --fix-pr; default: the current branch)")
		repoFlag          = fs.String("repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for GitHub integrations (default $GITHUB_REPOSITORY)")
		strictTools       = fs.Bool("strict-tools", os.Getenv("ACHILLES_STRICT_TOOLS") == "true", "fail (exit 2) if any scanner could not run or be normalized, instead of reporting a partial scan; recommended in containers and CI")
		diagnostics       = fs.String("diagnostics", "", "write a diagnostics sidecar (tool/parse failures + LLM token usage) to this JSON file")
		sbomOut           = fs.String("sbom", "", "generate a CycloneDX SBOM of the target (via Syft) and write it to this file")
		reviewOn          = fs.Bool("review", false, "run the holistic full-repo security review agent (needs --llm-model)")
		scaAdvice         = fs.Bool("sca-advice", false, "run the SCA dependency-upgrade advisor (merge-safety-scored; needs --llm-model)")
		threatModelOut    = fs.String("threat-model", "", "infer an OTM threat model and write it to this file (needs --llm-model)")
		targetLabel       = fs.String("target-label", "", "record this stable, non-secret identity (e.g. a repo URL) as the run's target instead of the scanned path (used by achilles-fleet for fetched checkouts)")
		sourceCommit      = fs.String("source-commit", "", "record the scanned source's commit sha in the run metadata (used by achilles-fleet)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: achilles [flags] <target-path>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	runID := newRunID()

	vaultOpts := vault.Options{Backend: *vaultBackend, Path: *vaultPath, Tenant: *vaultTenant, DSN: os.Getenv(vault.EnvPostgresDSN)}

	if *feedbackFP != "" {
		return runFeedback(ctx, vaultOpts, runID, *feedbackFP, *feedbackLbl, *feedbackNote)
	}

	if *ruleHealth {
		return runRuleHealth(ctx, vaultOpts)
	}

	if *metricsOn {
		return runMetrics(ctx, vaultOpts)
	}

	if *fromSarif != "" {
		return runFromSARIF(*fromSarif, *failOn)
	}

	if err := llm.ValidateAuthMode(*llmAuth); err != nil {
		return err
	}
	llmAuthMode = *llmAuth

	// --- resolve target + config ---
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	m, err := policy.ParseMode(*mode)
	if err != nil {
		return err
	}
	gate := policy.Gate{Mode: m, Attested: parseAttest(*attest)}

	runner, err := buildRunner(*runnerKind)
	if err != nil {
		return err
	}

	// --- rule flywheel (§9.4): load admitted generated rules into the scan.
	// Baseline + aged-in generated rules go to Opengrep's active rule set; rules
	// still inside the shadow window run in a separate report-only pass below. ---
	opengrepRules, shadowRules := "", ""
	var opengrepOpts []opengrep.Option
	haveOpengrep := false
	repo := research.NewRuleRepo(*ruleRepoDir, nil)
	if repo.Count("admitted") > 0 {
		baselineRules := ""
		for _, tc := range cfg.Tools {
			if tc.ID == "opengrep" && tc.Rules != "" {
				if abs, aerr := filepath.Abs(tc.Rules); aerr == nil {
					baselineRules = abs
				}
			}
		}
		set, cleanup, perr := repo.Provision(baselineRules, time.Duration(*ruleShadow)*24*time.Hour, time.Now().UTC())
		if perr != nil {
			fmt.Fprintf(os.Stderr, "achilles: rule provisioning: %v\n", perr)
		} else {
			defer cleanup()
			opengrepRules, shadowRules = set.ActiveDir, set.ShadowDir
			fmt.Fprintf(os.Stderr, "achilles: generated rules — %d active, %d in %dd shadow window\n",
				set.ActiveGenerated, set.Shadow, *ruleShadow)
		}
	}

	// --- build the registry: enabled tools that pass the license gate ---
	reg := scanner.NewRegistry()
	for _, tc := range cfg.Tools {
		if tc.ID == "syft" {
			continue // SBOM generator, not a findings scanner — see the --sbom step
		}
		if !tc.RunsInProfile(*profile) {
			continue
		}
		if err := gate.Allow(tc.ToLicense()); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: skipping %s — %v\n", tc.ID, err)
			continue
		}
		sc, err := buildScanner(tc, runner, opengrepRules)
		if err != nil {
			return err
		}
		if tc.ID == "opengrep" {
			haveOpengrep = true
			if tc.Bin != "" {
				opengrepOpts = append(opengrepOpts, opengrep.WithBin(tc.Bin))
			}
			if tc.Image != "" {
				opengrepOpts = append(opengrepOpts, opengrep.WithImage(tc.Image))
			}
		}
		if err := reg.Register(sc); err != nil {
			return err
		}
	}

	// --- Evidence Vault ---
	ev, err := vault.Open(ctx, vaultOpts)
	if err != nil {
		return err
	}
	recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta},
		scanMetaPayload(absTarget, *targetLabel, *sourceCommit, string(m), *profile, toolIDs(reg)))

	// --- run each applicable scanner ---
	scan := model.Scan{Target: absTarget}
	tgt := scanner.Target{Path: absTarget}
	// Detected languages drive applicability: a language-specific tool is skipped
	// when its language isn't present (language-agnostic tools declare "generic"
	// and always run). Fail open — if detection errors, Languages stays empty and
	// every tool runs.
	if inv, ierr := inventory.Scan(absTarget); ierr == nil {
		tgt.Languages = inv.Languages
	}

	applicable, skipped := applicableScanners(reg.All(), tgt)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "achilles: skipping %d tool(s) not applicable to %v: %v\n", len(skipped), tgt.Languages, skipped)
	}
	if *sarifOut != "" {
		if err := os.MkdirAll(*sarifOut, 0o755); err != nil {
			return err
		}
	}

	// Fan out applicable scanners over a bounded worker pool (DESIGN §6:
	// min(numCPU, N)). Workers do only the parallel-safe work (Run + normalize);
	// vault writes and aggregation happen single-threaded in the collector below,
	// and results are sorted by tool id so output stays deterministic regardless
	// of completion order.
	// Diagnostics sidecar: tools that failed to run or whose output couldn't be
	// normalized. Silent gaps read as "clean" — we surface them (DESIGN §6).
	var diags []toolDiag
	for _, r := range runScanners(ctx, applicable, tgt) {
		if r.err != nil {
			// A single tool failing degrades to a partial scan (DESIGN.md §6).
			fmt.Fprintf(os.Stderr, "achilles: %s failed: %v\n", r.id, r.err)
			diags = append(diags, toolDiag{Tool: r.id, Stage: "run", Error: r.err.Error()})
			continue
		}
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindRawOutput, Source: r.id},
			map[string]any{"sarif": json.RawMessage(r.raw.Data)})

		if r.normErr != nil {
			fmt.Fprintf(os.Stderr, "achilles: %s normalize failed: %v\n", r.id, r.normErr)
			diags = append(diags, toolDiag{Tool: r.id, Stage: "normalize", Error: r.normErr.Error()})
			continue
		}
		for _, f := range r.findings {
			recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindFinding,
				Source: r.id, Fingerprint: f.Fingerprint}, f)
		}
		scan.Tools = append(scan.Tools, r.id)
		scan.Findings = append(scan.Findings, r.findings...)

		if *sarifOut != "" {
			if err := os.WriteFile(filepath.Join(*sarifOut, r.id+".sarif"), r.raw.Data, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: %s sarif-out write failed: %v\n", r.id, err)
			}
		}
	}

	// --- shadow pass: run newly-admitted generated rules report-only (§9.4).
	// Findings are marked Shadow so they surface in the report but never gate CI
	// or get written into a baseline until the rules age into the active set. ---
	if haveOpengrep && shadowRules != "" {
		sc := opengrep.New(runner, shadowRules, opengrepOpts...)
		if raw, serr := sc.Run(ctx, tgt); serr != nil {
			fmt.Fprintf(os.Stderr, "achilles: shadow rules failed: %v\n", serr)
			diags = append(diags, toolDiag{Tool: "opengrep-shadow", Stage: "run", Error: serr.Error()})
		} else if fs, nerr := normalize.Normalize(raw.Format, raw.Tool, raw.Data); nerr == nil && len(fs) > 0 {
			recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindRawOutput, Source: "opengrep-shadow"},
				map[string]any{"sarif": json.RawMessage(raw.Data)})
			for i := range fs {
				fs[i].Shadow = true
				recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindFinding,
					Source: "opengrep-shadow", Fingerprint: fs[i].Fingerprint}, fs[i])
			}
			scan.Tools = append(scan.Tools, "opengrep-shadow")
			scan.Findings = append(scan.Findings, fs...)
			fmt.Fprintf(os.Stderr, "achilles: shadow rules — %d report-only finding(s)\n", len(fs))
		}
	}

	// --- noise filter: drop findings in vendored/generated/minified files
	// (before diff/baseline/gating, so they never surface, gate, or get
	// baselined). On by default; --no-default-excludes disables the built-ins. ---
	{
		nm := noise.DefaultMatcher()
		if *noDefaultExcludes {
			nm = noise.NewMatcher()
		}
		for _, p := range strings.Split(*excludePaths, ",") {
			nm.Add(p)
		}
		if kept, excluded := nm.Filter(scan.Findings); len(excluded) > 0 {
			scan.Findings = kept
			fmt.Fprintf(os.Stderr, "achilles: excluded %d finding(s) in vendored/generated/minified paths (--no-default-excludes to disable)\n", len(excluded))
			recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "noise"},
				map[string]any{"excluded": len(excluded)})
		}
	}

	// --- diff-aware: keep only findings in changed files ---
	if *diffRef != "" {
		changed, err := vcs.ChangedFiles(absTarget, *diffRef)
		if err != nil {
			return fmt.Errorf("git diff: %w", err)
		}
		before := len(scan.Findings)
		scan.Findings = vcs.FilterFindings(scan.Findings, changed)
		fmt.Fprintf(os.Stderr, "achilles: diff-aware — %d/%d finding(s) in %d changed file(s)\n", len(scan.Findings), before, len(changed))
	}

	// --- PR-mini: auto seed-vs-delta. If the baseline file doesn't exist yet,
	// this run seeds it (write it, don't gate); once it exists, subsequent runs
	// delta-scan against it (gate only on newly-introduced findings). ---
	seedMode := false
	if *prMini != "" {
		if *baselinePath != "" || *writeBl != "" {
			return fmt.Errorf("--pr-mini is mutually exclusive with --baseline/--write-baseline")
		}
		if _, statErr := os.Stat(*prMini); statErr == nil {
			*baselinePath = *prMini
		} else {
			*writeBl = *prMini
			seedMode = true
			fmt.Fprintf(os.Stderr, "achilles: pr-mini — no baseline at %s; seeding it (this run won't gate)\n", *prMini)
		}
	}

	// The in-scope set (post-diff) is what a baseline is written from. Shadow
	// findings are excluded so that when a generated rule ages into the active
	// set, its findings are genuinely "new" and gate — rather than arriving
	// pre-accepted in the baseline.
	inScope := make([]model.Finding, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		if !f.Shadow {
			inScope = append(inScope, f)
		}
	}

	// --- baseline: classify vs the baseline, surface only newly-introduced
	// findings so CI fails only on new ones, and record the full introduced/
	// pre-existing/fixed breakdown for the report + audit trail. ---
	if *baselinePath != "" {
		b, err := baseline.Load(*baselinePath)
		if err != nil {
			return err
		}
		c := b.Classify(scan.Findings)
		scan.Findings = c.Introduced
		fmt.Fprintf(os.Stderr, "achilles: baseline — %d introduced, %d pre-existing, %d fixed\n",
			len(c.Introduced), len(c.PreExisting), len(c.Fixed))
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "baseline"},
			map[string]any{
				"introduced":  len(c.Introduced),
				"preExisting": len(c.PreExisting),
				"fixed":       c.Fixed,
			})
	}

	// --- correlate: group findings that different tools reported for the same
	// defect (same file+line+CWE). This runs AFTER noise/diff/baseline so the
	// indices match the surfaced set, and it collapses NOTHING — every finding
	// keeps its own fingerprint, severity, and gating behaviour. The only
	// consumer is triage, which triages one representative per cluster instead
	// of every duplicate. ---
	var clusters []correlate.Cluster
	if !*noCorrelate {
		clusters = correlate.Clusters(scan.Findings)
		correlate.Annotate(scan.Findings, clusters)
		if len(clusters) > 0 {
			fmt.Fprintf(os.Stderr, "achilles: correlated %d finding(s) into %d cross-tool cluster(s) — %d LLM triage pass(es) saved (--no-correlate to disable)\n",
				len(clusters)+correlate.Saved(clusters), len(clusters), correlate.Saved(clusters))
			recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "correlate"},
				map[string]any{"clusters": len(clusters), "triagePassesSaved": correlate.Saved(clusters)})
		}
	}

	// Per-task model routing (shared by triage + review).
	var tasks map[string]llm.TaskModel
	if *modelConfig != "" {
		mr, err := config.LoadModelRouting(*modelConfig)
		if err != nil {
			return err
		}
		tasks = map[string]llm.TaskModel{}
		for name, tm := range mr.Tasks {
			tasks[name] = llm.TaskModel{Model: tm.Model, BaseURL: tm.BaseURL}
		}
	}

	// --- LLM cost pre-flight (--dry-run / --max-cost) ---
	var priceTable cost.Table
	if *priceConfig != "" {
		pt, err := cost.LoadTable(*priceConfig)
		if err != nil {
			return err
		}
		priceTable = pt
	}
	if *maxCost < 0 {
		return fmt.Errorf("--max-cost must not be negative")
	}
	if *maxCost > 0 && *priceConfig == "" {
		return fmt.Errorf("--max-cost needs --price-config: dollars require per-model prices, " +
			"which Achilles does not ship (see configs/prices.example.yaml)")
	}
	// Other LLM work is not part of the per-finding estimate; name it rather than
	// let a partial number read as the whole bill.
	var excluded []string
	if *reviewOn {
		excluded = append(excluded, "--review (one whole-repo call per scan)")
	}
	if *scaAdvice {
		excluded = append(excluded, "--sca-advice (one whole-repo call per scan)")
	}
	if *threatModelOut != "" {
		excluded = append(excluded, "--threat-model (one whole-repo call per scan)")
	}
	if *researchOn && !*dryRun {
		excluded = append(excluded, fmt.Sprintf("--research (up to %d dependencies researched + rules synthesized)", *maxTargets))
	}
	if *mineRules && !*dryRun {
		excluded = append(excluded, fmt.Sprintf("--mine-rules (up to %d rules mined)", *maxTargets))
	}
	if *ragOn {
		excluded = append(excluded, "--rag few-shot examples added to each triage prompt")
	}

	// Triage runs only on surfaced findings (cheaper: no LLM spend on known/unchanged).
	var llmUsage llm.Usage
	if *triageOn || *remediateOn {
		opts := triageOpts{
			baseURL: *llmBaseURL, triageModel: *llmModel, judgeModel: *llmJudge,
			embedModel: *llmEmbed, remediate: *remediateOn, rag: *ragOn, tasks: tasks,
			dryRun: *dryRun, maxCost: *maxCost, prices: priceTable, excluded: excluded,
		}
		u, err := runTriage(ctx, ev, runID, &scan, clusters, opts)
		if err != nil {
			return err
		}
		llmUsage = u
	} else if *dryRun {
		est := cost.Project(nil, priceTable)
		est.Excluded = excluded
		est.Write(os.Stderr)
		fmt.Fprintf(os.Stderr, "achilles: dry run — no per-finding LLM work requested (add --triage to estimate it)\n")
	}

	for _, d := range diags {
		scan.FailedTools = append(scan.FailedTools, d.Tool)
	}
	report.WriteHuman(os.Stdout, scan)
	fmt.Fprintf(os.Stderr, "\nEvidence Vault: %s (run %s)\n", vaultOpts.Backend, runID)

	// --- CI exports (on the surfaced set) ---
	if *sarifReport != "" {
		if err := writeToFile(*sarifReport, func(w io.Writer) error { return report.WriteSARIFReport(w, scan) }); err != nil {
			return err
		}
	}
	if *junitOut != "" {
		if err := writeToFile(*junitOut, func(w io.Writer) error { return report.WriteJUnit(w, scan) }); err != nil {
			return err
		}
	}
	if *markdownOut != "" {
		if err := writeToFile(*markdownOut, func(w io.Writer) error { return report.WriteMarkdown(w, scan) }); err != nil {
			return err
		}
	}
	if *githubAnn {
		_ = report.WriteGitHubAnnotations(os.Stdout, scan)
	}
	if *prComment > 0 && !*dryRun {
		if err := runPRComment(ctx, *prComment, *repoFlag, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: pr-comment: %v\n", err)
		}
	}
	if *prReview > 0 && !*dryRun {
		if err := runPRReview(ctx, *prReview, *prHeadSHA, *repoFlag, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: pr-review: %v\n", err)
		}
	}
	if *fileIssues && !*dryRun {
		// Auto-close reconciles against the full current finding set; a diff-limited
		// scan only sees changed files, so we skip closing then to avoid closing
		// issues whose findings simply weren't in the diff.
		if err := runFileIssues(ctx, *repoFlag, scan, *diffRef == ""); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: file-issues: %v\n", err)
		}
	}
	if *fixPR && !*dryRun {
		if err := runFixPR(ctx, absTarget, *repoFlag, *fixRemote, *fixBase, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: fix-pr: %v\n", err)
		}
	}
	if *writeBl != "" {
		if err := baseline.Write(*writeBl, inScope); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles: wrote baseline (%d finding(s)) to %s\n", len(inScope), *writeBl)
	}

	if *researchOn {
		if err := runResearch(ctx, ev, runID, absTarget, *ruleRepoDir, *maxTargets, runner, *llmBaseURL, *llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: research: %v\n", err)
		}
	}

	if *mineRules {
		if err := runMiner(ctx, ev, runID, *ruleRepoDir, *maxTargets, runner, *llmBaseURL, *llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: mine-rules: %v\n", err)
		}
	}

	// --- observability sidecar: coverage gaps + LLM token usage ---
	if len(diags) > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d tool(s) produced no findings due to run/normalize errors (see diagnostics)\n", len(diags))
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "diagnostics"},
			map[string]any{"parseFailures": diags})
	}
	if *diagnostics != "" {
		if err := writeToFile(*diagnostics, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"run": runID, "parseFailures": diags, "llm": llmUsage})
		}); err != nil {
			return err
		}
	}

	// --- SBOM (supply-chain artifact, independent of findings) ---
	if *sbomOut != "" {
		if err := runSBOM(ctx, runner, cfg, gate, absTarget, *sbomOut, ev, runID); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: sbom: %v\n", err)
		}
	}

	// Agent outputs captured for the unified HTML report (nil if not run/failed).
	var reviewRes *review.Review
	var adviceRes *advisor.Advice
	var threatRes *threatmodel.ThreatModel

	// --- holistic full-repo security review (Tier D) ---
	if *reviewOn && !*dryRun {
		r, err := runReview(ctx, ev, runID, absTarget, scan, *llmBaseURL, *llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: review: %v\n", err)
		}
		reviewRes = r
	}

	// --- SCA dependency-upgrade advisor (Tier D) ---
	if *scaAdvice && !*dryRun {
		a, err := runAdvisor(ctx, ev, runID, absTarget, scan, *llmBaseURL, *llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: sca-advice: %v\n", err)
		}
		adviceRes = a
	}

	// --- threat-model agent → OTM artifact (Tier D) ---
	if *threatModelOut != "" && !*dryRun {
		tm, err := runThreatModel(ctx, ev, runID, absTarget, scan, *threatModelOut, *llmBaseURL, *llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: threat-model: %v\n", err)
		}
		threatRes = tm
	}

	// --- unified HTML report (findings + AI review/advice/threat-model) ---
	if *htmlReport != "" {
		hr := report.HTMLReport{
			Target: absTarget, GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 MST"),
			Tools: scan.Tools, Scan: scan, Review: reviewRes, Advice: adviceRes, ThreatModel: threatRes,
		}
		if err := writeToFile(*htmlReport, func(w io.Writer) error { return report.WriteHTML(w, hr) }); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles: wrote HTML report to %s\n", *htmlReport)
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
	if *strictTools && len(diags) > 0 {
		return fmt.Errorf("--strict-tools: %d tool(s) failed to run or normalize (%s); the scan is incomplete",
			len(diags), strings.Join(scan.FailedTools, ", "))
	}

	if seedMode {
		return nil // pr-mini seed run: baseline established, nothing to gate yet
	}
	return applyFailOn(*failOn, scan)
}

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

	inv, err := inventory.Scan(target)
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

	inv, err := inventory.Scan(target)
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

	inv, err := inventory.Scan(target)
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
	inv, err := inventory.Scan(target)
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

type triageOpts struct {
	baseURL, triageModel, judgeModel, embedModel string
	remediate, rag                               bool
	tasks                                        map[string]llm.TaskModel // per-task model routing (--model-config)

	// Cost pre-flight (--dry-run / --max-cost / --price-config). dryRun stops
	// after printing the estimate; maxCost of 0 means no cap.
	dryRun   bool
	maxCost  float64
	prices   cost.Table
	excluded []string // LLM work the estimate deliberately omits, for the report
}

// runTriage runs the LLM triage + judge layer over the scan's findings,
// mutating them in place and recording provenance to the vault. It applies the
// learning layer: calibration auto-resolves chronically-noisy rules (from
// feedback) without an LLM call, and RAG (opt-in) injects similar past findings.
func runTriage(ctx context.Context, ev vault.Store, runID string, scan *model.Scan, clusters []correlate.Cluster, o triageOpts) (llm.Usage, error) {
	if o.triageModel == "" {
		return llm.Usage{}, fmt.Errorf("--triage/--remediate requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return llm.Usage{}, err
	}

	// Per-task model routing: start from --model-config, then let the
	// --llm-judge-model flag fill in "judge" if the config didn't. The default
	// client (used for any unrouted task) is the --llm-model.
	tasks := map[string]llm.TaskModel{}
	for name, tm := range o.tasks {
		tasks[name] = tm
	}
	if o.judgeModel != "" && o.judgeModel != o.triageModel {
		if _, ok := tasks["judge"]; !ok {
			tasks["judge"] = llm.TaskModel{Model: o.judgeModel}
		}
	}
	router := llm.BuildRouter(factory(o.baseURL, o.triageModel), tasks, o.baseURL, factory)

	en := enrich.New(3)
	en.IncludeBlame = true // best-effort git attribution in the prompt context
	eng := triage.NewEngine(router, ev, en, scan.Target)

	// Learning layer (DESIGN.md §8): calibration from accumulated feedback.
	fb := knowledge.NewFeedbackStore(ev)
	eng.SetCalibrator(knowledge.NewCalibrator(fb, calMinSamples, calFPThreshold))

	// RAG few-shot (opt-in; needs an embeddings model).
	if o.rag {
		if o.embedModel == "" {
			return llm.Usage{}, fmt.Errorf("--rag requires --llm-embed-model (or ACHILLES_LLM_EMBED_MODEL)")
		}
		// The embeddings client (chromem-go's, not ours) only sends a Bearer key, so
		// it can't use the api-key header style — fail loudly rather than silently
		// sending a credential the endpoint will reject.
		if llmAuthMode == llm.ModeAPIKey {
			return llm.Usage{}, fmt.Errorf("--rag does not support --llm-auth %s yet "+
				"(the embeddings client sends a static Bearer key); drop --rag or use --llm-auth key", llmAuthMode)
		}
		rag, err := knowledge.NewRAGOpenAI(o.baseURL, envOr("ACHILLES_LLM_API_KEY", os.Getenv("OPENAI_API_KEY")), o.embedModel)
		if err != nil {
			return llm.Usage{}, fmt.Errorf("rag init: %w", err)
		}
		if n, err := rag.PopulateFromVault(ctx, ev); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: rag populate: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "achilles: rag seeded with %d labeled example(s)\n", n)
		}
		eng.SetRetriever(rag)
	}

	// Correlated duplicates inherit their representative's verdict instead of
	// paying for their own triage+judge pair. inheritFrom maps a member index to
	// the index of the representative it should copy from; anything absent is
	// triaged normally.
	inheritFrom := map[int]int{}
	for _, c := range clusters {
		for _, m := range c.Members {
			inheritFrom[m] = c.Rep
		}
	}

	// --- cost pre-flight: estimate BEFORE the first model call, so --dry-run can
	// show the bill and --max-cost can refuse it. Only findings that will really
	// be triaged are planned: correlated duplicates inherit a verdict for free,
	// and the calibrator's auto-resolutions are skipped inside Plan. ---
	toTriage := make([]model.Finding, 0, len(scan.Findings))
	for i := range scan.Findings {
		if _, inherited := inheritFrom[i]; !inherited {
			toTriage = append(toTriage, scan.Findings[i])
		}
	}
	planned := cost.AssignModels(eng.Plan(toTriage, triage.PlanOpts{Remediate: o.remediate}),
		func(task string) string {
			if tm, ok := tasks[task]; ok && tm.Model != "" {
				return tm.Model
			}
			return o.triageModel
		})
	est := cost.Project(planned, o.prices)
	est.Excluded = o.excluded
	if o.remediate {
		est.Excluded = append(est.Excluded,
			"NOTE: remediation is counted for every triaged finding — an upper bound, since only high-confidence ones are fixed")
	}
	if n := len(scan.Findings) - len(toTriage); n > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d correlated duplicate(s) will inherit a verdict at no LLM cost\n", n)
	}

	if o.dryRun {
		est.Write(os.Stderr)
		fmt.Fprintf(os.Stderr, "achilles: dry run — stopping before the first model call\n")
		return llm.Usage{}, nil
	}
	if o.maxCost > 0 {
		if !est.Complete() {
			return llm.Usage{}, fmt.Errorf("--max-cost cannot be enforced: no price for %s "+
				"(add it to --price-config, or drop --max-cost)", strings.Join(est.Unpriced, ", "))
		}
		if est.TotalUSD > o.maxCost {
			est.Write(os.Stderr)
			return llm.Usage{}, fmt.Errorf("estimated LLM spend $%.4f exceeds --max-cost $%.4f; "+
				"no model was called (raise the cap, narrow the scan with --diff/--baseline, or route cheaper models)",
				est.TotalUSD, o.maxCost)
		}
		fmt.Fprintf(os.Stderr, "achilles: estimated LLM spend $%.4f is within --max-cost $%.4f\n",
			est.TotalUSD, o.maxCost)
	}

	triageOne := func(i int) {
		f := &scan.Findings[i]
		if err := eng.Triage(ctx, runID, f); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: triage failed for %s: %v\n", f.RuleID, err)
			return
		}
		if o.remediate {
			if err := eng.Remediate(ctx, runID, f); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: remediation failed for %s: %v\n", f.RuleID, err)
			}
		}
	}

	// Pass 1 — everything that gets its own triage: uncorrelated findings and
	// cluster representatives. A representative is not necessarily the lowest
	// index in its cluster (it's the highest-severity member), so this has to
	// complete before anything inherits.
	for i := range scan.Findings {
		if _, inherited := inheritFrom[i]; !inherited {
			triageOne(i)
		}
	}

	// Pass 2 — correlated duplicates inherit their representative's verdict.
	for i := range scan.Findings {
		rep, inherited := inheritFrom[i]
		if !inherited {
			continue
		}
		f := &scan.Findings[i]
		// Calibration first: feedback about THIS finding's own rule is stronger
		// evidence than a sibling's verdict, so a chronically-noisy rule still
		// auto-resolves even inside a cluster.
		if eng.AutoResolve(runID, f) {
			continue
		}
		// If the representative's own triage failed there is nothing to inherit;
		// triage this one directly rather than leaving the whole cluster unjudged.
		if scan.Findings[rep].Verdict == nil {
			triageOne(i)
			continue
		}
		eng.Inherit(runID, f, scan.Findings[rep])
	}

	u := eng.Usage()
	recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindScanMeta, Source: "llm-usage"},
		map[string]any{"promptTokens": u.PromptTokens, "completionTokens": u.CompletionTokens, "totalTokens": u.TotalTokens})
	fmt.Fprintf(os.Stderr, "achilles: llm usage — %d prompt + %d completion = %d total token(s)\n",
		u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	return u, nil
}

// Calibration thresholds shared by triage's auto-resolution and the rule-health
// report: a rule is auto-suppressed once it has >= calMinSamples labels and an
// FP rate >= calFPThreshold.
const (
	calMinSamples  = 3
	calFPThreshold = 0.8
)

// runRuleHealth prints per-rule TP/FP health accumulated from analyst feedback,
// so you can see which rules are noisy (auto-suppressed) vs. high-yield. No scan.
func runRuleHealth(ctx context.Context, opts vault.Options) error {
	ev, err := vault.Open(ctx, opts)
	if err != nil {
		return err
	}
	cal := knowledge.NewCalibrator(knowledge.NewFeedbackStore(ev), calMinSamples, calFPThreshold)
	rules := cal.Rules()
	if len(rules) == 0 {
		fmt.Println("No analyst feedback recorded yet — rule health builds up as findings are labeled (--feedback).")
		return nil
	}

	labeled := 0
	for _, h := range rules {
		labeled += h.Samples()
	}
	fmt.Printf("Rule health (%d labeled finding(s) across %d rule(s); auto-suppress at >=%d samples & >=%.0f%% FP):\n\n",
		labeled, len(rules), calMinSamples, calFPThreshold*100)
	fmt.Printf("  %-40s %4s %4s %8s %8s  %s\n", "TOOL/RULE", "TP", "FP", "SAMPLES", "FP-RATE", "STATUS")
	for _, h := range rules {
		status := "healthy"
		switch {
		case cal.Suppresses(h):
			status = "auto-suppressed"
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

// runPRComment posts (or updates) a sticky Markdown summary of the scan on a PR.
// Best-effort + outward-facing: it only runs when --pr-comment is set, and reads
// the token/repo from the environment the CI provides.
func runPRComment(ctx context.Context, pr int, repo string, scan model.Scan) error {
	var md strings.Builder
	if err := report.WriteMarkdown(&md, scan); err != nil {
		return err
	}
	gc, err := github.New(envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")), repo, os.Getenv("GITHUB_API_URL"))
	if err != nil {
		return err
	}
	created, err := gc.UpsertComment(ctx, pr, "pr-summary", md.String())
	if err != nil {
		return err
	}
	action := "updated"
	if created {
		action = "created"
	}
	fmt.Fprintf(os.Stderr, "achilles: pr-comment — %s sticky summary on %s#%d\n", action, repo, pr)
	return nil
}

// maxInlineComments caps how many inline review comments a run posts; the rest
// stay in the sticky summary. Keeps re-runs from hammering the API on a huge PR.
const maxInlineComments = 50

var fpMarkerRE = regexp.MustCompile(`achilles:fp:(\S+) -->`)

// runPRReview posts findings as inline review comments on the PR diff. It dedupes
// against comments it already left (a per-finding fingerprint marker), skips
// findings the API rejects (line not in the diff → 422), and is best-effort.
// Outward-facing + opt-in.
func runPRReview(ctx context.Context, pr int, headSHA, repo string, scan model.Scan) error {
	if headSHA == "" {
		return fmt.Errorf("--pr-review requires --pr-head-sha (github.event.pull_request.head.sha)")
	}
	gc, err := github.New(envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")), repo, os.Getenv("GITHUB_API_URL"))
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	if existing, err := gc.ListPullComments(ctx, pr); err == nil {
		for _, c := range existing {
			if m := fpMarkerRE.FindStringSubmatch(c.Body); m != nil {
				seen[m[1]] = true
			}
		}
	}

	posted, skipped := 0, 0
	for _, f := range scan.Findings {
		if posted >= maxInlineComments {
			break
		}
		if f.Shadow || f.Location.File == "" || f.Location.Region.StartLine == 0 || seen[f.Fingerprint] {
			continue
		}
		body := fmt.Sprintf("<!-- achilles:fp:%s -->\n**[%s] %s** — %s", f.Fingerprint, f.Severity, f.RuleID, strings.TrimSpace(f.Message))
		if err := gc.CreateReviewComment(ctx, pr, headSHA, f.Location.File, f.Location.Region.StartLine, body); err != nil {
			skipped++ // most often: the line isn't part of the diff (422)
			continue
		}
		seen[f.Fingerprint] = true
		posted++
	}
	fmt.Fprintf(os.Stderr, "achilles: pr-review — %d inline comment(s) posted, %d skipped on %s#%d\n", posted, skipped, repo, pr)
	return nil
}

// issueLabel scopes issue listing/creation to Achilles's own issues, so we never
// touch a human's issues when reconciling.
const issueLabel = "achilles"

// maxNewIssues caps issues opened per run so a first run on a noisy repo can't
// open hundreds at once.
const maxNewIssues = 50

// runFileIssues files/reconciles GitHub issues for kept findings, keyed by a
// per-finding fingerprint marker in the issue body:
//   - a finding with no existing issue → open one;
//   - a finding whose fingerprint matches an OPEN issue → already tracked, skip;
//   - a finding whose fingerprint matches a CLOSED issue → suppressed (a human
//     triaged/won't-fixed it) → skip;
//   - an OPEN Achilles issue whose fingerprint is no longer detected → auto-close
//     (only when reconcile is set; a diff-limited scan doesn't see the full set).
//
// Outward-facing + opt-in.
func runFileIssues(ctx context.Context, repo string, scan model.Scan, reconcile bool) error {
	gc, err := github.New(envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")), repo, os.Getenv("GITHUB_API_URL"))
	if err != nil {
		return err
	}
	existing, err := gc.ListIssues(ctx, issueLabel)
	if err != nil {
		return err
	}

	openByFP := map[string]int{}   // fingerprint -> open issue number
	closedFPs := map[string]bool{} // fingerprints a human closed (suppress)
	for _, is := range existing {
		m := fpMarkerRE.FindStringSubmatch(is.Body)
		if m == nil {
			continue
		}
		if is.State == "closed" {
			closedFPs[m[1]] = true
		} else {
			openByFP[m[1]] = is.Number
		}
	}

	current := map[string]bool{} // fingerprints detected this run (gate auto-close)
	filed, suppressed, tracked := 0, 0, 0
	for _, f := range scan.Findings {
		if f.Shadow || f.Fingerprint == "" {
			continue
		}
		current[f.Fingerprint] = true
		switch {
		case closedFPs[f.Fingerprint]:
			suppressed++
			continue
		case openByFP[f.Fingerprint] != 0:
			tracked++
			continue
		}
		if filed >= maxNewIssues {
			continue
		}
		title := fmt.Sprintf("[%s] %s in %s", f.Severity, f.RuleID, f.Location.File)
		body := fmt.Sprintf("<!-- achilles:fp:%s -->\n**Rule:** %s\n**Severity:** %s\n**Location:** `%s:%d`\n\n%s\n\n_Filed by Achilles. Close this issue to suppress the finding in future scans; it auto-closes when no longer detected._",
			f.Fingerprint, f.RuleID, f.Severity, f.Location.File, f.Location.Region.StartLine, strings.TrimSpace(f.Message))
		if _, err := gc.CreateIssue(ctx, title, body, []string{issueLabel}); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: file-issues: create %q: %v\n", title, err)
			continue
		}
		filed++
	}

	closed := 0
	if reconcile {
		for fp, num := range openByFP {
			if current[fp] {
				continue
			}
			if err := gc.CloseIssue(ctx, num, "Resolved — Achilles no longer detects this finding. Auto-closing."); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: file-issues: close #%d: %v\n", num, err)
				continue
			}
			closed++
		}
	}
	fmt.Fprintf(os.Stderr, "achilles: file-issues — %d filed, %d already tracked, %d suppressed (closed), %d auto-closed on %s\n",
		filed, tracked, suppressed, closed, repo)
	return nil
}

// maxFixesPerPR caps how many remediation diffs one auto-fix PR carries, keeping
// the PR reviewable and bounding the git work per run.
const maxFixesPerPR = 25

// runFixPR opens a review PR carrying Achilles's high-confidence auto-fixes: it
// applies each remediation's unified diff to a fresh branch, commits, pushes, and
// opens a PR. It NEVER merges (DESIGN §1 Non-Goals; the confirmed auto-fix
// guardrail). The branch name is derived from the fingerprints being fixed, so a
// re-run reuses the same branch/PR rather than spawning duplicates. Patches that
// don't apply cleanly are skipped, not fatal. Outward-facing + opt-in.
func runFixPR(ctx context.Context, dir, repo, remote, base string, scan model.Scan) error {
	type fix struct{ fp, rule, diff string }
	var fixes []fix
	for _, f := range scan.Findings {
		if f.Shadow || f.Remediation == nil {
			continue
		}
		if strings.TrimSpace(f.Remediation.Diff) == "" {
			continue // prose-only guidance — no machine-applicable patch
		}
		fixes = append(fixes, fix{f.Fingerprint, f.RuleID, f.Remediation.Diff})
	}
	if len(fixes) == 0 {
		fmt.Fprintln(os.Stderr, "achilles: fix-pr — no remediation carried a concrete diff; opened no PR (run with --remediate)")
		return nil
	}
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].fp < fixes[j].fp })
	if len(fixes) > maxFixesPerPR {
		fmt.Fprintf(os.Stderr, "achilles: fix-pr — capping at %d of %d fixes this PR\n", maxFixesPerPR, len(fixes))
		fixes = fixes[:maxFixesPerPR]
	}

	h := sha256.New()
	for _, fx := range fixes {
		io.WriteString(h, fx.fp+"\n")
	}
	branch := "achilles/autofix-" + hex.EncodeToString(h.Sum(nil))[:8]

	gc, err := github.New(envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")), repo, os.Getenv("GITHUB_API_URL"))
	if err != nil {
		return err
	}
	if pulls, err := gc.ListPullsForHead(ctx, branch); err == nil && len(pulls) > 0 {
		fmt.Fprintf(os.Stderr, "achilles: fix-pr — a PR is already open for %s (#%d %s); leaving it\n", branch, pulls[0].Number, pulls[0].HTMLURL)
		return nil
	}

	top, err := gitops.TopLevel(ctx, dir)
	if err != nil {
		return fmt.Errorf("locate git repo for %q: %w", dir, err)
	}
	r := &gitops.Repo{Dir: top}
	if base == "" {
		if base, err = r.CurrentBranch(ctx); err != nil {
			return err
		}
	}
	if err := r.CreateBranch(ctx, branch, base); err != nil {
		return err
	}

	applied := 0
	var body strings.Builder
	fmt.Fprintf(&body, "Automated fixes proposed by Achilles from confirmed, high-confidence findings.\n\n**Review before merging — Achilles opens this PR but never merges it.**\n\n")
	for _, fx := range fixes {
		if err := r.Apply(ctx, fx.diff); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: fix-pr — skip %s (%s): patch did not apply cleanly\n", fx.rule, fx.fp)
			continue
		}
		applied++
		fmt.Fprintf(&body, "- `%s` (fingerprint `%s`)\n", fx.rule, fx.fp)
	}
	if applied == 0 {
		return fmt.Errorf("no proposed diff applied cleanly; opened no PR")
	}
	if err := r.Commit(ctx, fmt.Sprintf("fix: Achilles auto-fix (%d finding(s))", applied)); err != nil {
		return err
	}
	if err := r.Push(ctx, remote, branch); err != nil {
		return err
	}
	pr, err := gc.CreatePull(ctx, fmt.Sprintf("Achilles auto-fix: %d finding(s)", applied), branch, base, body.String())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "achilles: fix-pr — opened PR #%d (%s) with %d fix(es); NOT merged\n", pr.Number, pr.HTMLURL, applied)
	return nil
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

func runFromSARIF(path, failOn string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read --from-sarif: %w", err)
	}
	findings, err := normalize.FromSARIF("unknown", data)
	if err != nil {
		return err
	}
	scan := model.Scan{Target: path, Findings: findings}
	report.WriteHuman(os.Stdout, scan)
	return applyFailOn(failOn, scan)
}

// toolDiag records a scanner that failed to run or whose output couldn't be
// normalized — surfaced in the diagnostics sidecar so coverage gaps aren't
// silent.
type toolDiag struct {
	Tool  string `json:"tool"`
	Stage string `json:"stage"` // "run" | "normalize"
	Error string `json:"error"`
}

// scanResult is one scanner's output, carried from a pool worker to the
// single-threaded collector.
type scanResult struct {
	id       string
	raw      scanner.RawResult
	findings []model.Finding
	err      error // Run failed
	normErr  error // SARIF normalize failed
}

// applicableScanners partitions scanners into those applicable to the target and
// the ids of those skipped (for a one-line "skipped" log). Order is preserved.
func applicableScanners(all []scanner.Scanner, tgt scanner.Target) (run []scanner.Scanner, skipped []string) {
	for _, sc := range all {
		if sc.Applicable(tgt) {
			run = append(run, sc)
		} else {
			skipped = append(skipped, sc.ID())
		}
	}
	return run, skipped
}

// runScanners executes scanners concurrently over a bounded worker pool and
// returns their results sorted by tool id (deterministic, independent of which
// tool finishes first). Workers touch no shared state; the caller serializes all
// vault writes and aggregation.
func runScanners(ctx context.Context, scanners []scanner.Scanner, tgt scanner.Target) []scanResult {
	if len(scanners) == 0 {
		return nil
	}
	workers := runtime.NumCPU()
	if workers > len(scanners) {
		workers = len(scanners)
	}

	jobs := make(chan scanner.Scanner)
	out := make(chan scanResult)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sc := range jobs {
				r := scanResult{id: sc.ID()}
				raw, err := sc.Run(ctx, tgt)
				if err != nil {
					r.err = err
					out <- r
					continue
				}
				r.raw = raw
				r.findings, r.normErr = normalize.Normalize(raw.Format, raw.Tool, raw.Data)
				out <- r
			}
		}()
	}
	go func() {
		for _, sc := range scanners {
			jobs <- sc
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	results := make([]scanResult, 0, len(scanners))
	for r := range out {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].id < results[j].id })
	return results
}

// buildScanner selects the bespoke adapter for tools that have one, else the
// generic config-driven adapter (DESIGN.md §4.4).
func buildScanner(tc config.ToolConfig, runner xexec.Runner, opengrepRules string) (scanner.Scanner, error) {
	rulesHost := ""
	if tc.Rules != "" {
		abs, err := filepath.Abs(tc.Rules)
		if err != nil {
			return nil, err
		}
		rulesHost = abs
	}

	switch {
	case tc.ID == "opengrep":
		// When the rule flywheel has provisioned an active rule set (baseline +
		// aged-in generated rules), it supersedes the configured rules dir.
		if opengrepRules != "" {
			rulesHost = opengrepRules
		}
		// Only override defaults when the config actually sets them, so an
		// omitted bin/image doesn't clobber the adapter's default.
		var opts []opengrep.Option
		if tc.Bin != "" {
			opts = append(opts, opengrep.WithBin(tc.Bin))
		}
		if tc.Image != "" {
			opts = append(opts, opengrep.WithImage(tc.Image))
		}
		return opengrep.New(runner, rulesHost, opts...), nil
	case tc.Bespoke:
		return nil, fmt.Errorf("tool %q marked bespoke but no adapter is wired", tc.ID)
	default:
		return generic.New(runner, tc, rulesHost), nil
	}
}

func buildRunner(kind string) (xexec.Runner, error) {
	switch kind {
	case "local":
		return xexec.LocalRunner{}, nil
	case "docker":
		return xexec.DockerRunner{Network: "none"}, nil // per-tool image comes from config
	default:
		return nil, fmt.Errorf("unknown --runner %q (want local|docker)", kind)
	}
}

func applyFailOn(failOn string, scan model.Scan) error {
	if failOn == "" {
		return nil
	}
	threshold := model.Severity(failOn)
	// Gate on non-shadow findings only: shadow (report-only) generated-rule
	// findings must never fail CI until they age into the active set.
	worst := report.GatingSeverity(scan)
	if worst != model.SeverityUnknown && worst.Rank() >= threshold.Rank() {
		os.Exit(1)
	}
	return nil
}

// vaultWrites tracks Evidence Vault write failures for the whole run. The vault
// IS the audit trail, the reproducibility record, and the learning corpus, so
// losing writes silently is worse than failing loudly: a scan would report
// success while recording nothing. We don't abort mid-scan on a transient error
// (the report and gate are still worth producing) but the run reports the
// failure count and the first cause, and exits non-zero.
var vaultWrites struct {
	failed    int
	firstErr  error
	attempted int
}

func recordJSON(ev vault.Store, r vault.Record, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		noteVaultFailure(fmt.Errorf("marshal %s record: %w", r.Kind, err))
		return
	}
	r.Payload = b
	vaultWrites.attempted++
	if _, err := ev.Append(r); err != nil {
		noteVaultFailure(fmt.Errorf("append %s record: %w", r.Kind, err))
	}
}

func noteVaultFailure(err error) {
	vaultWrites.failed++
	if vaultWrites.firstErr == nil {
		vaultWrites.firstErr = err
		// Surface the first one immediately — later ones are usually the same
		// cause, and a wall of identical errors helps nobody.
		fmt.Fprintf(os.Stderr, "achilles: VAULT WRITE FAILED: %v\n", err)
	}
}

// reportVaultFailures prints a summary if any vault write failed. Returns an
// error so the run exits non-zero: a scan whose evidence did not persist must
// not look like a clean success.
func reportVaultFailures() error {
	if vaultWrites.failed == 0 {
		return nil
	}
	return fmt.Errorf("evidence vault: %d of %d record(s) FAILED to write — "+
		"the scan ran but its audit trail is incomplete; first error: %w",
		vaultWrites.failed, vaultWrites.attempted, vaultWrites.firstErr)
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
