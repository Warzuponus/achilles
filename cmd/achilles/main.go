// Command achilles orchestrates open-source SAST tools, normalizes their SARIF
// to Findings, records provenance to the Evidence Vault, and prints a report.
//
// Phase 1: config-driven tool registry (configs/tools.yaml) + license-mode
// policy gate + Evidence Vault. A --from-sarif mode ingests existing SARIF,
// exercising the normalize→report spine without running any scanner.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/baseline"
	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/correlate"
	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/noise"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/research"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
	"github.com/Warzuponus/achilles/internal/threatmodel"
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
