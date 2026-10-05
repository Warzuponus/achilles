package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Warzuponus/achilles/internal/vault"
)

// options holds every command-line flag plus the target path. Names, defaults and
// help text are defined in parseFlags.
type options struct {
	configPath        string
	profile           string
	mode              string
	attest            string
	runnerKind        string
	vaultPath         string
	vaultBackend      string
	vaultTenant       string
	sarifOut          string
	fromSarif         string
	failOn            string
	timeout           time.Duration
	triageOn          bool
	remediateOn       bool
	ragOn             bool
	llmBaseURL        string
	llmModel          string
	llmJudge          string
	llmEmbed          string
	llmAuth           string
	modelConfig       string
	feedbackFP        string
	ruleHealth        bool
	metricsOn         bool
	feedbackLbl       string
	feedbackNote      string
	researchOn        bool
	mineRules         bool
	ruleRepoDir       string
	ruleShadow        int
	maxTargets        int
	diffRef           string
	excludePaths      string
	noDefaultExcludes bool
	noCorrelate       bool
	dryRun            bool
	maxCost           float64
	priceConfig       string
	baselinePath      string
	writeBl           string
	prMini            string
	sarifReport       string
	junitOut          string
	markdownOut       string
	htmlReport        string
	githubAnn         bool
	prComment         int
	prReview          int
	prHeadSHA         string
	fileIssues        bool
	fixPR             bool
	fixRemote         string
	fixBase           string
	repoFlag          string
	strictTools       bool
	diagnostics       string
	sbomOut           string
	reviewOn          bool
	scaAdvice         bool
	threatModelOut    string
	targetLabel       string
	sourceCommit      string

	target string // the path to scan (first positional argument; default ".")
}

func parseFlags(argv []string) (*options, error) {
	fs := flag.NewFlagSet("achilles", flag.ContinueOnError)
	o := &options{}
	fs.StringVar(&o.configPath, "config", "configs/tools.yaml", "tool registry file")
	fs.StringVar(&o.profile, "profile", "default", "scan profile: default (baseline tools) | full (also the heavy per-language tools)")
	fs.StringVar(&o.mode, "mode", "oss", "license mode: oss | commercial")
	fs.StringVar(&o.attest, "attest", "", "comma-separated tool IDs with a supplied license attestation")
	fs.StringVar(&o.runnerKind, "runner", "local", "how to run tools: local | docker")
	fs.StringVar(&o.vaultPath, "vault", ".achilles/vault.jsonl", "Evidence Vault path (file backend)")
	fs.StringVar(&o.vaultBackend, "vault-backend", "file", "Evidence Vault backend: file | postgres (DSN from $"+vault.EnvPostgresDSN+")")
	fs.StringVar(&o.vaultTenant, "vault-tenant", "default", "project this scan belongs to; the War Room lists results per project (postgres backend; the file backend is addressed by --vault)")
	fs.StringVar(&o.sarifOut, "sarif-out", "", "write each tool's SARIF into this directory")
	fs.StringVar(&o.fromSarif, "from-sarif", "", "skip scanning; normalize this existing SARIF file")
	fs.StringVar(&o.failOn, "fail-on", "", "exit non-zero if a finding at/above this severity exists: critical|high|medium|low")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "scan timeout")
	fs.BoolVar(&o.triageOn, "triage", false, "run LLM triage + adversarial judge on findings")
	fs.BoolVar(&o.remediateOn, "remediate", false, "propose fixes for high-confidence findings (implies --triage)")
	fs.BoolVar(&o.ragOn, "rag", false, "use RAG few-shot from past feedback (needs --llm-embed-model)")
	fs.StringVar(&o.llmBaseURL, "llm-base-url", envOr("ACHILLES_LLM_BASE_URL", "https://api.openai.com/v1"), "OpenAI-compatible base URL")
	fs.StringVar(&o.llmModel, "llm-model", os.Getenv("ACHILLES_LLM_MODEL"), "model for triage (API key from ACHILLES_LLM_API_KEY or OPENAI_API_KEY)")
	fs.StringVar(&o.llmJudge, "llm-judge-model", "", "model for the judge pass (default: same as --llm-model)")
	fs.StringVar(&o.llmEmbed, "llm-embed-model", os.Getenv("ACHILLES_LLM_EMBED_MODEL"), "embeddings model for --rag")
	fs.StringVar(&o.llmAuth, "llm-auth", envOr("ACHILLES_LLM_AUTH", "key"), "LLM credential: key (Bearer, from ACHILLES_LLM_API_KEY) | api-key (same key as an `api-key:` header, for Azure OpenAI) | none (no credential header; local runtimes) . Extra headers/query/timeout: see docs/llm-and-agents.md")
	fs.StringVar(&o.modelConfig, "model-config", "", "YAML routing per pipeline step to a model/endpoint (tasks: triage|judge|remediation|review|sca|threat-model|research|mine-rules)")
	fs.StringVar(&o.feedbackFP, "feedback", "", "record analyst feedback for a finding fingerprint, then exit")
	fs.BoolVar(&o.ruleHealth, "rule-health", false, "print per-rule TP/FP health from accumulated feedback, then exit")
	fs.BoolVar(&o.metricsOn, "metrics", false, "print a fleet metrics rollup over the Evidence Vault, then exit")
	fs.StringVar(&o.feedbackLbl, "label", "", "feedback label with --feedback: tp | fp")
	fs.StringVar(&o.feedbackNote, "note", "", "optional note with --feedback")
	fs.BoolVar(&o.researchOn, "research", false, "run research agents over the inventory to synthesize + validate new rules")
	fs.BoolVar(&o.mineRules, "mine-rules", false, "mine Opengrep rules from analyst-confirmed findings (validated + admitted; needs --llm-model)")
	fs.StringVar(&o.ruleRepoDir, "rule-repo", ".achilles/generated-rules", "generated-rule repository directory")
	fs.IntVar(&o.ruleShadow, "rule-shadow-days", 7, "admitted generated rules are report-only (do not gate) until this many days old")
	fs.IntVar(&o.maxTargets, "research-max", 20, "max dependencies to research per run (budget cap)")
	fs.StringVar(&o.diffRef, "diff", "", "diff-aware: keep only findings in files changed vs this git ref")
	fs.StringVar(&o.excludePaths, "exclude", "", "comma-separated extra noise patterns (path segment like 'tests' or glob like '*.gen.go')")
	fs.BoolVar(&o.noDefaultExcludes, "no-default-excludes", false, "disable the built-in vendored/generated/minified noise filter")
	fs.BoolVar(&o.noCorrelate, "no-correlate", false, "disable cross-tool finding correlation (triage every duplicate report separately)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "run the scan, print the LLM cost estimate, and stop before any model call or outward-facing action")
	fs.Float64Var(&o.maxCost, "max-cost", 0, "refuse to start LLM work if the estimated spend exceeds this many USD (needs --price-config)")
	fs.StringVar(&o.priceConfig, "price-config", "", "YAML per-model token prices for cost estimation (see configs/prices.example.yaml)")
	fs.StringVar(&o.baselinePath, "baseline", "", "suppress findings present in this baseline file")
	fs.StringVar(&o.writeBl, "write-baseline", "", "write current findings' fingerprints as a baseline to this file")
	fs.StringVar(&o.prMini, "pr-mini", "", "auto baseline: if this file is absent, seed it (full scan, no gate); if present, delta-scan against it")
	fs.StringVar(&o.sarifReport, "sarif-report", "", "write a unified SARIF report to this file")
	fs.StringVar(&o.junitOut, "junit", "", "write a JUnit XML report to this file")
	fs.StringVar(&o.markdownOut, "markdown", "", "write a Markdown summary to this file")
	fs.StringVar(&o.htmlReport, "html-report", "", "write a self-contained HTML report (findings + AI review/advice/threat-model) to this file")
	fs.BoolVar(&o.githubAnn, "github", false, "emit GitHub Actions annotations to stdout")
	fs.IntVar(&o.prComment, "pr-comment", 0, "post/update a sticky summary comment on this PR number (needs GITHUB_TOKEN + --repo/$GITHUB_REPOSITORY)")
	fs.IntVar(&o.prReview, "pr-review", 0, "post findings as inline review comments on this PR number (needs --pr-head-sha)")
	fs.StringVar(&o.prHeadSHA, "pr-head-sha", "", "the PR head commit SHA for --pr-review (github.event.pull_request.head.sha)")
	fs.BoolVar(&o.fileIssues, "file-issues", false, "file/reconcile GitHub issues for kept findings (dedupe by fingerprint; closed issues suppress; auto-close resolved). Intended for full-repo scans; skips auto-close under --diff")
	fs.BoolVar(&o.fixPR, "fix-pr", false, "open a review PR with high-confidence auto-fixes (needs --remediate; applies each remediation diff, pushes a branch, opens a PR — NEVER merges)")
	fs.StringVar(&o.fixRemote, "fix-remote", "origin", "git remote to push the auto-fix branch to (with --fix-pr)")
	fs.StringVar(&o.fixBase, "fix-base", "", "base branch for the auto-fix PR (with --fix-pr; default: the current branch)")
	fs.StringVar(&o.repoFlag, "repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for GitHub integrations (default $GITHUB_REPOSITORY)")
	fs.BoolVar(&o.strictTools, "strict-tools", os.Getenv("ACHILLES_STRICT_TOOLS") == "true", "fail (exit 2) if any scanner could not run or be normalized, instead of reporting a partial scan; recommended in containers and CI")
	fs.StringVar(&o.diagnostics, "diagnostics", "", "write a diagnostics sidecar (tool/parse failures + LLM token usage) to this JSON file")
	fs.StringVar(&o.sbomOut, "sbom", "", "generate a CycloneDX SBOM of the target (via Syft) and write it to this file")
	fs.BoolVar(&o.reviewOn, "review", false, "run the holistic full-repo security review agent (needs --llm-model)")
	fs.BoolVar(&o.scaAdvice, "sca-advice", false, "run the SCA dependency-upgrade advisor (merge-safety-scored; needs --llm-model)")
	fs.StringVar(&o.threatModelOut, "threat-model", "", "infer an OTM threat model and write it to this file (needs --llm-model)")
	fs.StringVar(&o.targetLabel, "target-label", "", "record this stable, non-secret identity (e.g. a repo URL) as the run's target instead of the scanned path (used by achilles-fleet for fetched checkouts)")
	fs.StringVar(&o.sourceCommit, "source-commit", "", "record the scanned source's commit sha in the run metadata (used by achilles-fleet)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: achilles [flags] <target-path>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return nil, err
	}
	o.target = "."
	if fs.NArg() > 0 {
		o.target = fs.Arg(0)
	}
	return o, nil
}
