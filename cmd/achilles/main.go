// Command achilles orchestrates open-source SAST tools, normalizes their SARIF
// to Findings, records provenance to the Evidence Vault, and prints a report.
//
// Tools come from a config-driven registry (configs/tools.yaml) behind a
// license-mode policy gate. A --from-sarif mode ingests existing SARIF,
// exercising the normalize→report spine without running any scanner.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		// The gate failing is exit 1 and says nothing more: the report already did.
		// Everything else is an error, exit 2.
		var gated *gateError
		if errors.As(err, &gated) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "achilles: "+err.Error())
		os.Exit(2)
	}
}

// gateError is returned when --fail-on found a finding at or above the threshold.
// It is an error value rather than an os.Exit inside the pipeline so that deferred
// cleanup (temporary rule directories, the signal handler) still runs, and so the
// exit-code contract can be tested: 0 clean, 1 gated, 2 error.
type gateError struct{ worst, threshold model.Severity }

func (e *gateError) Error() string {
	return fmt.Sprintf("a %s finding meets the --fail-on %s threshold", e.worst, e.threshold)
}

// errInterrupted is returned when the run was stopped by Ctrl-C or SIGTERM.
var errInterrupted = errors.New("interrupted; stopped before the scan finished (nothing was reported or filed)")

func run(argv []string) error {
	resetInventory()
	runMeter = nil
	if handled, err := runSubcommand(argv, os.Stdout, os.Stderr); handled {
		return err
	}
	o, err := parseFlags(argv)
	if err != nil {
		return err
	}
	if o.showVersion {
		printVersion(os.Stdout)
		return nil
	}
	o.announceSettings(os.Stderr)

	// One root context for the whole run. Ctrl-C or SIGTERM cancels it, which stops
	// the scanners (their process groups are killed), the model calls and the
	// GitHub calls, and lets the deferred cleanup run. Scanners are started in
	// their own process groups, so they no longer see the terminal's Ctrl-C
	// themselves: this handler is what stops them.
	root, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-root.Done()
		stopSignals() // a second Ctrl-C then ends the process the ordinary way
	}()

	// --timeout bounds the scanners (and the small vault-only commands below).
	ctx, cancel := context.WithTimeout(root, o.timeout)
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
	// Bad LLM setup (no key, wrong endpoint for the key, no model) is cheapest to
	// report now, before minutes of scanning.
	if err := o.validateLLM(); err != nil {
		return err
	}
	if o.aiOn {
		if err := os.MkdirAll(o.reportDir, 0o750); err != nil {
			return fmt.Errorf("--ai: create report directory: %w", err)
		}
	}
	// The routing file is read now, not after the scan: a bad one should cost
	// seconds, and every endpoint it names is checked and announced like the main one.
	tasks, err := loadTaskRouting(o.modelConfig)
	if err != nil {
		return err
	}
	if o.llmWanted() && !o.dryRun {
		if err := checkTaskEndpoints(tasks, o.llmAuth, llm.APIKeyFromEnv()); err != nil {
			return err
		}
		announceEgress(os.Stderr, o, tasks)
	}

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
	communityRulesAllowed = m != policy.ModeCommercial // Commons Clause pack: never in commercial scans
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
	ev = trackVault(ev) // every write from here on is counted, whoever makes it
	recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta},
		scanMetaPayload(absTarget, o.targetLabel, o.sourceCommit, string(m), o.profile, toolIDs(reg)))

	scan, diags, err := scanTarget(ctx, o, ev, runID, absTarget, reg, shadow)
	if err != nil {
		return err
	}
	if root.Err() != nil {
		return errInterrupted
	}
	// The repository's own scanner configuration is named, never applied silently.
	diags = append(diags, applyRepoConfigPolicy(o.noRepoConfig, repoConfigInEffect(cfg, reg, absTarget), &scan, os.Stderr)...)
	if s := o.repoSettings; s != nil && len(s.Applied) > 0 {
		scan.RepoConfig = append(scan.RepoConfig, "achilles: "+s.File)
	}
	// --timeout bounded the scanners. Every later phase gets its own clock, started
	// when the phase starts: sharing the scanners' clock meant a long scan starved
	// the AI review, and re-using it AFTER the AI review meant it had always already
	// expired. All of them hang off root, so an interrupt still stops everything.
	llmCtx, cancelLLM := context.WithTimeout(root, o.llmBudget)
	defer cancelLLM()
	outCtx, cancelOut := context.WithTimeout(root, 10*time.Minute)
	defer cancelOut()

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

	llmUsage, err := triageScan(llmCtx, o, ev, runID, &scan, clusters, tasks)
	// The AI review giving up is not a reason to discard a finished scan. The
	// reports are still written from what the scanners found, marked as unreviewed;
	// nothing is published to GitHub on the strength of it; no further model calls
	// are made; and the run still ends as an error.
	var aiAborted *triageAbortedError
	if errors.As(err, &aiAborted) {
		fmt.Fprintf(os.Stderr, "achilles: %v\nachilles: writing the reports from the scanners' results, WITHOUT AI verdicts\n", aiAborted)
		offline := *o
		offline.reviewOn, offline.scaAdvice, offline.threatModelOut = false, false, ""
		offline.researchOn, offline.mineRules = false, false
		offline.prComment, offline.prReview, offline.fileIssues, offline.fixPR = 0, 0, false, false
		if o.prComment > 0 || o.prReview > 0 || o.fileIssues || o.fixPR {
			fmt.Fprintln(os.Stderr, "achilles: not posting to GitHub (comments, issues, fix PR): the findings were not reviewed")
		}
		o = &offline
	} else if err != nil {
		return err
	}
	if root.Err() != nil {
		return errInterrupted
	}

	// Re-scan each proposed patch before anything (reports, --fix-pr, issues) presents
	// it as a fix; a no-op unless --remediate produced diffs and --verify-fixes is on.
	// It runs scanners again, after the AI review, so it needs a clock of its own:
	// on the scanners' --timeout every verification failed with "deadline exceeded"
	// as soon as scan plus review took longer than that timeout.
	verifyCtx, cancelVerify := context.WithTimeout(root, o.verifyTimeout)
	err = verifyRemediations(verifyCtx, o, absTarget, reg, &scan, ev, runID)
	cancelVerify()
	if err != nil {
		return err
	}
	if root.Err() != nil {
		return errInterrupted
	}

	for _, d := range diags {
		scan.FailedTools = append(scan.FailedTools, d.Tool)
	}
	report.WriteHuman(os.Stdout, scan)
	fmt.Fprintf(os.Stderr, "\nEvidence Vault: %s (run %s)\n", vaultOpts.Backend, runID)

	if err := writeReports(outCtx, o, absTarget, scan, inScope); err != nil {
		return err
	}

	if o.researchOn {
		if err := runResearch(llmCtx, ev, runID, absTarget, o.ruleRepoDir, o.maxTargets, runner, o.llmBaseURL, o.llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: research: %v\n", err)
		}
	}

	if o.mineRules {
		if err := runMiner(llmCtx, ev, runID, o.ruleRepoDir, o.maxTargets, runner, o.llmBaseURL, o.llmModel, tasks); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: mine-rules: %v\n", err)
		}
	}

	if err := writeDiagnostics(o, ev, runID, diags, llmUsage); err != nil {
		return err
	}

	// --- SBOM (supply-chain artifact, independent of findings) ---
	if o.sbomOut != "" {
		sbomCtx, cancelSBOM := context.WithTimeout(root, o.timeout) // a scanner run: a fresh --timeout
		err := runSBOM(sbomCtx, runner, cfg, gate, absTarget, o.sbomOut, ev, runID)
		cancelSBOM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: sbom: %v\n", err)
		}
	}

	if err := runAgents(llmCtx, o, ev, runID, absTarget, scan, tasks); err != nil {
		return err
	}
	if runMeter != nil {
		fmt.Fprintln(os.Stderr, runMeter.summary())
	}

	// Everything that can be written has been. The AI review failing is an error
	// (exit 2), whatever the gate would have said about unreviewed findings.
	if aiAborted != nil {
		return aiAborted
	}

	// A scan whose evidence didn't persist must not look like a clean success —
	// checked before the severity gate so a vault outage is never masked by a
	// passing gate.
	if err := reportVaultFailures(); err != nil {
		return err
	}
	if err := reportVaultReadFailures(ev); err != nil {
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
	factory, err := llm.NewFactory(llmAuthMode)
	if err != nil {
		return nil, err
	}
	return metered(factory, runMeter), nil // counted against --max-cost when it is set
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
