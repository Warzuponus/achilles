package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/baseline"
	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/correlate"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/noise"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/policy"
	"github.com/Warzuponus/achilles/internal/research"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/vcs"
)

// provisionGeneratedRules is the rule flywheel (§9.4): it loads admitted generated
// rules into the scan. Baseline + aged-in generated rules go to Opengrep's active
// rule set (activeDir); rules still inside the shadow window run in a separate
// report-only pass (shadowDir). Both are "" when there is nothing to provision.
// The caller must call cleanup.
func provisionGeneratedRules(o *options, cfg *config.Config) (activeDir, shadowDir string, cleanup func()) {
	cleanup = func() {}
	repo := research.NewRuleRepo(o.ruleRepoDir, nil)
	if repo.Count("admitted") == 0 {
		return "", "", cleanup
	}
	baselineRules := ""
	for _, tc := range cfg.Tools {
		if tc.ID == "opengrep" && tc.Rules != "" {
			if abs, aerr := filepath.Abs(tc.Rules); aerr == nil {
				baselineRules = abs
			}
		}
	}
	set, done, perr := repo.Provision(baselineRules, time.Duration(o.ruleShadow)*24*time.Hour, time.Now().UTC())
	if perr != nil {
		fmt.Fprintf(os.Stderr, "achilles: rule provisioning: %v\n", perr)
		return "", "", cleanup
	}
	fmt.Fprintf(os.Stderr, "achilles: generated rules — %d active, %d in %dd shadow window\n",
		set.ActiveGenerated, set.Shadow, o.ruleShadow)
	return set.ActiveDir, set.ShadowDir, done
}

// buildRegistry registers the enabled tools in the profile that pass the license
// gate. shadow is the report-only Opengrep pass over shadowRules; it is nil when
// Opengrep isn't registered or no rules are in the shadow window.
func buildRegistry(o *options, cfg *config.Config, gate policy.Gate, runner xexec.Runner, opengrepRules, shadowRules string) (*scanner.Registry, *opengrep.Scanner, error) {
	var opengrepOpts []opengrep.Option
	haveOpengrep := false
	reg := scanner.NewRegistry()
	for _, tc := range cfg.Tools {
		if tc.ID == "syft" {
			continue // SBOM generator, not a findings scanner — see the --sbom step
		}
		if !tc.RunsInProfile(o.profile) {
			continue
		}
		if err := gate.Allow(tc.ToLicense()); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: skipping %s — %v\n", tc.ID, err)
			continue
		}
		sc, err := buildScanner(tc, runner, opengrepRules)
		if err != nil {
			return nil, nil, err
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
			return nil, nil, err
		}
	}
	var shadow *opengrep.Scanner
	if haveOpengrep && shadowRules != "" {
		shadow = opengrep.New(runner, shadowRules, opengrepOpts...)
	}
	return reg, shadow, nil
}

// scanTarget runs each applicable scanner and the shadow pass, records raw output
// and findings to the vault, and returns the aggregated scan plus diagnostics for
// the tools that failed to run or normalize.
func scanTarget(ctx context.Context, o *options, ev vault.Store, runID, absTarget string, reg *scanner.Registry, shadow *opengrep.Scanner) (model.Scan, []toolDiag, error) {
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
	if o.sarifOut != "" {
		if err := os.MkdirAll(o.sarifOut, 0o700); err != nil {
			return model.Scan{}, nil, err
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

		if o.sarifOut != "" {
			if err := os.WriteFile(filepath.Join(o.sarifOut, r.id+".sarif"), r.raw.Data, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: %s sarif-out write failed: %v\n", r.id, err)
			}
		}
	}

	// --- shadow pass: run newly-admitted generated rules report-only (§9.4).
	// Findings are marked Shadow so they surface in the report but never gate CI
	// or get written into a baseline until the rules age into the active set. ---
	if shadow != nil {
		if raw, serr := shadow.Run(ctx, tgt); serr != nil {
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
	return scan, diags, nil
}

// filterFindings drops findings in vendored/generated/minified files and, with
// --diff, findings outside the changed files. It runs before baseline and gating,
// so filtered findings never surface, gate, or get baselined.
func filterFindings(o *options, ev vault.Store, runID, absTarget string, scan *model.Scan) error {
	// --- noise filter: on by default; --no-default-excludes disables the built-ins. ---
	nm := noise.DefaultMatcher()
	if o.noDefaultExcludes {
		nm = noise.NewMatcher()
	}
	for _, p := range strings.Split(o.excludePaths, ",") {
		nm.Add(p)
	}
	if kept, excluded := nm.Filter(scan.Findings); len(excluded) > 0 {
		scan.Findings = kept
		fmt.Fprintf(os.Stderr, "achilles: excluded %d finding(s) in vendored/generated/minified paths (--no-default-excludes to disable)\n", len(excluded))
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "noise"},
			map[string]any{"excluded": len(excluded)})
	}

	// --- diff-aware: keep only findings in changed files ---
	if o.diffRef != "" {
		changed, err := vcs.ChangedFiles(absTarget, o.diffRef)
		if err != nil {
			return fmt.Errorf("git diff: %w", err)
		}
		before := len(scan.Findings)
		scan.Findings = vcs.FilterFindings(scan.Findings, changed)
		fmt.Fprintf(os.Stderr, "achilles: diff-aware — %d/%d finding(s) in %d changed file(s)\n", len(scan.Findings), before, len(changed))
	}
	return nil
}

// applyPRMini is the --pr-mini auto seed-vs-delta. If the baseline file doesn't
// exist yet, this run seeds it (write it, don't gate); once it exists, subsequent
// runs delta-scan against it (gate only on newly-introduced findings).
func applyPRMini(o *options) (seedMode bool, err error) {
	if o.prMini == "" {
		return false, nil
	}
	if o.baselinePath != "" || o.writeBl != "" {
		return false, fmt.Errorf("--pr-mini is mutually exclusive with --baseline/--write-baseline")
	}
	if _, statErr := os.Stat(o.prMini); statErr == nil {
		o.baselinePath = o.prMini
		return false, nil
	}
	o.writeBl = o.prMini
	fmt.Fprintf(os.Stderr, "achilles: pr-mini — no baseline at %s; seeding it (this run won't gate)\n", o.prMini)
	return true, nil
}

// inScopeFindings is the set a baseline is written from. Shadow findings are
// excluded so that when a generated rule ages into the active set, its findings
// are genuinely "new" and gate — rather than arriving pre-accepted in the baseline.
func inScopeFindings(findings []model.Finding) []model.Finding {
	inScope := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Shadow {
			inScope = append(inScope, f)
		}
	}
	return inScope
}

// applyBaseline classifies findings against --baseline, surfaces only the newly
// introduced ones so CI fails only on new findings, and records the full
// introduced/pre-existing/fixed breakdown for the report + audit trail.
func applyBaseline(o *options, ev vault.Store, runID string, scan *model.Scan) error {
	if o.baselinePath == "" {
		return nil
	}
	b, err := baseline.Load(o.baselinePath)
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
	return nil
}

// correlateFindings groups findings that different tools reported for the same
// defect (same file+line+CWE). It runs AFTER noise/diff/baseline so the indices
// match the surfaced set, and it collapses NOTHING — every finding keeps its own
// fingerprint, severity, and gating behaviour. The only consumer is triage, which
// triages one representative per cluster instead of every duplicate.
func correlateFindings(o *options, ev vault.Store, runID string, scan *model.Scan) []correlate.Cluster {
	if o.noCorrelate {
		return nil
	}
	clusters := correlate.Clusters(scan.Findings)
	correlate.Annotate(scan.Findings, clusters)
	if len(clusters) > 0 {
		fmt.Fprintf(os.Stderr, "achilles: correlated %d finding(s) into %d cross-tool cluster(s) — %d LLM triage pass(es) saved (--no-correlate to disable)\n",
			len(clusters)+correlate.Saved(clusters), len(clusters), correlate.Saved(clusters))
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "correlate"},
			map[string]any{"clusters": len(clusters), "triagePassesSaved": correlate.Saved(clusters)})
	}
	return clusters
}
