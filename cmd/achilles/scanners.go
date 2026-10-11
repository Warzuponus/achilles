package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"

	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/generic"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
	"github.com/Warzuponus/achilles/internal/toolchain"
)

func runFromSARIF(path, failOn string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read --from-sarif: %w", err)
	}
	findings, err := normalize.Normalize("sarif", "unknown", data)
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
				r.findings, r.normErr = normalize.Normalize(raw.Format, raw.Tool, raw.Data)
				if r.normErr == nil {
					// From here on the raw output is only stored and written out
					// (vault, --sarif-out), so the matched text of credential
					// findings comes out of it now.
					raw.Data = normalize.ScrubRaw(raw.Format, raw.Data, r.findings)
				}
				r.raw = raw
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
		// An on-disk directory wins; the default "configs/rules" falls back to the
		// rules embedded in the binary (config.ResolveRulesDir has the precedence).
		dir, err := config.ResolveRulesDir(tc.Rules)
		if err != nil {
			return nil, err
		}
		rulesHost = dir
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
		// Rule precedence for Opengrep: the primary rules (an on-disk dir, else
		// the baseline embedded in the binary — always the offline fallback) are
		// ALWAYS loaded; the community pack installed by `achilles tools install`
		// is loaded IN ADDITION via a second -f when present.
		if dir := communityRulesDir(); dir != "" {
			opts = append(opts, opengrep.WithExtraRules(dir))
		}
		// Opengrep has no public container image, so under --runner docker it still
		// runs as the local binary (as docs/getting-started.md says) rather than
		// asking Docker for an empty image.
		if _, isDocker := runner.(xexec.DockerRunner); isDocker && tc.Image == "" {
			runner = xexec.LocalRunner{}
		}
		return opengrep.New(runner, rulesHost, opts...), nil
	case tc.Bespoke:
		return nil, fmt.Errorf("tool %q marked bespoke but no adapter is wired", tc.ID)
	default:
		return generic.New(runner, tc, rulesHost), nil
	}
}

// communityRulesAllowed is false under --mode commercial: the community pack
// (opengrep-rules) carries a Commons Clause that forbids selling it, so it must not
// run in a commercial scan. Set from the license mode in run().
var communityRulesAllowed = true

// communityRulesDir returns the installed community rules directory, or "" when it
// is not installed or not allowed in this mode.
func communityRulesDir() string {
	ir := toolchain.InstalledCommunityRules()
	if !ir.Installed {
		return ""
	}
	if !communityRulesAllowed {
		fmt.Fprintln(os.Stderr, "achilles: community rules are installed but skipped in --mode commercial (Commons Clause)")
		return ""
	}
	return ir.Dir
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
	threshold, ok := model.ParseSeverity(failOn)
	if !ok {
		// An unknown word ranks below every real severity, so without this check a
		// typo would make ANY finding fail the gate (and "critcal" would look strict).
		return fmt.Errorf("--fail-on %q is not a severity (want critical, high, medium, low or info)", failOn)
	}
	// Gate on non-shadow findings only: shadow (report-only) generated-rule
	// findings must never fail CI until they age into the active set.
	worst := report.GatingSeverity(scan)
	if worst != model.SeverityUnknown && worst.Rank() >= threshold.Rank() {
		return &gateError{worst: worst, threshold: threshold}
	}
	return nil
}
