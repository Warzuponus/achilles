package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/verifyfix"
)

// verifyConcurrency bounds how many patched copies are scanned at once: each one is
// a full copy of the target plus a scanner run.
const verifyConcurrency = 2

// fixVerifier is what verifyScanFixes needs from internal/verifyfix.
type fixVerifier interface {
	Verify(ctx context.Context, f model.Finding, diff string) verifyfix.Result
}

// verifyRemediations (--verify-fixes) re-scans every proposed patch: it applies the
// remediation's diff to a temporary copy of the target and re-runs the scanner that
// reported the finding. The result is stored on Remediation.Verification, appended
// to the vault, and summarised on stderr. It never fails the scan: every problem is
// a per-fix status, so the only error returned is a nil one (the signature keeps an
// error for the caller's convenience).
func verifyRemediations(ctx context.Context, o *options, absTarget string, reg *scanner.Registry, scan *model.Scan, ev vault.Store, runID string) error {
	if !o.verifyFixes || scan == nil || !hasFixDiff(scan.Findings) {
		return nil
	}
	var langs []string
	if inv, err := inventory.Scan(absTarget); err == nil {
		langs = inv.Languages
	}
	known := append(append([]model.Finding{}, scan.Findings...), scan.Dismissed...)
	v := verifyfix.New(reg, absTarget, verifyfix.Options{Languages: langs, Known: known})
	verifyScanFixes(ctx, v, scan, ev, runID)
	return nil
}

func hasFixDiff(fs []model.Finding) bool {
	for _, f := range fs {
		if wantsVerification(f) {
			return true
		}
	}
	return false
}

func wantsVerification(f model.Finding) bool {
	return !f.Shadow && f.Remediation != nil && strings.TrimSpace(f.Remediation.Diff) != ""
}

// verifyScanFixes runs v over every finding that carries a diff, stores each result
// on its remediation, then (single-threaded, as the vault counters are not
// goroutine-safe) records the results and prints the summary.
func verifyScanFixes(ctx context.Context, v fixVerifier, scan *model.Scan, ev vault.Store, runID string) {
	var idx []int
	for i := range scan.Findings {
		if wantsVerification(scan.Findings[i]) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "achilles: verifying %d proposed fix(es) by re-scanning each patched copy\n", len(idx))

	sem := make(chan struct{}, verifyConcurrency)
	var wg sync.WaitGroup
	for _, i := range idx {
		wg.Add(1)
		sem <- struct{}{}
		go func(f *model.Finding) {
			defer wg.Done()
			defer func() { <-sem }()
			res := v.Verify(ctx, *f, f.Remediation.Diff)
			// Copy before writing: never mutate a Remediation another finding might share.
			rem := *f.Remediation
			rem.Verification = &res
			f.Remediation = &rem
		}(&scan.Findings[i])
	}
	wg.Wait()

	counts := map[model.FixVerificationStatus]int{}
	for _, i := range idx {
		f := scan.Findings[i]
		counts[f.Remediation.Verification.Status]++
		if ev != nil {
			recordFixVerification(ev, runID, f)
		}
	}
	fmt.Fprintln(os.Stderr, "achilles: "+verifySummary(counts))
}

// recordFixVerification appends the remediation, now carrying its verification, as
// a record that supersedes the one triage wrote for the same finding (same payload
// shape, so readers of remediation records keep working).
func recordFixVerification(ev vault.Store, runID string, f model.Finding) {
	rec := vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindRemediation, Source: "verifyfix", Fingerprint: f.Fingerprint}
	for _, r := range ev.ByRun(runID) {
		if r.Kind == vault.KindRemediation && r.Fingerprint == f.Fingerprint && r.Source != "verifyfix" {
			rec.PrevID = r.ID
		}
	}
	recordJSON(ev, rec, f.Remediation)
}

// verifySummary renders the one-line stderr summary, e.g.
// "fix verification: 3 verified, 1 not fixed, 1 patch failed".
func verifySummary(counts map[model.FixVerificationStatus]int) string {
	var parts []string
	for _, s := range []struct {
		st    model.FixVerificationStatus
		label string
	}{
		{model.FixVerified, "verified"},
		{model.FixNotFixed, "not fixed"},
		{model.FixIntroducesNew, "introduce new findings"},
		{model.FixPatchFailed, "patch failed"},
		{model.FixSkipped, "skipped"},
		{model.FixError, "error"},
	} {
		if n := counts[s.st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s.label))
		}
	}
	return "fix verification: " + strings.Join(parts, ", ")
}
