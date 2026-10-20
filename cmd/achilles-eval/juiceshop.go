package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Warzuponus/achilles/internal/eval"
)

// runJuiceShop scans OWASP Juice Shop at the commit pinned in the truth file and
// scores Achilles' own rules against Juice Shop's own labels (see
// internal/eval/juiceshop.go). With no --juice-shop-dir it checks the pinned
// commit out into the cache directory, the way --mode detect does for its git
// targets; a directory given by hand must be at that commit.
func runJuiceShop(dir, truthPath, achillesBin, cacheDir, out string, timeout time.Duration) error {
	truth, err := eval.LoadJuiceShopTruth(truthPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	git := eval.ExecGit{}
	if dir == "" {
		dir, err = eval.ResolveSource(ctx, eval.GroundTruth{
			ID: "juice-shop", Source: eval.Source{URL: truth.URL, Commit: truth.Commit},
		}, cacheDir, git)
		if err != nil {
			return err
		}
	} else if head, err := git.Git(ctx, dir, "rev-parse", "HEAD"); err != nil || head != truth.Commit {
		return fmt.Errorf("%s is at %q, not the pinned %s: the judgements are by line, so they hold only at that commit", dir, head, truth.Commit)
	}

	labels, variants, err := eval.ParseJuiceShop(dir)
	if err != nil {
		return err
	}
	if len(labels) == 0 {
		return fmt.Errorf("%s: no vuln-code-snippet vuln-line comments (is this a Juice Shop checkout?)", dir)
	}

	bin, err := locateAchilles(ctx, achillesBin, cacheDir)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "achilles-juiceshop-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	sarif := filepath.Join(work, "report.sarif")
	fmt.Fprintf(os.Stderr, "achilles-eval: juice-shop — %d marked lines, %d candidate fixes; scanning with %s\n", len(labels), len(variants), bin)
	cmd := exec.CommandContext(ctx, bin, "--vault", filepath.Join(work, "vault.json"), "--sarif-report", sarif, dir) // #nosec G204 -- operator-chosen binary, fixed flags
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		// Exit 1 means findings at or above --fail-on: the expected outcome here.
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return fmt.Errorf("achilles: %w", err)
		}
	}
	data, err := os.ReadFile(sarif) // #nosec G304 -- a file in our own temp dir
	if err != nil {
		return fmt.Errorf("achilles wrote no SARIF report: %w", err)
	}
	findings, other, err := eval.JuiceShopFindings(data, dir)
	if err != nil {
		return err
	}
	res := eval.ScoreJuiceShop(truth, labels, variants, findings)
	eval.WriteJuiceShopReport(os.Stdout, res)
	if other > 0 {
		fmt.Printf("\n%d finding(s) from other scanners (gitleaks, osv-scanner, ...) are not scored: this measures Achilles' own rules.\n", other)
	}
	if res.Unjudged > 0 {
		fmt.Printf("\n%d finding(s) are not judged yet. Read each one and add it to %s as real or wrong.\n", res.Unjudged, truthPath)
	}
	if out != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}
