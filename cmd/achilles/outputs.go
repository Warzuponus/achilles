package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/baseline"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/threatmodel"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// writeReports writes the CI exports for the surfaced set, runs the opt-in GitHub
// integrations, and writes --write-baseline from inScope. Export write failures
// are errors; the outward-facing GitHub steps are best-effort and only warn.
func writeReports(ctx context.Context, o *options, absTarget string, scan model.Scan, inScope []model.Finding) error {
	if o.sarifReport != "" {
		if err := writeToFile(o.sarifReport, func(w io.Writer) error { return report.WriteSARIFReport(w, scan) }); err != nil {
			return err
		}
	}
	if o.jsonReport != "" {
		if err := writeToFile(o.jsonReport, func(w io.Writer) error { return report.WriteJSON(w, scan) }); err != nil {
			return err
		}
	}
	if o.gitlabSAST != "" || o.gitlabSecrets != "" {
		meta := report.GitLabMeta{Version: currentVersion().Version, Start: o.startedAt, End: time.Now(), Commit: scannedCommit(o)}
		if o.gitlabSAST != "" {
			if err := writeToFile(o.gitlabSAST, func(w io.Writer) error { return report.WriteGitLabSAST(w, scan, meta) }); err != nil {
				return err
			}
		}
		if o.gitlabSecrets != "" {
			if err := writeToFile(o.gitlabSecrets, func(w io.Writer) error { return report.WriteGitLabSecretDetection(w, scan, meta) }); err != nil {
				return err
			}
		}
	}
	if o.gitlabCodeQuality != "" {
		if err := writeToFile(o.gitlabCodeQuality, func(w io.Writer) error { return report.WriteGitLabCodeQuality(w, scan) }); err != nil {
			return err
		}
	}
	if o.junitOut != "" {
		if err := writeToFile(o.junitOut, func(w io.Writer) error { return report.WriteJUnit(w, scan) }); err != nil {
			return err
		}
	}
	if o.markdownOut != "" {
		if err := writeToFile(o.markdownOut, func(w io.Writer) error { return report.WriteMarkdown(w, scan) }); err != nil {
			return err
		}
	}
	if o.githubAnn {
		_ = report.WriteGitHubAnnotations(os.Stdout, scan)
	}
	if o.prComment > 0 && !o.dryRun {
		if err := runPRComment(ctx, o.prComment, o.repoFlag, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: pr-comment: %v\n", err)
		}
	}
	if o.prReview > 0 && !o.dryRun {
		if err := runPRReview(ctx, o.prReview, o.prHeadSHA, o.repoFlag, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: pr-review: %v\n", err)
		}
	}
	var issuesErr error // returned last, only under --issues-strict, so fix-pr and the baseline still run
	if o.fileIssues && !o.dryRun {
		if err := runFileIssues(ctx, o, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: file-issues: %v\n", err)
			if o.issuesStrict {
				issuesErr = fmt.Errorf("file-issues: %w", err)
			}
		}
	}
	if o.fixPR && !o.dryRun {
		if err := runFixPR(ctx, absTarget, o.repoFlag, o.fixRemote, o.fixBase, scan); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: fix-pr: %v\n", err)
		}
	}
	if o.writeBl != "" {
		if err := baseline.Write(o.writeBl, inScope); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles: wrote baseline (%d finding(s)) to %s\n", len(inScope), o.writeBl)
	}
	return issuesErr
}

// scannedCommit is the commit under scan, when the run was told or the CI system
// says: --source-commit, then GitLab's CI_COMMIT_SHA. Empty when unknown.
func scannedCommit(o *options) string {
	if o.sourceCommit != "" {
		return o.sourceCommit
	}
	return os.Getenv("CI_COMMIT_SHA")
}

// writeDiagnostics is the observability sidecar: coverage gaps (tools that failed
// to run or normalize) + LLM token usage, to the vault and to --diagnostics.
func writeDiagnostics(o *options, ev vault.Store, runID string, diags []toolDiag, llmUsage llm.Usage) error {
	if len(diags) > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d tool(s) failed, or ran but could not analyze everything; the scan is incomplete (see the lines above, or --diagnostics)\n", len(diags))
		recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "diagnostics"},
			map[string]any{"parseFailures": diags})
	}
	if o.diagnostics != "" {
		if err := writeToFile(o.diagnostics, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"run": runID, "parseFailures": diags, "llm": llmUsage})
		}); err != nil {
			return err
		}
	}
	return nil
}

// runAgents runs the opt-in whole-repo agents (security review, SCA
// upgrade advisor, threat model) and writes the unified HTML report. An agent
// failure only warns; its section is then missing from the report.
func runAgents(ctx context.Context, o *options, ev vault.Store, runID, absTarget string, scan model.Scan, tasks map[string]llm.TaskModel) error {
	// Agent outputs captured for the unified HTML report (nil if not run/failed).
	var reviewRes *review.Review
	var adviceRes *advisor.Advice
	var threatRes *threatmodel.ThreatModel

	// --- holistic full-repo security review ---
	if o.reviewOn && !o.dryRun {
		r, err := runReview(ctx, ev, runID, absTarget, scan, o.llmBaseURL, o.llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: review: %v\n", err)
		}
		reviewRes = r
	}

	// --- SCA dependency-upgrade advisor ---
	if o.scaAdvice && !o.dryRun {
		a, err := runAdvisor(ctx, ev, runID, absTarget, scan, o.llmBaseURL, o.llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: sca-advice: %v\n", err)
		}
		adviceRes = a
	}

	// --- threat-model agent → OTM artifact ---
	if o.threatModelOut != "" && !o.dryRun {
		tm, err := runThreatModel(ctx, ev, runID, absTarget, scan, o.threatModelOut, o.llmBaseURL, o.llmModel, tasks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "achilles: threat-model: %v\n", err)
		}
		threatRes = tm
	}

	// --- unified HTML report (findings + AI review/advice/threat-model) ---
	if o.htmlReport != "" {
		hr := report.HTMLReport{
			Target: absTarget, GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 MST"),
			Tools: scan.Tools, Scan: scan, Review: reviewRes, Advice: adviceRes, ThreatModel: threatRes,
		}
		if err := writeToFile(o.htmlReport, func(w io.Writer) error { return report.WriteHTML(w, hr) }); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles: wrote HTML report to %s\n", o.htmlReport)
	}
	return nil
}
