package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/gitops"
	"github.com/Warzuponus/achilles/internal/issues"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/report"
)

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

// runFileIssues files/reconciles GitHub issues for the scan's kept findings via
// internal/issues (dedupe, regression reopen, public-repo guard, redaction; see
// that package). It returns an error only for a fatal problem or, with
// --issues-strict, for any failed GitHub call; the caller decides whether that is
// fatal. Outward-facing + opt-in.
func runFileIssues(ctx context.Context, o *options, scan model.Scan) error {
	gc, err := github.New(envOr("GITHUB_TOKEN", os.Getenv("GH_TOKEN")), o.repoFlag, os.Getenv("GITHUB_API_URL"))
	if err != nil {
		return err
	}
	reconcile, why := issuesReconcile(o)
	_, err = issues.Sync(ctx, gc, scan, issues.Options{
		Repo:                o.repoFlag,
		Label:               o.issuesLabel,
		MinSeverity:         o.issuesMinSeverity,
		Max:                 o.issuesMax,
		Group:               issues.Group(o.issuesGroup),
		DryRun:              o.issuesDryRun,
		Strict:              o.issuesStrict,
		AllowPublic:         o.allowPublicIssues,
		CommitSHA:           os.Getenv("GITHUB_SHA"),
		ServerURL:           envOr("GITHUB_SERVER_URL", "https://github.com"),
		Reconcile:           reconcile,
		ReconcileSkipReason: why,
		Out:                 os.Stderr,
	})
	return err
}

// issuesReconcile reports whether closing issues for findings that are no longer
// detected is safe. It is only safe when the scan saw everything: a diff, a
// baseline or a PR-mini delta narrows what is reported, so an absent finding
// proves nothing. (Failed scanners are checked by issues.Sync from the scan.)
func issuesReconcile(o *options) (bool, string) {
	switch {
	case o.diffRef != "":
		return false, "--diff only scans changed files"
	case o.baselinePath != "":
		return false, "--baseline hides known findings"
	case o.prMini != "":
		return false, "--pr-mini reports only the delta against a baseline"
	}
	return true, ""
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
