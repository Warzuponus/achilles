package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/gitops"
	"github.com/Warzuponus/achilles/internal/issues"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/report"
	"github.com/Warzuponus/achilles/internal/verifyfix"
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

// An inline comment starts with this marker, naming the finding it is about.
var fpMarkerRE = regexp.MustCompile(`^\s*<!-- achilles:fp:(\S+) -->`)

var safeMarkerToken = regexp.MustCompile(`^[A-Za-z0-9:_.=+/-]{1,128}$`)

// markerToken is a finding's fingerprint in a form that is safe inside an HTML
// comment. A scanner may supply its own fingerprint, which is then repository-
// influenced text: one containing "-->" would end the marker early and put the
// rest of it into the comment as Markdown.
func markerToken(fingerprint string) string {
	if safeMarkerToken.MatchString(fingerprint) {
		return fingerprint
	}
	sum := sha256.Sum256([]byte(fingerprint))
	return "h:" + hex.EncodeToString(sum[:16])
}

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

	// Only comments Achilles itself wrote count as "already posted". Anyone can
	// comment on a pull request, including its author: honoring a marker in a
	// stranger's comment would let them suppress the inline comment for a finding
	// by planting its marker first.
	seen := map[string]bool{}
	if existing, err := gc.ListPullComments(ctx, pr); err == nil {
		for _, c := range gc.Own(ctx, existing) {
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
		token := markerToken(f.Fingerprint)
		if f.Shadow || f.Location.File == "" || f.Location.Region.StartLine == 0 || seen[token] {
			continue
		}
		// The rule id and the message come from scanning code that may be hostile.
		body := fmt.Sprintf("<!-- achilles:fp:%s -->\n**[%s] %s** — %s", token, f.Severity, report.MarkdownText(f.RuleID), report.FindingMessage(f))
		if err := gc.CreateReviewComment(ctx, pr, headSHA, f.Location.File, f.Location.Region.StartLine, body); err != nil {
			skipped++ // most often: the line isn't part of the diff (422)
			continue
		}
		seen[token] = true
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

// proposedFix is one remediation diff selected for the auto-fix PR.
type proposedFix struct {
	fp, rule, diff string
	file           string // the finding's file, relative to the scan target; the only path the diff may change
	verified       bool
}

// selectFixes picks the remediation diffs runFixPR may apply and returns one
// message for every diff it declines or caveats, so nothing is skipped silently. A
// diff is applied only if a re-scan verified it (Remediation.Verification). When
// verification did not run at all (--verify-fixes=false) the diff is applied with a
// note that it is unverified.
//
// Every diff, verified or not, must also pass verifyfix.CheckFix: it may change the
// finding's own file and nothing else. Verification re-runs one scanner; it would
// not notice a "fix" that also edits a workflow or a build script, so the scope
// rule cannot depend on whether verification happened to run.
func selectFixes(findings []model.Finding) (fixes []proposedFix, notes []string) {
	unverified := 0
	for _, f := range findings {
		if f.Shadow || f.Remediation == nil {
			continue
		}
		if strings.TrimSpace(f.Remediation.Diff) == "" {
			continue // prose-only guidance — no machine-applicable patch
		}
		v := f.Remediation.Verification
		if v != nil && v.Status != model.FixVerified {
			notes = append(notes, fmt.Sprintf("achilles: fix-pr — skip %s (%s): fix not verified (%s)%s",
				f.RuleID, f.Fingerprint, v.Status, detailSuffix(v.Detail)))
			continue
		}
		file := filepath.ToSlash(f.Location.File)
		if err := verifyfix.CheckFix(f.Remediation.Diff, file); err != nil {
			notes = append(notes, fmt.Sprintf("achilles: fix-pr — skip %s (%s): diff rejected: %v", f.RuleID, f.Fingerprint, err))
			continue
		}
		if v == nil {
			unverified++
		}
		fixes = append(fixes, proposedFix{fp: f.Fingerprint, rule: f.RuleID, diff: f.Remediation.Diff, file: file, verified: v != nil})
	}
	if unverified > 0 {
		notes = append(notes, fmt.Sprintf("achilles: fix-pr — note: %d diff(s) were not re-scanned (verification did not run; see --verify-fixes); applying them unverified", unverified))
	}
	return fixes, notes
}

func detailSuffix(d string) string {
	d = strings.Join(strings.Fields(d), " ")
	if d == "" {
		return ""
	}
	return ": " + d
}

// runFixPR opens a review PR carrying Achilles's high-confidence auto-fixes: it
// applies each remediation's unified diff to a fresh branch, commits, pushes, and
// opens a PR. It NEVER merges (DESIGN §1 Non-Goals; the confirmed auto-fix
// guardrail). The branch name is derived from the fingerprints being fixed, so a
// re-run reuses the same branch/PR rather than spawning duplicates. Only diffs
// whose re-scan verified them are applied (see selectFixes); patches that don't
// apply cleanly are skipped, not fatal. Outward-facing + opt-in.
//
// The branch is built in a temporary git worktree (see commitFixes), so the
// user's checkout is never switched, and only the files the fixes change are
// committed.
func runFixPR(ctx context.Context, dir, repo, remote, base string, scan model.Scan) error {
	fixes, held := selectFixes(scan.Findings)
	for _, msg := range held {
		fmt.Fprintln(os.Stderr, msg)
	}
	if len(fixes) == 0 {
		if len(held) > 0 {
			fmt.Fprintln(os.Stderr, "achilles: fix-pr — no proposed diff passed verification; opened no PR")
			return nil
		}
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

	applied, base, err := commitFixes(ctx, dir, branch, base, fixes, func(wt *gitops.Repo) error {
		return wt.Push(ctx, remote, branch)
	})
	if err != nil {
		return err
	}

	var body strings.Builder
	fmt.Fprintf(&body, "Automated fixes proposed by Achilles from confirmed, high-confidence findings.\n\n**Review before merging — Achilles opens this PR but never merges it.**\n\n")
	for _, fx := range applied {
		status := "not re-scanned"
		if fx.verified {
			status = "re-scan: finding gone, nothing new"
		}
		fmt.Fprintf(&body, "- `%s` in `%s` (fingerprint `%s`; %s)\n", fx.rule, fx.file, fx.fp, status)
	}
	fmt.Fprintf(&body, "\nEach fix changes only the file its finding is in. A model wrote these patches; "+
		"the re-scan shows the scanner no longer reports the finding, not that the change is correct.\n")
	pr, err := gc.CreatePull(ctx, fmt.Sprintf("Achilles auto-fix: %d finding(s)", len(applied)), branch, base, body.String())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "achilles: fix-pr — opened PR #%d (%s) with %d fix(es); NOT merged\n", pr.Number, pr.HTMLURL, len(applied))
	return nil
}

// commitFixes builds the auto-fix branch and hands it to publish (the push) while
// it still exists on disk. It returns the fixes that applied and the base branch
// the PR should target.
//
// Everything happens in a temporary git worktree created from base:
//
//   - the user's own checkout is never switched to another branch and nothing in
//     it is staged, so uncommitted work, an untracked .env, and the vault and
//     reports this very scan wrote into the tree cannot end up in the commit;
//   - the commit names exactly the files the applied fixes change (each fix may
//     change only its finding's file; see verifyfix.CheckFix). Nothing is ever
//     staged wholesale.
//
// A patch that does not apply cleanly is skipped. dir is the scan target, which
// may be a subdirectory of the repository: diffs are relative to it.
func commitFixes(ctx context.Context, dir, branch, base string, fixes []proposedFix, publish func(wt *gitops.Repo) error) ([]proposedFix, string, error) {
	top, err := gitops.TopLevel(ctx, dir)
	if err != nil {
		return nil, base, fmt.Errorf("locate git repo for %q: %w", dir, err)
	}
	repo := &gitops.Repo{Dir: top}
	prefix, err := (&gitops.Repo{Dir: dir}).Prefix(ctx)
	if err != nil {
		return nil, base, err
	}
	if base == "" {
		if base, err = repo.CurrentBranch(ctx); err != nil {
			return nil, base, err
		}
		if base == "HEAD" {
			return nil, base, fmt.Errorf("the checkout is on a detached HEAD, so there is no branch to open the PR against; pass --fix-base <branch>")
		}
	}
	if dirty, err := repo.Dirty(ctx); err == nil && dirty {
		fmt.Fprintf(os.Stderr, "achilles: fix-pr — the working tree has uncommitted or untracked changes. They are left untouched and are NOT "+
			"part of the fix branch, which is built from the committed %s; a fix written against uncommitted code may not apply.\n", base)
	}

	parent, err := os.MkdirTemp("", "achilles-fixpr-*")
	if err != nil {
		return nil, base, err
	}
	wtPath := filepath.Join(parent, "wt")
	if err := repo.AddWorktree(ctx, wtPath, branch, base); err != nil {
		_ = os.RemoveAll(parent)
		return nil, base, err
	}
	defer func() {
		// Not ctx: the worktree must be removed even when the run was cancelled.
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = repo.RemoveWorktree(cctx, wtPath)
		_ = os.RemoveAll(parent)
	}()

	wt := &gitops.Repo{Dir: filepath.Join(wtPath, filepath.FromSlash(prefix))}
	var applied []proposedFix
	var paths []string
	staged := map[string]bool{}
	for _, fx := range fixes {
		// Re-checked here, right before the write, so no caller can reach `git
		// apply` with a diff that was not scoped.
		if err := verifyfix.CheckFix(fx.diff, fx.file); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: fix-pr — skip %s (%s): diff rejected: %v\n", fx.rule, fx.fp, err)
			continue
		}
		if err := wt.Apply(ctx, fx.diff); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: fix-pr — skip %s (%s): patch did not apply cleanly\n", fx.rule, fx.fp)
			continue
		}
		applied = append(applied, fx)
		if !staged[fx.file] {
			staged[fx.file] = true
			paths = append(paths, fx.file)
		}
	}
	if len(applied) == 0 {
		return nil, base, fmt.Errorf("no proposed diff applied cleanly; opened no PR")
	}
	if err := wt.Commit(ctx, fmt.Sprintf("fix: Achilles auto-fix (%d finding(s))", len(applied)), paths...); err != nil {
		return nil, base, err
	}
	if publish != nil {
		if err := publish(wt); err != nil {
			return nil, base, err
		}
	}
	return applied, base, nil
}
