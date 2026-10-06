// Package issues files and maintains GitHub Issues for Achilles findings.
//
// The work is split in two so it is testable and previewable: BuildPlan is a pure
// function from (scan, existing issues) to a list of create/update/reopen/close
// actions, and Sync applies that plan through a small API interface. With
// Options.DryRun the plan is printed and no write API is called.
//
// Lifecycle of one tracked issue, identified by a hidden marker in its body:
//
//   - finding detected, no issue            -> create
//   - finding detected, issue open          -> update only if its content changed
//   - finding detected, issue closed by a human            -> suppressed (left closed)
//   - finding detected, issue closed by Achilles (labelled
//     achilles:resolved)                    -> reopen with a comment (regression)
//   - finding gone (full, clean scan only)  -> close, labelled achilles:resolved
//   - finding dismissed by the AI review    -> close, labelled achilles:resolved
//
// Issue bodies describe unfixed vulnerabilities, so nothing is filed in a public
// repository unless Options.AllowPublic is set, and secret-scanner findings never
// carry the secret or any code.
package issues

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/model"
)

// ResolvedLabel marks an issue Achilles itself closed. It is what tells a
// regression (reopen) apart from a human's "won't fix" (stay suppressed).
const ResolvedLabel = "achilles:resolved"

// Group selects how findings map to issues.
type Group string

const (
	GroupFinding Group = "finding" // one issue per fingerprint
	GroupRule    Group = "rule"    // one issue per tool+rule, listing locations
	GroupRollup  Group = "rollup"  // a single issue listing every finding
)

// API is the slice of the GitHub client that Sync uses. *github.Client implements
// it; tests use an in-memory fake.
type API interface {
	ListIssues(ctx context.Context, label string) ([]github.Issue, error)
	CreateIssue(ctx context.Context, title, body string, labels []string) (int, error)
	UpdateIssue(ctx context.Context, number int, u github.IssueUpdate) error
	AddComment(ctx context.Context, number int, body string) error
	EnsureLabel(ctx context.Context, name, color, description string) error
	RepoIsPrivate(ctx context.Context) (bool, error)
}

var _ API = (*github.Client)(nil)

// Options configures one Sync.
type Options struct {
	Repo        string // owner/name, used for permalinks and messages
	Label       string // label scoping Achilles's issues (default "achilles")
	MinSeverity string // lowest severity to file (default "medium")
	Max         int    // most NEW issues per run (default 25)
	Group       Group  // default GroupFinding
	DryRun      bool   // print the plan, call no write API
	Strict      bool   // Sync returns an error if any API call failed
	AllowPublic bool   // allow filing in a public repository

	CommitSHA string // for file:line permalinks; empty = plain text locations
	ServerURL string // default https://github.com

	// Reconcile allows closing issues whose finding is no longer detected. It is
	// only safe when the scan was complete and un-narrowed (no --diff, baseline or
	// failed tools); the caller passes the reason it is off in ReconcileSkipReason
	// so the summary can say why.
	Reconcile           bool
	ReconcileSkipReason string

	Out io.Writer // human summary; nil discards
}

// Summary is the outcome of a Sync.
type Summary struct {
	Created, Updated, Reopened, Closed int
	Unchanged                          int            // tracked issues already up to date
	Deferred                           int            // new issues held back by Max (filed on later runs)
	Skipped                            map[string]int // reason -> count (findings or issues, per reason text)
	Failed                             int
	Errors                             []string
	Blocked                            string // non-empty when nothing was filed (e.g. public repo guard)
	DryRun                             bool
}

// Sync reconciles the scan's findings with the repository's Achilles issues.
//
// A non-nil error means either a fatal precondition failed (could not list
// issues) or, with Strict, that the public-repo guard blocked filing or an API
// call failed. Without Strict, individual call failures are only reported in the
// returned Summary and on Out.
func Sync(ctx context.Context, api API, scan model.Scan, opts Options) (Summary, error) {
	opts, err := opts.normalize()
	if err != nil {
		return Summary{}, err
	}
	if len(scan.FailedTools) > 0 {
		opts.Reconcile = false
		opts.ReconcileSkipReason = fmt.Sprintf("%d scanner(s) failed, so the scan is incomplete", len(scan.FailedTools))
	}
	sum := Summary{Skipped: map[string]int{}, DryRun: opts.DryRun}

	if blocked := checkVisibility(ctx, api, opts); blocked != "" {
		sum.Blocked = blocked
		fmt.Fprintf(opts.Out, "achilles: file-issues: %s\n", blocked)
		if opts.Strict {
			return sum, errors.New(blocked)
		}
		return sum, nil
	}

	existing, err := api.ListIssues(ctx, opts.Label)
	if err != nil {
		return sum, fmt.Errorf("list issues: %w", err)
	}
	plan := BuildPlan(scan, existing, opts)
	sum.Skipped = plan.Skipped
	sum.Deferred = plan.Deferred
	sum.Unchanged = plan.Unchanged

	if opts.DryRun {
		plan.print(opts.Out)
		for _, a := range plan.Actions {
			sum.count(a.Kind)
		}
	} else {
		apply(ctx, api, plan, opts, &sum)
	}
	sum.print(opts, plan)

	if opts.Strict && sum.Failed > 0 {
		return sum, fmt.Errorf("%d GitHub call(s) failed (first: %s)", sum.Failed, sum.Errors[0])
	}
	return sum, nil
}

func (s *Summary) count(k ActionKind) {
	switch k {
	case ActionCreate:
		s.Created++
	case ActionUpdate:
		s.Updated++
	case ActionReopen:
		s.Reopened++
	case ActionClose:
		s.Closed++
	}
}

func (o Options) normalize() (Options, error) {
	if o.Label == "" {
		o.Label = "achilles"
	}
	if o.MinSeverity == "" {
		o.MinSeverity = "medium"
	}
	if o.Max <= 0 {
		o.Max = 25
	}
	if o.Group == "" {
		o.Group = GroupFinding
	}
	if o.ServerURL == "" {
		o.ServerURL = "https://github.com"
	}
	o.ServerURL = strings.TrimRight(o.ServerURL, "/")
	if o.Out == nil {
		o.Out = io.Discard
	}
	switch o.Group {
	case GroupFinding, GroupRule, GroupRollup:
	default:
		return o, fmt.Errorf("unknown --issues-group %q (want finding, rule or rollup)", o.Group)
	}
	if _, err := parseSeverity(o.MinSeverity); err != nil {
		return o, err
	}
	return o, nil
}

func parseSeverity(s string) (model.Severity, error) {
	sev := model.Severity(strings.ToLower(strings.TrimSpace(s)))
	if sev.Rank() == 0 {
		return "", fmt.Errorf("unknown --issues-min-severity %q (want critical, high, medium, low or info)", s)
	}
	return sev, nil
}

// checkVisibility enforces the public-repo guard. It returns a non-empty message
// when filing must not proceed. A failed lookup is treated as public: the cost of
// wrongly refusing is one flag, the cost of wrongly filing is a disclosed vuln.
func checkVisibility(ctx context.Context, api API, o Options) string {
	if o.AllowPublic {
		return ""
	}
	private, err := api.RepoIsPrivate(ctx)
	const hint = "Achilles will not file vulnerability details as issues in a public repository. " +
		"Re-run with --allow-public-issues to override, or publish results privately instead: " +
		"upload SARIF (--sarif-report) to the repository's Security tab."
	switch {
	case err != nil:
		return fmt.Sprintf("could not determine whether %s is public (%v), so it is treated as public. %s", o.Repo, err, hint)
	case !private:
		return fmt.Sprintf("%s is a public repository. %s", o.Repo, hint)
	}
	return ""
}

// apply executes the plan. Failures are recorded per action and the run
// continues, so one bad call does not strand the rest.
func apply(ctx context.Context, api API, plan Plan, o Options, sum *Summary) {
	fail := func(a Action, what string, err error) {
		sum.Failed++
		sum.Errors = append(sum.Errors, fmt.Sprintf("%s %s: %v", a.Kind, what, err))
	}
	if len(plan.Actions) == 0 {
		return
	}
	// Label creation is best-effort: GitHub also creates labels named in an issue
	// request, and a token that cannot manage labels may still manage issues.
	var needBase, needResolved bool
	for _, a := range plan.Actions {
		needBase = needBase || a.Kind == ActionCreate
		needResolved = needResolved || a.Kind == ActionClose
	}
	if needBase {
		if err := api.EnsureLabel(ctx, o.Label, "d93f0b", "Managed by Achilles"); err != nil {
			fmt.Fprintf(o.Out, "achilles: file-issues: warning: could not ensure label %q: %v\n", o.Label, err)
		}
	}
	if needResolved {
		if err := api.EnsureLabel(ctx, ResolvedLabel, "0e8a16", "Closed by Achilles: finding resolved or dismissed"); err != nil {
			fmt.Fprintf(o.Out, "achilles: file-issues: warning: could not ensure label %q: %v\n", ResolvedLabel, err)
		}
	}

	for _, a := range plan.Actions {
		if err := ctx.Err(); err != nil {
			sum.Failed++
			sum.Errors = append(sum.Errors, fmt.Sprintf("aborted before %s %s: %v", a.Kind, a.describe(), err))
			return
		}
		ok := true
		switch a.Kind {
		case ActionCreate:
			if _, err := api.CreateIssue(ctx, a.Title, a.Body, a.Labels); err != nil {
				fail(a, a.describe(), err)
				ok = false
			}
		case ActionUpdate:
			if err := api.UpdateIssue(ctx, a.Number, github.IssueUpdate{Title: &a.Title, Body: &a.Body, Labels: labelsPtr(a.Labels)}); err != nil {
				fail(a, a.describe(), err)
				ok = false
			}
		case ActionReopen:
			open, reason := "open", "reopened"
			u := github.IssueUpdate{Title: &a.Title, Body: &a.Body, State: &open, StateReason: &reason, Labels: labelsPtr(a.Labels)}
			if err := api.UpdateIssue(ctx, a.Number, u); err != nil {
				fail(a, a.describe(), err)
				ok = false
			} else if err := api.AddComment(ctx, a.Number, a.Comment); err != nil {
				// The state change is what matters; report the comment failure but count the reopen.
				fail(a, a.describe()+" (comment)", err)
			}
		case ActionClose:
			closed := "closed"
			u := github.IssueUpdate{State: &closed, StateReason: &a.StateReason, Labels: labelsPtr(a.Labels)}
			if err := api.UpdateIssue(ctx, a.Number, u); err != nil {
				fail(a, a.describe(), err)
				ok = false
			} else if err := api.AddComment(ctx, a.Number, a.Comment); err != nil {
				fail(a, a.describe()+" (comment)", err)
			}
		}
		if ok {
			sum.count(a.Kind)
		}
	}
}

func labelsPtr(l []string) *[]string {
	if l == nil {
		return nil
	}
	return &l
}

// print writes the one-paragraph human summary.
func (s Summary) print(o Options, plan Plan) {
	w := o.Out
	verb := ""
	if s.DryRun {
		verb = "would be "
	}
	fmt.Fprintf(w, "achilles: file-issues (%s, group=%s): %d %screated, %d %supdated, %d %sreopened, %d %sclosed, %d already up to date",
		o.Repo, o.Group, s.Created, verb, s.Updated, verb, s.Reopened, verb, s.Closed, verb, s.Unchanged)
	if s.DryRun {
		fmt.Fprint(w, " (dry run: no GitHub write call was made)")
	}
	fmt.Fprint(w, ".")
	if s.Deferred > 0 {
		fmt.Fprintf(w, " %d new issue(s) held back by --issues-max=%d (highest severity first); they will be filed on later runs.", s.Deferred, o.Max)
	}
	reasons := make([]string, 0, len(s.Skipped))
	for r := range s.Skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	if len(reasons) > 0 {
		parts := make([]string, 0, len(reasons))
		for _, r := range reasons {
			parts = append(parts, fmt.Sprintf("%d %s", s.Skipped[r], r))
		}
		fmt.Fprintf(w, " Skipped: %s.", strings.Join(parts, "; "))
	}
	if !o.Reconcile && o.ReconcileSkipReason != "" {
		fmt.Fprintf(w, " Auto-close of resolved findings was skipped: %s.", o.ReconcileSkipReason)
	}
	for _, n := range plan.Notes {
		fmt.Fprintf(w, " %s", n)
	}
	if s.Failed > 0 {
		fmt.Fprintf(w, " %d GitHub call(s) FAILED.", s.Failed)
	}
	fmt.Fprintln(w)
	for _, e := range s.Errors {
		fmt.Fprintf(w, "achilles: file-issues: failed: %s\n", e)
	}
}
