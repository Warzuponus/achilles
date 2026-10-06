package issues

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/model"
)

// ActionKind is one planned change to the issue tracker.
type ActionKind string

const (
	ActionCreate ActionKind = "create"
	ActionUpdate ActionKind = "update"
	ActionReopen ActionKind = "reopen"
	ActionClose  ActionKind = "close"
)

// Action is one planned change.
type Action struct {
	Kind        ActionKind
	Key         string // marker key, e.g. "fp:0123abcd"
	Number      int    // issue number; 0 for create
	Title, Body string // create/update/reopen
	// Labels is the complete label set to write; nil leaves labels unchanged.
	Labels      []string
	Comment     string // posted after a reopen/close
	StateReason string // close: "completed" | "not_planned"
	Severity    model.Severity
	Reason      string // why, for the dry-run listing
}

func (a Action) describe() string {
	if a.Number > 0 {
		return fmt.Sprintf("#%d", a.Number)
	}
	return fmt.Sprintf("%q", a.Title)
}

// Plan is the pure result of comparing findings with existing issues.
type Plan struct {
	Actions   []Action
	Skipped   map[string]int // reason -> count
	Deferred  int            // new issues beyond Max
	Unchanged int            // tracked issues already up to date
	Notes     []string
}

func (p Plan) print(w io.Writer) {
	for _, a := range p.Actions {
		switch a.Kind {
		case ActionCreate:
			fmt.Fprintf(w, "  create  %s\n", a.Title)
		default:
			fmt.Fprintf(w, "  %-7s #%d %s\n", a.Kind, a.Number, a.Reason)
		}
	}
}

var markerRE = regexp.MustCompile(`<!-- achilles:(fp:\S+|rule:\S+|rollup) -->`)
var revRE = regexp.MustCompile(`<!-- achilles:rev:(\w+) -->`)

// tracked is an existing Achilles issue and the key parsed from its marker.
type tracked struct {
	github.Issue
	key string
}

func modeOfKey(key string) Group {
	switch {
	case strings.HasPrefix(key, "fp:"):
		return GroupFinding
	case strings.HasPrefix(key, "rule:"):
		return GroupRule
	default:
		return GroupRollup
	}
}

// unit is one issue's worth of findings.
type unit struct {
	key      string
	findings []model.Finding // sorted by file, line
	sev      model.Severity
}

func keyFor(f model.Finding, g Group) string {
	switch g {
	case GroupRule:
		return "rule:" + sanitizeKey(f.Tool) + ":" + sanitizeKey(f.RuleID)
	case GroupRollup:
		return "rollup"
	default:
		if f.Fingerprint == "" {
			return ""
		}
		return "fp:" + sanitizeKey(f.Fingerprint)
	}
}

// sanitizeKey keeps a marker key on one token that cannot close the HTML comment.
func sanitizeKey(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == ':', r == '/', r == '@', r == '+', r == '=':
			return r
		}
		return '_'
	}, s)
}

// sortFindings orders by severity (worst first), then rule, file, line.
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		return a.Location.Region.StartLine < b.Location.Region.StartLine
	})
}

// BuildPlan decides what to create, update, reopen and close. It is pure: no I/O.
func BuildPlan(scan model.Scan, existing []github.Issue, opts Options) Plan {
	opts, err := opts.normalize()
	if err != nil {
		// Sync validates first; a direct caller with bad options gets an empty plan.
		return Plan{Skipped: map[string]int{}, Notes: []string{err.Error()}}
	}
	min, _ := parseSeverity(opts.MinSeverity)
	plan := Plan{Skipped: map[string]int{}}

	// 1. Which keys are still detected, and which findings are fileable?
	present := map[string]bool{} // any finding (any severity, shadow too) with this key
	var eligible []model.Finding
	for _, f := range scan.Findings {
		key := keyFor(f, opts.Group)
		if key != "" && opts.Group != GroupRollup {
			present[key] = true
		}
		switch {
		case f.Shadow:
			plan.Skipped["shadow finding(s) (never filed)"]++
		case key == "":
			plan.Skipped["finding(s) without a fingerprint"]++
		case f.Severity.Rank() < min.Rank():
			plan.Skipped["finding(s) below --issues-min-severity"]++
		default:
			eligible = append(eligible, f)
		}
	}
	sortFindings(eligible)

	// 2. Group the fileable findings into units (one per issue).
	var units []*unit
	byKey := map[string]*unit{}
	for _, f := range eligible {
		key := keyFor(f, opts.Group)
		u := byKey[key]
		if u == nil {
			u = &unit{key: key, sev: f.Severity}
			byKey[key] = u
			units = append(units, u) // eligible is severity-sorted, so units are too
		}
		u.findings = append(u.findings, f)
	}
	if opts.Group == GroupRollup && len(units) > 0 {
		present["rollup"] = true
	}
	if opts.Group != GroupRollup {
		for _, u := range units {
			sortFindings(u.findings) // severity, then rule, file, line
		}
	}

	// 3. Findings the AI review dismissed (only meaningful when nothing active
	// shares the key).
	dismissed := map[string]model.Finding{}
	if opts.Group != GroupRollup {
		for _, f := range scan.Dismissed {
			key := keyFor(f, opts.Group)
			if key == "" || present[key] {
				continue
			}
			if _, ok := dismissed[key]; !ok {
				dismissed[key] = f
			}
		}
	}

	// 4. Index existing issues of THIS group mode. Other modes are left alone.
	byIssueKey := map[string][]tracked{}
	other := 0
	for _, is := range existing {
		if is.PullRequest != nil {
			continue
		}
		m := markerRE.FindStringSubmatch(is.Body)
		if m == nil {
			continue
		}
		if modeOfKey(m[1]) != opts.Group {
			other++
			continue
		}
		byIssueKey[m[1]] = append(byIssueKey[m[1]], tracked{is, m[1]})
	}
	if other > 0 {
		plan.Notes = append(plan.Notes, fmt.Sprintf("%d existing Achilles issue(s) use a different --issues-group and were left untouched.", other))
	}
	for k := range byIssueKey {
		sort.Slice(byIssueKey[k], func(i, j int) bool { return byIssueKey[k][i].Number < byIssueKey[k][j].Number })
	}

	r := newRenderer(scan.Target, opts)
	var reopens, updates, closes, creates []Action

	// 5. Findings -> create / update / reopen / suppress.
	for _, u := range units {
		title, body := r.render(u)
		group := byIssueKey[u.key]
		open, closedIssue := pickIssues(group)
		switch {
		case open != nil:
			if extra := countOpen(group) - 1; extra > 0 {
				plan.Notes = append(plan.Notes, fmt.Sprintf("%d duplicate open issue(s) for one finding were left as-is (e.g. #%d).", extra, open.Number))
			}
			hasResolved := open.HasLabel(ResolvedLabel)
			if open.Title == title && sameRev(open.Body, body) && !hasResolved {
				plan.Unchanged++
				continue
			}
			a := Action{Kind: ActionUpdate, Key: u.key, Number: open.Number, Title: title, Body: body, Severity: u.sev,
				Reason: "content changed: " + title}
			if hasResolved { // a human reopened an Achilles-closed issue; it is theirs again
				a.Labels = withoutLabel(labelNames(open.Issue), ResolvedLabel)
			}
			updates = append(updates, a)
		case closedIssue != nil:
			if !closedIssue.HasLabel(ResolvedLabel) {
				plan.Skipped["issue(s) suppressed (closed by a human)"]++
				continue
			}
			reopens = append(reopens, Action{
				Kind: ActionReopen, Key: u.key, Number: closedIssue.Number, Title: title, Body: body, Severity: u.sev,
				Labels:  ensureLabel(withoutLabel(labelNames(closedIssue.Issue), ResolvedLabel), opts.Label),
				Comment: r.reopenComment(), Reason: "finding detected again: " + title,
			})
		default:
			creates = append(creates, Action{
				Kind: ActionCreate, Key: u.key, Title: title, Body: body, Severity: u.sev,
				Labels: []string{opts.Label}, Reason: title,
			})
		}
	}

	// 6. Open issues whose finding is no longer in the actionable set -> close.
	keys := make([]string, 0, len(byIssueKey))
	for k := range byIssueKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if byKey[k] != nil || present[k] {
			continue // still detected (possibly below the severity threshold): leave it
		}
		for _, t := range byIssueKey[k] {
			if t.State == "closed" {
				continue
			}
			labels := ensureLabel(ensureLabel(labelNames(t.Issue), ResolvedLabel), opts.Label)
			if f, ok := dismissed[k]; ok {
				closes = append(closes, Action{
					Kind: ActionClose, Key: k, Number: t.Number, Labels: labels, StateReason: "not_planned",
					Comment: r.dismissedComment(f), Reason: "AI review now dismisses this finding",
				})
				continue
			}
			if !opts.Reconcile {
				plan.Skipped["open issue(s) kept (finding not detected, auto-close off)"]++
				continue
			}
			closes = append(closes, Action{
				Kind: ActionClose, Key: k, Number: t.Number, Labels: labels, StateReason: "completed",
				Comment: r.resolvedComment(), Reason: "finding no longer detected",
			})
		}
	}

	// 7. Cap NEW issues (creates are already worst-first).
	if len(creates) > opts.Max {
		plan.Deferred = len(creates) - opts.Max
		creates = creates[:opts.Max]
	}

	plan.Actions = append(plan.Actions, reopens...)
	plan.Actions = append(plan.Actions, updates...)
	plan.Actions = append(plan.Actions, closes...)
	plan.Actions = append(plan.Actions, creates...)
	return plan
}

// pickIssues returns the open issue to maintain (lowest number) if any, else the
// most recent closed one.
func pickIssues(group []tracked) (open, closed *tracked) {
	for i := range group {
		t := &group[i]
		if t.State != "closed" {
			if open == nil {
				open = t
			}
			continue
		}
		if closed == nil || t.Number > closed.Number {
			closed = t
		}
	}
	return open, closed
}

func countOpen(group []tracked) int {
	n := 0
	for _, t := range group {
		if t.State != "closed" {
			n++
		}
	}
	return n
}

// sameRev reports whether an existing body was rendered from the same content as
// want (compared by the embedded rev marker, which ignores the commit SHA in
// permalinks so a new commit alone does not rewrite every issue).
func sameRev(existingBody, want string) bool {
	a, b := revRE.FindStringSubmatch(existingBody), revRE.FindStringSubmatch(want)
	return a != nil && b != nil && a[1] == b[1]
}

func labelNames(is github.Issue) []string {
	out := make([]string, 0, len(is.Labels)+1)
	for _, l := range is.Labels {
		out = append(out, l.Name)
	}
	return out
}

func withoutLabel(labels []string, drop string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		if !strings.EqualFold(l, drop) {
			out = append(out, l)
		}
	}
	return out
}

func ensureLabel(labels []string, want string) []string {
	for _, l := range labels {
		if strings.EqualFold(l, want) {
			return labels
		}
	}
	return append(labels, want)
}
