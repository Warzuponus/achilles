package issues

import (
	"context"
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/model"
)

// fakeAPI is an in-memory GitHub: it applies writes to its issue list so tests
// can run several Syncs back to back.
type fakeAPI struct {
	issues     []github.Issue
	private    bool
	privateErr error
	failOn     map[string]error // "create" | "update" | "comment" -> error
	next       int

	writes   []string // every write call, in order, e.g. "create", "update #3"
	comments map[int][]string
	labels   []string // labels ensured
}

func newFake() *fakeAPI {
	return &fakeAPI{private: true, next: 100, comments: map[int][]string{}, failOn: map[string]error{}}
}

func (f *fakeAPI) find(n int) *github.Issue {
	for i := range f.issues {
		if f.issues[i].Number == n {
			return &f.issues[i]
		}
	}
	return nil
}

func (f *fakeAPI) ListIssues(_ context.Context, label string) ([]github.Issue, error) {
	var out []github.Issue
	for _, is := range f.issues {
		if is.HasLabel(label) {
			out = append(out, is)
		}
	}
	return out, nil
}

func (f *fakeAPI) CreateIssue(_ context.Context, title, body string, labels []string) (int, error) {
	f.writes = append(f.writes, "create")
	if err := f.failOn["create"]; err != nil {
		return 0, err
	}
	f.next++
	is := github.Issue{Number: f.next, Title: title, Body: body, State: "open"}
	for _, l := range labels {
		is.Labels = append(is.Labels, github.Label{Name: l})
	}
	f.issues = append(f.issues, is)
	return f.next, nil
}

func (f *fakeAPI) UpdateIssue(_ context.Context, n int, u github.IssueUpdate) error {
	f.writes = append(f.writes, fmt.Sprintf("update #%d", n))
	if err := f.failOn["update"]; err != nil {
		return err
	}
	is := f.find(n)
	if is == nil {
		return fmt.Errorf("no issue #%d", n)
	}
	if u.Title != nil {
		is.Title = *u.Title
	}
	if u.Body != nil {
		is.Body = *u.Body
	}
	if u.State != nil {
		is.State = *u.State
	}
	if u.StateReason != nil {
		is.StateReason = *u.StateReason
	}
	if u.Labels != nil {
		is.Labels = nil
		for _, l := range *u.Labels {
			is.Labels = append(is.Labels, github.Label{Name: l})
		}
	}
	return nil
}

func (f *fakeAPI) AddComment(_ context.Context, n int, body string) error {
	f.writes = append(f.writes, fmt.Sprintf("comment #%d", n))
	if err := f.failOn["comment"]; err != nil {
		return err
	}
	f.comments[n] = append(f.comments[n], body)
	return nil
}

func (f *fakeAPI) EnsureLabel(_ context.Context, name, _, _ string) error {
	f.writes = append(f.writes, "label "+name)
	f.labels = append(f.labels, name)
	return nil
}

func (f *fakeAPI) RepoIsPrivate(context.Context) (bool, error) { return f.private, f.privateErr }

// count returns how many recorded writes start with prefix.
func (f *fakeAPI) count(prefix string) int {
	n := 0
	for _, w := range f.writes {
		if strings.HasPrefix(w, prefix) {
			n++
		}
	}
	return n
}

// fnd builds a finding with a stable fingerprint derived from tool/rule/snippet.
func fnd(rule, file string, line int, sev model.Severity) model.Finding {
	f := model.Finding{
		Tool: "semgrep", RuleID: rule, Message: "message for " + rule,
		Location: model.Location{File: file, Region: model.Region{StartLine: line}},
		Severity: sev,
	}
	f.Fingerprint = model.ComputeFingerprint(f.Tool, f.RuleID, f.Location.File, "snippet "+rule)
	return f
}

func scanOf(fs ...model.Finding) model.Scan {
	return model.Scan{Target: "/work/proj", Findings: fs}
}

func baseOpts() Options {
	return Options{Repo: "acme/app", Reconcile: true, AllowPublic: false}
}

// issueFor renders what Achilles would file for the given scan, and returns it as
// an existing issue in the given state, so tests start from a realistic body.
func issueFor(num int, state string, scan model.Scan, opts Options, extraLabels ...string) github.Issue {
	opts.Label = firstNonEmpty(opts.Label, "achilles")
	p := BuildPlan(scan, nil, opts)
	if len(p.Actions) != 1 || p.Actions[0].Kind != ActionCreate {
		panic(fmt.Sprintf("issueFor wants exactly one create, got %+v", p.Actions))
	}
	a := p.Actions[0]
	is := github.Issue{Number: num, Title: a.Title, Body: a.Body, State: state}
	for _, l := range append([]string{opts.Label}, extraLabels...) {
		is.Labels = append(is.Labels, github.Label{Name: l})
	}
	return is
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
