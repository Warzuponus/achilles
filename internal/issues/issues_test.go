package issues

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/model"
)

func run(t *testing.T, api API, scan model.Scan, opts Options) (Summary, string, error) {
	t.Helper()
	var out bytes.Buffer
	opts.Out = &out
	sum, err := Sync(context.Background(), api, scan, opts)
	return sum, out.String(), err
}

func TestSync_Lifecycle(t *testing.T) {
	high := fnd("sqli", "src/db.go", 10, model.SeverityHigh)
	one := scanOf(high)

	tests := []struct {
		name     string
		existing func() []github.Issue
		scan     model.Scan
		mod      func(*Options)
		check    func(t *testing.T, f *fakeAPI, s Summary, out string)
	}{
		{
			name:     "new finding creates an issue",
			existing: func() []github.Issue { return nil },
			scan:     one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if s.Created != 1 || f.count("create") != 1 {
					t.Fatalf("summary=%+v writes=%v", s, f.writes)
				}
				is := f.issues[0]
				if !is.HasLabel("achilles") || !strings.Contains(is.Body, "<!-- achilles:fp:"+high.Fingerprint+" -->") {
					t.Errorf("bad issue: %+v", is)
				}
				if is.Title != "[HIGH] sqli in src/db.go" {
					t.Errorf("title=%q", is.Title)
				}
			},
		},
		{
			name:     "existing open issue is a no-op",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan:     one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if len(f.writes) != 0 || s.Unchanged != 1 {
					t.Errorf("summary=%+v writes=%v", s, f.writes)
				}
			},
		},
		{
			name:     "new commit alone does not rewrite the issue",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan:     one,
			mod:      func(o *Options) { o.CommitSHA = "deadbeefcafe" },
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if len(f.writes) != 0 {
					t.Errorf("writes=%v", f.writes)
				}
			},
		},
		{
			name: "severity changed updates the issue",
			existing: func() []github.Issue {
				return []github.Issue{issueFor(7, "open", scanOf(fnd("sqli", "src/db.go", 10, model.SeverityMedium)), baseOpts())}
			},
			scan: scanOf(func() model.Finding { f := high; return f }()),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				// Same fingerprint requires same rule/snippet: fnd derives it from rule, so the two match.
				if s.Updated != 1 || !strings.HasPrefix(f.find(7).Title, "[HIGH]") {
					t.Errorf("summary=%+v title=%q writes=%v", s, f.find(7).Title, f.writes)
				}
			},
		},
		{
			name: "location moved updates the issue",
			existing: func() []github.Issue {
				return []github.Issue{issueFor(7, "open", scanOf(fnd("sqli", "src/db.go", 99, model.SeverityHigh)), baseOpts())}
			},
			scan: one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if s.Updated != 1 || !strings.Contains(f.find(7).Body, "src/db.go:10") {
					t.Errorf("summary=%+v body=%q", s, f.find(7).Body)
				}
			},
		},
		{
			name:     "fix added updates the issue",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan: func() model.Scan {
				f := high
				f.Remediation = &model.Remediation{Summary: "use a parameterized query", Diff: "--- a/x\n+++ b/x\n@@\n-q\n+q2", Confidence: 0.9}
				return scanOf(f)
			}(),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				b := f.find(7).Body
				if s.Updated != 1 || !strings.Contains(b, "parameterized query") || !strings.Contains(b, "```diff") {
					t.Errorf("summary=%+v body=%q", s, b)
				}
			},
		},
		{
			name:     "human-closed issue stays suppressed",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "closed", one, baseOpts())} },
			scan:     one,
			check: func(t *testing.T, f *fakeAPI, s Summary, out string) {
				if len(f.writes) != 0 {
					t.Errorf("writes=%v", f.writes)
				}
				if s.Skipped["issue(s) suppressed (closed by a human)"] != 1 || !strings.Contains(out, "suppressed") {
					t.Errorf("skipped=%v out=%s", s.Skipped, out)
				}
			},
		},
		{
			name: "achilles-closed issue reopens on regression",
			existing: func() []github.Issue {
				return []github.Issue{issueFor(7, "closed", one, baseOpts(), ResolvedLabel)}
			},
			scan: one,
			mod:  func(o *Options) { o.CommitSHA = "0123456789abcdef" },
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				is := f.find(7)
				if s.Reopened != 1 || is.State != "open" || is.HasLabel(ResolvedLabel) || !is.HasLabel("achilles") {
					t.Errorf("summary=%+v issue=%+v", s, is)
				}
				if len(f.comments[7]) != 1 || !strings.Contains(f.comments[7][0], "detects this finding again") || !strings.Contains(f.comments[7][0], "0123456") {
					t.Errorf("comments=%v", f.comments[7])
				}
				if f.count("create") != 0 {
					t.Error("regression must reopen, not file a duplicate")
				}
			},
		},
		{
			name:     "resolved finding closes with the resolved marker",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan:     scanOf(),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				is := f.find(7)
				if s.Closed != 1 || is.State != "closed" || !is.HasLabel(ResolvedLabel) || is.StateReason != "completed" {
					t.Errorf("summary=%+v issue=%+v", s, is)
				}
				if len(f.comments[7]) != 1 || !strings.Contains(f.comments[7][0], "<!-- achilles:resolved -->") {
					t.Errorf("comments=%v", f.comments[7])
				}
			},
		},
		{
			name:     "resolved finding is kept open when reconcile is off, and the summary says why",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan:     scanOf(),
			mod: func(o *Options) {
				o.Reconcile = false
				o.ReconcileSkipReason = "--diff narrows the scan to changed files"
			},
			check: func(t *testing.T, f *fakeAPI, s Summary, out string) {
				if len(f.writes) != 0 || !strings.Contains(out, "--diff narrows the scan") {
					t.Errorf("writes=%v out=%s", f.writes, out)
				}
			},
		},
		{
			name:     "failed scanner disables reconcile even if the caller allowed it",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan:     model.Scan{Target: "/work/proj", FailedTools: []string{"semgrep"}},
			check: func(t *testing.T, f *fakeAPI, s Summary, out string) {
				if len(f.writes) != 0 || !strings.Contains(out, "scanner(s) failed") {
					t.Errorf("writes=%v out=%s", f.writes, out)
				}
			},
		},
		{
			name:     "AI-dismissed finding closes the issue even without reconcile",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan: func() model.Scan {
				d := high
				d.Verdict = &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9, Reasoning: "input is a constant"}
				return model.Scan{Target: "/work/proj", Dismissed: []model.Finding{d}}
			}(),
			mod: func(o *Options) { o.Reconcile = false },
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				is := f.find(7)
				if s.Closed != 1 || is.State != "closed" || !is.HasLabel(ResolvedLabel) {
					t.Fatalf("summary=%+v issue=%+v", s, is)
				}
				c := f.comments[7][0]
				if !strings.Contains(c, "false positive") || !strings.Contains(c, "input is a constant") || !strings.Contains(c, "90%") {
					t.Errorf("comment=%q", c)
				}
			},
		},
		{
			name:     "a finding suppressed by a comment in the code closes its issue, saying it was not fixed",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan: func() model.Scan {
				s := high
				s.Suppression = &model.Suppression{File: "/work/proj/src/a.go", Line: 11, Reason: "the query is built from constants @everyone"}
				return model.Scan{Target: "/work/proj", Suppressed: []model.Finding{s}}
			}(),
			mod: func(o *Options) { o.Reconcile = false },
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				is := f.find(7)
				if s.Closed != 1 || is.State != "closed" || is.StateReason != "not_planned" {
					t.Fatalf("summary=%+v issue=%+v", s, is)
				}
				c := f.comments[7][0]
				for _, want := range []string{"achilles:ignore", "src/a.go:11", "the query is built from constants", "It was not fixed"} {
					if !strings.Contains(c, want) {
						t.Errorf("comment lacks %q: %q", want, c)
					}
				}
				// The reason is text from the scanned code: it must not ping anyone, and
				// the comment must not name a path on the scanning machine.
				if strings.Contains(c, "@everyone") || strings.Contains(c, "/work/proj") {
					t.Errorf("comment=%q", c)
				}
			},
		},
		{
			name:     "a suppressed copy does not close an issue whose fingerprint is still active",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan: func() model.Scan {
				s := one
				sup := high
				sup.Suppression = &model.Suppression{File: "a.go", Line: 1, Reason: "r"}
				s.Suppressed = []model.Finding{sup}
				return s
			}(),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if len(f.writes) != 0 {
					t.Errorf("writes=%v", f.writes)
				}
			},
		},
		{
			name:     "dismissed copy does not close an issue whose fingerprint is still active",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts())} },
			scan: func() model.Scan {
				s := one
				s.Dismissed = []model.Finding{high}
				return s
			}(),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if len(f.writes) != 0 {
					t.Errorf("writes=%v", f.writes)
				}
			},
		},
		{
			name:     "human reopened an achilles-closed issue: label is cleared so a later human close sticks",
			existing: func() []github.Issue { return []github.Issue{issueFor(7, "open", one, baseOpts(), ResolvedLabel)} },
			scan:     one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if s.Updated != 1 || f.find(7).HasLabel(ResolvedLabel) {
					t.Errorf("summary=%+v issue=%+v", s, f.find(7))
				}
			},
		},
		{
			name: "legacy issue body (marker only) is upgraded",
			existing: func() []github.Issue {
				return []github.Issue{{Number: 3, State: "open", Title: "old", Body: "<!-- achilles:fp:" + high.Fingerprint + " -->\n**Rule:** sqli",
					Labels: []github.Label{{Name: "achilles"}}}}
			},
			scan: one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if s.Updated != 1 || !strings.Contains(f.find(3).Body, "achilles:rev:") {
					t.Errorf("summary=%+v", s)
				}
			},
		},
		{
			name: "pull requests and unmarked issues are ignored",
			existing: func() []github.Issue {
				raw := json.RawMessage(`{}`)
				return []github.Issue{
					{Number: 2, State: "open", Body: "just a human issue", Labels: []github.Label{{Name: "achilles"}}},
					{Number: 1, State: "open", Body: "<!-- achilles:fp:" + high.Fingerprint + " -->", PullRequest: &raw, Labels: []github.Label{{Name: "achilles"}}},
				}
			},
			scan: one,
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if f.count("create") != 1 {
					t.Errorf("writes=%v", f.writes)
				}
			},
		},
		{
			name: "finding below the threshold keeps its tracked issue open",
			existing: func() []github.Issue {
				return []github.Issue{issueFor(7, "open", scanOf(fnd("sqli", "src/db.go", 10, model.SeverityHigh)), baseOpts())}
			},
			scan: scanOf(fnd("sqli", "src/db.go", 10, model.SeverityLow)),
			check: func(t *testing.T, f *fakeAPI, s Summary, _ string) {
				if len(f.writes) != 0 {
					t.Errorf("a threshold change must not bulk-close issues: %v", f.writes)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.issues = tc.existing()
			opts := baseOpts()
			opts.AllowPublic = true
			if tc.mod != nil {
				tc.mod(&opts)
			}
			s, out, err := run(t, f, tc.scan, opts)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, f, s, out)
		})
	}
}

func TestSync_IdempotentAndRegressionAcrossRuns(t *testing.T) {
	f := newFake()
	opts := baseOpts()
	opts.AllowPublic = true
	sc := scanOf(fnd("sqli", "a.go", 1, model.SeverityHigh), fnd("xss", "b.go", 2, model.SeverityCritical))

	if s, _, err := run(t, f, sc, opts); err != nil || s.Created != 2 {
		t.Fatalf("run1 %+v %v", s, err)
	}
	f.writes = nil
	if _, _, err := run(t, f, sc, opts); err != nil || len(f.writes) != 0 {
		t.Fatalf("second run must be a no-op, writes=%v err=%v", f.writes, err)
	}
	// Fix one finding: it auto-closes.
	fixed := scanOf(fnd("xss", "b.go", 2, model.SeverityCritical))
	if s, _, _ := run(t, f, fixed, opts); s.Closed != 1 {
		t.Fatalf("expected one close, %+v", s)
	}
	// It regresses: reopened, not duplicated.
	if s, _, _ := run(t, f, sc, opts); s.Reopened != 1 || s.Created != 0 {
		t.Fatalf("expected a reopen, %+v", s)
	}
	// A human then closes it: stays closed forever.
	for i := range f.issues {
		if strings.Contains(f.issues[i].Title, "sqli") {
			f.issues[i].State = "closed"
		}
	}
	f.writes = nil
	if _, _, _ = run(t, f, sc, opts); len(f.writes) != 0 {
		t.Fatalf("human-closed issue was touched: %v", f.writes)
	}
}

func TestSync_CapSeverityOrderAndDeferred(t *testing.T) {
	f := newFake()
	opts := baseOpts()
	opts.AllowPublic = true
	opts.Max = 2
	sc := scanOf(
		fnd("r-med", "a.go", 1, model.SeverityMedium),
		fnd("r-crit", "b.go", 1, model.SeverityCritical),
		fnd("r-high", "c.go", 1, model.SeverityHigh),
		fnd("r-med2", "d.go", 1, model.SeverityMedium),
		fnd("r-high2", "e.go", 1, model.SeverityHigh),
	)
	// An existing tracked issue must not count against the cap.
	f.issues = []github.Issue{issueFor(1, "open", scanOf(fnd("r-med", "a.go", 1, model.SeverityMedium)), opts)}
	s, out, err := run(t, f, sc, opts)
	if err != nil {
		t.Fatal(err)
	}
	if s.Created != 2 || s.Deferred != 2 {
		t.Fatalf("summary=%+v", s)
	}
	var titles []string
	for _, is := range f.issues[1:] {
		titles = append(titles, is.Title)
	}
	if titles[0] != "[CRITICAL] r-crit in b.go" || titles[1] != "[HIGH] r-high in c.go" {
		t.Errorf("filed %v; want the most severe first", titles)
	}
	if !strings.Contains(out, "2 new issue(s) held back") {
		t.Errorf("deferred count missing from summary: %s", out)
	}
}

func TestSync_Filters(t *testing.T) {
	shadow := fnd("shadowy", "s.go", 1, model.SeverityCritical)
	shadow.Shadow = true
	nofp := fnd("nofp", "n.go", 1, model.SeverityHigh)
	nofp.Fingerprint = ""
	sc := scanOf(
		fnd("low", "l.go", 1, model.SeverityLow),
		fnd("info", "i.go", 1, model.SeverityInfo),
		fnd("med", "m.go", 1, model.SeverityMedium),
		shadow, nofp,
	)
	for _, tc := range []struct {
		min  string
		want int
	}{{"", 1}, {"low", 2}, {"high", 0}, {"info", 3}} {
		f := newFake()
		opts := baseOpts()
		opts.AllowPublic = true
		opts.MinSeverity = tc.min
		s, _, err := run(t, f, sc, opts)
		if err != nil || s.Created != tc.want {
			t.Errorf("min=%q created=%d want %d err=%v", tc.min, s.Created, tc.want, err)
		}
		for _, is := range f.issues {
			if strings.Contains(is.Title, "shadowy") {
				t.Error("shadow finding was filed")
			}
		}
		if s.Skipped["shadow finding(s) (never filed)"] != 1 || s.Skipped["finding(s) without a fingerprint"] != 1 {
			t.Errorf("skipped=%v", s.Skipped)
		}
	}
	if _, _, err := run(t, newFake(), sc, Options{Repo: "a/b", MinSeverity: "bogus", AllowPublic: true}); err == nil {
		t.Error("bad min severity must error")
	}
}

func TestSync_SameFingerprintMergedIntoOneIssue(t *testing.T) {
	a := fnd("hardcoded-x", "one/a.go", 3, model.SeverityHigh)
	b := fnd("hardcoded-x", "two/b.go", 8, model.SeverityHigh)
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("test premise: fingerprints must collide")
	}
	f := newFake()
	opts := baseOpts()
	opts.AllowPublic = true
	s, _, err := run(t, f, scanOf(b, a), opts)
	if err != nil || s.Created != 1 || len(f.issues) != 1 {
		t.Fatalf("summary=%+v issues=%d err=%v", s, len(f.issues), err)
	}
	body := f.issues[0].Body
	if !strings.Contains(body, "one/a.go:3") || !strings.Contains(body, "two/b.go:8") || !strings.Contains(f.issues[0].Title, "(+1 more)") {
		t.Errorf("merged issue should list both locations:\n%s\n%s", f.issues[0].Title, body)
	}
	// A second run stays at one issue.
	f.writes = nil
	run(t, f, scanOf(b, a), opts)
	if len(f.writes) != 0 {
		t.Errorf("writes=%v", f.writes)
	}
}

func TestSync_GroupModes(t *testing.T) {
	sc := scanOf(
		fnd("sqli", "a.go", 1, model.SeverityHigh),
		fnd("sqli", "b.go", 2, model.SeverityMedium),
		fnd("sqli", "c.go", 3, model.SeverityHigh),
		fnd("xss", "d.go", 4, model.SeverityCritical),
	)
	t.Run("rule", func(t *testing.T) {
		f := newFake()
		opts := baseOpts()
		opts.AllowPublic, opts.Group = true, GroupRule
		s, _, err := run(t, f, sc, opts)
		if err != nil || s.Created != 2 {
			t.Fatalf("%+v %v", s, err)
		}
		var sq github.Issue
		for _, is := range f.issues {
			if strings.Contains(is.Body, "<!-- achilles:rule:semgrep:sqli -->") {
				sq = is
			}
		}
		if sq.Number == 0 || sq.Title != "[HIGH] sqli (3 locations)" ||
			!strings.Contains(sq.Body, "| Severity | Location | Message |") || !strings.Contains(sq.Body, "`b.go:2`") {
			t.Errorf("rule issue wrong: %q\n%s", sq.Title, sq.Body)
		}
		f.writes = nil
		run(t, f, sc, opts)
		if len(f.writes) != 0 {
			t.Errorf("rule mode not idempotent: %v", f.writes)
		}
	})
	t.Run("rollup", func(t *testing.T) {
		f := newFake()
		opts := baseOpts()
		opts.AllowPublic, opts.Group = true, GroupRollup
		s, _, err := run(t, f, sc, opts)
		if err != nil || s.Created != 1 {
			t.Fatalf("%+v %v", s, err)
		}
		b := f.issues[0].Body
		if !strings.Contains(b, "<!-- achilles:rollup -->") || strings.Index(b, "xss") > strings.Index(b, "`sqli`") {
			t.Errorf("rollup should list the critical finding first:\n%s", b)
		}
		// All findings fixed -> the rollup closes.
		if s, _, _ := run(t, f, scanOf(), opts); s.Closed != 1 {
			t.Errorf("rollup should close when nothing is left: %+v", s)
		}
	})
	t.Run("does not mix modes", func(t *testing.T) {
		f := newFake()
		fo := baseOpts()
		fo.AllowPublic = true
		run(t, f, sc, fo) // finding mode: 4 issues
		before := len(f.issues)
		ro := fo
		ro.Group = GroupRule
		f.writes = nil
		s, out, _ := run(t, f, sc, ro)
		if s.Created != 2 || s.Closed != 0 || f.count("update") != 0 {
			t.Errorf("fp issues must be left alone: %+v writes=%v", s, f.writes)
		}
		if len(f.issues) != before+2 || !strings.Contains(out, "different --issues-group") {
			t.Errorf("issues=%d out=%s", len(f.issues), out)
		}
	})
}

func TestBody_SecretFindingCarriesNoCode(t *testing.T) {
	f := fnd("aws-access-token", "cfg/app.env", 4, model.SeverityCritical)
	f.Tool = "gitleaks"
	f.CWE = []string{"CWE-798"}
	f.Message = "AWS key AKIAIOSFODNN7EXAMPLE found: aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	f.CodeContext = "AWS_SECRET=hunter2hunter2hunter2"
	f.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.95, Reasoning: "the key hunter2hunter2hunter2 is live"}
	f.Remediation = &model.Remediation{Summary: "remove hunter2hunter2hunter2", Diff: "-AWS_SECRET=hunter2hunter2hunter2\n+AWS_SECRET=${AWS_SECRET}"}
	_, body := renderOne(t, f, baseOpts())
	for _, bad := range []string{"AKIA", "hunter2", "wJalr", "AWS_SECRET", "```", "AI review", "Suggested fix"} {
		if strings.Contains(body, bad) {
			t.Errorf("secret finding leaked %q:\n%s", bad, body)
		}
	}
	for _, want := range []string{"`CRITICAL`", "aws-access-token", "`cfg/app.env:4`", "rotate or revoke"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
}

func TestIsSecretFinding(t *testing.T) {
	for _, tc := range []struct {
		tool, rule string
		cwe        []string
		want       bool
	}{
		{"gitleaks", "anything", nil, true},
		{"semgrep", "generic.secrets.hardcoded-password", nil, true},
		{"semgrep", "jwt-token-exposed", nil, true},
		{"semgrep", "weak-crypto", []string{"CWE-798"}, true},
		{"semgrep", "weak-crypto", []string{"259"}, true},
		{"semgrep", "sql-injection", []string{"CWE-89"}, false},
	} {
		f := model.Finding{Tool: tc.tool, RuleID: tc.rule, CWE: tc.cwe}
		if got := isSecretFinding(f); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}

func TestBody_RedactsSecretsInProse(t *testing.T) {
	f := fnd("sqli", "a.go", 1, model.SeverityHigh)
	tok := "ghp_" + strings.Repeat("a1B2", 10)
	f.Message = "query built from input; leaked " + tok + " in config"
	f.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9, Reasoning: "see " + tok}
	f.Remediation = &model.Remediation{Diff: "--- a/a.go\n+++ b/a.go\n@@\n-x := \"" + tok + "\"\n+x := os.Getenv(\"T\")"}
	title, body := renderOne(t, f, baseOpts())
	if strings.Contains(body, tok) || strings.Contains(title, tok) {
		t.Errorf("token leaked:\n%s", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Errorf("expected masked text:\n%s", body)
	}
}

func TestBody_DefusesInjectedMarkersAndMentions(t *testing.T) {
	f := fnd("sqli", "a.go", 1, model.SeverityHigh)
	f.Message = "<!-- achilles:fp:forged --> ping @octocat"
	_, body := renderOne(t, f, baseOpts())
	if m := markerRE.FindStringSubmatch(body); m == nil || m[1] != "fp:"+f.Fingerprint {
		t.Errorf("first marker must be ours: %v", m)
	}
	if strings.Contains(body, "<!-- achilles:fp:forged") || strings.Contains(body, "@octocat") {
		t.Errorf("not defused:\n%s", body)
	}
}

func TestBody_PermalinkAndRelativePaths(t *testing.T) {
	f := fnd("sqli", "/work/proj/src/my dir/a.go", 12, model.SeverityHigh)
	f.Location.Region.EndLine = 15
	f.Message = "found in /work/proj/src/my dir/a.go"
	opts := baseOpts()
	opts.CommitSHA, opts.ServerURL = "abc123def456", "https://ghe.example.com/"
	title, body := renderOne(t, f, opts)
	want := "[`src/my dir/a.go:12`](https://ghe.example.com/acme/app/blob/abc123def456/src/my%20dir/a.go#L12-L15)"
	if !strings.Contains(body, want) {
		t.Errorf("permalink missing:\n%s", body)
	}
	if strings.Contains(body, "/work/proj") || strings.Contains(title, "/work/proj") {
		t.Errorf("absolute path leaked:\n%s\n%s", title, body)
	}
	_, plain := renderOne(t, f, baseOpts())
	if !strings.Contains(plain, "**Location:** `src/my dir/a.go:12`") {
		t.Errorf("without a SHA the location is plain text:\n%s", plain)
	}
}

func TestRelPath(t *testing.T) {
	for _, tc := range []struct{ target, file, want string }{
		{"/w/p", "/w/p/a/b.go", "a/b.go"},
		{"/w/p", "a/b.go", "a/b.go"},
		{"/w/p", "./a/b.go", "a/b.go"},
		{"/w/p", "file:///w/p/a.go", "a.go"},
		{"/w/p", "/etc/passwd", "passwd"},
		{"/w/p", "../../etc/x.go", "x.go"},
		{"/w/p", "C:/" + "Users/me/x.go", "x.go"},
		{".", "a.go", "a.go"},
		{"", "", ""},
	} {
		if got := relPath(tc.target, tc.file); got != tc.want {
			t.Errorf("relPath(%q,%q)=%q want %q", tc.target, tc.file, got, tc.want)
		}
	}
}

func TestBody_TruncationCutsDiffFirstAndStaysUnderLimit(t *testing.T) {
	// A rule-grouped issue with many locations plus a big fix is the realistic way
	// to approach GitHub's limit.
	mk := func(n int, fileLen int) model.Scan {
		var fs []model.Finding
		for i := 0; i < n; i++ {
			f := fnd("sqli", fmt.Sprintf("%s%03d.go", strings.Repeat("d/", fileLen/2), i), i+1, model.SeverityHigh)
			f.Message = strings.Repeat("m ", 1000)
			if i == 0 {
				f.Verdict = &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9, Reasoning: strings.Repeat("r ", 3000)}
				f.Remediation = &model.Remediation{Confidence: 0.8, Summary: strings.Repeat("s ", 1400), Guidance: strings.Repeat("g ", 1400),
					Diff: "--- a/a\n+++ b/a\n@@\n" + strings.Repeat("+line of the patch\n", 6000)}
			}
			fs = append(fs, f)
		}
		return scanOf(fs...)
	}
	opts := baseOpts()
	opts.Group = GroupRule

	t.Run("diff is dropped first", func(t *testing.T) {
		body := BuildPlan(mk(100, 60), nil, opts).Actions[0].Body
		if len(body) > maxBody || strings.Contains(body, "```diff") || !strings.Contains(body, "truncated") {
			t.Errorf("len=%d diff=%v", len(body), strings.Contains(body, "```diff"))
		}
		if !strings.Contains(body, "Fix confidence") || !strings.Contains(body, "Managed by Achilles") {
			t.Error("the rest of the issue should survive losing the diff")
		}
	})
	t.Run("hard truncation keeps marker and footer", func(t *testing.T) {
		o := opts
		o.CommitSHA = strings.Repeat("a", 40)
		body := BuildPlan(mk(100, 240), nil, o).Actions[0].Body
		if len(body) > maxBody || !strings.Contains(body, "[truncated:") {
			t.Fatalf("len=%d", len(body))
		}
		if !strings.HasPrefix(body, "<!-- achilles:rule:") || !strings.Contains(body, "Managed by Achilles") {
			t.Error("marker and footer must survive truncation")
		}
	})
	t.Run("a diff that fits is kept", func(t *testing.T) {
		f := fnd("sqli", "a.go", 1, model.SeverityHigh)
		f.Remediation = &model.Remediation{Diff: "--- a/a\n+++ b/a\n@@\n" + strings.Repeat("+line of the patch\n", 100)}
		if _, body := renderOne(t, f, baseOpts()); !strings.Contains(body, "```diff") {
			t.Error("diff dropped though the body is small")
		}
	})
	t.Run("an oversized diff is cut at a line boundary", func(t *testing.T) {
		f := fnd("sqli", "a.go", 1, model.SeverityHigh)
		f.Remediation = &model.Remediation{Diff: "--- a/a\n+++ b/a\n@@\n" + strings.Repeat("+line of the patch\n", 6000)}
		_, body := renderOne(t, f, baseOpts())
		if !strings.Contains(body, "(diff truncated)") || len(body) > maxBody {
			t.Errorf("len=%d", len(body))
		}
	})
}

func TestBody_FenceCannotBeClosedByContent(t *testing.T) {
	f := fnd("sqli", "a.go", 1, model.SeverityHigh)
	f.Remediation = &model.Remediation{Diff: "--- a/a\n+++ b/a\n@@\n+```\n+# injected heading\n"}
	_, body := renderOne(t, f, baseOpts())
	if !strings.Contains(body, "````diff") {
		t.Errorf("fence must be longer than any backtick run:\n%s", body)
	}
}

func TestTitle_Bounded(t *testing.T) {
	f := fnd(strings.Repeat("very-long-rule-", 20), "a.go", 1, model.SeverityHigh)
	title, _ := renderOne(t, f, baseOpts())
	if n := len([]rune(title)); n > 120 {
		t.Errorf("title is %d runes", n)
	}
	f2 := fnd("r", "a\nb.go", 1, model.SeverityHigh)
	if title, _ := renderOne(t, f2, baseOpts()); strings.ContainsAny(title, "\n\r") {
		t.Errorf("title has newline: %q", title)
	}
}

func TestSync_PublicRepoGuard(t *testing.T) {
	sc := scanOf(fnd("sqli", "a.go", 1, model.SeverityHigh))
	t.Run("public repo is refused", func(t *testing.T) {
		f := newFake()
		f.private = false
		s, out, err := run(t, f, sc, baseOpts())
		if err != nil || len(f.writes) != 0 || s.Blocked == "" {
			t.Fatalf("err=%v writes=%v blocked=%q", err, f.writes, s.Blocked)
		}
		if !strings.Contains(out, "--allow-public-issues") || !strings.Contains(out, "Security tab") {
			t.Errorf("message should be actionable: %s", out)
		}
	})
	t.Run("strict turns the refusal into an error", func(t *testing.T) {
		f := newFake()
		f.private = false
		o := baseOpts()
		o.Strict = true
		if _, _, err := run(t, f, sc, o); err == nil || len(f.writes) != 0 {
			t.Errorf("err=%v writes=%v", err, f.writes)
		}
	})
	t.Run("allow flag permits a public repo", func(t *testing.T) {
		f := newFake()
		f.private = false
		o := baseOpts()
		o.AllowPublic = true
		if s, _, err := run(t, f, sc, o); err != nil || s.Created != 1 {
			t.Errorf("%+v %v", s, err)
		}
	})
	t.Run("lookup failure fails closed", func(t *testing.T) {
		f := newFake()
		f.privateErr = errors.New("HTTP 404")
		_, out, err := run(t, f, sc, baseOpts())
		if err != nil || len(f.writes) != 0 || !strings.Contains(out, "treated as public") || !strings.Contains(out, "HTTP 404") {
			t.Errorf("err=%v writes=%v out=%s", err, f.writes, out)
		}
	})
	t.Run("private repo proceeds", func(t *testing.T) {
		f := newFake()
		if s, _, err := run(t, f, sc, baseOpts()); err != nil || s.Created != 1 {
			t.Errorf("%+v %v", s, err)
		}
	})
}

func TestSync_DryRunMakesNoWriteCalls(t *testing.T) {
	one := scanOf(fnd("sqli", "a.go", 1, model.SeverityHigh))
	f := newFake()
	f.issues = []github.Issue{
		issueFor(5, "open", scanOf(fnd("gone", "g.go", 1, model.SeverityHigh)), baseOpts()),
		issueFor(6, "closed", one, baseOpts(), ResolvedLabel),
	}
	// Issue 6 reopens, issue 5 closes, plus a new one.
	sc := scanOf(fnd("sqli", "a.go", 1, model.SeverityHigh), fnd("new", "n.go", 1, model.SeverityHigh))
	o := baseOpts()
	o.AllowPublic, o.DryRun = true, true
	s, out, err := run(t, f, sc, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote: %v", f.writes)
	}
	if s.Created != 1 || s.Reopened != 1 || s.Closed != 1 || !s.DryRun {
		t.Errorf("plan counts: %+v", s)
	}
	for _, want := range []string{"create  [HIGH] new in n.go", "reopen  #6", "close   #5", "dry run"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q:\n%s", want, out)
		}
	}
}

func TestSync_FailuresCollectedAndRunContinues(t *testing.T) {
	sc := scanOf(fnd("a", "a.go", 1, model.SeverityHigh), fnd("b", "b.go", 1, model.SeverityHigh))
	for _, strict := range []bool{false, true} {
		f := newFake()
		f.failOn["create"] = fmt.Errorf("HTTP 500")
		o := baseOpts()
		o.AllowPublic, o.Strict = true, strict
		s, out, err := run(t, f, sc, o)
		if f.count("create") != 2 || s.Failed != 2 || s.Created != 0 {
			t.Errorf("strict=%v: run must continue past a failure: %+v writes=%v", strict, s, f.writes)
		}
		if (err != nil) != strict {
			t.Errorf("strict=%v err=%v", strict, err)
		}
		if !strings.Contains(out, "HTTP 500") || !strings.Contains(out, "FAILED") {
			t.Errorf("errors must be printed: %s", out)
		}
	}
}

func TestSync_ContextCancelledStopsApplying(t *testing.T) {
	f := newFake()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := baseOpts()
	o.AllowPublic = true
	s, err := Sync(ctx, f, scanOf(fnd("a", "a.go", 1, model.SeverityHigh)), o)
	if err != nil || s.Failed != 1 || f.count("create") != 0 {
		t.Errorf("%+v %v %v", s, err, f.writes)
	}
}

func TestSync_ListFailureIsFatal(t *testing.T) {
	api := &listFails{newFake()}
	o := baseOpts()
	o.AllowPublic = true
	if _, err := Sync(context.Background(), api, scanOf(), o); err == nil {
		t.Error("expected error")
	}
}

type listFails struct{ *fakeAPI }

func (listFails) ListIssues(context.Context, string) ([]github.Issue, error) {
	return nil, errors.New("boom")
}

// renderOne returns the title and body Achilles would file for one finding.
func renderOne(t *testing.T, f model.Finding, opts Options) (string, string) {
	t.Helper()
	p := BuildPlan(scanOf(f), nil, opts)
	if len(p.Actions) != 1 {
		t.Fatalf("plan=%+v", p)
	}
	return p.Actions[0].Title, p.Actions[0].Body
}

func TestBody_Golden(t *testing.T) {
	f := fnd("go.sql.injection", "/work/proj/src/db.go", 42, model.SeverityHigh)
	f.CWE = []string{"CWE-89"}
	f.Message = "User input flows into a SQL string."
	f.Location.Region.EndLine = 44
	f.Verdict = &model.Verdict{
		Classification: model.ClassTruePositive, Confidence: 0.92, Exploitability: model.ExploitReachable,
		Reasoning: "The id parameter comes from the query string and is concatenated.", SuggestedFix: "Use a parameterized query.",
	}
	f.Remediation = &model.Remediation{
		Summary: "Bind the id as a parameter.", Guidance: "Prefer db.QueryContext with placeholders.", Confidence: 0.85,
		Diff: "--- a/src/db.go\n+++ b/src/db.go\n@@ -42 +42 @@\n-q := \"SELECT * FROM t WHERE id=\" + id\n+q := \"SELECT * FROM t WHERE id=?\"",
	}
	opts := baseOpts()
	opts.CommitSHA = "abc1234"
	title, body := renderOne(t, f, opts)

	wantTitle := "[HIGH] go.sql.injection in src/db.go"
	if title != wantTitle {
		t.Errorf("title=%q", title)
	}
	want := "<!-- achilles:fp:" + f.Fingerprint + " -->\n" +
		"<!-- achilles:rev:" + revOf(body) + " -->\n" +
		"**Severity:** `HIGH` · **Rule:** `go.sql.injection` · **Tool:** `semgrep` · **CWE:** CWE-89\n" +
		"\n" +
		"**Location:** [`src/db.go:42`](https://github.com/acme/app/blob/abc1234/src/db.go#L42-L44)\n" +
		"\n" +
		"User input flows into a SQL string.\n" +
		"\n" +
		"### AI review\n" +
		"\n" +
		"- **Verdict:** true positive (confidence 92%)\n" +
		"- **Exploitability:** reachable\n" +
		"\n" +
		"The id parameter comes from the query string and is concatenated.\n" +
		"\n" +
		"### Suggested fix\n" +
		"\n" +
		"Use a parameterized query.\n" +
		"\n" +
		"Bind the id as a parameter.\n" +
		"\n" +
		"Prefer db.QueryContext with placeholders.\n" +
		"\n" +
		"_Fix confidence: 85%. Review before applying; Achilles proposes fixes but never applies them._\n" +
		"\n" +
		"```diff\n" +
		"--- a/src/db.go\n" +
		"+++ b/src/db.go\n" +
		"@@ -42 +42 @@\n" +
		"-q := \"SELECT * FROM t WHERE id=\" + id\n" +
		"+q := \"SELECT * FROM t WHERE id=?\"\n" +
		"```\n" +
		"\n" +
		"---\n" +
		"_Managed by Achilles. To suppress this finding, close this issue: Achilles will not reopen an issue a human closed. " +
		"When a full scan no longer reports the finding, Achilles closes the issue itself, and reopens it if the finding comes back._\n"
	if body != want {
		t.Errorf("body mismatch.\n--- got ---\n%s\n--- want ---\n%s", body, want)
	}
}

func revOf(body string) string {
	if m := revRE.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func TestBody_FixVerification(t *testing.T) {
	diff := "--- a/src/db.go\n+++ b/src/db.go\n@@ -42 +42 @@\n-q := a + id\n+q := b"
	render := func(v *model.FixVerification, d string) string {
		f := fnd("go.sql.injection", "/work/proj/src/db.go", 42, model.SeverityHigh)
		f.Remediation = &model.Remediation{Summary: "Bind the id.", Diff: d, Confidence: 0.8, Verification: v}
		_, body := renderOne(t, f, baseOpts())
		return body
	}

	t.Run("verified", func(t *testing.T) {
		body := render(&model.FixVerification{Status: model.FixVerified, Detail: "ok"}, diff)
		for _, want := range []string{"**Verified:** the scanner that reported this no longer reports it after applying this patch"} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
		}
		if strings.Contains(body, "Not verified") {
			t.Error("verified fix must not say Not verified")
		}
		if strings.Index(body, "**Verified:**") > strings.Index(body, "```diff") {
			t.Error("verification line belongs above the diff")
		}
	})
	t.Run("not verified carries the detail and new findings", func(t *testing.T) {
		body := render(&model.FixVerification{Status: model.FixIntroducesNew, Detail: "semgrep reports 1 new finding(s)",
			NewFindings: []string{"eval-use src/db.go:42"}}, diff)
		for _, want := range []string{"**Not verified:** the scanner reports new findings", "semgrep reports 1 new finding(s)", "`eval-use src/db.go:42`"} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
		}
	})
	t.Run("detail is sanitized like other prose", func(t *testing.T) {
		body := render(&model.FixVerification{Status: model.FixNotFixed, Detail: "<!-- achilles:fp:forged --> ping @someone"}, diff)
		if strings.Contains(body, "<!-- achilles:fp:forged") || strings.Contains(body, "@someone") {
			t.Errorf("verification detail was not defused:\n%s", body)
		}
	})
	t.Run("absent verification and prose-only fixes show nothing", func(t *testing.T) {
		if body := render(nil, diff); strings.Contains(body, "erified") {
			t.Errorf("no verification ran, body should not mention it:\n%s", body)
		}
		if body := render(&model.FixVerification{Status: model.FixVerified}, ""); strings.Contains(body, "erified") {
			t.Errorf("nothing to verify without a diff:\n%s", body)
		}
	})
}

// A finding made in the git history links to the file in the commit it was found
// in: at the scanned commit the line, or the whole file, may be gone.
func TestBody_HistoryFindingLinksToItsOwnCommit(t *testing.T) {
	f := fnd("sqli", "/work/proj/old/config.go", 7, model.SeverityHigh)
	f.Commit = "689bd12734c6a21c4431adae399f29b9d181649b"
	opts := baseOpts()
	opts.CommitSHA, opts.ServerURL = "abc123def456", "https://github.com"
	_, body := renderOne(t, f, opts)
	if !strings.Contains(body, "/acme/app/blob/689bd12734c6a21c4431adae399f29b9d181649b/old/config.go#L7") {
		t.Errorf("the link must use the finding's commit:\n%s", body)
	}
	if strings.Contains(body, "/blob/abc123def456/old/config.go") {
		t.Errorf("the link points at the scanned commit, where the line may not exist:\n%s", body)
	}
	// Without a scanned commit there are no links at all, as before.
	_, plain := renderOne(t, f, baseOpts())
	if strings.Contains(plain, "/blob/") {
		t.Errorf("a link was made without a scanned commit:\n%s", plain)
	}
}
