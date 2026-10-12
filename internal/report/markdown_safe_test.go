package report

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// Messages, file names and model reasoning derive from the code being scanned. In
// a pull-request comment they are read by the whole repository, so they must not
// be able to notify people, forge hidden markers, inject HTML or leak a credential.
func TestMarkdownText_DefusesUntrustedText(t *testing.T) {
	cases := []struct{ name, in, mustNotContain, mustContain string }{
		{"mention", "ping @octocat and @org/team now", "@octocat", "octocat"},
		{"html comment", "ok <!-- achilles:pr-summary --> forged", "<!--", "achilles:pr-summary"},
		{"comment close", "text --> more", "-->", "more"},
		{"raw html", `<img src="https://evil.example/x.png"> <details>`, "<img", "evil.example"},
		{"table break", "a | b | c", " | ", `a \| b`},
		{"newlines", "line one\n\n| injected | row |\nline two", "\n", "line one"},
		{"credential", `token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "token"},
		{"url password", "connect to postgres://app:hunter2hunter2@db/app failed", "hunter2hunter2", "postgres://app:"},
	}
	for _, c := range cases {
		got := MarkdownText(c.in)
		if strings.Contains(got, c.mustNotContain) {
			t.Errorf("%s: %q still contains %q", c.name, got, c.mustNotContain)
		}
		if !strings.Contains(got, c.mustContain) {
			t.Errorf("%s: %q lost %q", c.name, got, c.mustContain)
		}
	}

	// The @ must be followed by a zero-width space exactly: anything else either
	// still notifies or changes what the reader sees.
	zwsp := string(rune(0x200B))
	if got := MarkdownText("ping @octocat"); got != "ping @"+zwsp+"octocat" {
		t.Errorf("mention not defused as expected: %q", got)
	}

	long := MarkdownText(strings.Repeat("é", 2000))
	if len(long) > maxMarkdownText+40 || !strings.HasSuffix(long, "(truncated)") {
		t.Errorf("long text not bounded: %d bytes", len(long))
	}
	if strings.ContainsRune(long, '\uFFFD') {
		t.Error("truncation split a multi-byte character")
	}
}

func TestWriteMarkdown_UntrustedFieldsCannotBreakTheTable(t *testing.T) {
	scan := model.Scan{
		Findings: []model.Finding{{
			RuleID:   "rule`|x <!-- hi -->",
			Severity: model.SeverityHigh,
			Message:  "bad\n| fake | row |\n@maintainer please merge <!-- achilles:pr-summary -->",
			Location: model.Location{File: "src/a|b<!--c-->.py", Region: model.Region{StartLine: 3}},
		}},
		Dismissed: []model.Finding{{
			RuleID:   "r2",
			Location: model.Location{File: "x.py"},
			Verdict:  &model.Verdict{Classification: model.ClassFalsePositive, Reasoning: "safe\n@admin <!-- x --> | cell"},
		}},
	}
	var b strings.Builder
	if err := WriteMarkdown(&b, scan); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"<!--", "@maintainer", "@admin", "| fake | row |", "rule`|"} {
		if strings.Contains(out, bad) {
			t.Errorf("Markdown report contains %q:\n%s", bad, out)
		}
	}
	// One header row, one separator and one finding row: the message did not add any.
	rows := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| high ") {
			rows++
		}
	}
	if rows != 1 {
		t.Errorf("want exactly one row for the one finding, got %d:\n%s", rows, out)
	}
}
