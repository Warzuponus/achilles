package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func finding(tool, rule string, sev model.Severity, file string, line int) model.Finding {
	return model.Finding{Tool: tool, RuleID: rule, Severity: sev, Message: "m",
		Location: model.Location{File: file, Region: model.Region{StartLine: line}}}
}

// A long report opens with what each rule contributed, most severe and most
// frequent first; the per-finding detail follows unchanged.
func TestWriteHuman_SummarizesByRule(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < 8; i++ {
		fs = append(fs, finding("gosec", "G304", model.SeverityMedium, fmt.Sprintf("f%d.go", i%3), i+1))
	}
	for i := 0; i < 3; i++ {
		fs = append(fs, finding("gosec", "G204", model.SeverityHigh, "cmd.go", i+1))
	}
	fs = append(fs, finding("Trivy", "CVE-2020-1", model.SeverityCritical, "go.sum", 0))
	var b bytes.Buffer
	WriteHuman(&b, model.Scan{Target: "/x", Findings: fs})
	out := b.String()
	summary, detail, ok := strings.Cut(out, "\nDetail:")
	if !ok || !strings.Contains(summary, "By rule (3 rules):") {
		t.Fatalf("no rule summary before the detail:\n%s", out)
	}
	want := []string{
		"critical    1  CVE-2020-1 (Trivy, 1 file)",
		"high        3  G204 (gosec, 1 file)",
		"medium      8  G304 (gosec, 3 files)",
	}
	last := -1
	for _, w := range want {
		i := strings.Index(summary, w)
		if i < 0 {
			t.Fatalf("summary lacks %q:\n%s", w, summary)
		}
		if i < last {
			t.Errorf("%q is out of order:\n%s", w, summary)
		}
		last = i
	}
	if n := strings.Count(detail, "\n  ["); n != len(fs) {
		t.Errorf("detail lists %d findings, want all %d", n, len(fs))
	}
}

func TestWriteHuman_NoRuleSummaryWhenItWouldNotHelp(t *testing.T) {
	short := []model.Finding{finding("gosec", "G304", model.SeverityMedium, "a.go", 1), finding("gosec", "G304", model.SeverityMedium, "a.go", 2)}
	var distinct []model.Finding
	for i := 0; i < 12; i++ {
		distinct = append(distinct, finding("gosec", fmt.Sprintf("G%d", i), model.SeverityLow, "a.go", i))
	}
	for name, fs := range map[string][]model.Finding{"few findings": short, "one finding per rule": distinct} {
		var b bytes.Buffer
		WriteHuman(&b, model.Scan{Target: "/x", Findings: fs})
		if strings.Contains(b.String(), "By rule") {
			t.Errorf("%s: summary shown:\n%s", name, b.String())
		}
	}
}

func TestWriteHuman_RuleSummaryIsCapped(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < byRuleMax+5; i++ {
		fs = append(fs, finding("gosec", fmt.Sprintf("G%d", i), model.SeverityLow, "a.go", 1), finding("gosec", fmt.Sprintf("G%d", i), model.SeverityLow, "a.go", 2))
	}
	var b bytes.Buffer
	WriteHuman(&b, model.Scan{Target: "/x", Findings: fs})
	if !strings.Contains(b.String(), "... and 5 more rule(s)") {
		t.Errorf("summary not capped at %d rules:\n%s", byRuleMax, b.String())
	}
}
