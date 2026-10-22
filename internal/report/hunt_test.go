package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func huntScan() model.Scan {
	s := flowScan()
	s.Hunted = []model.Finding{{
		Tool: "achilles-hunt", RuleID: "hunt/ssrf", Severity: model.SeverityHigh, Fingerprint: "h", Hunted: true,
		Message:  "url parameter reaches requests.get. Nothing checks the host",
		Location: model.Location{File: "fetch.py", Region: model.Region{StartLine: 9}},
		Verdict:  &model.Verdict{Classification: model.ClassUncertain, Confidence: 0.5, Reasoning: "allowlist may exist upstream"},
	}}
	return s
}

func TestHunted_ListedApartInEveryReport(t *testing.T) {
	var h, md, txt bytes.Buffer
	if err := WriteHTML(&h, HTMLReport{Target: "/r", Scan: huntScan()}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&md, huntScan()); err != nil {
		t.Fatal(err)
	}
	WriteHuman(&txt, huntScan())
	for name, tc := range map[string]struct{ out, want string }{
		"html":     {h.String(), "Hunt candidates the AI review did not confirm"},
		"markdown": {md.String(), "1 hunt candidate(s) the AI review did not confirm"},
		"human":    {txt.String(), "hunt/ssrf at fetch.py:9 — url parameter reaches requests.get"},
	} {
		if !strings.Contains(tc.out, tc.want) {
			t.Errorf("%s report missing %q\n%s", name, tc.want, tc.out)
		}
	}
	if !strings.Contains(h.String(), "1 hunt candidate(s) the AI review did not confirm (listed at the end)") {
		t.Error("HTML summary should count the hunt candidates")
	}
}

// An unconfirmed hunt candidate is a lead, not an alert: code scanning never sees it.
func TestHunted_NotInSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, huntScan()); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "hunt/ssrf" {
			t.Error("unconfirmed hunt candidate exported to SARIF")
		}
	}
}
