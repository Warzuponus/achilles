package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// A finding suppressed by a comment in the code is in every report, with the
// reason the comment gives, and the reports say when the change under review
// added the comment. SARIF marks it suppressed in source.
func TestReports_ListSuppressedFindingsWithTheirReasons(t *testing.T) {
	s := model.Scan{
		Target: "/repo",
		Findings: []model.Finding{{Tool: "gosec", RuleID: "G304", Severity: model.SeverityMedium, Message: "file inclusion",
			Location: model.Location{File: "b.go", Region: model.Region{StartLine: 3}}, Fingerprint: "fp-b"}},
		Suppressed: []model.Finding{
			{Tool: "gosec", RuleID: "G204", Severity: model.SeverityHigh, Message: "subprocess",
				Location: model.Location{File: "a.go", Region: model.Region{StartLine: 11}}, Fingerprint: "fp-a",
				Suppression: &model.Suppression{File: "a.go", Line: 10, Reason: "bin is on an allowlist"}},
			{Tool: "gosec", RuleID: "G204", Severity: model.SeverityHigh, Message: "subprocess",
				Location: model.Location{File: "c.go", Region: model.Region{StartLine: 5}}, Fingerprint: "fp-c",
				Suppression: &model.Suppression{File: "c.go", Line: 5, Reason: "trust me <script>", New: true}},
		},
	}

	var text bytes.Buffer
	WriteHuman(&text, s)
	for _, want := range []string{"2 more finding(s) suppressed by comments", "a.go:11", "bin is on an allowlist", "ADDED BY THE CHANGE UNDER REVIEW"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report lacks %q:\n%s", want, text.String())
		}
	}

	var md bytes.Buffer
	if err := WriteMarkdown(&md, s); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 finding(s) suppressed by comments in the code", "1 of them added by this change", "bin is on an allowlist", "| added by this change |"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("Markdown report lacks %q:\n%s", want, md.String())
		}
	}
	if strings.Contains(md.String(), "<script>") {
		t.Errorf("a reason is text from the scanned code and must not reach Markdown as HTML:\n%s", md.String())
	}

	var html bytes.Buffer
	if err := WriteHTML(&html, HTMLReport{Target: "/repo", Scan: s}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Suppressed by comments in the code", "bin is on an allowlist", "added by this change", "2 suppressed by comments in the code"} {
		if !strings.Contains(html.String(), want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	if strings.Contains(html.String(), "trust me <script>") {
		t.Error("a reason reached the HTML report unescaped")
	}

	var sarif bytes.Buffer
	if err := WriteSARIFReport(&sarif, s); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("%d SARIF result(s), want the finding and both suppressed ones", len(results))
	}
	if len(results[0].Suppressions) != 0 {
		t.Errorf("the open finding is marked suppressed: %+v", results[0])
	}
	for _, r := range results[1:] {
		if len(r.Suppressions) != 1 || r.Suppressions[0].Kind != "inSource" || r.Suppressions[0].Justification == "" {
			t.Errorf("suppressed result = %+v, want one inSource suppression with its justification", r)
		}
	}

	// With nothing else to report, the scan is not called clean.
	text.Reset()
	WriteHuman(&text, model.Scan{Target: "/repo", Suppressed: s.Suppressed})
	if strings.Contains(text.String(), "Clean scan") || !strings.Contains(text.String(), "No findings besides the 2 suppressed") {
		t.Errorf("a scan whose only findings are suppressed:\n%s", text.String())
	}
}
