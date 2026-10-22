package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func flowScan() model.Scan {
	return model.Scan{Target: "/r", Findings: []model.Finding{{
		RuleID: "sqli", Severity: model.SeverityHigh, Fingerprint: "a", Message: "sql", Tool: "opengrep",
		Location: model.Location{File: "db.py", Region: model.Region{StartLine: 12}},
		Flow: []model.FlowStep{
			{File: "app.py", Line: 3, Note: "token AKIAABCDEFGHIJKLMNOP read"},
			{File: "db.py", Line: 12, Note: "cursor.execute"},
		},
	}}}
}

func TestPath_RenderedEverywhere(t *testing.T) {
	var h, txt bytes.Buffer
	if err := WriteHTML(&h, HTMLReport{Target: "/r", Scan: flowScan()}); err != nil {
		t.Fatal(err)
	}
	WriteHuman(&txt, flowScan())
	for name, out := range map[string]string{"html": h.String(), "human": txt.String()} {
		if !strings.Contains(out, "traced by opengrep") || !strings.Contains(out, "db.py:12 cursor.execute") {
			t.Errorf("%s report missing the path\n%s", name, out)
		}
		if strings.Contains(out, "AKIAABCDEFGHIJKLMNOP") {
			t.Errorf("%s report printed a credential from a path note", name)
		}
	}
}

// The deep verifier's path, every step a line it was shown, wins over the
// scanner's claim.
func TestPath_PrefersDeepVerification(t *testing.T) {
	s := flowScan()
	s.Findings[0].Deep = &model.DeepVerification{Conclusion: model.ClassTruePositive, Steps: 4,
		Path: []model.FlowStep{{File: "views.py", Line: 7}, {File: "db.py", Line: 12}}}
	var txt bytes.Buffer
	WriteHuman(&txt, s)
	if out := txt.String(); !strings.Contains(out, "traced by deep verification") || !strings.Contains(out, "views.py:7") {
		t.Errorf("human report should show the deep path\n%s", out)
	}
}

func TestPath_ExportedAsSARIFCodeFlow(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIFReport(&buf, flowScan()); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	cf := log.Runs[0].Results[0].CodeFlows
	if len(cf) != 1 || len(cf[0].ThreadFlows) != 1 || len(cf[0].ThreadFlows[0].Locations) != 2 {
		t.Fatalf("codeFlows = %+v", cf)
	}
	first := cf[0].ThreadFlows[0].Locations[0].Location
	if first.PhysicalLocation.ArtifactLocation.URI != "app.py" || first.PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("first step = %+v", first)
	}
	if first.Message == nil || strings.Contains(first.Message.Text, "AKIA") {
		t.Errorf("step message should be present and masked: %+v", first.Message)
	}
}
