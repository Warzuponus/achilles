package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func planScan() model.Scan {
	return model.Scan{Target: "/x", Tools: []string{"opengrep", "zizmor"}, ToolPlan: &model.ToolPlan{
		Depth: "full", DepthReasons: []string{"businessCritical = yes (context file)"}, ContextFile: ".achilles/threat-context.yaml",
		Decisions: []model.ToolDecision{
			{Tool: "checkov", Action: model.ToolSkipped, Reason: "no infrastructure-as-code files", Fix: "--all-tools"},
			{Tool: "zizmor", Action: model.ToolAdded, Reason: "the repository has GitHub Actions workflows"},
			{Tool: "--profile full", Action: model.ToolRecommended, Reason: "scan depth is full", Fix: "--profile full"},
		},
	}}
}

// A scanner the plan skipped or added is named, with the reason, in every report:
// a scanner that did not run must never be silent.
func TestReports_ShowTheToolPlan(t *testing.T) {
	s := planScan()
	var human, md, html, js, sarif bytes.Buffer
	WriteHuman(&human, s)
	if err := WriteMarkdown(&md, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&html, HTMLReport{Target: "x", Scan: s, Tools: s.Tools}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&js, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIFReport(&sarif, s); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"human": human.String(), "markdown": md.String(), "html": html.String()} {
		for _, want := range []string{"depth full", "skipped checkov", "--all-tools runs it", "added zizmor", "recommends --profile full"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report lacks %q:\n%s", name, want, out)
			}
		}
	}
	var doc struct {
		ToolPlan *model.ToolPlan `json:"toolPlan"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil || doc.ToolPlan == nil || len(doc.ToolPlan.Decisions) != 3 {
		t.Errorf("json: %v %+v", err, doc.ToolPlan)
	}
	var log model.SarifLog
	if err := json.Unmarshal(sarif.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	inv := log.Runs[0].Invocations
	if len(inv) != 1 || !inv[0].ExecutionSuccessful || len(inv[0].ToolExecutionNotifications) != 2 {
		t.Fatalf("sarif invocations: %+v", inv)
	}
	if n := inv[0].ToolExecutionNotifications[0]; n.Level != "note" || !strings.Contains(n.Message.Text, "skipped checkov") {
		t.Errorf("sarif notification: %+v", n)
	}
}

// A skip is not a failure: with no failed tool the run is still successful, and a
// failed tool still makes it unsuccessful.
func TestSARIF_ToolPlanDoesNotHideAFailure(t *testing.T) {
	s := planScan()
	s.FailedTools = []string{"trivy"}
	var b bytes.Buffer
	if err := WriteSARIFReport(&b, s); err != nil {
		t.Fatal(err)
	}
	var log model.SarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || inv.ToolExecutionNotifications[0].Level != "error" {
		t.Errorf("a failed tool still fails the invocation: %+v", inv)
	}
}
