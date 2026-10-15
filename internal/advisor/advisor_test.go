package advisor

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
	"github.com/Warzuponus/achilles/internal/vault"
)

func TestAdvise(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{`{
		"summary":"One security-driven upgrade; the rest are hygiene.",
		"upgrades":[
			{"package":"golang.org/x/text","ecosystem":"go","currentVersion":"v0.3.5",
			 "recommendedVersion":"v0.3.8","upgradeType":"patch","mergeRisk":"low",
			 "securityDriven":true,"rationale":"Fixes GO-2021-0113; patch bump, low blast radius."}
		]}`}}
	router := llm.NewRouter(fake)

	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(router, v)

	inv := inventory.Inventory{Dependencies: []inventory.Dependency{
		{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: "go"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}}
	scan := model.Scan{Findings: []model.Finding{
		{Tool: "govulncheck", RuleID: "GO-2021-0113", Severity: model.SeverityHigh, Message: "x/text BidiRule panic"},
		{Tool: "gosec", RuleID: "G404", Severity: model.SeverityMedium, Message: "weak rand"}, // not SCA → excluded from prompt
		// Trivy names itself "Trivy": its advisories go in, its misconfigurations do not.
		{Tool: "Trivy", Scanner: "trivy", RuleID: "CVE-2021-23337", Severity: model.SeverityHigh, Message: "lodash command injection"},
		{Tool: "Trivy", Scanner: "trivy", RuleID: "DS002", Severity: model.SeverityHigh, Message: "image runs as root"},
	}}

	a, err := eng.Advise(context.Background(), "run1", inv, scan)
	if err != nil {
		t.Fatal(err)
	}
	if a.Summary == "" || len(a.Upgrades) != 1 {
		t.Fatalf("parse wrong: %+v", a)
	}
	u := a.Upgrades[0]
	if u.Package != "golang.org/x/text" || u.MergeRisk != "low" || !u.SecurityDriven {
		t.Errorf("upgrade fields wrong: %+v", u)
	}

	// Prompt must carry the deps and only the SCA findings (not gosec).
	prompt := fake.Calls[0].Messages[1].Content
	if !strings.Contains(prompt, "golang.org/x/text@v0.3.5 [go]") || !strings.Contains(prompt, "lodash@4.17.21") {
		t.Errorf("deps missing from prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "GO-2021-0113") || !strings.Contains(prompt, "CVE-2021-23337") {
		t.Errorf("SCA finding missing from prompt:\n%s", prompt)
	}
	if strings.Contains(prompt, "DS002") {
		t.Errorf("a Trivy misconfiguration reached the dependency advisor:\n%s", prompt)
	}
	if strings.Contains(prompt, "G404") {
		t.Errorf("non-SCA finding (gosec G404) should not be in the advisor prompt:\n%s", prompt)
	}

	// Advice recorded to the vault.
	got := 0
	for _, rec := range v.ByRun("run1") {
		if rec.Kind == vault.KindAdvisory {
			got++
		}
	}
	if got != 1 {
		t.Errorf("expected 1 KindAdvisory vault record, got %d", got)
	}
}
