package threatmodel

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
	"github.com/Warzuponus/achilles/internal/vault"
)

func TestGenerate(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{`{
		"trustZones":[{"id":"tz-internet","name":"Internet","risk":"untrusted"}],
		"components":[{"id":"c-api","name":"HTTP API","type":"web-service","parent":"tz-internet","description":"handles user requests"}],
		"threats":[{"id":"t-1","name":"SQL injection via query params","category":"Tampering",
			"description":"Untrusted params reach SQL.","risk":"high","mitigation":"Parameterize queries.","component":"c-api"}]
	}`}}
	router := llm.NewRouter(fake)
	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(router, v)

	inv := inventory.Inventory{Languages: []string{"go"}, Dependencies: []inventory.Dependency{{Name: "x"}}}
	scan := model.Scan{
		Target: "/repo/My App", Tools: []string{"gosec"},
		Findings: []model.Finding{{RuleID: "G201", Severity: model.SeverityHigh}},
	}

	tm, err := eng.Generate(context.Background(), "run1", scan.Target, inv, scan)
	if err != nil {
		t.Fatal(err)
	}

	// We set otmVersion + project (grounding); the LLM fills the rest.
	if tm.OTMVersion != "0.2.0" {
		t.Errorf("otmVersion: got %q", tm.OTMVersion)
	}
	if tm.Project.Name != "My App" || tm.Project.ID != "my-app" {
		t.Errorf("project derived from target wrong: %+v", tm.Project)
	}
	if len(tm.TrustZones) != 1 || len(tm.Components) != 1 || len(tm.Threats) != 1 {
		t.Fatalf("parse wrong: %+v", tm)
	}
	if tm.Threats[0].Category != "Tampering" || tm.Threats[0].Component != "c-api" {
		t.Errorf("threat fields wrong: %+v", tm.Threats[0])
	}

	// Output is valid JSON (OTM document).
	if _, err := json.Marshal(tm); err != nil {
		t.Errorf("threat model must marshal to JSON: %v", err)
	}

	// Prompt carries the profile.
	if p := fake.Calls[0].Messages[1].Content; !strings.Contains(p, "Languages: go") || !strings.Contains(p, "Findings: 1") {
		t.Errorf("profile missing from prompt:\n%s", p)
	}

	// Recorded to the vault.
	got := 0
	for _, rec := range v.ByRun("run1") {
		if rec.Kind == vault.KindThreatModel {
			got++
		}
	}
	if got != 1 {
		t.Errorf("expected 1 KindThreatModel vault record, got %d", got)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"My App": "my-app", "svc_v2": "svc-v2", "": "project", "---": "project"} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeThreats_CanonicalizesObservedDrift(t *testing.T) {
	// Exactly what kimi-k2.6 emitted on the eval corpus: human spelling of the
	// STRIDE enum and title-cased risk. Semantically right, schema-wrong.
	in := []Threat{
		{Category: "Elevation of Privilege", Risk: "High"},
		{Category: "Information Disclosure", Risk: "Medium"},
		{Category: "elevation-of-privilege", Risk: "CRITICAL"},
		{Category: "Tampering", Risk: "low"},
	}
	got := normalizeThreats(in)
	want := []struct{ cat, risk string }{
		{"ElevationOfPrivilege", "high"},
		{"InformationDisclosure", "medium"},
		{"ElevationOfPrivilege", "critical"},
		{"Tampering", "low"},
	}
	for i, w := range want {
		if got[i].Category != w.cat || got[i].Risk != w.risk {
			t.Errorf("[%d] got %q/%q, want %q/%q", i, got[i].Category, got[i].Risk, w.cat, w.risk)
		}
	}
	// The input must not be mutated.
	if in[0].Category != "Elevation of Privilege" {
		t.Error("normalizeThreats must not mutate its input")
	}
}

func TestNormalizeThreats_LeavesUnknownValuesVisible(t *testing.T) {
	// An unrecognized category is a real defect. Coercing it to a plausible
	// neighbour would hide it; the eval's enum check should still catch it.
	got := normalizeThreats([]Threat{{Category: "Cromulence", Risk: "spicy"}})
	if got[0].Category != "Cromulence" || got[0].Risk != "spicy" {
		t.Errorf("unknown values must pass through untouched, got %q/%q", got[0].Category, got[0].Risk)
	}
}

func TestSquash(t *testing.T) {
	for in, want := range map[string]string{
		"Elevation of Privilege": "elevationofprivilege",
		"elevation-of-privilege": "elevationofprivilege",
		"ElevationOfPrivilege":   "elevationofprivilege",
		"Information_Disclosure": "informationdisclosure",
	} {
		if got := squash(in); got != want {
			t.Errorf("squash(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestThreatUnmarshal_AcceptsStrideKeyAlias(t *testing.T) {
	// Exactly what kimi-k2.6 sent on the wire: "stride" instead of "category".
	// Dropping it produced documents where every threat had a blank category.
	var th Threat
	raw := `{"id":"T1","name":"n","stride":"Elevation of Privilege","component":"app","risk":"high","mitigation":"m"}`
	if err := json.Unmarshal([]byte(raw), &th); err != nil {
		t.Fatal(err)
	}
	if th.Category != "Elevation of Privilege" {
		t.Errorf("category from the stride alias = %q, want the value", th.Category)
	}
	if th.Component != "app" {
		t.Errorf("component = %q, want app", th.Component)
	}
}

func TestThreatUnmarshal_CanonicalKeyWins(t *testing.T) {
	// A response that uses the schema's own key must never be second-guessed.
	var th Threat
	raw := `{"id":"T1","category":"Tampering","stride":"Spoofing"}`
	if err := json.Unmarshal([]byte(raw), &th); err != nil {
		t.Fatal(err)
	}
	if th.Category != "Tampering" {
		t.Errorf("canonical key should win, got %q", th.Category)
	}
}

func TestThreatUnmarshal_ComponentIdAliases(t *testing.T) {
	for _, raw := range []string{
		`{"id":"T1","componentId":"svc"}`,
		`{"id":"T1","component_id":"svc"}`,
	} {
		var th Threat
		if err := json.Unmarshal([]byte(raw), &th); err != nil {
			t.Fatal(err)
		}
		if th.Component != "svc" {
			t.Errorf("%s -> component %q, want svc", raw, th.Component)
		}
	}
}

func TestThreatUnmarshal_AcceptsPluralArrayAliases(t *testing.T) {
	// Third shape observed from the same model on the same prompt:
	// `"categories":["Elevation of Privilege"]` — plural key AND an array where the
	// schema declares a scalar. A string-typed alias would fail to decode this
	// rather than merely miss it.
	var th Threat
	raw := `{"id":"B602","name":"Shell Injection","categories":["Elevation of Privilege"],"components":["python-app"],"risk":"high"}`
	if err := json.Unmarshal([]byte(raw), &th); err != nil {
		t.Fatal(err)
	}
	if th.Category != "Elevation of Privilege" {
		t.Errorf("category from the plural array = %q, want the value", th.Category)
	}
	if th.Component != "python-app" {
		t.Errorf("component from the plural array = %q, want python-app", th.Component)
	}
}

func TestThreatUnmarshal_ScalarWinsOverPlural(t *testing.T) {
	var th Threat
	raw := `{"id":"T1","category":"Tampering","categories":["Spoofing"],"stride":"Repudiation"}`
	if err := json.Unmarshal([]byte(raw), &th); err != nil {
		t.Fatal(err)
	}
	if th.Category != "Tampering" {
		t.Errorf("the schema's own key must win, got %q", th.Category)
	}
}

func TestFirst(t *testing.T) {
	if first(nil) != "" || first([]string{}) != "" {
		t.Error("empty input must yield an empty string")
	}
	if first([]string{"a", "b"}) != "a" {
		t.Error("first should take the leading element")
	}
}
