package review

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

func TestReview(t *testing.T) {
	// Wrapped in a markdown code fence on purpose: open models (GLM/Kimi/MiniMax
	// via Ollama) routinely fence their JSON, and the agent must tolerate it the
	// same way triage does (regression for the fence-parse bug).
	fake := &llmtest.Fake{Responses: []string{"```json\n" + `{
		"summary":"Input from HTTP handlers reaches SQL and shell sinks without validation.",
		"risks":[
			{"title":"Systemic missing input validation","severity":"high","area":"input-validation",
			 "rationale":"Multiple SQL/command findings share an untrusted-params root cause.",
			 "recommendation":"Introduce a validation layer at request boundaries."}
		]}` + "\n```"}}
	router := llm.NewRouter(fake)

	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(router, v)

	inv := inventory.Inventory{Languages: []string{"go", "python"}, Dependencies: []inventory.Dependency{{Name: "x"}}}
	scan := model.Scan{
		Target: "/repo", Tools: []string{"gosec", "opengrep"},
		Findings: []model.Finding{
			{RuleID: "G201", Severity: model.SeverityHigh, Location: model.Location{File: "db.go"}},
			{RuleID: "G204", Severity: model.SeverityHigh, Location: model.Location{File: "run.go"}},
		},
	}

	r, err := eng.Review(context.Background(), "run1", inv, scan)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary == "" || len(r.Risks) != 1 {
		t.Fatalf("parse wrong: %+v", r)
	}
	if r.Risks[0].Severity != "high" || r.Risks[0].Area != "input-validation" {
		t.Errorf("risk fields wrong: %+v", r.Risks[0])
	}

	// The prompt must carry the codebase profile (languages + finding count).
	prompt := fake.Calls[0].Messages[1].Content
	if !strings.Contains(prompt, "go, python") || !strings.Contains(prompt, "Findings: 2 total") {
		t.Errorf("profile missing from prompt:\n%s", prompt)
	}

	// The review must be recorded to the vault.
	got := 0
	for _, rec := range v.ByRun("run1") {
		if rec.Kind == vault.KindReview {
			got++
		}
	}
	if got != 1 {
		t.Errorf("expected 1 KindReview vault record, got %d", got)
	}
}
