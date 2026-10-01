package research

import (
	"context"
	"testing"

	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

func TestLLMAgent_DiscardsUncitedIssues(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{`{"issues":[
	  {"title":"Real CVE","description":"x","citation":"CVE-2024-1234","language":"python"},
	  {"title":"Hallucination","description":"y","citation":"","language":"python"}
	]}`}}

	issues, err := NewLLMAgent(fake).Research(context.Background(), Target{Tech: "flask", Version: "2.0.1", Ecosystem: "pypi"})
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 {
		t.Fatalf("want 1 cited issue (uncited discarded), got %d", len(issues))
	}
	if issues[0].Title != "Real CVE" || issues[0].Citation != "CVE-2024-1234" {
		t.Errorf("kept the wrong issue: %+v", issues[0])
	}
}

func TestLLMSynthesizer_BuildsRuleWithProvenance(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{`{
	  "ruleYAML":"rules:\n  - id: x\n    languages: [python]\n    severity: ERROR\n    message: m\n    pattern: eval(...)",
	  "language":"python",
	  "vulnerableSnippet":"eval(x)",
	  "patchedSnippet":"ast.literal_eval(x)"
	}`}}

	syn := NewLLMSynthesizer(fake, func() string { return "2026-07-06" })
	rule, err := syn.Synthesize(context.Background(), Issue{Title: "eval RCE", Citation: "CVE-2024-1234", Language: "python"})
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" || rule.RuleYAML == "" || rule.VulnerableSnippet == "" || rule.PatchedSnippet == "" {
		t.Fatalf("incomplete generated rule: %+v", rule)
	}
	if rule.Provenance.SourceCitation != "CVE-2024-1234" || rule.Provenance.Created != "2026-07-06" {
		t.Errorf("provenance wrong: %+v", rule.Provenance)
	}
	if rule.Provenance.PromptVersion != PromptVersion {
		t.Errorf("prompt version: %q", rule.Provenance.PromptVersion)
	}
}
