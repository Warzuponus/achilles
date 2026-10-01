package research

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// Agent researches a target and returns candidate issues.
type Agent interface {
	Research(ctx context.Context, t Target) ([]Issue, error)
}

// Synthesizer turns an issue into a validatable generated rule.
type Synthesizer interface {
	Synthesize(ctx context.Context, i Issue) (GeneratedRule, error)
}

// LLMAgent is an Agent backed by an LLM. It enforces the citation guardrail:
// any issue without a resolvable citation is discarded before it leaves here.
type LLMAgent struct {
	client llm.Client
}

func NewLLMAgent(c llm.Client) *LLMAgent { return &LLMAgent{client: c} }

func (a *LLMAgent) Research(ctx context.Context, t Target) ([]Issue, error) {
	resp, err := llm.CompleteJSON(ctx, a.client, researchMessages(t), &llm.Schema{Name: "issues", Definition: issuesSchema})
	if err != nil {
		return nil, fmt.Errorf("research llm: %w", err)
	}
	var out struct {
		Issues []Issue `json:"issues"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Content)), &out); err != nil {
		return nil, fmt.Errorf("parse issues: %w", err)
	}

	// Anti-hallucination: drop any issue lacking a real citation (DESIGN.md §9.2).
	kept := out.Issues[:0]
	for _, iss := range out.Issues {
		if strings.TrimSpace(iss.Citation) == "" {
			continue
		}
		if iss.Language == "" {
			iss.Language = t.Tech // best-effort
		}
		kept = append(kept, iss)
	}
	return kept, nil
}

// LLMSynthesizer is a Synthesizer backed by an LLM.
type LLMSynthesizer struct {
	client llm.Client
	// now returns a timestamp string; injectable for deterministic tests.
	now func() string
}

func NewLLMSynthesizer(c llm.Client, now func() string) *LLMSynthesizer {
	if now == nil {
		now = func() string { return "" }
	}
	return &LLMSynthesizer{client: c, now: now}
}

func (s *LLMSynthesizer) Synthesize(ctx context.Context, i Issue) (GeneratedRule, error) {
	resp, err := llm.CompleteJSON(ctx, s.client, synthesisMessages(i), &llm.Schema{Name: "rule", Definition: ruleSchema})
	if err != nil {
		return GeneratedRule{}, fmt.Errorf("synthesis llm: %w", err)
	}
	var out struct {
		RuleYAML          string `json:"ruleYAML"`
		Language          string `json:"language"`
		VulnerableSnippet string `json:"vulnerableSnippet"`
		PatchedSnippet    string `json:"patchedSnippet"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Content)), &out); err != nil {
		return GeneratedRule{}, fmt.Errorf("parse rule: %w", err)
	}

	lang := out.Language
	if lang == "" {
		lang = i.Language
	}
	rule := GeneratedRule{
		ID:                ruleID(i.Title, out.RuleYAML),
		Language:          lang,
		RuleYAML:          out.RuleYAML,
		VulnerableSnippet: out.VulnerableSnippet,
		PatchedSnippet:    out.PatchedSnippet,
		Provenance: Provenance{
			SourceCitation: i.Citation,
			IssueTitle:     i.Title,
			Model:          resp.Model,
			PromptVersion:  PromptVersion,
			Created:        s.now(),
		},
	}
	return rule, nil
}
