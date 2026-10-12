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
	client   llm.Client
	grounder Grounder // nil: citations are only required to be present
}

func NewLLMAgent(c llm.Client) *LLMAgent { return &LLMAgent{client: c} }

// WithGrounder makes the agent keep only issues whose cited advisory exists.
func (a *LLMAgent) WithGrounder(g Grounder) *LLMAgent {
	a.grounder = g
	return a
}

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

	// Anti-hallucination: drop any issue lacking a citation, and, when a grounder
	// is set, any whose cited advisory cannot be found (DESIGN.md §9.2). A lookup
	// that cannot be made fails the target: nothing is kept unverified.
	kept := out.Issues[:0]
	for _, iss := range out.Issues {
		if strings.TrimSpace(iss.Citation) == "" {
			continue
		}
		if a.grounder != nil {
			ok, err := grounded(ctx, a.grounder, iss.Citation)
			if err != nil {
				return nil, fmt.Errorf("could not verify the citation for %q, so nothing from this target is used: %w", iss.Title, err)
			}
			if !ok {
				continue
			}
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
			Origin:         i.Origin,
			IssueTitle:     i.Title,
			Model:          resp.Model,
			PromptVersion:  PromptVersion,
			Created:        s.now(),
		},
	}
	return rule, nil
}
