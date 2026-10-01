// Package review is the full-repo security review agent (DESIGN §7, Tier D). It
// is deliberately DIFFERENT from finding-level triage: instead of judging one
// scanner hit at a time, it reasons over the whole codebase profile + the set of
// findings to surface systemic/architectural risks, themes across findings, and
// missing controls — things no single rule reports.
package review

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// Risk is one systemic/holistic risk the reviewer raises (not a single finding).
type Risk struct {
	Title          string `json:"title"`
	Severity       string `json:"severity"` // critical | high | medium | low
	Area           string `json:"area"`     // e.g. authentication, input-validation, secrets, deps
	Rationale      string `json:"rationale"`
	Recommendation string `json:"recommendation"`
}

// Review is the holistic assessment produced by the agent.
type Review struct {
	Summary string `json:"summary"`
	Risks   []Risk `json:"risks"`
}

var reviewSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "summary":{"type":"string"},
    "risks":{"type":"array","items":{
      "type":"object",
      "properties":{
        "title":{"type":"string"},
        "severity":{"type":"string","enum":["critical","high","medium","low"]},
        "area":{"type":"string"},
        "rationale":{"type":"string"},
        "recommendation":{"type":"string"}
      },
      "required":["title","severity","rationale","recommendation"],
      "additionalProperties":false
    }}
  },
  "required":["summary","risks"],
  "additionalProperties":false
}`)

// Engine runs the review agent through the llm.Router (task "review", so it can
// use a stronger model than triage) and records the result to the vault.
type Engine struct {
	router *llm.Router
	vault  vault.Store
}

func NewEngine(router *llm.Router, v vault.Store) *Engine {
	return &Engine{router: router, vault: v}
}

// Review produces a holistic assessment from the codebase profile + findings.
func (e *Engine) Review(ctx context.Context, runID string, inv inventory.Inventory, scan model.Scan) (*Review, error) {
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt},
		{Role: llm.RoleUser, Content: profile(inv, scan)},
	}
	var r Review
	resp, err := llm.CompleteAndDecode(ctx, e.router.For("review"), msgs,
		&llm.Schema{Name: "review", Definition: reviewSchema}, &r,
		func() error {
			if strings.TrimSpace(r.Summary) == "" && len(r.Risks) == 0 {
				return fmt.Errorf("empty review (no summary and no risks)")
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("review: %w", err)
	}
	if e.vault != nil {
		payload, _ := json.Marshal(r)
		_, _ = e.vault.Append(vault.Record{RunID: runID, Phase: "review", Kind: vault.KindReview,
			Source: resp.Model, Payload: payload})
	}
	return &r, nil
}

const systemPrompt = `You are a senior application-security architect performing a holistic review.
You are given a codebase profile and the findings from automated scanners.
Do NOT restate individual findings — that is handled elsewhere. Instead identify
SYSTEMIC risks: architectural weaknesses, themes across multiple findings, missing
security controls, and risky dependency/technology choices. Be concrete and
prioritize. Return ONLY a single JSON object matching the schema — no markdown
fences, no prose. Fill a non-empty summary AND at least one risk, every field the
exact type shown (strings must be plain strings, never nested objects). Use
exactly these key names, shaped like:
{"summary":"Untrusted request params reach SQL and shell sinks with no validation layer.",
"risks":[{"title":"Missing input validation at request boundaries","severity":"high",
"area":"input-validation","rationale":"Several SQLi/command-injection findings share one root cause.",
"recommendation":"Add centralized request-input validation and parameterized queries."}]}`

// profile builds a compact codebase summary for the prompt: languages, a
// dependency count (+ a sample), the tools run, per-severity finding counts, and
// the most common rules/files — enough signal for a holistic read without
// shipping the whole tree.
func profile(inv inventory.Inventory, scan model.Scan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", scan.Target)
	fmt.Fprintf(&b, "Languages: %s\n", strings.Join(inv.Languages, ", "))
	fmt.Fprintf(&b, "Dependencies: %d\n", len(inv.Dependencies))
	if len(scan.Tools) > 0 {
		fmt.Fprintf(&b, "Scanners run: %s\n", strings.Join(scan.Tools, ", "))
	}

	counts := map[model.Severity]int{}
	rules := map[string]int{}
	files := map[string]int{}
	for _, f := range scan.Findings {
		counts[f.Severity]++
		rules[f.RuleID]++
		files[f.Location.File]++
	}
	fmt.Fprintf(&b, "Findings: %d total (critical=%d high=%d medium=%d low=%d)\n",
		len(scan.Findings), counts[model.SeverityCritical], counts[model.SeverityHigh],
		counts[model.SeverityMedium], counts[model.SeverityLow])
	fmt.Fprintf(&b, "Top rules: %s\n", topN(rules, 8))
	fmt.Fprintf(&b, "Most-affected files: %s\n", topN(files, 8))
	return b.String()
}

// topN returns the highest-count keys as "key(n)", most frequent first.
func topN(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) > n {
		items = items[:n]
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprintf("%s(%d)", it.k, it.v)
	}
	return strings.Join(parts, ", ")
}
