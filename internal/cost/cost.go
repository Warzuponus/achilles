// Package cost estimates what a run's LLM work will cost BEFORE any model call
// is made, so an operator can see the bill under --dry-run and cap it with
// --max-cost (DESIGN.md §14, "LLM triage cost at scale").
//
// The split of responsibility here is deliberate:
//
//   - TOKENS are computable from our own prompts, so we estimate them ourselves
//     and always report them.
//   - DOLLARS need per-model prices, which are the operator's ground truth —
//     they change without notice, differ per provider (OpenAI vs Azure vs
//     Ollama Cloud vs a self-hosted endpoint), and can be negotiated. So this
//     package ships NO built-in price table. Supply one with --price-config
//     (see configs/prices.example.yaml). A money guardrail built on prices we
//     guessed would be worse than no guardrail at all.
//
// Everything here is an estimate, and the printed report says so. Output-token
// counts in particular cannot be known in advance; they come from per-task
// constants in the caller.
package cost

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Price is a model's cost per million tokens, in USD.
type Price struct {
	InputPerMTok  float64 `yaml:"inputPerMTok"`
	OutputPerMTok float64 `yaml:"outputPerMTok"`
}

// Table maps a model name to its price. An empty Table prices nothing, which is
// the default state — see the package comment.
type Table struct {
	Models map[string]Price `yaml:"models"`
}

// LoadTable reads a price table YAML file.
func LoadTable(path string) (Table, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Table{}, fmt.Errorf("read price-config: %w", err)
	}
	var t Table
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Table{}, fmt.Errorf("parse price-config %s: %w", path, err)
	}
	for name, p := range t.Models {
		if p.InputPerMTok < 0 || p.OutputPerMTok < 0 {
			return Table{}, fmt.Errorf("price-config %s: model %q has a negative price", path, name)
		}
	}
	return t, nil
}

// For returns a model's price. Lookup is exact first, then case-insensitive,
// then on the segment after the last "/" so a provider-qualified name like
// "google/gemini-3.6-flash" matches an entry for "gemini-3.6-flash".
func (t Table) For(model string) (Price, bool) {
	if p, ok := t.Models[model]; ok {
		return p, true
	}
	want := strings.ToLower(model)
	for name, p := range t.Models {
		if strings.ToLower(name) == want {
			return p, true
		}
	}
	if i := strings.LastIndex(model, "/"); i >= 0 {
		return t.For(model[i+1:])
	}
	return Price{}, false
}

// Call is one LLM call a run intends to make.
type Call struct {
	Task         string
	Model        string
	InputTokens  int
	OutputTokens int
}

// AssignModels fills in each call's Model from the caller's task routing, which
// is where model selection lives (--model-config plus --llm-model).
func AssignModels(calls []Call, resolve func(task string) string) []Call {
	out := make([]Call, len(calls))
	for i, c := range calls {
		c.Model = resolve(c.Task)
		out[i] = c
	}
	return out
}

// TaskTotal aggregates every planned call for one (task, model) pair.
type TaskTotal struct {
	Task         string
	Model        string
	Calls        int
	InputTokens  int
	OutputTokens int
	USD          float64
	Priced       bool // false when the model has no price-table entry
}

// Estimate is the pre-flight projection for a whole run.
type Estimate struct {
	Totals   []TaskTotal
	TotalUSD float64
	// Unpriced names the distinct models with no price entry. When it is
	// non-empty, TotalUSD covers only the priced subset and must not be treated
	// as the whole bill.
	Unpriced []string
	// Excluded names LLM work this estimate deliberately does NOT cover, so a
	// partial number is never mistaken for a complete one.
	Excluded []string
}

// Complete reports whether every planned call could be priced. A --max-cost
// check is only meaningful when this is true.
func (e Estimate) Complete() bool { return len(e.Unpriced) == 0 }

// TotalTokens returns the projected input+output token count across all calls,
// which is reportable even with no price table at all.
func (e Estimate) TotalTokens() (in, out int) {
	for _, t := range e.Totals {
		in += t.InputTokens
		out += t.OutputTokens
	}
	return in, out
}

// Project aggregates planned calls into an estimate, pricing what it can.
// Totals come back sorted by task then model, so output is deterministic.
func Project(calls []Call, t Table) Estimate {
	type key struct{ task, model string }
	agg := map[key]*TaskTotal{}
	for _, c := range calls {
		k := key{c.Task, c.Model}
		if agg[k] == nil {
			agg[k] = &TaskTotal{Task: c.Task, Model: c.Model}
		}
		a := agg[k]
		a.Calls++
		a.InputTokens += c.InputTokens
		a.OutputTokens += c.OutputTokens
	}

	var e Estimate
	unpriced := map[string]bool{}
	for _, a := range agg {
		if p, ok := t.For(a.Model); ok {
			a.Priced = true
			a.USD = float64(a.InputTokens)/1e6*p.InputPerMTok +
				float64(a.OutputTokens)/1e6*p.OutputPerMTok
			e.TotalUSD += a.USD
		} else {
			unpriced[a.Model] = true
		}
		e.Totals = append(e.Totals, *a)
	}
	sort.Slice(e.Totals, func(i, j int) bool {
		if e.Totals[i].Task != e.Totals[j].Task {
			return e.Totals[i].Task < e.Totals[j].Task
		}
		return e.Totals[i].Model < e.Totals[j].Model
	})
	for m := range unpriced {
		e.Unpriced = append(e.Unpriced, m)
	}
	sort.Strings(e.Unpriced)
	return e
}

// Tokens approximates the token count of a prompt string at ~4 characters per
// token. It is a heuristic, not a tokenizer: it needs no per-model vocabulary
// and works identically for every OpenAI-compatible endpoint, at the price of
// being roughly ±20% on mixed prose and code.
func Tokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}

// Write renders the estimate for a terminal. It always reports tokens, reports
// dollars only for models it could price, and states what it left out.
func (e Estimate) Write(w io.Writer) {
	in, out := e.TotalTokens()
	calls := 0
	for _, t := range e.Totals {
		calls += t.Calls
	}
	fmt.Fprintf(w, "LLM cost estimate (pre-flight; no model has been called)\n")
	if calls == 0 {
		fmt.Fprintf(w, "  no LLM calls planned\n")
		return
	}
	fmt.Fprintf(w, "  %-14s %-28s %6s %12s %12s %10s\n", "TASK", "MODEL", "CALLS", "IN TOKENS", "OUT TOKENS", "USD")
	for _, t := range e.Totals {
		usd := fmt.Sprintf("%.4f", t.USD)
		if !t.Priced {
			usd = "unpriced"
		}
		fmt.Fprintf(w, "  %-14s %-28s %6d %12d %12d %10s\n",
			t.Task, truncate(t.Model, 28), t.Calls, t.InputTokens, t.OutputTokens, usd)
	}
	fmt.Fprintf(w, "  %-14s %-28s %6d %12d %12d %10s\n", "TOTAL", "", calls, in, out,
		fmt.Sprintf("%.4f", e.TotalUSD))

	if len(e.Unpriced) > 0 {
		fmt.Fprintf(w, "\n  NOTE: no price for %s — the USD total covers only the priced models.\n",
			strings.Join(e.Unpriced, ", "))
		fmt.Fprintf(w, "        Add them with --price-config (see configs/prices.example.yaml).\n")
	}
	if len(e.Excluded) > 0 {
		fmt.Fprintf(w, "\n  NOT included in this estimate:\n")
		for _, x := range e.Excluded {
			fmt.Fprintf(w, "        - %s\n", x)
		}
	}
	fmt.Fprintf(w, "\n  Token counts are approximations (~4 chars/token) and output sizes are\n")
	fmt.Fprintf(w, "  per-task defaults; compare against --diagnostics after a real run.\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
