package cost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func table() Table {
	return Table{Models: map[string]Price{
		"cheap":  {InputPerMTok: 1, OutputPerMTok: 2},
		"strong": {InputPerMTok: 10, OutputPerMTok: 30},
		"free":   {InputPerMTok: 0, OutputPerMTok: 0},
	}}
}

func TestProject_PricesPerTaskAndModel(t *testing.T) {
	calls := []Call{
		{Task: "triage", Model: "cheap", InputTokens: 1_000_000, OutputTokens: 500_000},
		{Task: "judge", Model: "strong", InputTokens: 100_000, OutputTokens: 10_000},
	}
	e := Project(calls, table())

	if len(e.Totals) != 2 {
		t.Fatalf("want 2 task totals, got %d", len(e.Totals))
	}
	// 1M in @ $1/M + 0.5M out @ $2/M = 1 + 1 = $2
	// 0.1M in @ $10/M + 0.01M out @ $30/M = 1 + 0.3 = $1.30
	if got := e.TotalUSD; got < 3.2999 || got > 3.3001 {
		t.Errorf("TotalUSD = %v, want 3.30", got)
	}
	if !e.Complete() {
		t.Errorf("everything was priced, so Complete() should be true (unpriced=%v)", e.Unpriced)
	}
}

func TestProject_AggregatesRepeatedCalls(t *testing.T) {
	var calls []Call
	for i := 0; i < 50; i++ {
		calls = append(calls, Call{Task: "triage", Model: "cheap", InputTokens: 1000, OutputTokens: 200})
	}
	e := Project(calls, table())

	if len(e.Totals) != 1 {
		t.Fatalf("50 calls on one (task,model) should aggregate to 1 row, got %d", len(e.Totals))
	}
	got := e.Totals[0]
	if got.Calls != 50 || got.InputTokens != 50_000 || got.OutputTokens != 10_000 {
		t.Errorf("aggregate wrong: %+v", got)
	}
}

func TestProject_UnpricedModelIsReportedNotGuessed(t *testing.T) {
	calls := []Call{
		{Task: "triage", Model: "who-knows", InputTokens: 1_000_000, OutputTokens: 1_000_000},
		{Task: "judge", Model: "cheap", InputTokens: 1_000_000, OutputTokens: 0},
	}
	e := Project(calls, table())

	if e.Complete() {
		t.Error("an unpriced model must make the estimate incomplete")
	}
	if len(e.Unpriced) != 1 || e.Unpriced[0] != "who-knows" {
		t.Errorf("Unpriced = %v, want [who-knows]", e.Unpriced)
	}
	// Only the priced call contributes dollars — no invented price for the other.
	if got := e.TotalUSD; got < 0.9999 || got > 1.0001 {
		t.Errorf("TotalUSD = %v, want 1.00 (the priced call only)", got)
	}
	// Tokens are still fully reported, since those we can compute.
	in, out := e.TotalTokens()
	if in != 2_000_000 || out != 1_000_000 {
		t.Errorf("tokens = %d/%d, want 2000000/1000000", in, out)
	}
}

func TestProject_ZeroPricedModelIsPricedNotUnpriced(t *testing.T) {
	// A self-hosted model declared free must count as priced, so --max-cost works.
	e := Project([]Call{{Task: "triage", Model: "free", InputTokens: 9e6, OutputTokens: 9e6}}, table())
	if !e.Complete() {
		t.Errorf("a 0-priced model is priced, not unpriced: %v", e.Unpriced)
	}
	if e.TotalUSD != 0 {
		t.Errorf("TotalUSD = %v, want 0", e.TotalUSD)
	}
}

func TestProject_DeterministicOrder(t *testing.T) {
	calls := []Call{
		{Task: "remediation", Model: "strong", InputTokens: 1},
		{Task: "triage", Model: "cheap", InputTokens: 1},
		{Task: "judge", Model: "strong", InputTokens: 1},
		{Task: "judge", Model: "cheap", InputTokens: 1},
	}
	want := []string{"judge/cheap", "judge/strong", "remediation/strong", "triage/cheap"}
	for i := 0; i < 10; i++ {
		var got []string
		for _, tt := range Project(calls, table()).Totals {
			got = append(got, tt.Task+"/"+tt.Model)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("run %d order = %v, want %v", i, got, want)
		}
	}
}

func TestProject_Empty(t *testing.T) {
	e := Project(nil, table())
	if len(e.Totals) != 0 || e.TotalUSD != 0 {
		t.Errorf("no calls should mean no totals and no cost: %+v", e)
	}
	if !e.Complete() {
		t.Error("an empty estimate is trivially complete")
	}
}

func TestTableFor_LookupFallbacks(t *testing.T) {
	tb := table()
	cases := []struct {
		model string
		want  bool
	}{
		{"cheap", true},
		{"CHEAP", true},                 // case-insensitive
		{"google/cheap", true},          // provider-qualified suffix
		{"publishers/x/cheap", true},    // deeper qualification
		{"cheaper", false},              // not a prefix match
		{"cheap/something-else", false}, // suffix is what matters, not prefix
	}
	for _, c := range cases {
		if _, ok := tb.For(c.model); ok != c.want {
			t.Errorf("For(%q) matched=%v, want %v", c.model, ok, c.want)
		}
	}
}

func TestAssignModels_UsesCallerRouting(t *testing.T) {
	calls := []Call{{Task: "triage"}, {Task: "judge"}, {Task: "remediation"}}
	routed := AssignModels(calls, func(task string) string {
		if task == "judge" {
			return "strong"
		}
		return "cheap"
	})
	if routed[0].Model != "cheap" || routed[1].Model != "strong" || routed[2].Model != "cheap" {
		t.Errorf("routing not applied: %+v", routed)
	}
	// The input slice must not be mutated.
	if calls[0].Model != "" {
		t.Error("AssignModels should not mutate its input")
	}
}

func TestTokens(t *testing.T) {
	if Tokens("") != 0 {
		t.Error("empty string is 0 tokens")
	}
	if got := Tokens("abcd"); got != 1 {
		t.Errorf("4 chars ≈ 1 token, got %d", got)
	}
	if got := Tokens("abcde"); got != 2 {
		t.Errorf("5 chars should round up to 2, got %d", got)
	}
	// Monotonic: more text is never fewer tokens.
	if Tokens(strings.Repeat("x", 1000)) <= Tokens(strings.Repeat("x", 100)) {
		t.Error("token estimate should grow with input length")
	}
}

func TestLoadTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prices.yaml")
	if err := os.WriteFile(path, []byte("models:\n  m1:\n    inputPerMTok: 1.5\n    outputPerMTok: 6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tb, err := LoadTable(path)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := tb.For("m1")
	if !ok || p.InputPerMTok != 1.5 || p.OutputPerMTok != 6 {
		t.Errorf("loaded price wrong: %+v ok=%v", p, ok)
	}
}

func TestLoadTable_RejectsNegativePrice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("models:\n  m1:\n    inputPerMTok: -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTable(path); err == nil {
		t.Error("a negative price should be rejected, not silently used")
	}
}

func TestLoadTable_MissingFile(t *testing.T) {
	if _, err := LoadTable(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("a missing price config should error")
	}
}

func TestWrite_ReportsTokensAndFlagsUnpriced(t *testing.T) {
	e := Project([]Call{
		{Task: "triage", Model: "mystery", InputTokens: 1234, OutputTokens: 250},
	}, table())
	e.Excluded = []string{"--review (one whole-repo call per scan)"}

	var b strings.Builder
	e.Write(&b)
	out := b.String()

	for _, want := range []string{"pre-flight", "no model has been called", "unpriced", "mystery", "1234", "--review", "approximation"} {
		if !strings.Contains(out, want) {
			t.Errorf("estimate output missing %q:\n%s", want, out)
		}
	}
}

func TestWrite_NoCallsPlanned(t *testing.T) {
	var b strings.Builder
	Project(nil, table()).Write(&b)
	if !strings.Contains(b.String(), "no LLM calls planned") {
		t.Errorf("want an explicit empty message, got:\n%s", b.String())
	}
}
