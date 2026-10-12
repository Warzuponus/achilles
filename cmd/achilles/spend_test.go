package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

type countingClient struct {
	calls int
	usage llm.Usage
}

func (c *countingClient) Complete(context.Context, llm.Request) (llm.Response, error) {
	c.calls++
	return llm.Response{Content: "{}", Usage: c.usage}, nil
}

// Prices chosen so the arithmetic is exact: 10 prompt + 5 completion tokens cost
// one cent and a half.
var testPrices = cost.Table{Models: map[string]cost.Price{"m": {InputPerMTok: 1000, OutputPerMTok: 1000}}}

func TestSpendMeter_StopsNewCallsAtTheCap(t *testing.T) {
	m := newSpendMeter(0.04, testPrices)
	inner := &countingClient{usage: llm.Usage{PromptTokens: 10, CompletionTokens: 5}}
	c := metered(func(string, string) llm.Client { return inner }, m)("https://x/v1", "m")

	var refused error
	for i := 0; i < 10; i++ {
		if _, err := c.Complete(context.Background(), llm.Request{}); err != nil {
			refused = err
			break
		}
	}
	// $0.015 a call: after two calls $0.03 is under the cap, so a third starts and
	// takes it to $0.045. The fourth is refused without reaching the endpoint.
	if inner.calls != 3 {
		t.Errorf("made %d calls, want 3", inner.calls)
	}
	if !errors.Is(refused, errCostCap) {
		t.Fatalf("err = %v, want the cost cap", refused)
	}
	if !m.reached() || !strings.Contains(m.summary(), "$0.0450 of $0.0400") || !strings.Contains(m.summary(), "NOT made") {
		t.Errorf("summary = %q", m.summary())
	}
}

// A model with no price cannot be counted, so with a cap set it is not called at
// all: a cap that silently did not apply to one model would not be a cap.
func TestSpendMeter_RefusesAModelItCannotPrice(t *testing.T) {
	m := newSpendMeter(100, testPrices)
	inner := &countingClient{}
	c := metered(func(string, string) llm.Client { return inner }, m)("https://x/v1", "m")

	_, err := c.Complete(context.Background(), llm.Request{Model: "some-other-model"})
	if !errors.Is(err, errCostCap) || !strings.Contains(err.Error(), "no price") || inner.calls != 0 {
		t.Errorf("err = %v, calls = %d: an unpriced model must be refused before the call", err, inner.calls)
	}
	if !strings.Contains(m.summary(), "some-other-model") {
		t.Errorf("summary must name the unpriced model: %q", m.summary())
	}
	// With no cap, nothing is wrapped and nothing is refused.
	plain := metered(func(string, string) llm.Client { return inner }, nil)("https://x/v1", "m")
	if _, err := plain.Complete(context.Background(), llm.Request{Model: "some-other-model"}); err != nil || inner.calls != 1 {
		t.Errorf("no meter: err = %v, calls = %d", err, inner.calls)
	}
}

// End to end through the AI review: --max-cost used to be checked once, against an
// estimate, before anything ran. Now the review stops when the money is spent, and
// what it did not reach is reported as not reviewed rather than as failed.
func TestRunTriage_StopsAtTheCostCap(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1", "real-2", "real-3", "real-4", "real-5", "real-6")
	runMeter = newSpendMeter(0.07, testPrices) // each call costs $0.015: the fifth passes the cap
	t.Cleanup(func() { runMeter = nil })

	_, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", concurrency: 1})
	if err != nil {
		t.Fatalf("reaching the cap is not an error of the review: %v", err)
	}
	if n := fe.calls.Load(); n != 5 {
		t.Errorf("the endpoint was called %d times, want 5 (the sixth call must not be made)", n)
	}
	// The fifth call was the third finding's first pass; its adversarial pass was
	// refused. A verdict nobody tried to refute is not a review, so that finding
	// counts as not reached, like the three after it.
	st := scan.Triage
	if st == nil || st.Triaged != 2 || st.Failed != 0 || st.Skipped != 4 {
		t.Errorf("coverage = %+v, want 2 reviewed, 0 failed, 4 not reached", st)
	}
	if st != nil && st.Aborted != "" {
		t.Errorf("a cost cap is not an aborted review: %q", st.Aborted)
	}
	if len(scan.Dismissed) != 0 || len(scan.Findings) != 6 {
		t.Errorf("unreviewed findings must stay in the report: %d kept, %d dismissed", len(scan.Findings), len(scan.Dismissed))
	}
}
