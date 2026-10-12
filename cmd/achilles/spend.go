package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// errCostCap is returned for a model call that --max-cost does not allow: the
// run's counted spend has reached the cap, or the model has no price and so
// cannot be counted. It is not a failure of the endpoint, and callers treat the
// work it would have done as "not reached".
var errCostCap = errors.New("--max-cost")

// spendMeter enforces --max-cost while a run is under way.
//
// The pre-flight estimate (cost.Project) covers the per-finding review only, and
// only before it starts. It says nothing about deep verification, the repo
// review, the dependency advisor, the threat model or research, and nothing about
// what a run actually spends: `--max-cost 1 --deep-verify 50` could spend many
// times the cap. The meter sits under every chat client a run creates, prices
// each reply's reported token usage, and refuses to start another call once the
// total has reached the cap.
//
// It stops new calls; calls already in flight finish, so the total can pass the
// cap by at most what --llm-concurrency calls cost. Embedding calls for --rag go
// through a different client and are not counted.
type spendMeter struct {
	mu       sync.Mutex
	cap      float64
	prices   cost.Table
	spent    float64
	calls    int
	refused  int
	unpriced map[string]bool
}

// runMeter is the current run's meter; nil when --max-cost is not set. It is
// package-level for the reason llmAuthMode is: every LLM entry point builds its
// clients through newLLMFactory.
var runMeter *spendMeter

func newSpendMeter(capUSD float64, prices cost.Table) *spendMeter {
	return &spendMeter{cap: capUSD, prices: prices, unpriced: map[string]bool{}}
}

// allow reports whether a call to model may start, and the model's price.
func (m *spendMeter) allow(model string) (cost.Price, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	price, ok := m.prices.For(model)
	if !ok {
		m.refused++
		m.unpriced[model] = true
		return cost.Price{}, fmt.Errorf("%w cannot be enforced for model %q: it has no price in --price-config, so the call was not made", errCostCap, model)
	}
	if m.spent >= m.cap {
		m.refused++
		return cost.Price{}, fmt.Errorf("%w reached ($%.4f spent of $%.4f): the call was not made", errCostCap, m.spent, m.cap)
	}
	return price, nil
}

func (m *spendMeter) add(p cost.Price, u llm.Usage) {
	m.mu.Lock()
	m.calls++
	m.spent += float64(u.PromptTokens)/1e6*p.InputPerMTok + float64(u.CompletionTokens)/1e6*p.OutputPerMTok
	m.mu.Unlock()
}

// reached reports whether the cap has stopped, or would now stop, a call.
func (m *spendMeter) reached() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refused > 0 || m.spent >= m.cap
}

// summary is one line on what was spent and what the cap prevented.
func (m *spendMeter) summary() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := fmt.Sprintf("achilles: LLM spend counted against --max-cost: $%.4f of $%.4f over %d call(s)", m.spent, m.cap, m.calls)
	if m.refused > 0 {
		s += fmt.Sprintf("; %d further call(s) were NOT made", m.refused)
	}
	if len(m.unpriced) > 0 {
		names := make([]string, 0, len(m.unpriced))
		for n := range m.unpriced {
			names = append(names, n)
		}
		sort.Strings(names)
		s += fmt.Sprintf(" (no price for: %s)", strings.Join(names, ", "))
	}
	return s
}

// meteredClient is a chat client whose calls are counted against the cap.
type meteredClient struct {
	inner llm.Client
	model string // the client's default model, used when a request names none
	meter *spendMeter
}

func (c meteredClient) Complete(ctx context.Context, req llm.Request) (llm.Response, error) {
	model := req.Model
	if model == "" {
		model = c.model
	}
	price, err := c.meter.allow(model)
	if err != nil {
		return llm.Response{}, err
	}
	resp, err := c.inner.Complete(ctx, req)
	c.meter.add(price, resp.Usage) // a failed call may still report tokens it used
	return resp, err
}

// metered wraps a client factory so that every client it builds is counted
// against m. A nil meter returns the factory unchanged.
func metered(factory func(baseURL, model string) llm.Client, m *spendMeter) func(string, string) llm.Client {
	if m == nil {
		return factory
	}
	return func(baseURL, model string) llm.Client {
		return meteredClient{inner: factory(baseURL, model), model: model, meter: m}
	}
}
