// Package llmtest provides a fake LLM client for hermetic tests. It lives in its
// own package (imported only by tests) so it never enters the production binary.
package llmtest

import (
	"context"
	"sync"

	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// Fake returns scripted responses in order and records every request it saw.
type Fake struct {
	Responses []string // returned in sequence; the last repeats once exhausted
	Err       error    // if set, Complete always returns it
	FirstErr  error    // if set, Complete returns it on the FIRST call only (retry-fallback tests)
	Calls     []llm.Request
	i         int
	mu        sync.Mutex // findings are triaged concurrently
}

// Complete implements llm.Client.
func (f *Fake) Complete(_ context.Context, req llm.Request) (llm.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, req)
	if f.Err != nil {
		return llm.Response{}, f.Err
	}
	if f.FirstErr != nil && len(f.Calls) == 1 {
		return llm.Response{}, f.FirstErr
	}
	if len(f.Responses) == 0 {
		return llm.Response{}, nil
	}
	idx := f.i
	if idx >= len(f.Responses) {
		idx = len(f.Responses) - 1
	} else {
		f.i++
	}
	return llm.Response{Content: f.Responses[idx], Model: "fake"}, nil
}
