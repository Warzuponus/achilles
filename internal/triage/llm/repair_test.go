package llm

import (
	"context"
	"testing"
)

// localFake is a minimal Client for this package's tests (the shared llmtest.Fake
// lives in a subpackage that imports llm, so it can't be used here).
type localFake struct {
	responses []string
	calls     []Request
	i         int
}

func (f *localFake) Complete(_ context.Context, req Request) (Response, error) {
	f.calls = append(f.calls, req)
	idx := f.i
	f.i++
	if idx >= len(f.responses) {
		idx = len(f.responses) - 1
	}
	return Response{Content: f.responses[idx], Model: "fake"}, nil
}

var testSchema = &Schema{Name: "t", Definition: []byte(`{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"]}`)}

func TestCompleteAndDecode_CleanFirstTry(t *testing.T) {
	fake := &localFake{responses: []string{`{"summary":"ok"}`}}
	var out struct {
		Summary string `json:"summary"`
	}
	resp, err := CompleteAndDecode(context.Background(), fake, nil, testSchema, &out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary != "ok" {
		t.Errorf("summary=%q", out.Summary)
	}
	if len(fake.calls) != 1 {
		t.Errorf("expected 1 call (no repair), got %d", len(fake.calls))
	}
	_ = resp
}

func TestCompleteAndDecode_RepairsShapeDrift(t *testing.T) {
	// First response drifts (summary is an object, not a string) — as open models
	// do on nested schemas; the repair round-trip returns valid JSON.
	fake := &localFake{responses: []string{
		`{"summary":{"text":"nested wrongly"}}`,
		"```json\n{\"summary\":\"fixed\"}\n```", // repair reply, fenced, to also exercise ExtractJSON
	}}
	var out struct {
		Summary string `json:"summary"`
	}
	resp, err := CompleteAndDecode(context.Background(), fake, nil, testSchema, &out, nil)
	if err != nil {
		t.Fatalf("expected repair to succeed: %v", err)
	}
	if out.Summary != "fixed" {
		t.Errorf("summary=%q, want fixed", out.Summary)
	}
	if len(fake.calls) != 2 {
		t.Errorf("expected 2 calls (initial + repair), got %d", len(fake.calls))
	}
	// The repair prompt must echo the decode error + schema so the model can fix it.
	last := fake.calls[1].Messages
	if last[len(last)-1].Role != RoleUser {
		t.Error("repair should end with a user instruction")
	}
	_ = resp
}

func TestCompleteAndDecode_RepairAlsoFails(t *testing.T) {
	fake := &localFake{responses: []string{`{"summary":{"x":1}}`, `still not valid`}}
	var out struct {
		Summary string `json:"summary"`
	}
	if _, err := CompleteAndDecode(context.Background(), fake, nil, testSchema, &out, nil); err == nil {
		t.Error("expected an error when repair also fails")
	}
}
