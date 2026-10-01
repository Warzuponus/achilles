package llm

import (
	"context"
	"testing"
)

// tagClient is a fake Client that just records how it was built, so we can
// assert which client a task routed to.
type tagClient struct{ baseURL, model string }

func (tagClient) Complete(context.Context, Request) (Response, error) { return Response{}, nil }

func TestBuildRouter(t *testing.T) {
	def := tagClient{model: "default"}
	factory := func(baseURL, model string) Client { return tagClient{baseURL: baseURL, model: model} }

	tasks := map[string]TaskModel{
		"triage": {Model: "cheap"},                          // uses default base URL
		"judge":  {Model: "strong", BaseURL: "https://alt"}, // per-task endpoint
		"skip":   {Model: ""},                               // empty model → skipped
	}
	r := BuildRouter(def, tasks, "https://def", factory)

	got := r.For("triage").(tagClient)
	if got.model != "cheap" || got.baseURL != "https://def" {
		t.Errorf("triage: got %+v, want model=cheap baseURL=https://def", got)
	}
	if j := r.For("judge").(tagClient); j.model != "strong" || j.baseURL != "https://alt" {
		t.Errorf("judge: got %+v, want model=strong baseURL=https://alt", j)
	}
	// Empty-model task and any unrouted task fall back to the default client.
	if s := r.For("skip").(tagClient); s.model != "default" {
		t.Errorf("empty-model task should fall back to default, got %+v", s)
	}
	if u := r.For("remediation").(tagClient); u.model != "default" {
		t.Errorf("unrouted task should fall back to default, got %+v", u)
	}
}
