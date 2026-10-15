// Package llm is Achilles's LLM client. The interface is deliberately narrow (one
// Complete method): any endpoint speaking the OpenAI Chat Completions schema works
// (OpenAI, Azure, vLLM/Ollama, gateways) through OpenAIClient, and Anthropic's
// Messages API through AnthropicClient, without touching triage logic (DESIGN.md §7).
package llm

import (
	"context"
	"encoding/json"
)

// Roles for chat messages.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message is one chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Schema is a JSON Schema for strict structured output.
type Schema struct {
	Name       string
	Definition json.RawMessage
}

// Request is a completion request. Model is optional; when empty the client's
// configured default model is used (this is what enables per-task routing).
type Request struct {
	Model       string
	Messages    []Message
	Temperature float64
	// JSON requests a JSON-object response where the endpoint supports it.
	JSON bool
	// Schema, when set, requests strict json_schema output. Endpoints that don't
	// support it will error, which callers can catch and retry with JSON=true.
	Schema *Schema
}

// Usage is the token accounting an endpoint reports for a completion. Zero when
// the endpoint omits it.
type Usage struct {
	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`
	TotalTokens      int `json:"totalTokens"`
}

// Add accumulates another usage into this one.
func (u *Usage) Add(o Usage) {
	u.PromptTokens += o.PromptTokens
	u.CompletionTokens += o.CompletionTokens
	u.TotalTokens += o.TotalTokens
}

// Response is the model's reply text.
type Response struct {
	Content string
	Model   string
	Usage   Usage
	// Truncated reports that the model stopped because it reached its output
	// limit (finish_reason "length"), not because it had finished. The content is
	// then cut off mid-answer; for JSON that means it will not parse, and asking
	// again with the same limit cuts it off again.
	Truncated bool
}

// Client completes a chat request.
type Client interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// Router maps a task name (e.g. "triage", "judge", "remediation") to a Client,
// enabling model routing — a cheap model for triage, a stronger one for the
// judge/remediation. Unset tasks fall back to the default client.
type Router struct {
	byTask map[string]Client
	def    Client
}

// NewRouter creates a router with a default client used for any unrouted task.
func NewRouter(def Client) *Router {
	return &Router{byTask: map[string]Client{}, def: def}
}

// Set routes a task to a specific client.
func (r *Router) Set(task string, c Client) *Router {
	r.byTask[task] = c
	return r
}

// For returns the client for a task, or the default.
func (r *Router) For(task string) Client {
	if c, ok := r.byTask[task]; ok {
		return c
	}
	return r.def
}

// TaskModel is a per-task model override (from a model-routing config): which
// model to use for a task, and optionally which endpoint.
type TaskModel struct {
	Model   string
	BaseURL string // empty → the run's default base URL
}

// BuildRouter builds a Router routing each named task to a client made by
// factory(baseURL, model). Tasks with an empty Model are skipped (they fall
// back to def); an empty per-task BaseURL uses defaultBaseURL. factory keeps
// this package free of any concrete transport/credential detail, which also
// makes routing unit-testable.
func BuildRouter(def Client, tasks map[string]TaskModel, defaultBaseURL string, factory func(baseURL, model string) Client) *Router {
	r := NewRouter(def)
	for task, tm := range tasks {
		if tm.Model == "" {
			continue
		}
		base := tm.BaseURL
		if base == "" {
			base = defaultBaseURL
		}
		r.Set(task, factory(base, tm.Model))
	}
	return r
}
