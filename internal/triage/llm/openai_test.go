package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIClient_Complete(t *testing.T) {
	var gotBody chatRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path: got %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"m","choices":[{"message":{"role":"assistant","content":"hello"}}]}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "sk-test", "gpt-x")
	resp, err := c.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
		JSON:     true,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "hello" {
		t.Errorf("content: got %q", resp.Content)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("auth header: got %q", gotAuth)
	}
	if gotBody.Model != "gpt-x" {
		t.Errorf("model: got %q", gotBody.Model)
	}
	if gotBody.ResponseFormat == nil || gotBody.ResponseFormat.Type != "json_object" {
		t.Errorf("JSON response_format not set: %+v", gotBody.ResponseFormat)
	}
}

func TestOpenAIClient_RequestModelOverridesDefault(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body chatRequest
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		gotModel = body.Model
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "", "default-model")
	_, err := c.Complete(context.Background(), Request{Model: "override-model", Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotModel != "override-model" {
		t.Errorf("per-request model should win: got %q", gotModel)
	}
}

func TestOpenAIClient_JSONSchemaFormat(t *testing.T) {
	var gotFormat *respFormat
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body chatRequest
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		gotFormat = body.ResponseFormat
		io.WriteString(w, `{"choices":[{"message":{"content":"{}"}}]}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "", "m")
	_, err := c.Complete(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		Schema:   &Schema{Name: "verdict", Definition: json.RawMessage(`{"type":"object"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotFormat == nil || gotFormat.Type != "json_schema" {
		t.Fatalf("want json_schema response_format, got %+v", gotFormat)
	}
	if gotFormat.JSONSchema == nil || gotFormat.JSONSchema.Name != "verdict" || !gotFormat.JSONSchema.Strict {
		t.Errorf("json_schema block wrong: %+v", gotFormat.JSONSchema)
	}
}

func TestOpenAIClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"bad key"}}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "nope", "m")
	if _, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err == nil {
		t.Error("want error on HTTP 401")
	}
}

func TestRouter(t *testing.T) {
	def := &countClient{}
	judge := &countClient{}
	r := NewRouter(def).Set("judge", judge)

	r.For("triage").Complete(context.Background(), Request{}) // -> default
	r.For("judge").Complete(context.Background(), Request{})  // -> judge

	if def.n != 1 || judge.n != 1 {
		t.Errorf("routing wrong: default=%d judge=%d", def.n, judge.n)
	}
}

type countClient struct{ n int }

func (c *countClient) Complete(context.Context, Request) (Response, error) {
	c.n++
	return Response{}, nil
}
