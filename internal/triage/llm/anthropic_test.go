package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMessages is a Messages API that streams the reply the test sets. It
// records each request body and its headers.
type fakeMessages struct {
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
	paths   []string
	// status, when not 200, is answered with an error object instead of a stream.
	status int
	// text is streamed as the answer; stop is the stop reason.
	text, stop string
	// overloaded answers this many requests with 529 before streaming.
	overloaded int
	// cut ends the stream before message_stop; midError sends an error event.
	cut, midError bool
}

func (f *fakeMessages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	f.headers = append(f.headers, r.Header.Clone())
	f.paths = append(f.paths, r.URL.Path)
	status, text, stop := f.status, f.text, f.stop
	if f.overloaded > 0 {
		f.overloaded--
		status = 529
	}
	cut, midError := f.cut, f.midError
	f.mu.Unlock()

	if status != 0 && status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
		return
	}
	if midError {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"bad\"}}\n\n")
		return
	}
	if stop == "" {
		stop = "end_turn"
	}
	w.Header().Set("Content-Type", "text/event-stream")
	event := func(name, data string) { fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data) }
	textJSON, _ := json.Marshal(text)
	event("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":1,"cache_creation_input_tokens":20,"cache_read_input_tokens":300}}}`)
	// A thinking block comes first on current models; it is not part of the answer.
	event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`)
	event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"weighing the evidence"}}`)
	event("content_block_stop", `{"type":"content_block_stop","index":0}`)
	event("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`)
	event("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":%s}}`, textJSON))
	event("content_block_stop", `{"type":"content_block_stop","index":1}`)
	if cut {
		return // the connection ends here, without message_stop
	}
	event("message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%q,"stop_sequence":null},"usage":{"output_tokens":42}}`, stop))
	event("message_stop", `{"type":"message_stop"}`)
}

func newFakeAnthropic(t *testing.T, f *fakeMessages, o Options) *AnthropicClient {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := NewAnthropic(srv.URL+"/v1", "sk-ant-test-key", "claude-test", o)
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestAnthropic_Complete(t *testing.T) {
	f := &fakeMessages{text: `{"verdict":"true_positive"}`}
	c := newFakeAnthropic(t, f, Options{})
	resp, err := c.Complete(context.Background(), Request{
		Messages: []Message{
			{Role: RoleSystem, Content: "You review security findings."},
			{Role: RoleUser, Content: "Is this exploitable?"},
		},
		Temperature: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != `{"verdict":"true_positive"}` {
		t.Errorf("content = %q (the thinking block must not be part of it)", resp.Content)
	}
	if resp.Truncated {
		t.Error("an end_turn reply was reported truncated")
	}
	// Cached and uncached input both count as prompt tokens.
	if resp.Usage.PromptTokens != 420 || resp.Usage.CompletionTokens != 42 || resp.Usage.TotalTokens != 462 {
		t.Errorf("usage = %+v", resp.Usage)
	}

	if len(f.bodies) != 1 {
		t.Fatalf("%d requests, want 1", len(f.bodies))
	}
	if f.paths[0] != "/v1/messages" {
		t.Errorf("path = %s, want /v1/messages (the /v1 of the preset must not be doubled)", f.paths[0])
	}
	if got := f.headers[0].Get("X-Api-Key"); got != "sk-ant-test-key" {
		t.Errorf("x-api-key = %q", got)
	}
	if got := f.headers[0].Get("Anthropic-Version"); got != "2023-06-01" {
		t.Errorf("anthropic-version = %q", got)
	}
	body := f.bodies[0]
	if body["model"] != "claude-test" || body["max_tokens"] != float64(anthropicDefaultMaxTokens) || body["stream"] != true {
		t.Errorf("model/max_tokens/stream = %v/%v/%v", body["model"], body["max_tokens"], body["stream"])
	}
	if _, ok := body["temperature"]; ok {
		t.Error("temperature was sent; current Claude models reject it")
	}
	system, _ := body["system"].([]any)
	if len(system) != 1 {
		t.Fatalf("system = %v, want the system prompt as one block", body["system"])
	}
	if sb, _ := system[0].(map[string]any); sb["text"] != "You review security findings." || sb["cache_control"] == nil {
		t.Errorf("system block = %v, want the prompt with cache_control", sb)
	}
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Errorf("messages = %v, want the one user message (system goes in its own field)", msgs)
	}
}

func TestAnthropic_SchemaBecomesStructuredOutput(t *testing.T) {
	f := &fakeMessages{text: `{}`}
	c := newFakeAnthropic(t, f, Options{MaxTokens: 2048})
	schema := &Schema{Name: "verdict", Definition: json.RawMessage(`{"type":"object","properties":{"verdict":{"type":"string"}},"required":["verdict"],"additionalProperties":false}`)}
	if _, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}, Schema: schema}); err != nil {
		t.Fatal(err)
	}
	body := f.bodies[0]
	if body["max_tokens"] != float64(2048) {
		t.Errorf("max_tokens = %v, want ACHILLES_LLM_MAX_TOKENS", body["max_tokens"])
	}
	oc, _ := body["output_config"].(map[string]any)
	format, _ := oc["format"].(map[string]any)
	if format["type"] != "json_schema" {
		t.Fatalf("output_config = %v", body["output_config"])
	}
	if s, _ := format["schema"].(map[string]any); s["type"] != "object" || s["required"] == nil {
		t.Errorf("schema = %v", format["schema"])
	}
}

func TestAnthropic_MaxTokensStopIsTruncated(t *testing.T) {
	f := &fakeMessages{text: `{"verdict":"tr`, stop: "max_tokens"}
	resp, err := newFakeAnthropic(t, f, Options{}).Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated {
		t.Error("a max_tokens stop was not reported as truncated")
	}
}

func TestAnthropic_RefusalIsAnError(t *testing.T) {
	f := &fakeMessages{text: "", stop: "refusal"}
	_, err := newFakeAnthropic(t, f, Options{}).Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("err = %v, want a refusal error (an empty answer must not read as a verdict)", err)
	}
}

// A rejected key surfaces as the HTTPError the triage loop stops on, after no
// retries (401 is not retried).
func TestAnthropic_AuthErrorIsAnHTTPError(t *testing.T) {
	f := &fakeMessages{status: http.StatusUnauthorized}
	_, err := newFakeAnthropic(t, f, Options{}).Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v (%T), want *HTTPError 401", err, err)
	}
	if len(f.bodies) != 1 {
		t.Errorf("%d requests for a 401, want 1", len(f.bodies))
	}
}

// Anthropic's own environment variables (ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY,
// ANTHROPIC_AUTH_TOKEN) must not redirect the request or add a credential.
func TestAnthropic_IgnoresTheAnthropicEnvironment(t *testing.T) {
	stray := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request went to ANTHROPIC_BASE_URL: %s", r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(stray.Close)
	t.Setenv("ANTHROPIC_BASE_URL", stray.URL)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-from-the-environment")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "token-from-the-environment")
	f := &fakeMessages{text: "ok"}
	if _, err := newFakeAnthropic(t, f, Options{}).Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if got := f.headers[0].Get("X-Api-Key"); got != "sk-ant-test-key" {
		t.Errorf("x-api-key = %q, want the key Achilles passed", got)
	}
	if got := f.headers[0].Get("Authorization"); got != "" {
		t.Errorf("a second credential from the environment was sent: Authorization = %q", got)
	}
}

// Overload (529) and a stream that ends early are retried; an error event that
// is not overload is not.
func TestAnthropic_Retries(t *testing.T) {
	ctx := context.Background()
	msgs := []Message{{Role: RoleUser, Content: "x"}}

	f := &fakeMessages{text: "ok", overloaded: 2}
	resp, err := newFakeAnthropic(t, f, Options{}).Complete(ctx, Request{Messages: msgs})
	if err != nil || resp.Content != "ok" || len(f.bodies) != 3 {
		t.Errorf("after two 529s: content %q, err %v, %d requests; want ok after 3", resp.Content, err, len(f.bodies))
	}

	f = &fakeMessages{text: "ok", overloaded: 5}
	_, err = newFakeAnthropic(t, f, Options{MaxRetries: 1}).Complete(ctx, Request{Messages: msgs})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 529 || len(f.bodies) != 2 {
		t.Errorf("past the retry limit: err %v, %d requests; want 529 after 2", err, len(f.bodies))
	}

	f = &fakeMessages{text: "partial", cut: true}
	_, err = newFakeAnthropic(t, f, Options{}).Complete(ctx, Request{Messages: msgs})
	if err == nil || !strings.Contains(err.Error(), "message_stop") || len(f.bodies) != 3 {
		t.Errorf("cut stream: err %v, %d requests; want a cut-off error after 3 tries (a partial answer is never used)", err, len(f.bodies))
	}

	f = &fakeMessages{midError: true}
	_, err = newFakeAnthropic(t, f, Options{}).Complete(ctx, Request{Messages: msgs})
	if err == nil || !strings.Contains(err.Error(), "invalid_request_error") || len(f.bodies) != 1 {
		t.Errorf("error event: err %v, %d requests; want the error, not retried", err, len(f.bodies))
	}
}

func TestAnthropic_HeadersAndAuthNone(t *testing.T) {
	f := &fakeMessages{text: "ok"}
	c := newFakeAnthropic(t, f, Options{AuthHeader: AuthNone, Headers: map[string]string{"X-Gateway-Token": "gw"}})
	if _, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if got := f.headers[0].Get("X-Api-Key"); got != "" {
		t.Errorf("--llm-auth none sent x-api-key %q", got)
	}
	if got := f.headers[0].Get("X-Gateway-Token"); got != "gw" {
		t.Errorf("ACHILLES_LLM_HEADERS not sent: %q", got)
	}
}

func TestNewFactory_RoutesAnthropicToTheNativeClient(t *testing.T) {
	t.Setenv("ACHILLES_LLM_API_KEY", "k")
	factory, err := NewFactory(ModeKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := factory(Providers["anthropic"], "claude-test").(*AnthropicClient); !ok {
		t.Error("the anthropic preset did not get the native client")
	}
	if _, ok := factory("https://api.anthropic.com", "claude-test").(*AnthropicClient); !ok {
		t.Error("https://api.anthropic.com did not get the native client")
	}
	if _, ok := factory("https://openrouter.ai/api/v1", "anthropic/claude").(*OpenAIClient); !ok {
		t.Error("OpenRouter must stay on the OpenAI-compatible client")
	}
}
