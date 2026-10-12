package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// capture records the last request a fake server saw.
type capture struct {
	path   string
	query  url.Values
	header http.Header
	raw    map[string]any
	n      int32
}

func fakeServer(t *testing.T, c *capture, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c.n, 1)
		c.path, c.query, c.header = r.URL.Path, r.URL.Query(), r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		c.raw = map[string]any{}
		_ = json.Unmarshal(b, &c.raw)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const okReply = `{"model":"m","choices":[{"message":{"content":"hi"}}]}`

var userMsg = []Message{{Role: RoleUser, Content: "x"}}

func TestAzureStyle_APIKeyHeaderAndQuery(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	cl := NewOpenAI(srv.URL+"/openai/deployments/gpt4o", "az-key", "gpt4o").Apply(Options{
		AuthHeader: AuthAPIKey,
		Query:      url.Values{"api-version": {"2024-10-21"}},
	})
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if c.path != "/openai/deployments/gpt4o/chat/completions" {
		t.Errorf("path = %q", c.path)
	}
	if c.query.Get("api-version") != "2024-10-21" {
		t.Errorf("query = %v", c.query)
	}
	if c.header.Get("api-key") != "az-key" {
		t.Errorf("api-key header = %q", c.header.Get("api-key"))
	}
	if c.header.Get("Authorization") != "" {
		t.Errorf("Authorization must not be sent in api-key mode, got %q", c.header.Get("Authorization"))
	}
}

func TestAuthNone_SendsNoCredentialButKeepsCustomHeaders(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	cl := NewOpenAI(srv.URL, "ignored", "m").Apply(Options{
		AuthHeader: AuthNone,
		Headers:    map[string]string{"HTTP-Referer": "https://example.com", "X-Title": "achilles"},
	})
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if c.header.Get("Authorization") != "" || c.header.Get("api-key") != "" {
		t.Errorf("credential leaked in none mode: %v", c.header)
	}
	if c.header.Get("HTTP-Referer") != "https://example.com" || c.header.Get("X-Title") != "achilles" {
		t.Errorf("custom headers missing: %v", c.header)
	}
}

func TestKeylessLocalRuntime_NoAuthorizationHeader(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	if _, err := NewOpenAI(srv.URL, "", "llama3").Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if c.header.Get("Authorization") != "" {
		t.Errorf("empty key must send no Authorization header, got %q", c.header.Get("Authorization"))
	}
}

func TestTemperature_SentByDefault_OmittedForReasoningModels(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	cl := NewOpenAI(srv.URL, "", "m")
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if v, ok := c.raw["temperature"]; !ok || v.(float64) != 0 {
		t.Errorf("default must send temperature:0, got %v (present=%v)", v, ok)
	}
	cl.Apply(Options{OmitTemperature: true})
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.raw["temperature"]; ok {
		t.Errorf("temperature must be omitted for reasoning models: %v", c.raw)
	}
}

func TestMaxTokens_ParamNameIsConfigurable(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	cl := NewOpenAI(srv.URL, "", "m").Apply(Options{MaxTokens: 512})
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if c.raw["max_tokens"] != float64(512) || c.raw["max_completion_tokens"] != nil {
		t.Errorf("want max_tokens only: %v", c.raw)
	}
	cl.Apply(Options{MaxTokens: 512, MaxTokensParam: "max_completion_tokens"})
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if c.raw["max_completion_tokens"] != float64(512) || c.raw["max_tokens"] != nil {
		t.Errorf("want max_completion_tokens only: %v", c.raw)
	}
}

func TestReasoningContentFallback(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, `{"choices":[{"message":{"content":"","reasoning_content":"{\"a\":1}"}}]}`)
	resp, err := NewOpenAI(srv.URL, "", "m").Complete(context.Background(), Request{Messages: userMsg})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != `{"a":1}` {
		t.Errorf("content = %q", resp.Content)
	}
}

// retryServer replies with each status in order, then 200.
func retryServer(t *testing.T, statuses []int, retryAfter string) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt32(&n, 1)) - 1
		if i < len(statuses) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			http.Error(w, "nope", statuses[i])
			return
		}
		io.WriteString(w, okReply)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func noSleep(waits *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		return nil
	}
}

func TestRetry_429HonorsRetryAfterThenSucceeds(t *testing.T) {
	srv, n := retryServer(t, []int{429, 503}, "3")
	cl := NewOpenAI(srv.URL, "", "m")
	var waits []time.Duration
	cl.sleep = noSleep(&waits)
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatal(err)
	}
	if *n != 3 {
		t.Errorf("calls = %d, want 3", *n)
	}
	if len(waits) != 2 || waits[0] != 3*time.Second {
		t.Errorf("waits = %v, want Retry-After (3s) first", waits)
	}
}

func TestRetry_BackoffGrowsAndIsCapped(t *testing.T) {
	if backoff(0, 0) != time.Second || backoff(1, 0) != 2*time.Second || backoff(2, 0) != 4*time.Second {
		t.Error("exponential backoff expected")
	}
	if backoff(0, time.Hour) != maxBackoff {
		t.Errorf("hostile Retry-After must be capped, got %v", backoff(0, time.Hour))
	}
}

func TestRetry_ExhaustedReturnsHTTPError(t *testing.T) {
	srv, n := retryServer(t, []int{429, 429, 429, 429}, "")
	cl := NewOpenAI(srv.URL, "", "m")
	var waits []time.Duration
	cl.sleep = noSleep(&waits)
	_, err := cl.Complete(context.Background(), Request{Messages: userMsg})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 429 {
		t.Fatalf("err = %v, want HTTPError 429", err)
	}
	if *n != int32(defaultRetries+1) {
		t.Errorf("calls = %d, want %d", *n, defaultRetries+1)
	}
}

func TestRetry_NotForClientErrorsOrWhenDisabled(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		opts   Options
	}{
		"401 is not transient":    {401, Options{}},
		"400 is not transient":    {400, Options{}},
		"retries can be disabled": {429, Options{MaxRetries: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			srv, n := retryServer(t, []int{tc.status, tc.status, tc.status}, "")
			cl := NewOpenAI(srv.URL, "", "m").Apply(tc.opts)
			cl.sleep = func(context.Context, time.Duration) error { t.Error("must not sleep"); return nil }
			if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err == nil {
				t.Fatal("want error")
			}
			if *n != 1 {
				t.Errorf("calls = %d, want 1", *n)
			}
		})
	}
}

func TestRetry_StopsWhenContextCancelledDuringWait(t *testing.T) {
	srv, _ := retryServer(t, []int{429, 429, 429}, "")
	cl := NewOpenAI(srv.URL, "", "m")
	ctx, cancel := context.WithCancel(context.Background())
	cl.sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	if _, err := cl.Complete(ctx, Request{Messages: userMsg}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// --- strict-schema compatibility -------------------------------------------

func TestStrictCompatible(t *testing.T) {
	cases := map[string]struct {
		schema string
		want   bool
	}{
		"all required, closed": {`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"],"additionalProperties":false}`, true},
		// Our verdict schema shape: an optional property (suggestedFix) — OpenAI strict mode answers 400.
		"optional property": {`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a"],"additionalProperties":false}`, false},
		"open object":       {`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}`, false},
		"nested optional":   {`{"type":"object","properties":{"a":{"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false}},"required":["a"],"additionalProperties":false}`, false},
		"nested ok":         {`{"type":"object","properties":{"a":{"type":"object","properties":{"x":{"type":"string"}},"required":["x"],"additionalProperties":false}},"required":["a"],"additionalProperties":false}`, true},
		"not json":          {`{`, false},
	}
	for name, tc := range cases {
		if got := strictCompatible(json.RawMessage(tc.schema)); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestSchemaRequest_StrictOnlyWhenCompatible(t *testing.T) {
	var c capture
	srv := fakeServer(t, &c, okReply)
	cl := NewOpenAI(srv.URL, "", "m")
	strictOf := func(def string) any {
		_, err := cl.Complete(context.Background(), Request{Messages: userMsg, Schema: &Schema{Name: "s", Definition: json.RawMessage(def)}})
		if err != nil {
			t.Fatal(err)
		}
		return c.raw["response_format"].(map[string]any)["json_schema"].(map[string]any)["strict"]
	}
	if strictOf(`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"],"additionalProperties":false}`) != true {
		t.Error("compatible schema should be sent strict")
	}
	if strictOf(`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a"],"additionalProperties":false}`) != nil {
		t.Error("schema with optional fields must not be sent strict")
	}
}

// --- CompleteJSON fallback gating ------------------------------------------

type scriptedClient struct {
	errs  []error
	calls []Request
}

func (s *scriptedClient) Complete(_ context.Context, r Request) (Response, error) {
	i := len(s.calls)
	s.calls = append(s.calls, r)
	if i < len(s.errs) && s.errs[i] != nil {
		return Response{}, s.errs[i]
	}
	return Response{Content: `{}`}, nil
}

func TestCompleteJSON_FallbackOnlyWhenFormatMayBeTheProblem(t *testing.T) {
	schema := &Schema{Name: "s", Definition: json.RawMessage(`{"type":"object"}`)}
	for _, tc := range []struct {
		name         string
		err          error
		wantFallback bool
	}{
		{"400 bad schema", &HTTPError{Status: 400}, true},
		{"422", &HTTPError{Status: 422}, true},
		{"500 grammar crash", &HTTPError{Status: 500}, true},
		{"200 with unusable body", errors.New("llm decode: boom"), true},
		{"401 bad key", &HTTPError{Status: 401}, false},
		{"403", &HTTPError{Status: 403}, false},
		{"429 after retries", &HTTPError{Status: 429}, false},
		{"503", &HTTPError{Status: 503}, false},
		{"network down", &net_Err{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &scriptedClient{errs: []error{tc.err}}
			_, err := CompleteJSON(context.Background(), sc, userMsg, schema)
			if tc.wantFallback {
				if err != nil || len(sc.calls) != 2 || !sc.calls[1].JSON || sc.calls[1].Schema != nil {
					t.Errorf("want json_object fallback; err=%v calls=%d", err, len(sc.calls))
				}
			} else if err == nil || len(sc.calls) != 1 {
				t.Errorf("want no fallback; err=%v calls=%d", err, len(sc.calls))
			}
		})
	}
}

func TestCompleteJSON_NoFallbackWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sc := &scriptedClient{errs: []error{&HTTPError{Status: 400}}}
	if _, err := CompleteJSON(ctx, sc, userMsg, &Schema{Name: "s", Definition: json.RawMessage(`{}`)}); err == nil || len(sc.calls) != 1 {
		t.Errorf("err=%v calls=%d", err, len(sc.calls))
	}
}

type net_Err struct{}

func (*net_Err) Error() string   { return "dial tcp: connection refused" }
func (*net_Err) Timeout() bool   { return false }
func (*net_Err) Temporary() bool { return false }

// --- tolerant JSON extraction ----------------------------------------------

func TestExtractJSON_ReasoningModels(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain":                {`{"a":1}`, `{"a":1}`},
		"fenced":               {"```json\n{\"a\":1}\n```", `{"a":1}`},
		"prose":                {`Sure! {"a":1} Hope that helps.`, `{"a":1}`},
		"think with braces":    {`<think>maybe {"a":2} or {"b":}</think>{"a":1}`, `{"a":1}`},
		"multiline think":      {"<think>\nlet me {think}\n</think>\n{\"a\":1}", `{"a":1}`},
		"closing tag only":     {"I reason {x}.\n</think>\n{\"a\":1}", `{"a":1}`},
		"thinking tag variant": {`<thinking>{}</thinking>{"a":1}`, `{"a":1}`},
	} {
		if got := ExtractJSON(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

// --- options and factory ---------------------------------------------------

func TestOptionsFromEnv(t *testing.T) {
	t.Setenv(EnvHeaders, "HTTP-Referer=https://x.test, X-Title=achilles ,X-Token=a=b==")
	t.Setenv(EnvQuery, "api-version=2024-10-21")
	t.Setenv(EnvTimeout, "10m")
	t.Setenv(EnvOmitTemp, "true")
	t.Setenv(EnvMaxTokens, "2048")
	t.Setenv(EnvMaxTokensParam, "max_completion_tokens")
	t.Setenv(EnvMaxRetries, "-1")
	o, err := OptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if o.Headers["HTTP-Referer"] != "https://x.test" || o.Headers["X-Title"] != "achilles" || o.Headers["X-Token"] != "a=b==" {
		t.Errorf("headers = %v", o.Headers)
	}
	if o.Query.Get("api-version") != "2024-10-21" || o.Timeout != 10*time.Minute || !o.OmitTemperature ||
		o.MaxTokens != 2048 || o.MaxTokensParam != "max_completion_tokens" || o.MaxRetries != -1 {
		t.Errorf("options = %+v", o)
	}
}

func TestOptionsFromEnv_Errors(t *testing.T) {
	for _, tc := range []struct{ env, val string }{
		{EnvHeaders, "novalue"}, {EnvQuery, "=x"}, {EnvTimeout, "soon"}, {EnvTimeout, "-1s"},
		{EnvOmitTemp, "maybe"}, {EnvMaxTokens, "lots"}, {EnvMaxTokensParam, "limit"}, {EnvMaxRetries, "x"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.env, tc.val)
			_, err := OptionsFromEnv()
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), tc.val) && tc.env == EnvHeaders {
				t.Errorf("header errors must not echo values (may be secrets): %v", err)
			}
		})
	}
}

func TestNewFactory_Modes(t *testing.T) {
	t.Setenv("ACHILLES_LLM_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")

	for _, bad := range []string{"oauth", "gcp", ""} {
		if _, err := NewFactory(bad); err == nil {
			t.Errorf("unknown mode %q must error", bad)
		}
	}
	if _, err := NewFactory(ModeKey); err != nil {
		t.Errorf("keyless key-mode (local Ollama) must work: %v", err)
	}
	if _, err := NewFactory(ModeAPIKey); err == nil {
		t.Error("api-key mode without a key must error")
	}

	t.Setenv("ACHILLES_LLM_API_KEY", "k")
	f, err := NewFactory(ModeAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	c := f("http://x", "m").(*OpenAIClient)
	if c.Opts.AuthHeader != AuthAPIKey || c.APIKey != "k" || c.Model != "m" {
		t.Errorf("client = %+v", c)
	}
	f, _ = NewFactory(ModeNone)
	if f("http://x", "m").(*OpenAIClient).Opts.AuthHeader != AuthNone {
		t.Error("none mode must set AuthNone")
	}
}

// --- repair bookkeeping ------------------------------------------------------

type usageClient struct{ replies []string }

func (u *usageClient) Complete(_ context.Context, _ Request) (Response, error) {
	r := u.replies[0]
	u.replies = u.replies[1:]
	return Response{Content: r, Usage: Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}}, nil
}

func TestCompleteAndDecode_RepairSumsUsageAndClearsStaleFields(t *testing.T) {
	var out struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	validate := func() error {
		if out.B == "" {
			return errors.New("b is required")
		}
		return nil
	}
	c := &usageClient{replies: []string{`{"a":"stale"}`, `{"b":"fresh"}`}}
	resp, err := CompleteAndDecode(context.Background(), c, userMsg, &Schema{Name: "s", Definition: json.RawMessage(`{}`)}, &out, validate)
	if err != nil {
		t.Fatal(err)
	}
	if out.A != "" || out.B != "fresh" {
		t.Errorf("out = %+v; a field from the failed first attempt leaked into the repaired result", out)
	}
	if resp.Usage.TotalTokens != 30 {
		t.Errorf("usage = %+v, want both calls (30 total tokens)", resp.Usage)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Anthropic's OpenAI-compatible endpoint answers 400 to an explicit temperature
// on current Claude models, and triage sends temperature 0 on every call. The
// preset therefore failed on the first request, every time.
func TestTemperature_OmittedForTheAnthropicEndpoint(t *testing.T) {
	sent := func(baseURL string) map[string]any {
		t.Helper()
		var body map[string]any
		cl := NewOpenAI(baseURL, "k", "claude-opus-5-5")
		cl.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			return &http.Response{StatusCode: 200, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(okReply))}, nil
		})}
		if _, err := cl.Complete(context.Background(), Request{Messages: userMsg, Temperature: 0.3}); err != nil {
			t.Fatal(err)
		}
		return body
	}

	for _, u := range []string{"https://api.anthropic.com/v1", "https://API.Anthropic.com/v1/"} {
		if v, ok := sent(u)["temperature"]; ok {
			t.Errorf("%s: temperature must not be sent, got %v", u, v)
		}
	}
	// Every other endpoint still gets what the caller asked for.
	for _, u := range []string{"https://api.openai.com/v1", "https://openrouter.ai/api/v1", "http://localhost:11434/v1",
		"https://api.anthropic.com.evil.example/v1"} {
		if v, ok := sent(u)["temperature"]; !ok || v.(float64) != 0.3 {
			t.Errorf("%s: temperature should be sent as given, got %v (present=%v)", u, v, ok)
		}
	}
}
