package llm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests call a live Messages API. They are skipped unless
// ACHILLES_TEST_ANTHROPIC_API_KEY is set, and cost a few cents a run:
//
//	ACHILLES_TEST_ANTHROPIC_API_KEY=... go test -count=1 -run Live ./internal/triage/llm
//
// ACHILLES_TEST_ANTHROPIC_MODELS is a comma-separated list of models to try
// (default claude-opus-5-5). A dedicated variable keeps a key exported for other
// tools from running them by accident.
//
// ACHILLES_TEST_ANTHROPIC_BASE_URL points them at another server speaking the
// Messages API, such as OpenRouter's (https://openrouter.ai/api, with an
// OpenRouter key and models such as anthropic/claude-sonnet-5.5). Anywhere but
// api.anthropic.com the key is sent as a Bearer token, which is what such
// gateways take.

func liveAnthropic(t *testing.T) (key string, models []string) {
	t.Helper()
	key = os.Getenv("ACHILLES_TEST_ANTHROPIC_API_KEY")
	if key == "" {
		t.Skip("ACHILLES_TEST_ANTHROPIC_API_KEY not set")
	}
	models = strings.FieldsFunc(os.Getenv("ACHILLES_TEST_ANTHROPIC_MODELS"), func(r rune) bool { return r == ',' || r == ' ' })
	if len(models) == 0 {
		models = []string{"claude-opus-5-5"}
	}
	return key, models
}

func liveClient(key, model string) *AnthropicClient {
	base := os.Getenv("ACHILLES_TEST_ANTHROPIC_BASE_URL")
	if base == "" {
		base = Providers["anthropic"]
	}
	o := Options{Timeout: 5 * time.Minute}
	if !IsAnthropicBaseURL(base) {
		o.AuthHeader = AuthNone
		o.Headers = map[string]string{"Authorization": "Bearer " + key}
	}
	return NewAnthropic(base, key, model, o)
}

// liveSystem is long enough to pass the minimum cacheable prefix, so the second
// call of a run should read it from the cache.
var liveSystem = func() string {
	s := "You are a security reviewer triaging static-analysis findings. Answer only with the JSON the schema asks for.\n"
	for i := 0; i < 400; i++ {
		s += "Rule: judge reachability from attacker-controlled input before calling a finding a true positive.\n"
	}
	return s
}()

const liveFinding = `Finding: python.lang.security.audit.subprocess-shell-true
File app.py line 12:

    from flask import request
    import subprocess
    @app.route("/ping")
    def ping():
        host = request.args.get("host")
        return subprocess.check_output("ping -c 1 " + host, shell=True)
`

// The triage verdict schema, as internal/triage sends it.
var liveVerdictSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "classification":{"type":"string","enum":["true_positive","false_positive","uncertain"]},
    "confidence":{"type":"number"},
    "exploitability":{"type":"string","enum":["reachable","not-reachable","unknown"]},
    "reasoning":{"type":"string"}
  },
  "required":["classification","confidence","exploitability","reasoning"],
  "additionalProperties":false
}`)

// The deep-verify step schema, as internal/deep sends it: no
// additionalProperties, a property named "pattern", optional fields.
var liveStepSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "action":{"type":"string","enum":["read_file","grep","list_dir","find_references","conclude"]},
    "path":{"type":"string"},
    "pattern":{"type":"string"},
    "classification":{"type":"string","enum":["true_positive","false_positive","uncertain"]},
    "confidence":{"type":"number"},
    "reasoning":{"type":"string"}
  },
  "required":["action"]
}`)

func TestLiveAnthropic_StructuredVerdict(t *testing.T) {
	key, models := liveAnthropic(t)
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			c := liveClient(key, model)
			msgs := []Message{{Role: RoleSystem, Content: liveSystem}, {Role: RoleUser, Content: liveFinding}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			for i := 0; i < 2; i++ { // twice: the second call exercises the cached system prompt
				// Complete, not CompleteJSON: a 400 here must fail the test, not
				// fall back to unenforced JSON.
				resp, err := c.Complete(ctx, Request{Messages: msgs, Schema: &Schema{Name: "verdict", Definition: liveVerdictSchema}})
				if err != nil {
					t.Fatalf("call %d: %v", i+1, err)
				}
				if resp.Truncated {
					t.Fatalf("call %d: truncated at max_tokens", i+1)
				}
				var v struct {
					Classification string  `json:"classification"`
					Confidence     float64 `json:"confidence"`
					Exploitability string  `json:"exploitability"`
					Reasoning      string  `json:"reasoning"`
				}
				if err := json.Unmarshal([]byte(resp.Content), &v); err != nil {
					t.Fatalf("call %d: reply is not the schema's JSON: %v\n%s", i+1, err, resp.Content)
				}
				if v.Classification != "true_positive" || v.Reasoning == "" {
					t.Errorf("call %d: verdict %+v; command injection from a query parameter should be a true positive", i+1, v)
				}
				if resp.Model == "" || resp.Usage.PromptTokens == 0 || resp.Usage.CompletionTokens == 0 {
					t.Errorf("call %d: model %q usage %+v", i+1, resp.Model, resp.Usage)
				}
				t.Logf("call %d: model %s usage %+v", i+1, resp.Model, resp.Usage)
			}
		})
	}
}

func TestLiveAnthropic_DeepStepSchema(t *testing.T) {
	key, models := liveAnthropic(t)
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			c := liveClient(key, model)
			msgs := []Message{
				{Role: RoleSystem, Content: "You verify a finding by asking for code with tool actions, then conclude. Answer with one JSON step."},
				{Role: RoleUser, Content: liveFinding + "\nYou have seen enough. Conclude."},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			resp, err := c.Complete(ctx, Request{Messages: msgs, Schema: &Schema{Name: "deep_step", Definition: liveStepSchema}})
			if err != nil {
				t.Fatal(err)
			}
			var step struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal([]byte(resp.Content), &step); err != nil || step.Action == "" {
				t.Fatalf("step %q: %v", resp.Content, err)
			}
		})
	}
}

func TestLiveAnthropic_PlainReply(t *testing.T) {
	key, models := liveAnthropic(t)
	c := liveClient(key, models[0])
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "Reply with the single word: ready"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content == "" {
		t.Fatalf("empty reply: %+v", resp)
	}
}

func TestLiveAnthropic_BadKeyIsUnauthorized(t *testing.T) {
	_, models := liveAnthropic(t)
	c := liveClient("sk-ant-api03-not-a-real-key", models[0])
	c.Opts.MaxRetries = -1
	_, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 401 {
		t.Fatalf("err = %v, want a 401 HTTPError", err)
	}
}
