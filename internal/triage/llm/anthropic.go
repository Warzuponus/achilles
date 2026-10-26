package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AnthropicClient talks to Anthropic's Messages API directly, over net/http. It
// replaces the OpenAI-compatibility endpoint for --llm-provider anthropic: that
// endpoint is meant for trying Claude out, ignores response_format, and
// rejected the sampling parameters triage used to send.
//
// It is hand-written rather than built on Anthropic's Go SDK on purpose: the
// SDK added eleven modules and grew the release binary by two thirds, for the
// one request this client makes.
type AnthropicClient struct {
	BaseURL string // ends in /v1
	APIKey  string
	Model   string
	Opts    Options
	HTTP    *http.Client

	sleep func(context.Context, time.Duration) error // tests: no real waiting between retries
}

const (
	// anthropicVersion is the API version header the Messages API requires.
	anthropicVersion = "2023-06-01"
	// anthropicDefaultMaxTokens is the output budget when ACHILLES_LLM_MAX_TOKENS
	// is unset. Current Claude models think before they answer, and the thinking
	// counts against max_tokens, so it is well above what a verdict needs.
	anthropicDefaultMaxTokens = 16000
	// anthropicDefaultTimeout bounds one attempt (stream included) when
	// ACHILLES_LLM_TIMEOUT is unset.
	anthropicDefaultTimeout = 10 * time.Minute
	// anthropicMaxReply bounds what one streamed reply may add up to.
	anthropicMaxReply = 32 << 20
)

// IsAnthropicBaseURL reports whether baseURL is Anthropic's own API, which
// NewFactory then serves with this client.
func IsAnthropicBaseURL(baseURL string) bool {
	u, err := url.Parse(baseURL)
	return err == nil && strings.EqualFold(u.Hostname(), "api.anthropic.com")
}

// NewAnthropic returns a Messages API client. baseURL may or may not carry the
// /v1 suffix the OpenAI-style presets use. The key, the endpoint and the extra
// headers come from Achilles' own flags and environment, which CheckEndpoint
// has vetted; nothing is read from ANTHROPIC_* variables.
func NewAnthropic(baseURL, apiKey, model string, o Options) *AnthropicClient {
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = anthropicDefaultTimeout
	}
	return &AnthropicClient{BaseURL: base, APIKey: apiKey, Model: model, Opts: o, HTTP: &http.Client{Timeout: timeout}}
}

type anthropicRequest struct {
	Model        string                 `json:"model"`
	MaxTokens    int                    `json:"max_tokens"`
	System       []anthropicText        `json:"system,omitempty"`
	Messages     []anthropicMessage     `json:"messages"`
	Stream       bool                   `json:"stream"`
	OutputConfig *anthropicOutputConfig `json:"output_config,omitempty"`
}

type anthropicText struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	CacheControl *anthropicCache `json:"cache_control,omitempty"`
}

type anthropicCache struct {
	Type string `json:"type"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content []anthropicText `json:"content"`
}

type anthropicOutputConfig struct {
	Format anthropicFormat `json:"format"`
}

type anthropicFormat struct {
	Type   string          `json:"type"`
	Schema json.RawMessage `json:"schema"`
}

// Complete sends one request and waits for the whole reply. The reply is
// streamed: a long thinking phase on a plain request can outlast a proxy's idle
// timeout. Rate limits, overload and transport failures are retried like the
// OpenAI client's.
func (c *AnthropicClient) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = c.Model
	}
	if model == "" {
		return Response{}, fmt.Errorf("llm: no model configured")
	}
	maxTokens := c.Opts.MaxTokens
	if maxTokens <= 0 {
		maxTokens = anthropicDefaultMaxTokens
	}
	// No temperature: current Claude models fix their sampling, and an explicit
	// one is rejected.
	body := anthropicRequest{Model: model, MaxTokens: maxTokens, Stream: true}
	for _, m := range req.Messages {
		block := anthropicText{Type: "text", Text: m.Content}
		switch m.Role {
		case RoleSystem:
			body.System = append(body.System, block)
		case RoleAssistant:
			body.Messages = append(body.Messages, anthropicMessage{Role: "assistant", Content: []anthropicText{block}})
		default:
			body.Messages = append(body.Messages, anthropicMessage{Role: "user", Content: []anthropicText{block}})
		}
	}
	if n := len(body.System); n > 0 {
		// The system prompt is the same for every finding of a run, so it is
		// cached: later calls read it at a fraction of the input price.
		body.System[n-1].CacheControl = &anthropicCache{Type: "ephemeral"}
	}
	if req.Schema != nil {
		// Structured outputs: the reply is held to the schema.
		body.OutputConfig = &anthropicOutputConfig{Format: anthropicFormat{Type: "json_schema", Schema: anthropicSchema(req.Schema.Definition)}}
	}
	// req.JSON has no Messages API equivalent short of a schema; the prompts ask
	// for JSON and callers extract it.
	buf, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}
	endpoint := c.BaseURL + "/messages"
	if len(c.Opts.Query) > 0 {
		endpoint += "?" + c.Opts.Query.Encode()
	}

	retries := c.Opts.MaxRetries
	switch {
	case retries == 0:
		retries = defaultRetries
	case retries < 0:
		retries = 0
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.attempt(ctx, endpoint, buf)
		if err == nil || attempt >= retries || ctx.Err() != nil {
			return resp, err
		}
		var (
			he   *HTTPError
			te   *transportError
			wait time.Duration
		)
		switch {
		case errors.As(err, &he) && retryableStatus(he.Status):
			wait = backoff(attempt, he.RetryAfter)
			if he.RetryAfter <= 0 {
				wait = jitter(wait)
			}
		case errors.As(err, &te):
			wait = jitter(backoff(attempt, 0))
		default:
			return resp, err
		}
		if serr := c.wait(ctx, wait); serr != nil {
			return Response{}, serr
		}
	}
}

func (c *AnthropicClient) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// attempt performs one request and reads its event stream to the end.
func (c *AnthropicClient) attempt(ctx context.Context, endpoint string, buf []byte) (Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Anthropic-Version", anthropicVersion)
	for k, v := range c.Opts.Headers {
		httpReq.Header.Set(k, v)
	}
	if c.Opts.AuthHeader != AuthNone && c.APIKey != "" {
		httpReq.Header.Set("X-Api-Key", c.APIKey)
	}

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Response{}, &transportError{fmt.Errorf("llm request: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return Response{}, &HTTPError{
			Status: resp.StatusCode, Body: strings.TrimSpace(string(data)),
			RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	return readAnthropicStream(io.LimitReader(resp.Body, anthropicMaxReply))
}

// anthropicEvent is the union of the stream events this client reads. Every
// field it does not need is ignored, so new event types and fields pass by.
type anthropicEvent struct {
	Type    string `json:"type"`
	Message struct {
		Model string         `json:"model"`
		Usage anthropicUsage `json:"usage"`
	} `json:"message"`
	Index        int `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		StopReason  string `json:"stop_reason"`
		StopDetails struct {
			Category string `json:"category"`
		} `json:"stop_details"`
	} `json:"delta"`
	Usage anthropicUsage `json:"usage"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// anthropicErrorStatus is the HTTP status the Messages API uses for an error
// type.
func anthropicErrorStatus(errType string) int {
	switch errType {
	case "invalid_request_error":
		return http.StatusBadRequest
	case "authentication_error":
		return http.StatusUnauthorized
	case "billing_error":
		return http.StatusPaymentRequired
	case "permission_error":
		return http.StatusForbidden
	case "not_found_error":
		return http.StatusNotFound
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	case "rate_limit_error":
		return http.StatusTooManyRequests
	case "overloaded_error":
		return 529
	default: // api_error, and anything new
		return http.StatusInternalServerError
	}
}

type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

// readAnthropicStream reads server-sent events up to message_stop and returns
// the reply: the text blocks joined (thinking blocks are not part of it), the
// stop reason, and the usage.
func readAnthropicStream(r io.Reader) (Response, error) {
	br := bufio.NewReader(r)
	var (
		text       strings.Builder
		textBlocks = map[int]bool{}
		usage      anthropicUsage
		model      string
		stop       string
		category   string
		stopped    bool
	)
	for !stopped {
		line, err := br.ReadString('\n')
		if data, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "data:"); ok {
			var ev anthropicEvent
			if jerr := json.Unmarshal([]byte(strings.TrimSpace(data)), &ev); jerr != nil {
				return Response{}, fmt.Errorf("llm: unreadable stream event: %w", jerr)
			}
			switch ev.Type {
			case "message_start":
				model = ev.Message.Model
				usage = ev.Message.Usage
			case "content_block_start":
				if ev.ContentBlock.Type == "text" {
					textBlocks[ev.Index] = true
					text.WriteString(ev.ContentBlock.Text)
				}
			case "content_block_delta":
				if ev.Delta.Type == "text_delta" && textBlocks[ev.Index] {
					text.WriteString(ev.Delta.Text)
				}
			case "message_delta":
				if ev.Delta.StopReason != "" {
					stop = ev.Delta.StopReason
				}
				if ev.Delta.StopDetails.Category != "" {
					category = ev.Delta.StopDetails.Category
				}
				// Output tokens in message_delta are the running total.
				if ev.Usage.OutputTokens > 0 {
					usage.OutputTokens = ev.Usage.OutputTokens
				}
			case "message_stop":
				stopped = true
			case "error":
				// An error after the 200, such as overload mid-stream. It gets the
				// status the same error has before a stream, so it is retried (or
				// not) the same way.
				return Response{}, &HTTPError{Status: anthropicErrorStatus(ev.Error.Type), Body: ev.Error.Type + ": " + ev.Error.Message}
			}
		}
		if err != nil {
			if stopped {
				break
			}
			// The stream ended, or dropped, before message_stop: the answer may be
			// cut short anywhere, so it is not used.
			return Response{}, &transportError{fmt.Errorf("llm: reply stream ended before message_stop: %w", err)}
		}
	}
	if stop == "refusal" {
		if category != "" {
			return Response{}, fmt.Errorf("llm: the model declined to answer (refusal, category %q)", category)
		}
		return Response{}, fmt.Errorf("llm: the model declined to answer (refusal)")
	}
	prompt := usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens
	return Response{
		Content: text.String(),
		Model:   model,
		Usage: Usage{
			PromptTokens:     prompt,
			CompletionTokens: usage.OutputTokens,
			TotalTokens:      prompt + usage.OutputTokens,
		},
		Truncated: stop == "max_tokens",
	}, nil
}

// anthropicUnsupported are JSON Schema keywords the Messages API's structured
// outputs reject. Achilles' schemas are shared with OpenAI-compatible endpoints,
// so they are adapted here rather than at each call site.
var anthropicUnsupported = []string{
	"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
	"minLength", "maxLength", "maxItems", "uniqueItems",
}

// anthropicSchema adapts a schema to what structured outputs accept: every object
// gets additionalProperties false (required there, and an object schema without
// it is a 400), and unsupported constraints are dropped. The callers validate
// what they decode, so a dropped bound is still checked. A schema that does not
// parse is passed through for the API to reject.
func anthropicSchema(def json.RawMessage) json.RawMessage {
	var v any
	if err := json.Unmarshal(def, &v); err != nil {
		return def
	}
	adaptSchema(v)
	out, err := json.Marshal(v)
	if err != nil {
		return def
	}
	return out
}

func adaptSchema(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for _, k := range anthropicUnsupported {
		delete(m, k)
	}
	// minItems is accepted only as 0 or 1.
	if n, ok := m["minItems"].(float64); ok && n > 1 {
		delete(m, "minItems")
	}
	_, hasProps := m["properties"]
	if t, _ := m["type"].(string); t == "object" || hasProps {
		m["additionalProperties"] = false
	}
	// properties and $defs map names to schemas: recurse into the values only, so
	// a property called "minimum" or "pattern" is left alone.
	for _, k := range []string{"properties", "$defs", "definitions"} {
		if sub, ok := m[k].(map[string]any); ok {
			for _, s := range sub {
				adaptSchema(s)
			}
		}
	}
	if items, ok := m["items"]; ok {
		adaptSchema(items)
	}
	for _, k := range []string{"anyOf", "allOf", "oneOf"} {
		if list, ok := m[k].([]any); ok {
			for _, s := range list {
				adaptSchema(s)
			}
		}
	}
}
