package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicClient talks to Anthropic's Messages API through the official SDK.
// It replaces the OpenAI-compatibility endpoint for --llm-provider anthropic:
// that endpoint is meant for trying Claude out, ignores response_format, and
// rejects the sampling parameters triage used to send.
type AnthropicClient struct {
	BaseURL string
	Model   string
	Opts    Options
	client  anthropic.Client
}

const (
	// anthropicDefaultMaxTokens is the output budget when ACHILLES_LLM_MAX_TOKENS
	// is unset. Current Claude models think before they answer, and the thinking
	// counts against max_tokens, so it is well above what a verdict needs.
	anthropicDefaultMaxTokens = 16000
	// anthropicDefaultTimeout bounds one call (stream included) when
	// ACHILLES_LLM_TIMEOUT is unset.
	anthropicDefaultTimeout = 10 * time.Minute
)

// IsAnthropicBaseURL reports whether baseURL is Anthropic's own API, which
// NewFactory then serves with the native client.
func IsAnthropicBaseURL(baseURL string) bool {
	u, err := url.Parse(baseURL)
	return err == nil && strings.EqualFold(u.Hostname(), "api.anthropic.com")
}

// NewAnthropic returns a Messages API client. baseURL may carry the /v1 suffix
// the OpenAI-style presets use; the SDK adds its own.
//
// The SDK's environment defaults (ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL, its
// config files) are switched off: the key and the endpoint come from Achilles'
// own flags and environment, which check.go has already vetted, so a stray
// ANTHROPIC_BASE_URL cannot send the key somewhere else.
func NewAnthropic(baseURL, apiKey, model string, o Options) *AnthropicClient {
	base := strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1") + "/"
	retries := o.MaxRetries
	switch {
	case retries == 0:
		retries = defaultRetries
	case retries < 0:
		retries = 0
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = anthropicDefaultTimeout
	}
	opts := []option.RequestOption{
		option.WithoutEnvironmentDefaults(),
		option.WithBaseURL(base),
		option.WithMaxRetries(retries),
		option.WithRequestTimeout(timeout),
	}
	if o.AuthHeader != AuthNone && apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	for k, v := range o.Headers {
		opts = append(opts, option.WithHeader(k, v))
	}
	for k, vs := range o.Query {
		for _, v := range vs {
			opts = append(opts, option.WithQueryAdd(k, v))
		}
	}
	return &AnthropicClient{BaseURL: base, Model: model, Opts: o, client: anthropic.NewClient(opts...)}
}

// Complete sends one request and waits for the whole reply. It streams under
// the hood: a long thinking phase on a non-streaming request can outlast
// proxies' idle timeouts.
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
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: int64(maxTokens),
	}
	// No temperature: current Claude models fix their sampling, and an explicit
	// one is rejected.
	var system []anthropic.TextBlockParam
	for _, m := range req.Messages {
		switch m.Role {
		case RoleSystem:
			system = append(system, anthropic.TextBlockParam{Text: m.Content})
		case RoleAssistant:
			params.Messages = append(params.Messages, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		default:
			params.Messages = append(params.Messages, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		}
	}
	if len(system) > 0 {
		// The system prompt is the same for every finding of a run, so it is
		// cached: later calls read it at a fraction of the input price.
		system[len(system)-1].CacheControl = anthropic.NewCacheControlEphemeralParam()
		params.System = system
	}
	if req.Schema != nil {
		var schema map[string]any
		if err := json.Unmarshal(req.Schema.Definition, &schema); err != nil {
			return Response{}, fmt.Errorf("llm: schema %s: %w", req.Schema.Name, err)
		}
		params.OutputConfig = anthropic.OutputConfigParam{Format: anthropic.JSONOutputFormatParam{Schema: schema}}
	}
	// req.JSON has no Messages API equivalent short of a schema; the prompts ask
	// for JSON and callers extract it.

	stream := c.client.Messages.NewStreaming(ctx, params)
	msg := anthropic.Message{}
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			_ = stream.Close()
			return Response{}, fmt.Errorf("llm: reading the reply: %w", err)
		}
	}
	if err := stream.Err(); err != nil {
		return Response{}, asHTTPError(err)
	}

	if msg.StopReason == anthropic.StopReasonRefusal {
		return Response{}, fmt.Errorf("llm: the model declined to answer (refusal, category %q)", msg.StopDetails.Category)
	}
	var text strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	u := msg.Usage
	prompt := int(u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens)
	return Response{
		Content: text.String(),
		Model:   string(msg.Model),
		Usage: Usage{
			PromptTokens:     prompt,
			CompletionTokens: int(u.OutputTokens),
			TotalTokens:      prompt + int(u.OutputTokens),
		},
		Truncated: msg.StopReason == anthropic.StopReasonMaxTokens,
	}, nil
}

// asHTTPError turns the SDK's API error into the HTTPError the rest of Achilles
// understands, so a rejected key or exhausted credit (401, 402) still stops the
// run and a rejected schema (400) still falls back to plain JSON.
func asHTTPError(err error) error {
	var ae *anthropic.Error
	if errors.As(err, &ae) {
		body := ae.RawJSON()
		if body == "" {
			body = ae.Error()
		}
		return &HTTPError{Status: ae.StatusCode, Body: body}
	}
	return err
}
