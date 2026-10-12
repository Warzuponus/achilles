package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OpenAIClient talks to any OpenAI-compatible /chat/completions endpoint.
type OpenAIClient struct {
	BaseURL string // e.g. https://api.openai.com/v1 or http://localhost:11434/v1
	APIKey  string // may be empty for keyless local runtimes
	Model   string
	HTTP    *http.Client

	// Opts carries the transport knobs that differ between OpenAI-compatible
	// providers (auth header, extra headers, query string, timeout, ...).
	Opts Options

	// sleep waits between retries; nil means a context-aware time.Sleep. Tests
	// replace it so backoff costs no wall-clock time.
	sleep func(context.Context, time.Duration) error
}

// HTTPError is a non-200 reply from the endpoint. It is a distinct type so
// callers can tell "this server rejected response_format" (worth a fallback)
// from "bad credential" or "rate limited" (a fallback would only double the load).
type HTTPError struct {
	Status     int
	Body       string
	RetryAfter time.Duration // from the Retry-After header, 0 if absent
}

func (e *HTTPError) Error() string { return fmt.Sprintf("llm HTTP %d: %s", e.Status, e.Body) }

// fixedSampling reports whether the endpoint at baseURL is known to reject an
// explicit temperature, so the field is left out without the operator having to
// find ACHILLES_LLM_OMIT_TEMPERATURE.
//
// Anthropic's OpenAI-compatibility endpoint: current Claude models no longer take
// sampling parameters, and answer 400 to the temperature of 0 that triage sends.
// Every call failed, so the --llm-provider anthropic preset never produced a
// verdict. (That endpoint also ignores response_format, which is harmless: replies
// are validated and repaired the same way as for any model without JSON mode.)
func fixedSampling(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), "api.anthropic.com")
}

// NewOpenAI builds a client. A trailing slash on baseURL is tolerated.
func NewOpenAI(baseURL, apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	// Temperature is a pointer so it can be omitted: reasoning models only accept
	// the default and reject an explicit value.
	Temperature         *float64    `json:"temperature,omitempty"`
	MaxTokens           *int        `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int        `json:"max_completion_tokens,omitempty"`
	ResponseFormat      *respFormat `json:"response_format,omitempty"`
}

type respFormat struct {
	Type       string      `json:"type"`
	JSONSchema *jsonSchema `json:"json_schema,omitempty"`
}

type jsonSchema struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict,omitempty"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content string `json:"content"`
			// Reasoning servers (DeepSeek-style, vLLM, Ollama) put the answer here
			// instead of Content when the output is cut off or Content is unused.
			ReasoningContent string `json:"reasoning_content"`
			Reasoning        string `json:"reasoning"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete sends the request and returns the first choice's content. 429 and
// transient 5xx replies are retried with backoff (honoring Retry-After).
func (c *OpenAIClient) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = c.Model
	}
	if model == "" {
		return Response{}, fmt.Errorf("llm: no model configured")
	}

	body := chatRequest{Model: model, Messages: req.Messages}
	if !c.Opts.OmitTemperature && !fixedSampling(c.BaseURL) {
		t := req.Temperature
		body.Temperature = &t
	}
	if n := c.Opts.MaxTokens; n > 0 {
		if c.Opts.MaxTokensParam == "max_completion_tokens" {
			body.MaxCompletionTokens = &n
		} else {
			body.MaxTokens = &n
		}
	}
	switch {
	case req.Schema != nil:
		body.ResponseFormat = &respFormat{
			Type: "json_schema",
			// strict only when the schema satisfies OpenAI's strict-mode rules;
			// otherwise it is rejected outright (see strictCompatible).
			JSONSchema: &jsonSchema{Name: req.Schema.Name, Schema: req.Schema.Definition, Strict: strictCompatible(req.Schema.Definition)},
		}
	case req.JSON:
		body.ResponseFormat = &respFormat{Type: "json_object"}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return Response{}, err
	}

	endpoint := c.BaseURL + "/chat/completions"
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

const (
	defaultRetries = 2
	maxBackoff     = 30 * time.Second
)

// retryableStatus reports the HTTP statuses that a second try can fix: rate
// limits, timeouts, and a server or gateway having a bad moment. 500 is included
// because providers answer it for transient internal errors far more often than
// for anything about the request; the retry count bounds the cost of being wrong.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
		529: // "overloaded", used by some providers
		return true
	}
	return false
}

// transportError is a request that never got an HTTP answer, or got part of one:
// a reset connection, an EOF mid-body, a dial or TLS timeout. These are the most
// ordinary transient failures there are and were not retried at all.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// jitter spreads a wait over the upper half of its range. Findings are reviewed in
// parallel, so without it every worker that hit the same rate limit retries at the
// same instant and hits it again.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// retryAfter reads a Retry-After header: a number of seconds, or an HTTP date.
func retryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs > 0 {
			return time.Duration(secs) * time.Second
		}
		return 0
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// backoff is the server's Retry-After when given, else 1s, 2s, 4s... — always
// capped so a hostile or broken header cannot stall a scan.
func backoff(attempt int, retryAfter time.Duration) time.Duration {
	d := retryAfter
	if d <= 0 {
		d = time.Second << attempt
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func (c *OpenAIClient) wait(ctx context.Context, d time.Duration) error {
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

// attempt performs one HTTP round trip.
func (c *OpenAIClient) attempt(ctx context.Context, endpoint string, buf []byte) (Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range c.Opts.Headers {
		httpReq.Header.Set(k, v)
	}
	if err := c.setCredential(httpReq); err != nil {
		return Response{}, err
	}

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Response{}, &transportError{fmt.Errorf("llm request: %w", err)}
	}
	defer resp.Body.Close()

	data, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Response{}, &HTTPError{
			Status: resp.StatusCode, Body: strings.TrimSpace(string(data)),
			RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	if readErr != nil {
		// The connection dropped mid-body. Decoding what arrived would report
		// "unexpected end of JSON input", which hides what happened and is not retried.
		return Response{}, &transportError{fmt.Errorf("llm response cut off: %w", readErr)}
	}

	var cr chatResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return Response{}, fmt.Errorf("llm decode: %w", err)
	}
	if cr.Error != nil {
		return Response{}, fmt.Errorf("llm error: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return Response{}, fmt.Errorf("llm: no choices in response")
	}
	m := cr.Choices[0].Message
	content := m.Content
	if content == "" {
		content = m.ReasoningContent
	}
	if content == "" {
		content = m.Reasoning
	}
	return Response{
		Content:   content,
		Truncated: cr.Choices[0].FinishReason == "length",
		Model:     cr.Model,
		Usage: Usage{
			PromptTokens:     cr.Usage.PromptTokens,
			CompletionTokens: cr.Usage.CompletionTokens,
			TotalTokens:      cr.Usage.TotalTokens,
		},
	}, nil
}

// setCredential attaches the credential in the style the provider expects.
func (c *OpenAIClient) setCredential(r *http.Request) error {
	if c.Opts.AuthHeader == AuthNone {
		return nil
	}
	cred := c.APIKey
	if cred == "" {
		return nil
	}
	if c.Opts.AuthHeader == AuthAPIKey {
		r.Header.Set("api-key", cred) // Azure OpenAI
		return nil
	}
	r.Header.Set("Authorization", "Bearer "+cred)
	return nil
}

// strictCompatible reports whether a JSON Schema satisfies OpenAI strict
// structured-output rules: every object sets additionalProperties:false and lists
// ALL of its properties in required. A schema with optional fields (ours have
// some) must be sent non-strict or the API answers 400 — which, before this
// check, silently cost one wasted request per call and then fell back.
func strictCompatible(def json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(def, &v); err != nil {
		return false
	}
	return strictNode(v)
}

func strictNode(v any) bool {
	switch n := v.(type) {
	case map[string]any:
		if props, ok := n["properties"].(map[string]any); ok {
			if ap, ok := n["additionalProperties"].(bool); !ok || ap {
				return false
			}
			req := map[string]bool{}
			if rs, ok := n["required"].([]any); ok {
				for _, r := range rs {
					if s, ok := r.(string); ok {
						req[s] = true
					}
				}
			}
			for name := range props {
				if !req[name] {
					return false
				}
			}
		}
		for _, child := range n {
			if !strictNode(child) {
				return false
			}
		}
	case []any:
		for _, child := range n {
			if !strictNode(child) {
				return false
			}
		}
	}
	return true
}
