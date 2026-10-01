package llm

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Credential styles for Options.AuthHeader.
const (
	AuthBearer = ""        // Authorization: Bearer <key> (OpenAI, Ollama, vLLM, LiteLLM, OpenRouter, ...)
	AuthAPIKey = "api-key" // api-key: <key> (Azure OpenAI)
	AuthNone   = "none"    // no credential header (local runtimes, or auth supplied via Headers)
)

// Options are the transport knobs that differ between OpenAI-compatible
// providers. The zero value is plain OpenAI behavior.
type Options struct {
	// AuthHeader selects how the credential is sent (AuthBearer, AuthAPIKey, AuthNone).
	AuthHeader string
	// Headers are sent on every request: OpenRouter's HTTP-Referer / X-Title, a
	// gateway's routing header, or a custom auth header combined with AuthNone.
	Headers map[string]string
	// Query is appended to the URL: Azure's api-version=....
	Query url.Values
	// Timeout is the per-request HTTP timeout; 0 keeps the client default (120s).
	// Raise it for slow CPU-bound local models.
	Timeout time.Duration
	// OmitTemperature drops the temperature field. Reasoning models (OpenAI o-series
	// and GPT-5 class) accept only the default and answer 400 to any explicit value.
	OmitTemperature bool
	// MaxTokens caps output when > 0. MaxTokensParam names the wire field:
	// "max_tokens" (default, widest support) or "max_completion_tokens" (newer
	// OpenAI models).
	MaxTokens      int
	MaxTokensParam string
	// MaxRetries bounds retries on 429/502/503/504. 0 = default (2); negative disables.
	MaxRetries int
}

// Environment variables read by OptionsFromEnv. They are env-only (not flags) so
// the fleet and CI can forward them to subprocesses without new plumbing.
const (
	EnvHeaders        = "ACHILLES_LLM_HEADERS"          // "Name=Value,Name2=Value2"
	EnvQuery          = "ACHILLES_LLM_QUERY"            // "api-version=2024-10-21"
	EnvTimeout        = "ACHILLES_LLM_TIMEOUT"          // Go duration, e.g. "10m"
	EnvOmitTemp       = "ACHILLES_LLM_OMIT_TEMPERATURE" // "true" for reasoning models
	EnvMaxTokens      = "ACHILLES_LLM_MAX_TOKENS"       // integer
	EnvMaxTokensParam = "ACHILLES_LLM_MAX_TOKENS_PARAM" // max_tokens | max_completion_tokens
	EnvMaxRetries     = "ACHILLES_LLM_MAX_RETRIES"      // integer; negative disables
)

// OptionsFromEnv reads Options from the environment. Header values may be
// secrets, so errors here never echo them.
func OptionsFromEnv() (Options, error) {
	var o Options
	var err error
	if o.Headers, err = parsePairs(os.Getenv(EnvHeaders)); err != nil {
		return o, fmt.Errorf("%s: %w", EnvHeaders, err)
	}
	q, err := parsePairs(os.Getenv(EnvQuery))
	if err != nil {
		return o, fmt.Errorf("%s: %w", EnvQuery, err)
	}
	if len(q) > 0 {
		o.Query = url.Values{}
		for k, v := range q {
			o.Query.Set(k, v)
		}
	}
	if v := os.Getenv(EnvTimeout); v != "" {
		if o.Timeout, err = time.ParseDuration(v); err != nil || o.Timeout <= 0 {
			return o, fmt.Errorf("%s: want a positive Go duration like 10m", EnvTimeout)
		}
	}
	if v := os.Getenv(EnvOmitTemp); v != "" {
		if o.OmitTemperature, err = strconv.ParseBool(v); err != nil {
			return o, fmt.Errorf("%s: want true or false", EnvOmitTemp)
		}
	}
	if v := os.Getenv(EnvMaxTokens); v != "" {
		if o.MaxTokens, err = strconv.Atoi(v); err != nil || o.MaxTokens < 0 {
			return o, fmt.Errorf("%s: want a non-negative integer", EnvMaxTokens)
		}
	}
	switch p := os.Getenv(EnvMaxTokensParam); p {
	case "", "max_tokens", "max_completion_tokens":
		o.MaxTokensParam = p
	default:
		return o, fmt.Errorf("%s: want max_tokens or max_completion_tokens", EnvMaxTokensParam)
	}
	if v := os.Getenv(EnvMaxRetries); v != "" {
		if o.MaxRetries, err = strconv.Atoi(v); err != nil {
			return o, fmt.Errorf("%s: want an integer", EnvMaxRetries)
		}
	}
	return o, nil
}

// parsePairs parses "k=v,k2=v2". Values may contain '=' (base64) but not ','.
func parsePairs(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("want comma-separated name=value pairs")
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// Apply sets the options on the client and returns it for chaining.
func (c *OpenAIClient) Apply(o Options) *OpenAIClient {
	c.Opts = o
	if o.Timeout > 0 {
		c.HTTP.Timeout = o.Timeout
	}
	return c
}
