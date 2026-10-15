package llm

import (
	"fmt"
	"os"
)

// Auth modes accepted by --llm-auth / ACHILLES_LLM_AUTH.
const (
	ModeKey    = "key"     // static key from ACHILLES_LLM_API_KEY / OPENAI_API_KEY, sent as a Bearer token
	ModeAPIKey = "api-key" // the same key, sent as an `api-key:` header (Azure OpenAI)
	ModeNone   = "none"    // no credential header (local runtimes, or auth via ACHILLES_LLM_HEADERS)
)

// ValidAuthModes lists the accepted --llm-auth values, for flag help and errors.
const ValidAuthModes = "key | api-key | none"

// ValidateAuthMode returns an error for an unknown mode.
func ValidateAuthMode(mode string) error {
	switch mode {
	case ModeKey, ModeAPIKey, ModeNone:
		return nil
	}
	return fmt.Errorf("--llm-auth must be one of %s, got %q", ValidAuthModes, mode)
}

// NewFactory returns the client constructor for one run: factory(baseURL, model)
// yields a client with the run's credential and transport options. It is the
// single place that turns --llm-auth plus the environment into clients, so the
// scanner and the eval harness cannot drift apart.
//
// A missing key is NOT an error under ModeKey: keyless local runtimes (Ollama,
// llama.cpp, LM Studio) are a first-class target. ModeAPIKey requires one.
func NewFactory(mode string) (func(baseURL, model string) Client, error) {
	if err := ValidateAuthMode(mode); err != nil {
		return nil, err
	}
	opts, err := OptionsFromEnv()
	if err != nil {
		return nil, err
	}

	apiKey := os.Getenv("ACHILLES_LLM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	switch mode {
	case ModeAPIKey:
		if apiKey == "" {
			return nil, fmt.Errorf("--llm-auth api-key needs a key: set ACHILLES_LLM_API_KEY")
		}
		opts.AuthHeader = AuthAPIKey
	case ModeNone:
		opts.AuthHeader = AuthNone
	}
	// Anthropic's own API gets the native Messages client; everything else speaks
	// the OpenAI Chat Completions schema. Both take the key from the same place
	// (ACHILLES_LLM_API_KEY), which CheckEndpoint has already vetted for this host.
	return func(b, m string) Client {
		if IsAnthropicBaseURL(b) {
			return NewAnthropic(b, apiKey, m, opts)
		}
		return NewOpenAI(b, apiKey, m).Apply(opts)
	}, nil
}
