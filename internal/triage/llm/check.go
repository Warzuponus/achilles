package llm

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Providers are the --llm-provider presets: name -> base URL. "anthropic" is
// Anthropic's own API, which NewFactory serves with the native Messages client
// (AnthropicClient), not the OpenAI-compatibility endpoint.
var Providers = map[string]string{
	"openai":     "https://api.openai.com/v1",
	"openrouter": "https://openrouter.ai/api/v1",
	"ollama":     "http://localhost:11434/v1",
	"anthropic":  "https://api.anthropic.com/v1",
}

// ProviderNames lists the presets, for flag help and errors.
const ProviderNames = "openai | openrouter | ollama | anthropic"

// ProviderBaseURL resolves a preset name ("" is not a preset).
func ProviderBaseURL(name string) (string, error) {
	u, ok := Providers[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return "", fmt.Errorf("--llm-provider must be one of %s, got %q", ProviderNames, name)
	}
	return u, nil
}

// IsLocalEndpoint reports whether baseURL points at this machine or a private
// network, where a keyless runtime (Ollama, vLLM, llama.cpp) is normal and plain
// http is acceptable.
func IsLocalEndpoint(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case h == "localhost", strings.HasSuffix(h, ".localhost"), h == "host.docker.internal":
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// APIKeyFromEnv is the key the clients will use (ACHILLES_LLM_API_KEY, then
// OPENAI_API_KEY). Never log it.
func APIKeyFromEnv() string {
	if k := os.Getenv("ACHILLES_LLM_API_KEY"); k != "" {
		return k
	}
	return os.Getenv("OPENAI_API_KEY")
}

// CheckEndpoint rejects the configurations that otherwise fail late, one finding
// at a time, or worse, succeed while sending a credential to the wrong company:
// a missing key for a hosted endpoint, a key that plainly belongs to another
// provider, and an API key sent over plain http. It runs before any scanning.
func CheckEndpoint(baseURL, authMode, apiKey string) error {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("--llm-base-url %q is not a valid http(s) URL", baseURL)
	}
	local := IsLocalEndpoint(baseURL)
	host := strings.ToLower(u.Hostname())

	if authMode != ModeNone && !local && u.Scheme != "https" {
		return fmt.Errorf("refusing to send an API key to %s over plain http; use https, or --llm-auth none", host)
	}
	if authMode == ModeNone {
		return nil
	}
	if apiKey == "" {
		if local {
			return nil // keyless local runtime
		}
		return fmt.Errorf("no LLM API key for %s: set ACHILLES_LLM_API_KEY "+
			"(for a local model use --llm-provider ollama or --llm-auth none)", host)
	}
	switch {
	case strings.HasPrefix(apiKey, "sk-or-") && strings.Contains(host, "openai.com"):
		return fmt.Errorf("the API key looks like an OpenRouter key but --llm-base-url is %s; "+
			"it would be sent to OpenAI. Use --llm-provider openrouter", host)
	case strings.HasPrefix(apiKey, "sk-ant-") && !strings.Contains(host, "anthropic.com") && !strings.Contains(host, "openrouter.ai"):
		return fmt.Errorf("the API key looks like an Anthropic key but --llm-base-url is %s; "+
			"it would be sent there. Use --llm-provider anthropic", host)
	}
	return nil
}
