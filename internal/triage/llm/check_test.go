package llm

import (
	"strings"
	"testing"
)

func TestCheckEndpoint(t *testing.T) {
	cases := []struct {
		name, base, mode, key, wantErr string
	}{
		{"hosted with key", "https://api.openai.com/v1", ModeKey, "sk-proj-abcdefghijklmnopqrstuv", ""},
		{"hosted without key", "https://openrouter.ai/api/v1", ModeKey, "", "no LLM API key for openrouter.ai"},
		{"local without key", "http://localhost:11434/v1", ModeKey, "", ""},
		{"private network without key", "http://10.0.0.5:8000/v1", ModeKey, "", ""},
		{"none mode", "https://gateway.example.com/v1", ModeNone, "", ""},
		{"openrouter key sent to openai", "https://api.openai.com/v1", ModeKey, "sk-or-v1-abcdefghijklmnop", "OpenRouter key"},
		{"anthropic key sent to openai", "https://api.openai.com/v1", ModeKey, "sk-ant-api03-abcdefghij", "Anthropic key"},
		{"anthropic key via openrouter is fine", "https://openrouter.ai/api/v1", ModeKey, "sk-ant-abcdefghij", ""},
		{"key over plain http", "http://llm.example.com/v1", ModeKey, "k", "plain http"},
		{"bad url", "not a url", ModeKey, "k", "not a valid"},
	}
	for _, c := range cases {
		err := CheckEndpoint(c.base, c.mode, c.key)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.wantErr)
		}
	}
}

func TestProviderBaseURL(t *testing.T) {
	if u, err := ProviderBaseURL(" OpenRouter "); err != nil || u != "https://openrouter.ai/api/v1" {
		t.Errorf("openrouter -> %q, %v", u, err)
	}
	if _, err := ProviderBaseURL("nope"); err == nil {
		t.Error("unknown provider should error")
	}
}
