package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// The API key from the environment goes to every endpoint the routing file names.
// Only --llm-base-url was checked, so a per-task baseURL could send the key over
// plain http, or to another provider, with no complaint.
func TestCheckTaskEndpoints(t *testing.T) {
	ok := map[string]llm.TaskModel{
		"triage": {Model: "a"},                                        // inherits the main endpoint
		"judge":  {Model: "b", BaseURL: "https://gateway.example/v1"}, // https: fine
		"review": {Model: "c", BaseURL: "http://localhost:11434/v1"},  // local, plain http is fine
	}
	if err := checkTaskEndpoints(ok, "key", "sk-test"); err != nil {
		t.Errorf("valid routing rejected: %v", err)
	}

	cases := []struct {
		name, base, key, want string
	}{
		{"plain http to a remote host", "http://gateway.example/v1", "sk-test", "plain http"},
		{"another provider's key", "https://api.openai.com/v1", "sk-or-v1-abc", "OpenRouter"},
		{"not a URL", "gateway.example/v1", "sk-test", "not a valid"},
	}
	for _, c := range cases {
		err := checkTaskEndpoints(map[string]llm.TaskModel{"judge": {Model: "m", BaseURL: c.base}}, "key", c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), `task "judge"`) {
			t.Errorf("%s: err = %v, want one naming the task and %q", c.name, err, c.want)
		}
	}
}

func TestAnnounceEgress_NamesEveryEndpointThatReceivesCode(t *testing.T) {
	o := &options{llmBaseURL: "https://openrouter.ai/api/v1"}
	tasks := map[string]llm.TaskModel{
		"triage":      {Model: "a"},
		"judge":       {Model: "b", BaseURL: "https://gateway.example/v1"},
		"remediation": {Model: "c", BaseURL: "https://gateway.example/v1"},
		"review":      {Model: "d", BaseURL: "https://openrouter.ai/api/v1"}, // same host as the main one
	}
	var b strings.Builder
	announceEgress(&b, o, tasks)
	out := b.String()
	if !strings.Contains(out, "openrouter.ai") {
		t.Errorf("main endpoint not announced:\n%s", out)
	}
	if !strings.Contains(out, "also sends to: gateway.example (judge, remediation)") {
		t.Errorf("the second endpoint and its tasks must be named:\n%s", out)
	}
	if strings.Count(out, "openrouter.ai") != 1 {
		t.Errorf("the main host must not be repeated as an extra endpoint:\n%s", out)
	}
}

// End to end: a routing file that would send the key over plain http stops the run
// before any scanner starts.
func TestRun_BadModelConfigEndpointFailsBeforeScanning(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	routing := filepath.Join(t.TempDir(), "models.yaml")
	if err := os.WriteFile(routing, []byte("tasks:\n  judge:\n    model: m\n    baseURL: http://gateway.example/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACHILLES_LLM_API_KEY", "sk-test-key")

	err := run([]string{"--config", cfg, "--vault", vaultPath, "--triage",
		"--llm-base-url", "https://api.example.com/v1", "--llm-model", "m", "--model-config", routing, target})
	if err == nil || !strings.Contains(err.Error(), "plain http") || !strings.Contains(err.Error(), "judge") {
		t.Fatalf("err = %v, want the per-task endpoint refused", err)
	}
	if _, statErr := os.Stat(vaultPath); statErr == nil {
		t.Error("the vault was written: the run must stop before scanning")
	}
}
