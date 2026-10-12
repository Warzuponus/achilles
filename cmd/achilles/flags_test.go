package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAIPresetEnablesEverythingAndNamesReports(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	o, err := parseFlags([]string{"--ai", "--report-dir", "out", "--llm-provider", "openrouter", "."})
	if err != nil {
		t.Fatal(err)
	}
	if !o.triageOn || !o.remediateOn || !o.reviewOn || !o.scaAdvice {
		t.Errorf("--ai should enable triage, remediate, review and sca-advice: %+v", o)
	}
	if o.htmlReport != filepath.Join("out", "report.html") || o.markdownOut != filepath.Join("out", "report.md") ||
		o.sarifReport != filepath.Join("out", "achilles.sarif") {
		t.Errorf("report paths: %q %q %q", o.htmlReport, o.markdownOut, o.sarifReport)
	}
	if o.llmBaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("provider preset not applied: %q", o.llmBaseURL)
	}
}

func TestExplicitFlagsBeatPresets(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	o, err := parseFlags([]string{"--ai", "--html-report", "mine.html", "--llm-provider", "openrouter",
		"--llm-base-url", "https://gateway.internal/v1", "."})
	if err != nil {
		t.Fatal(err)
	}
	if o.htmlReport != "mine.html" || o.llmBaseURL != "https://gateway.internal/v1" {
		t.Errorf("explicit flags were overridden: html=%q base=%q", o.htmlReport, o.llmBaseURL)
	}
}

func TestOllamaPresetIsKeylessAndLocal(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	t.Setenv("ACHILLES_LLM_AUTH", "")
	o, err := parseFlags([]string{"--triage", "--llm-provider", "ollama", "--llm-model", "qwen", "."})
	if err != nil {
		t.Fatal(err)
	}
	if o.llmAuth != "none" || !strings.HasPrefix(o.llmBaseURL, "http://localhost") {
		t.Errorf("ollama preset: auth=%q base=%q", o.llmAuth, o.llmBaseURL)
	}
	t.Setenv("ACHILLES_LLM_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	if err := o.validateLLM(); err != nil {
		t.Errorf("a local keyless model must validate: %v", err)
	}
}

func TestValidateLLMFailsFastWithActionableMessages(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	t.Setenv("ACHILLES_LLM_AUTH", "")
	t.Setenv("ACHILLES_LLM_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")

	o, _ := parseFlags([]string{"--triage", "--llm-provider", "openrouter", "."})
	if err := o.validateLLM(); err == nil || !strings.Contains(err.Error(), "need a model") {
		t.Errorf("missing model: %v", err)
	}
	o, _ = parseFlags([]string{"--triage", "--llm-provider", "openrouter", "--llm-model", "x/y", "."})
	if err := o.validateLLM(); err == nil || !strings.Contains(err.Error(), "ACHILLES_LLM_API_KEY") {
		t.Errorf("missing key: %v", err)
	}
	t.Setenv("ACHILLES_LLM_API_KEY", "sk-or-v1-abcdefghijklmnopqrstuvwxyz")
	o, _ = parseFlags([]string{"--triage", "--llm-model", "x/y", "."}) // forgot the provider: defaults to OpenAI
	if err := o.validateLLM(); err == nil || !strings.Contains(err.Error(), "OpenRouter") {
		t.Errorf("wrong endpoint for the key: %v", err)
	}
	o, _ = parseFlags([]string{"--llm-model", "x/y", "."}) // no AI feature requested: nothing to check
	if err := o.validateLLM(); err != nil {
		t.Errorf("no LLM features requested but validate failed: %v", err)
	}
}

// A typo in --fail-on used to rank below every severity, so ANY finding failed the
// gate; and "critical" looked accepted while nothing could ever be critical.
func TestFailOnMustBeARealSeverity(t *testing.T) {
	for _, bad := range []string{"hgih", "sev1", "none", "unknown", "5"} {
		if _, err := parseFlags([]string{"--fail-on", bad, "."}); err == nil || !strings.Contains(err.Error(), "--fail-on") {
			t.Errorf("--fail-on %q should be rejected, got err=%v", bad, err)
		}
	}
	for in, want := range map[string]string{"high": "high", "High": "high", " CRITICAL ": "critical", "info": "info"} {
		o, err := parseFlags([]string{"--fail-on", in, "."})
		if err != nil {
			t.Errorf("--fail-on %q: %v", in, err)
			continue
		}
		if o.failOn != want {
			t.Errorf("--fail-on %q normalized to %q, want %q", in, o.failOn, want)
		}
	}
	o, err := parseFlags([]string{"."})
	if err != nil || o.failOn != "" {
		t.Errorf("no --fail-on: failOn=%q err=%v", o.failOn, err)
	}
}

// Flags after the target used to be dropped without a word: `achilles . --ai` ran
// a plain scan, and `achilles . --fail-on high` ran with no gate and exited 0.
func TestFlagsAreHonoredAfterTheTarget(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	o, err := parseFlags([]string{"src", "--fail-on", "high", "--strict-tools", "--triage", "--llm-model", "m"})
	if err != nil {
		t.Fatal(err)
	}
	if o.target != "src" || o.failOn != "high" || !o.strictTools || !o.triageOn || o.llmModel != "m" {
		t.Errorf("flags after the target were not applied: target=%q failOn=%q strict=%v triage=%v model=%q",
			o.target, o.failOn, o.strictTools, o.triageOn, o.llmModel)
	}

	// Mixed: some before, some after.
	o, err = parseFlags([]string{"--mode", "commercial", "src", "--fail-on", "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if o.mode != "commercial" || o.target != "src" || o.failOn != "critical" {
		t.Errorf("mixed order: mode=%q target=%q failOn=%q", o.mode, o.target, o.failOn)
	}

	// The documented order still works, and no target still means ".".
	if o, err = parseFlags([]string{"--fail-on", "low", "src"}); err != nil || o.target != "src" || o.failOn != "low" {
		t.Errorf("flags first: %+v err=%v", o, err)
	}
	if o, err = parseFlags([]string{"--fail-on", "low"}); err != nil || o.target != "." {
		t.Errorf("no target: target=%q err=%v", o.target, err)
	}
}

func TestBadArgumentsAfterTheTargetAreErrorsNotSilence(t *testing.T) {
	// A typo after the path must be reported like one before it.
	if _, err := parseFlags([]string{"src", "--fial-on", "high"}); err == nil {
		t.Error("an unknown flag after the target must be an error")
	}
	// Two paths is a mistake (often an unquoted glob), not "scan the first".
	_, err := parseFlags([]string{"src", "lib"})
	if err == nil || !strings.Contains(err.Error(), "one target path") {
		t.Errorf("two targets: err = %v", err)
	}
	if _, err := parseFlags([]string{"src", "--fail-on", "high", "extra"}); err == nil {
		t.Error("a stray argument after a trailing flag must be an error")
	}
}

func TestDoubleDashEndsFlagParsing(t *testing.T) {
	o, err := parseFlags([]string{"--fail-on", "high", "--", "--oddly-named-dir"})
	if err != nil {
		t.Fatal(err)
	}
	if o.target != "--oddly-named-dir" || o.failOn != "high" {
		t.Errorf("target=%q failOn=%q", o.target, o.failOn)
	}
	if _, err := parseFlags([]string{"--", "a", "b"}); err == nil {
		t.Error("two paths after -- is still two targets")
	}
}
