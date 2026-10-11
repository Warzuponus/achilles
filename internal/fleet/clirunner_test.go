package fleet

import (
	"path/filepath"
	"strings"
	"testing"
)

func argsStr(r CLIRunner, j Job) string { return strings.Join(r.buildArgs(j), " ") }

func TestBuildArgs_NoLLM(t *testing.T) {
	r := CLIRunner{Backend: "file", VaultRoot: "/v", ScanRunner: "local"}
	j := Job{Tenant: "acme", Target: "/code", Mode: "commercial", Profile: "default"}
	got := argsStr(r, j)
	// The vault path is built with the host's separator.
	want := "--vault " + filepath.Join("/v", "acme", "vault.jsonl") + " --runner local --mode commercial --profile default /code"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestBuildArgs_ForwardsLLMBeforeTarget(t *testing.T) {
	r := CLIRunner{Backend: "postgres", ScanRunner: "local",
		LLM: LLMOptions{BaseURL: "https://ollama.com/v1", Model: "glm-5.2",
			ModelConfig: "/etc/achilles/models.ollama.yaml",
			Analyses:    []string{"sca-advice", "review", "bogus"}}} // bogus must be dropped
	j := Job{Tenant: "acme", Target: "/code", Mode: "commercial", Profile: "full"}
	got := r.buildArgs(j)
	joined := strings.Join(got, " ")

	for _, want := range []string{
		"--vault-backend postgres", "--vault-tenant acme",
		"--llm-base-url https://ollama.com/v1", "--llm-model glm-5.2",
		"--model-config /etc/achilles/models.ollama.yaml", "--sca-advice", "--review",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, "bogus") {
		t.Error("disallowed analysis leaked into argv")
	}
	// The target must be LAST (flags precede positionals for stdlib flag parsing).
	if got[len(got)-1] != "/code" {
		t.Errorf("target not last: %v", got)
	}
	// LLM flags must come before the target.
	if strings.Index(joined, "--llm-base-url") > strings.Index(joined, "/code") {
		t.Error("--llm-base-url appears after the target")
	}
}

func TestBuildArgs_ForwardsLLMAuthModeButNeverACredential(t *testing.T) {
	// Azure-style auth needs --llm-auth api-key forwarded to every per-project scan;
	// the key itself is inherited through the environment and must not appear in argv.
	r := CLIRunner{Backend: "postgres", ScanRunner: "local",
		LLM: LLMOptions{
			BaseURL: "https://example-resource.openai.azure.com/openai/deployments/d",
			Model:   "d", Auth: "api-key", Analyses: []string{"review"}}}
	joined := strings.Join(r.buildArgs(Job{Tenant: "acme", Target: "/code"}), " ")
	if !strings.Contains(joined, "--llm-auth api-key") {
		t.Errorf("missing --llm-auth api-key in %q", joined)
	}
	for _, leak := range []string{"ACHILLES_LLM_API_KEY", "Bearer", "sk-"} {
		if strings.Contains(joined, leak) {
			t.Errorf("credential material %q leaked into argv", leak)
		}
	}
}

func TestBuildArgs_LLMConnOnly_NoAnalyses(t *testing.T) {
	// base/model set but no analyses → conn flags present, no --triage/--review.
	r := CLIRunner{Backend: "file", VaultRoot: "/v", ScanRunner: "docker",
		LLM: LLMOptions{BaseURL: "u", Model: "m"}}
	joined := argsStr(r, Job{Tenant: "t", Target: "/c"})
	if !strings.Contains(joined, "--llm-model m") {
		t.Error("expected --llm-model")
	}
	for _, bad := range []string{"--triage", "--review", "--sca-advice"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unexpected %q with no analyses", bad)
		}
	}
}

func TestBuildArgs_GitSourceRecordsStableIdentity(t *testing.T) {
	r := CLIRunner{Backend: "file", VaultRoot: "/v", ScanRunner: "local"}
	src := &GitSource{URL: "https://example.com/acme/example-app.git", Ref: "main"}
	// FetchingRunner hands the CLI the ephemeral checkout path + resolved sha.
	j := Job{Tenant: "acme", Target: "/ws/achilles-fleet-123/example-app", Mode: "oss", Profile: "default",
		Source: src, Commit: "0123456789abcdef0123456789abcdef01234567"}
	got := r.buildArgs(j)
	joined := strings.Join(got, " ")
	for _, want := range []string{
		"--target-label https://example.com/acme/example-app.git",
		"--source-commit 0123456789abcdef0123456789abcdef01234567",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if got[len(got)-1] != "/ws/achilles-fleet-123/example-app" {
		t.Errorf("checkout path must be the last (positional) arg: %v", got)
	}
	// Path jobs must not grow identity flags.
	if p := argsStr(r, Job{Tenant: "acme", Target: "/code", Mode: "oss", Profile: "default"}); strings.Contains(p, "--target-label") || strings.Contains(p, "--source-commit") {
		t.Errorf("path target gained identity flags: %q", p)
	}
}

func TestVaultArgs_PostgresNeverCarriesTheDSN(t *testing.T) {
	t.Setenv("ACHILLES_VAULT_DSN", "postgres://u:secret-pw@db/x")
	args := CLIRunner{Backend: "postgres"}.vaultArgs("acme")
	want := []string{"--vault-backend", "postgres", "--vault-tenant", "acme"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", args, want)
	}
	for _, a := range args {
		if strings.Contains(a, "secret-pw") || strings.Contains(a, "postgres://") {
			t.Errorf("DSN leaked into argv: %q", a)
		}
	}
}
