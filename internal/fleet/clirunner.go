package fleet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// CLIRunner scans each job by invoking the `achilles` CLI as a subprocess,
// routing findings to the job's tenant vault. It matches the per-tenant vault
// conventions the War Room reads (file: <root>/<tenant>/vault.jsonl; postgres:
// the key "tenant-<id>"), so fleet-written data shows up there and in
// `achilles --metrics`.
type CLIRunner struct {
	Bin        string // path to the achilles binary
	Backend    string // "file" | "postgres"
	VaultRoot  string // per-tenant vault root (file backend)
	ScanRunner string // tool runner passed through: "local" | "docker"
	LLM        LLMOptions
}

// LLMOptions forwards the engine's LLM connection + which analyses to run to each
// per-tenant `achilles` invocation. No credential is passed here: the achilles
// subprocess inherits ACHILLES_LLM_API_KEY from the environment, so nothing secret
// lands on a command line.
type LLMOptions struct {
	BaseURL     string   // --llm-base-url
	Model       string   // --llm-model (default/fallback)
	ModelConfig string   // --model-config (per-task routing YAML in the image)
	Auth        string   // --llm-auth: "key" | "api-key" | "none"
	Analyses    []string // subset of AllowedAnalyses -> the matching --<name> flags
}

// AllowedAnalyses are the vault-recording, no-output-path analyses the fleet may
// enable per tenant. threat-model/fix-pr/remediate-to-PR need a path or write
// side effects, so they're deliberately excluded from fleet fan-out.
var AllowedAnalyses = map[string]bool{
	"triage": true, "review": true, "sca-advice": true,
}

// llmArgs renders the LLM flags. Empty fields are skipped; analyses are emitted as
// `--<name>` for each allowed entry (unknown entries are ignored — the CLI
// validates them up front).
func (o LLMOptions) llmArgs() []string {
	var a []string
	if o.BaseURL != "" {
		a = append(a, "--llm-base-url", o.BaseURL)
	}
	if o.Model != "" {
		a = append(a, "--llm-model", o.Model)
	}
	if o.ModelConfig != "" {
		a = append(a, "--model-config", o.ModelConfig)
	}
	if o.Auth != "" {
		a = append(a, "--llm-auth", o.Auth)
	}
	for _, an := range o.Analyses {
		if AllowedAnalyses[an] {
			a = append(a, "--"+an)
		}
	}
	return a
}

// buildArgs assembles the full achilles argv for a job. Flags MUST precede the
// target (stdlib flag parsing stops at the first positional).
func (r CLIRunner) buildArgs(j Job) []string {
	runner := r.ScanRunner
	if runner == "" {
		runner = "docker"
	}
	args := r.vaultArgs(j.Tenant)
	args = append(args, "--runner", runner, "--mode", j.Mode, "--profile", j.Profile)
	args = append(args, r.LLM.llmArgs()...)
	if j.Source != nil {
		// A fetched checkout lives in an ephemeral dir; record the stable,
		// credential-free repo URL + resolved commit as the run's identity instead
		// of that throwaway path.
		args = append(args, "--target-label", j.Source.URL)
		if j.Commit != "" {
			args = append(args, "--source-commit", j.Commit)
		}
	}
	args = append(args, j.Target)
	return args
}

// Scan runs one job. It never returns an error from the function itself — a
// failed scan is reported in Result.Err so the dispatcher keeps going.
func (r CLIRunner) Scan(ctx context.Context, j Job) Result {
	cmd := exec.CommandContext(ctx, r.Bin, r.buildArgs(j)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// achilles exits 1 on a gating finding (not a run failure); treat only
		// non-run errors as failures. Exit 1 with output is still a completed scan.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return Result{Job: j, Detail: "findings gated (exit 1)"}
		}
		return Result{Job: j, Err: err, Detail: tail(stderr.String())}
	}
	return Result{Job: j}
}

// vaultArgs builds the CLI flags that route to the tenant's isolated vault.
func (r CLIRunner) vaultArgs(tenant string) []string {
	switch r.Backend {
	case "postgres":
		// The DSN (a password) is NOT forwarded as a flag: the scan inherits
		// ACHILLES_VAULT_DSN from this process's environment.
		return []string{"--vault-backend", "postgres", "--vault-tenant", tenant}
	}
	return []string{"--vault", filepath.Join(r.VaultRoot, tenant, "vault.jsonl")}
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	const max = 400
	if len(s) > max {
		return "..." + s[len(s)-max:]
	}
	return s
}

// Ensure CLIRunner satisfies Runner.
var _ Runner = CLIRunner{}

// Describe is a human summary of where a runner writes (for the CLI banner).
func (r CLIRunner) Describe() string {
	switch r.Backend {
	case "postgres":
		return "postgres (one database, a key per project)"
	}
	return fmt.Sprintf("file (%s/<tenant>/vault.jsonl)", r.VaultRoot)
}
