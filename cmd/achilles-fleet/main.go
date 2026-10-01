// Command achilles-fleet is the MSSP fleet-scan control plane: it reads a fleet
// definition (tenants -> targets) and dispatches a achilles scan for each target
// into that tenant's isolated Evidence Vault (DESIGN.md §10/§11, Tier E).
//
// It is a SEPARATE binary from `achilles` on purpose — the multi-tenant control
// plane is the natural OSS/commercial boundary. It shells out to the `achilles`
// CLI (the OSS engine) per target, so the engine stays the single source of
// scanning truth and cloud specifics are just flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Warzuponus/achilles/internal/fleet"
	"github.com/Warzuponus/achilles/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "achilles-fleet: "+err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("achilles-fleet", flag.ContinueOnError)
	var (
		configPath  = fs.String("config", "fleet.yaml", "fleet definition (tenants -> targets)")
		achillesBin = fs.String("achilles", "achilles", "path to the achilles binary")
		backend     = fs.String("vault-backend", "file", "per-project vault backend: file | postgres (DSN from $"+vault.EnvPostgresDSN+", inherited by each scan)")
		vaultRoot   = fs.String("vault-root", ".achilles/tenants", "per-tenant vault root (file backend)")
		scanRunner  = fs.String("runner", "docker", "tool runner passed to achilles: local | docker")
		concurrency = fs.Int("concurrency", 0, "max concurrent scans (0 = numCPU)")
		llmBaseURL  = fs.String("llm-base-url", os.Getenv("ACHILLES_LLM_BASE_URL"), "OpenAI-compatible base URL forwarded to each scan (credential per --llm-auth)")
		llmModel    = fs.String("llm-model", os.Getenv("ACHILLES_LLM_MODEL"), "default/fallback model forwarded to each scan")
		modelConfig = fs.String("model-config", "", "per-task model-routing YAML forwarded to each scan")
		llmAuth     = fs.String("llm-auth", os.Getenv("ACHILLES_LLM_AUTH"), "LLM credential forwarded to each scan: key | api-key | none")
		analyses    = fs.String("analyses", "", "comma-separated LLM analyses to run per tenant: triage | review | sca-advice")
		workspace   = fs.String("workspace", "", "parent dir for ephemeral git-source checkouts (default: the OS temp dir); each job gets its own subdir, removed afterwards")
		fetchTO     = fs.Duration("fetch-timeout", fleet.DefaultFetchTimeout, "max time to fetch one git source")
		every       = fs.Duration("every", 0, "re-run the whole dispatch on this interval until SIGINT/SIGTERM (0 = run once and exit)")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}

	cfg, err := fleet.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	switch *backend {
	case "file", "postgres":
	default:
		return fmt.Errorf("--vault-backend must be file or postgres, got %q", *backend)
	}
	if *backend == "postgres" && os.Getenv(vault.EnvPostgresDSN) == "" {
		return fmt.Errorf("%s is required for the postgres backend", vault.EnvPostgresDSN)
	}

	var analysisList []string
	for _, a := range strings.Split(*analyses, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !fleet.AllowedAnalyses[a] {
			return fmt.Errorf("--analyses %q not allowed (choose from: triage, review, sca-advice)", a)
		}
		analysisList = append(analysisList, a)
	}
	if len(analysisList) > 0 && *llmModel == "" {
		return fmt.Errorf("--analyses requires --llm-model (or ACHILLES_LLM_MODEL)")
	}

	jobs := cfg.Plan()
	if *every < 0 {
		return fmt.Errorf("--every must be a positive duration (or 0 to run once)")
	}
	cli := fleet.CLIRunner{
		Bin: *achillesBin, Backend: *backend,
		VaultRoot: *vaultRoot, ScanRunner: *scanRunner,
		LLM: fleet.LLMOptions{
			BaseURL: *llmBaseURL, Model: *llmModel, ModelConfig: *modelConfig,
			Auth: *llmAuth, Analyses: analysisList,
		},
	}
	// Git-source targets are fetched into an ephemeral dir under --workspace and
	// removed afterwards; path targets pass straight through to the CLI runner.
	runner := fleet.FetchingRunner{
		Inner: cli, Workspace: *workspace, Timeout: *fetchTO,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "achilles-fleet: "+format+"\n", args...)
		},
	}
	fmt.Fprintf(os.Stderr, "achilles-fleet: %d target(s) across %d tenant(s) -> %s\n",
		len(jobs), len(cfg.Tenants), cli.Describe())
	if len(analysisList) > 0 {
		fmt.Fprintf(os.Stderr, "achilles-fleet: LLM analyses per tenant: %s (model %s)\n",
			strings.Join(analysisList, ", "), *llmModel)
	}

	dispatch := func(ctx context.Context) fleet.Summary {
		sum := fleet.Dispatch(ctx, jobs, runner, *concurrency)
		for _, res := range sum.Results {
			status := "ok"
			if res.Err != nil {
				status = "FAILED: " + res.Detail
			} else if res.Detail != "" {
				status = res.Detail
			}
			target := res.Job.Target
			if res.Job.Commit != "" {
				target += " @" + res.Job.Commit[:12]
			}
			fmt.Printf("  [%s] %s  %s\n", res.Job.Tenant, target, status)
		}
		fmt.Fprintf(os.Stderr, "achilles-fleet: %d scan(s) — %d ok, %d failed\n", sum.Total, sum.Succeeded, sum.Failed)
		return sum
	}

	if *every == 0 {
		if dispatch(context.Background()).Failed > 0 {
			os.Exit(1)
		}
		return nil
	}

	// Scheduled mode: loop until SIGINT/SIGTERM. The signal cancels ctx, which
	// kills in-flight scans/fetches (their workspaces are still cleaned up).
	// Failures are reported each cycle but don't stop the loop.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "achilles-fleet: running every %s until interrupted\n", *every)
	fleet.Every(ctx, *every, func(ctx context.Context) { dispatch(ctx) })
	fmt.Fprintln(os.Stderr, "achilles-fleet: shutting down")
	return nil
}
