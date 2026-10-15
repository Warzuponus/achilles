package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Warzuponus/achilles/internal/mcp"
	"github.com/Warzuponus/achilles/internal/vault"
)

const mcpUsage = `usage: achilles mcp [--vault PATH] [--vault-backend file|postgres] [--vault-tenant ID]

Serves the Evidence Vault, read-only, to an MCP client (an assistant in an editor
or terminal) over stdin and stdout. The client starts this command; it is not run
by hand. Tools: list_scans, list_findings, get_finding, rule_health.

See docs/mcp.md.
`

// runMCP serves the vault over the Model Context Protocol until the client closes
// stdin. Only protocol messages go to stdout; everything for a human goes to stderr.
func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("achilles mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, mcpUsage) }
	path := fs.String("vault", ".achilles/vault.jsonl", "Evidence Vault path (file backend)")
	backend := fs.String("vault-backend", "file", "Evidence Vault backend: file | postgres (DSN from $"+vault.EnvPostgresDSN+")")
	tenant := fs.String("vault-tenant", "default", "project to serve (postgres backend)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("achilles mcp takes no arguments besides its flags, got %q", fs.Arg(0))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := vault.Open(ctx, vault.Options{Backend: *backend, Path: *path, Tenant: *tenant, DSN: os.Getenv(vault.EnvPostgresDSN)})
	if err != nil {
		return fmt.Errorf("open the Evidence Vault: %w", err)
	}
	where := *backend
	if *backend == "" || *backend == "file" {
		where = *path
		if _, statErr := os.Stat(*path); statErr != nil {
			// Not an error: the client may start the server before the first scan.
			fmt.Fprintf(stderr, "achilles mcp: there is no vault at %s yet; the tools will have nothing to return until a scan writes one\n", *path)
		}
	}
	fmt.Fprintf(stderr, "achilles mcp: serving the Evidence Vault (%s) read-only on stdin/stdout\n", where)

	srv := mcp.New(store, currentVersion().Version, stderr)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, stdin, stdout) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil // interrupted while waiting for the client
	}
}
