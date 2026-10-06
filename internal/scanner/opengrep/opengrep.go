// Package opengrep adapts the Opengrep engine (LGPL-2.1 Semgrep CE fork) to the
// scanner.Scanner interface. Opengrep is Achilles's primary multi-language
// engine and is commercial-safe (see DESIGN.md §3).
package opengrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// Scanner runs Opengrep and returns its SARIF output.
type Scanner struct {
	runner xexec.Runner
	// RulesPath is a host directory of rule YAML passed to `-f`.
	rulesPath string
	// bin is the executable name; empty relies on the container entrypoint.
	bin   string
	image string
	// extraRules is an optional second rules directory (the installed community
	// pack), passed as an additional `-f`. The primary rulesPath stays the offline
	// fallback; both are loaded when this is set.
	extraRules string
}

// Option configures the scanner.
type Option func(*Scanner)

func WithBin(bin string) Option   { return func(s *Scanner) { s.bin = bin } }
func WithImage(img string) Option { return func(s *Scanner) { s.image = img } }

// WithExtraRules adds a second rules directory loaded alongside the primary one.
func WithExtraRules(dir string) Option { return func(s *Scanner) { s.extraRules = dir } }

// New builds an Opengrep scanner. runner selects local vs container execution;
// rulesPath points at a directory of rule YAML.
func New(runner xexec.Runner, rulesPath string, opts ...Option) *Scanner {
	s := &Scanner{runner: runner, rulesPath: rulesPath, bin: "opengrep"}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Scanner) ID() string { return "opengrep" }

func (s *Scanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:             "opengrep",
		License:        "LGPL-2.1",
		CommercialSafe: true,
		Languages:      []string{"python", "javascript", "typescript", "go", "java", "ruby", "generic"},
		Image:          s.image,
	}
}

// Applicable: Opengrep is multi-language, so it applies to any non-empty target.
func (s *Scanner) Applicable(t scanner.Target) bool { return t.Path != "" }

// Run executes `opengrep scan --sarif-output=<out>/results.sarif -f <rules> <src>`
// and returns the SARIF bytes.
func (s *Scanner) Run(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	outDir, err := os.MkdirTemp("", "achilles-opengrep-*")
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("temp out dir: %w", err)
	}
	defer os.RemoveAll(outDir)

	cmd := xexec.Command{
		Bin:   s.bin,
		Image: s.image,
		Args: []string{
			"scan",
			"--quiet",
			// Keep each rule's own id instead of prefixing the (absolute, and
			// here temp) rules-dir path — otherwise ruleIds, and the
			// fingerprints derived from them, would vary by machine and by run.
			"--no-rewrite-rule-ids",
			"--sarif-output={out}/results.sarif",
			"-f", "{rules}",
			"{src}",
		},
		Mounts: []xexec.Mount{
			{Name: "src", HostPath: t.Path, ReadOnly: true},
			{Name: "rules", HostPath: s.rulesPath, ReadOnly: true},
			{Name: "out", HostPath: outDir, ReadOnly: false},
		},
	}

	if s.extraRules != "" {
		// Second -f before the {src} positional (the last argument).
		n := len(cmd.Args) - 1
		cmd.Args = append(cmd.Args[:n:n], "-f", "{rules2}", cmd.Args[n])
		cmd.Mounts = append(cmd.Mounts, xexec.Mount{Name: "rules2", HostPath: s.extraRules, ReadOnly: true})
	}

	res, err := s.runner.Run(ctx, cmd)
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("opengrep run: %w", err)
	}
	// Opengrep/Semgrep exit codes: 0 = no findings, 1 = findings, >=2 = error.
	if res.ExitCode >= 2 {
		return scanner.RawResult{}, fmt.Errorf("opengrep failed (exit %d): %s", res.ExitCode, string(res.Stderr))
	}

	data, err := os.ReadFile(filepath.Join(outDir, "results.sarif"))
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("read opengrep sarif output: %w (stderr: %s)", err, string(res.Stderr))
	}

	return scanner.RawResult{
		Tool:     s.ID(),
		Format:   "sarif",
		Data:     data,
		ExitCode: res.ExitCode,
		Stderr:   string(res.Stderr),
	}, nil
}
