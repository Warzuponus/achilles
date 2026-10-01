// Package generic is a config-driven scanner adapter: it runs any tool declared
// in configs/tools.yaml that emits SARIF, with no tool-specific Go code. This is
// the modularity claim from DESIGN.md §4.4 made real — gosec, Trivy, and most
// SARIF-emitting tools are just config entries plus this one adapter.
package generic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// Scanner runs one config-declared tool.
type Scanner struct {
	runner    xexec.Runner
	cfg       config.ToolConfig
	rulesHost string // absolute host path for {rules}, empty if the tool needs none
}

// New builds a generic scanner from a tool declaration. rulesHost is the
// resolved absolute path for the {rules} mount (empty when the tool has none).
func New(runner xexec.Runner, cfg config.ToolConfig, rulesHost string) *Scanner {
	return &Scanner{runner: runner, cfg: cfg, rulesHost: rulesHost}
}

func (s *Scanner) ID() string { return s.cfg.ID }

func (s *Scanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:             s.cfg.ID,
		License:        s.cfg.License,
		CommercialSafe: s.cfg.CommercialSafe,
		Languages:      s.cfg.Languages,
		Image:          s.cfg.Image,
	}
}

// Applicable is true when the target's detected languages overlap the tool's,
// or when either side is unspecified (let the tool decide).
func (s *Scanner) Applicable(t scanner.Target) bool {
	if t.Path == "" {
		return false
	}
	if len(s.cfg.Languages) == 0 || len(t.Languages) == 0 {
		return true
	}
	want := map[string]bool{}
	for _, l := range s.cfg.Languages {
		want[strings.ToLower(l)] = true
	}
	// "generic" is a wildcard: language-agnostic tools (SCA / secrets / IaC)
	// apply to any target regardless of the languages detected.
	if want["generic"] {
		return true
	}
	for _, l := range t.Languages {
		if want[strings.ToLower(l)] {
			return true
		}
	}
	return false
}

// Run executes the tool's argv (with {src}/{rules}/{out} mounts) and reads back
// the SARIF file it wrote.
func (s *Scanner) Run(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	if len(s.cfg.Argv) == 0 {
		return scanner.RawResult{}, fmt.Errorf("%s: no argv configured", s.cfg.ID)
	}
	if s.cfg.OutputFile == "" {
		return scanner.RawResult{}, fmt.Errorf("%s: no outputFile configured", s.cfg.ID)
	}

	// Prerequisites the tool shells out to. Only runners that can check (the local
	// one) are asked; the docker runner's image carries them.
	if p, ok := s.runner.(interface{ Has(string) bool }); ok {
		for _, req := range s.cfg.Requires {
			if !p.Has(req) {
				return scanner.RawResult{}, fmt.Errorf("%s needs `%s` on PATH (it shells out to it) — "+
					"install it, or use the image with the toolchain included", s.cfg.ID, req)
			}
		}
	}

	outDir, err := os.MkdirTemp("", "achilles-"+s.cfg.ID+"-*")
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("temp out dir: %w", err)
	}
	defer os.RemoveAll(outDir)

	mounts := []xexec.Mount{
		{Name: "src", HostPath: t.Path, ReadOnly: true},
		{Name: "out", HostPath: outDir, ReadOnly: false},
	}
	if s.rulesHost != "" {
		mounts = append(mounts, xexec.Mount{Name: "rules", HostPath: s.rulesHost, ReadOnly: true})
	}

	// Honor the target's own ignore/config files: append each rule's arg when the
	// file is present in the target (so the tool applies the repo's suppressions).
	args := append([]string(nil), s.cfg.Argv...)
	for _, lc := range s.cfg.LocalConfig {
		if lc.File == "" {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(t.Path, lc.File)); statErr == nil {
			args = append(args, lc.Arg)
		}
	}

	res, err := s.runner.Run(ctx, xexec.Command{Bin: s.cfg.Bin, Image: s.cfg.Image, Network: s.cfg.Network, Args: args, Mounts: mounts})
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("%s run: %w", s.cfg.ID, err)
	}

	// Resolve {out} in the output path to read the file the tool wrote. Many
	// scanners exit non-zero when they find issues, so we key success on the
	// output file existing, not on the exit code.
	outHost := strings.ReplaceAll(s.cfg.OutputFile, "{out}", outDir)
	data, err := os.ReadFile(outHost)
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("%s: reading %s failed (exit %d): %w (stderr: %s)",
			s.cfg.ID, filepath.Base(outHost), res.ExitCode, err, string(res.Stderr))
	}

	format := s.cfg.Format
	if format == "" {
		format = "sarif" // default/common path
	}
	return scanner.RawResult{
		Tool:     s.cfg.ID,
		Format:   format,
		Data:     data,
		ExitCode: res.ExitCode,
		Stderr:   string(res.Stderr),
	}, nil
}
