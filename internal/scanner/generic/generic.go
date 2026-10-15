// Package generic is a config-driven scanner adapter: it runs any tool declared
// in configs/tools.yaml that emits SARIF, with no tool-specific Go code. This is
// the modularity claim from DESIGN.md §4.4 made real — gosec, Trivy, and most
// SARIF-emitting tools are just config entries plus this one adapter.
package generic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// StdoutReport as a tool's outputFile means its report is what it prints on
// standard output.
const StdoutReport = "{stdout}"

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
	if s.cfg.OutputFile == StdoutReport {
		// A tool with no "write the report to this file" option prints it instead.
		// (The read above found no such file; its result is replaced here.)
		data, err = res.Stdout, nil
		if len(strings.TrimSpace(string(data))) == 0 {
			data, err = nil, errors.New("the tool printed no report")
		}
	}
	// "Nothing here for me" is a finished run with no results. The exit code a tool
	// uses to say so (osv-scanner: 128, zizmor: 3) is then not an unexpected one.
	nothing := false
	if err != nil && nothingToScan(s.cfg.NothingToScan, res) {
		data, err = []byte(fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":%q}},"results":[]}]}`, s.cfg.ID)), nil
		nothing = true
	}
	if err != nil {
		return scanner.RawResult{}, fmt.Errorf("%s: reading %s failed (exit %d): %w (stderr: %s)",
			s.cfg.ID, filepath.Base(outHost), res.ExitCode, err, string(res.Stderr))
	}

	format := s.cfg.Format
	if format == "" {
		format = "sarif" // default/common path
	}
	incomplete := incompleteReason(s.cfg.IncompleteWhen, res)
	if incomplete == "" && !nothing {
		incomplete = unexpectedExit(s.cfg.SuccessExitCodes, res)
	}
	return scanner.RawResult{
		Tool:       s.cfg.ID,
		Format:     format,
		Data:       data,
		ExitCode:   res.ExitCode,
		Stderr:     string(res.Stderr),
		Incomplete: incomplete,
	}, nil
}

// unexpectedExit returns why a run that wrote a report is still not a complete
// one: the tool exited with a code that is not among those the registry lists as
// "finished" (see config.ToolConfig.SuccessExitCodes). It is "" when the code is
// expected or the registry lists none. The last line the tool printed is quoted,
// since that is usually the error.
func unexpectedExit(ok []int, res xexec.Result) string {
	if len(ok) == 0 {
		return ""
	}
	for _, code := range ok {
		if res.ExitCode == code {
			return ""
		}
	}
	reason := fmt.Sprintf("exited with code %d after writing a report, which is not how it ends a completed scan", res.ExitCode)
	lines := strings.Split(strings.TrimSpace(string(res.Stderr)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		if r := []rune(last); len(r) > 300 {
			last = string(r[:300]) + "..."
		}
		reason += ": " + last
	}
	return reason
}

// incompleteReason returns what the tool said about not analyzing part of the
// target (see config.ToolConfig.IncompleteWhen), or "" if it said nothing of the
// kind. It quotes the first matching line and counts the rest, so the user sees
// the tool's own words: usually the name of the package that failed and why.
func incompleteReason(phrases []string, res xexec.Result) string {
	if len(phrases) == 0 {
		return ""
	}
	first, n := "", 0
	for _, line := range strings.Split(string(res.Stderr)+"\n"+string(res.Stdout), "\n") {
		for _, p := range phrases {
			if p != "" && strings.Contains(line, p) {
				if n == 0 {
					first = strings.TrimSpace(line)
				}
				n++
				break
			}
		}
	}
	if n == 0 {
		return ""
	}
	if r := []rune(first); len(r) > 300 {
		first = string(r[:300]) + "..."
	}
	if n > 1 {
		return fmt.Sprintf("%s (and %d more like it)", first, n-1)
	}
	return first
}

// nothingToScan reports whether the tool said, in its output, that the target has
// nothing it applies to (see config.ToolConfig.NothingToScan).
func nothingToScan(phrases []string, res xexec.Result) bool {
	out := string(res.Stderr) + "\n" + string(res.Stdout)
	for _, p := range phrases {
		if p != "" && strings.Contains(out, p) {
			return true
		}
	}
	return false
}
