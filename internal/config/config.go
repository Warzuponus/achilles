// Package config loads the declarative tool registry (configs/tools.yaml).
// Adding a SARIF-emitting scanner should be a config entry, not Go code
// (DESIGN.md §4.4).
package config

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/Warzuponus/achilles/configs"
	"github.com/Warzuponus/achilles/internal/policy"
)

// ToolConfig declares one scanner.
type ToolConfig struct {
	ID                  string `yaml:"id"`
	License             string `yaml:"license"`
	CommercialSafe      bool   `yaml:"commercialSafe"`
	RequiresAttestation bool   `yaml:"requiresAttestation"`
	// Enabled marks a tool as part of the always-on baseline (runs in every
	// profile). Heavy/opt-in tools leave this false and list a profile instead.
	Enabled bool `yaml:"enabled"`
	// Profiles are the scan profiles (besides the baseline) this tool runs in,
	// e.g. [full]. Selected via `--profile`.
	Profiles []string `yaml:"profiles"`
	// OptIn names a feature that turns this tool on, for a pass that is neither part
	// of the baseline nor of a profile: "secrets-history" (the --secrets-history
	// flag) runs the tool over the git history. Such a tool runs only when asked for.
	OptIn string `yaml:"optIn"`
	// Bespoke marks a tool that has a hand-written adapter rather than the
	// generic config-driven runner (e.g. opengrep).
	Bespoke   bool     `yaml:"bespoke"`
	Languages []string `yaml:"languages"`
	Image     string   `yaml:"image"`
	Bin       string   `yaml:"bin"`
	// Requires lists extra executables the tool itself shells out to (gosec needs
	// `go` to type-check packages). With the local runner each must be on PATH; if
	// not, the tool FAILS with a clear message. Without this, such tools exit 0 with
	// an empty report and the scan looks clean. Ignored by the docker runner (the
	// image carries them).
	Requires   []string `yaml:"requires"`
	Format     string   `yaml:"format"`
	Argv       []string `yaml:"argv"`
	OutputFile string   `yaml:"outputFile"`
	// DiffArg is appended to Argv on a diff-aware scan (--diff REF), with {diff}
	// replaced by REF. For a tool that reads commits rather than files, it is how
	// the scan is limited to the commits under review.
	DiffArg string `yaml:"diffArg"`
	// NothingToScan lists phrases a tool prints when it exits without writing a
	// report because the target has nothing it applies to (osv-scanner on a tree
	// with no dependency manifests). Seeing one means "no results", not "the tool
	// failed", so the scan is not marked incomplete.
	NothingToScan []string `yaml:"nothingToScan"`
	// IncompleteWhen lists phrases a tool prints when it ran and wrote a report but
	// could not analyze part of the target (gosec when a package will not
	// type-check: it exits 0, writes a valid report, and silently skips every
	// analysis that needs type information). The findings it did produce are kept,
	// and the tool is reported as incomplete so the scan is never presented as a
	// full one.
	IncompleteWhen []string `yaml:"incompleteWhen"`
	// SuccessExitCodes are the exit codes that mean the tool finished its work
	// (for many scanners that includes "1: findings were reported"). When set, any
	// other exit code marks the run incomplete even though a report file exists: a
	// tool that crashes halfway can leave a well-formed report of the half it did.
	// Empty means the exit code is not checked, only that a report was written.
	SuccessExitCodes []int  `yaml:"successExitCodes"`
	Rules            string `yaml:"rules"`
	// Network is the docker network policy ("none" default for containment,
	// "default" to allow egress for tools that need it — SCA DBs, NuGet restore).
	Network string `yaml:"network"`
	// LocalConfig honors a target repo's own ignore/config files: for each rule,
	// if the target contains File, Arg is appended to the tool's argv (so the
	// tool applies the repo's existing suppressions instead of re-reporting them).
	LocalConfig []LocalConfigRule `yaml:"localConfig"`
	// RepoConfig names the files this tool reads from the scanned repository ON
	// ITS OWN, with no flag from Achilles (gitleaks loads <target>/.gitleaks.toml
	// by itself). Achilles cannot withhold these, so it names them when present,
	// and under --no-repo-config reports the tool as incomplete.
	RepoConfig []string `yaml:"repoConfig"`
}

// LocalConfigRule maps a target-local config file to the argv flag that points a
// tool at it (Arg may contain {src}/{out}/{rules} placeholders).
type LocalConfigRule struct {
	File string `yaml:"file"`
	Arg  string `yaml:"arg"`
}

// RunsInProfile reports whether this tool is active for the given scan profile:
// baseline tools (Enabled) run in every profile; others run only when the profile
// is listed in Profiles.
func (t ToolConfig) RunsInProfile(profile string) bool {
	return t.Enabled || slices.Contains(t.Profiles, profile)
}

// ToLicense projects a ToolConfig onto the fields the policy gate needs.
func (t ToolConfig) ToLicense() policy.ToolLicense {
	return policy.ToolLicense{
		ID:                  t.ID,
		License:             t.License,
		CommercialSafe:      t.CommercialSafe,
		RequiresAttestation: t.RequiresAttestation,
	}
}

// Config is the whole registry file.
type Config struct {
	Tools []ToolConfig `yaml:"tools"`
}

// Load reads and validates a tools.yaml file. An empty path loads the copy
// embedded in the binary (configs/tools.yaml, byte-identical) and points each
// tool's rules at a real directory (see ResolveRulesDir), so a downloaded
// `achilles` needs no repository checkout. An explicit path is read as-is.
func Load(path string) (*Config, error) {
	if path == "" {
		return loadEmbedded()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(data, path)
}

func loadEmbedded() (*Config, error) {
	data, err := configs.ToolsYAML()
	if err != nil {
		return nil, fmt.Errorf("read embedded config: %w", err)
	}
	c, err := parse(data, "(embedded configs/tools.yaml)")
	if err != nil {
		return nil, err
	}
	for i := range c.Tools {
		if c.Tools[i].Rules == "" {
			continue
		}
		dir, err := ResolveRulesDir(c.Tools[i].Rules)
		if err != nil {
			return nil, fmt.Errorf("tool %q: rules: %w", c.Tools[i].ID, err)
		}
		c.Tools[i].Rules = dir
	}
	return c, nil
}

func parse(data []byte, label string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", label, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c Config) validate() error {
	seen := map[string]bool{}
	for i, t := range c.Tools {
		if t.ID == "" {
			return fmt.Errorf("tool #%d: missing id", i)
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate tool id %q", t.ID)
		}
		seen[t.ID] = true
		// Any tool that can actually run (baseline or in some profile) and isn't
		// a bespoke adapter must define how to invoke it.
		if !t.Bespoke && (t.Enabled || len(t.Profiles) > 0 || t.OptIn != "") && len(t.Argv) == 0 {
			return fmt.Errorf("tool %q: runnable generic tool needs an argv", t.ID)
		}
	}
	return nil
}
