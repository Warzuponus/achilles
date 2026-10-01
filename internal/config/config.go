// Package config loads the declarative tool registry (configs/tools.yaml).
// Adding a SARIF-emitting scanner should be a config entry, not Go code
// (DESIGN.md §4.4).
package config

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

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
	Rules      string   `yaml:"rules"`
	// Network is the docker network policy ("none" default for containment,
	// "default" to allow egress for tools that need it — SCA DBs, NuGet restore).
	Network string `yaml:"network"`
	// LocalConfig honors a target repo's own ignore/config files: for each rule,
	// if the target contains File, Arg is appended to the tool's argv (so the
	// tool applies the repo's existing suppressions instead of re-reporting them).
	LocalConfig []LocalConfigRule `yaml:"localConfig"`
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

// Load reads and validates a tools.yaml file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
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
		if !t.Bespoke && (t.Enabled || len(t.Profiles) > 0) && len(t.Argv) == 0 {
			return fmt.Errorf("tool %q: runnable generic tool needs an argv", t.ID)
		}
	}
	return nil
}
