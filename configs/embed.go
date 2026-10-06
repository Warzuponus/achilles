// Package configs embeds the default tool registry and the baseline Opengrep
// rules so a downloaded `achilles` binary runs with no repository checkout.
//
// The embedded files ARE the on-disk files in this directory — there is no
// second copy to drift. An explicit --config path, or a configs/rules directory
// that exists on disk, still takes precedence (see internal/config).
package configs

import "embed"

// FS holds tools.yaml and the rules/ directory.
//
//go:embed tools.yaml rules
var FS embed.FS

// ToolsYAML returns the embedded default tool registry.
func ToolsYAML() ([]byte, error) { return FS.ReadFile("tools.yaml") }
