package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// repoConfigUse is one scanner configuration file found in the scanned repository.
//
// These files decide what a scanner reports: an allowlist in .gitleaks.toml or a
// line in .trivyignore removes findings before Achilles ever sees them. That is
// what they are for, but it also means the repository under review can turn its
// own scan down, and a pull request can add a secret and the allowlist entry that
// hides it in the same change. So their use is never silent.
type repoConfigUse struct {
	Tool string
	File string
	// SelfRead: the tool finds this file on its own. Otherwise Achilles passes it
	// (localConfig in the registry) and can simply not pass it.
	SelfRead bool
}

func (u repoConfigUse) String() string { return u.Tool + ": " + u.File }

// repoConfigInEffect lists the configuration files in target that the registered
// scanners will read, sorted by tool then file.
func repoConfigInEffect(cfg *config.Config, reg *scanner.Registry, target string) []repoConfigUse {
	registered := map[string]bool{}
	for _, s := range reg.All() {
		registered[s.ID()] = true
	}
	var uses []repoConfigUse
	for _, tc := range cfg.Tools {
		if !registered[tc.ID] {
			continue
		}
		selfRead := map[string]bool{}
		files := append([]string(nil), tc.RepoConfig...)
		for _, f := range tc.RepoConfig {
			selfRead[f] = true
		}
		for _, lc := range tc.LocalConfig {
			if lc.File != "" && !selfRead[lc.File] {
				files = append(files, lc.File)
			}
		}
		for _, f := range files {
			if _, err := os.Lstat(filepath.Join(target, f)); err == nil {
				uses = append(uses, repoConfigUse{Tool: tc.ID, File: f, SelfRead: selfRead[f]})
			}
		}
	}
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].Tool != uses[j].Tool {
			return uses[i].Tool < uses[j].Tool
		}
		return uses[i].File < uses[j].File
	})
	return uses
}

// applyRepoConfigPolicy records and announces the repository's own scanner
// configuration, and enforces --no-repo-config.
//
// Without the flag every file in effect is named on stderr and in the reports.
// With it, files Achilles passes itself are not passed (buildRegistry dropped
// them); a file the scanner reads on its own cannot be withheld from it, so that
// scanner's result is reported as incomplete: its findings stand, but its silence
// proves nothing, and --strict-tools fails the run.
func applyRepoConfigPolicy(noRepoConfig bool, uses []repoConfigUse, scan *model.Scan, warn io.Writer) []toolDiag {
	var diags []toolDiag
	byTool := map[string][]string{}
	for _, u := range uses {
		switch {
		case !noRepoConfig:
			scan.RepoConfig = append(scan.RepoConfig, u.String())
			fmt.Fprintf(warn, "achilles: %s is configured by %s from the scanned repository (it can hide findings; --no-repo-config to refuse)\n", u.Tool, u.File)
		case u.SelfRead:
			scan.RepoConfig = append(scan.RepoConfig, u.String())
			byTool[u.Tool] = append(byTool[u.Tool], u.File)
		default:
			fmt.Fprintf(warn, "achilles: --no-repo-config: not applying %s from the scanned repository to %s\n", u.File, u.Tool)
		}
	}
	tools := make([]string, 0, len(byTool))
	for t := range byTool {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		msg := fmt.Sprintf("--no-repo-config: %s reads %s from the scanned repository on its own and Achilles cannot stop it, so what it did not report is not evidence of safety",
			t, strings.Join(byTool[t], ", "))
		fmt.Fprintln(warn, "achilles: "+msg)
		diags = append(diags, toolDiag{Tool: t, Stage: "partial", Error: msg})
	}
	return diags
}

// repoConfigChanged returns the scanner configuration files in effect that the
// diff under review itself changes: the change is editing what the scanners will
// report about it.
func repoConfigChanged(inEffect []string, changed []string) []string {
	touched := map[string]bool{}
	for _, c := range changed {
		touched[filepath.ToSlash(filepath.Clean(c))] = true
	}
	var out []string
	for _, entry := range inEffect {
		if _, file, ok := strings.Cut(entry, ": "); ok && touched[filepath.ToSlash(filepath.Clean(file))] {
			out = append(out, entry)
		}
	}
	return out
}
