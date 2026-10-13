//go:build integration

// Runs `--with zizmor` with the REAL zizmor, to prove what the hermetic tests can
// only assume: its arguments, that its report arrives on stdout, how it says there
// is nothing to scan, what it says about a workflow it cannot parse, and that
// --no-config makes it ignore the repository's own configuration.
//
//	achilles tools install zizmor   # or have zizmor on PATH
//	go test -tags integration ./cmd/achilles -run Zizmor
//
// Skips when zizmor is not installed.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	"gopkg.in/yaml.v3"
)

const injectableWorkflow = `on: pull_request
permissions: {}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`

func TestIntegration_ZizmorWithRealBinary(t *testing.T) {
	if _, err := exec.LookPath("zizmor"); err != nil {
		t.Skip("zizmor not installed")
	}
	t.Setenv("ACHILLES_HOME", t.TempDir())

	// A registry holding only the embedded zizmor entry, so no other scanner has
	// to be installed.
	embedded, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var only config.Config
	for _, tc := range embedded.Tools {
		if tc.ID == "zizmor" {
			only.Tools = append(only.Tools, tc)
		}
	}
	if len(only.Tools) != 1 {
		t.Fatal("the embedded registry has no zizmor entry")
	}
	registry, err := yaml.Marshal(only)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(cfg, registry, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "scan.json")
	type report struct {
		FailedTools []string `json:"failedTools"`
		RepoConfig  []string `json:"repoConfig"`
		Findings    []struct {
			Tool     string `json:"tool"`
			RuleID   string `json:"ruleId"`
			Severity string `json:"severity"`
			Location struct {
				File   string `json:"file"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"location"`
		} `json:"findings"`
	}
	scan := func(target string, extra ...string) report {
		t.Helper()
		args := append([]string{"--config", cfg, "--vault", filepath.Join(t.TempDir(), "v.jsonl"), "--json-report", out, "--with", "zizmor"}, extra...)
		if err := run(append(args, target)); err != nil {
			t.Fatalf("run %v: %v", extra, err)
		}
		var r report
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	has := func(r report, rule string) bool {
		for _, f := range r.Findings {
			if f.RuleID == rule && f.Tool == "zizmor" && f.Location.File == ".github/workflows/pr.yml" && f.Location.Region.StartLine > 0 {
				return true
			}
		}
		return false
	}

	// A repository with no workflows: nothing to scan is a clean, complete result.
	empty := t.TempDir()
	writeFile(t, filepath.Join(empty, "app.py"), "x = 1\n")
	if r := scan(empty, "--strict-tools"); len(r.Findings) != 0 || len(r.FailedTools) != 0 {
		t.Errorf("no workflows: findings=%d failedTools=%v", len(r.Findings), r.FailedTools)
	}

	// A workflow that puts attacker-controlled text into a shell command.
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".github", "workflows", "pr.yml"), injectableWorkflow)
	r := scan(repo, "--strict-tools")
	if !has(r, "zizmor/template-injection") {
		t.Fatalf("template injection was not reported: %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.RuleID == "zizmor/template-injection" && f.Severity != "high" {
			t.Errorf("template injection severity = %s, want high", f.Severity)
		}
	}

	// The repository's own zizmor configuration can switch the rule off. That is
	// honoured and named, and --no-repo-config refuses it: the finding is back, and
	// because zizmor can be told to ignore the file the scan is still complete.
	writeFile(t, filepath.Join(repo, ".github", "zizmor.yml"), "rules:\n  template-injection:\n    disable: true\n")
	r = scan(repo)
	if has(r, "zizmor/template-injection") {
		t.Errorf("the repository's zizmor.yml was not applied: %+v", r.Findings)
	}
	if len(r.RepoConfig) != 1 || r.RepoConfig[0] != "zizmor: .github/zizmor.yml" {
		t.Errorf("repoConfig = %v, want the file named", r.RepoConfig)
	}
	r = scan(repo, "--no-repo-config", "--strict-tools")
	if !has(r, "zizmor/template-injection") || len(r.FailedTools) != 0 || len(r.RepoConfig) != 0 {
		t.Errorf("--no-repo-config: found=%v failedTools=%v repoConfig=%v", has(r, "zizmor/template-injection"), r.FailedTools, r.RepoConfig)
	}
	if err := os.Remove(filepath.Join(repo, ".github", "zizmor.yml")); err != nil {
		t.Fatal(err)
	}

	// A workflow zizmor cannot parse is skipped by it. The rest is still audited,
	// and the scan says it is incomplete.
	writeFile(t, filepath.Join(repo, ".github", "workflows", "broken.yml"), "this: [is not\n  valid yaml\n")
	r = scan(repo)
	if !has(r, "zizmor/template-injection") {
		t.Errorf("the readable workflow was not audited: %+v", r.Findings)
	}
	if strings.Join(r.FailedTools, ",") != "zizmor" {
		t.Errorf("failedTools = %v, want zizmor reported as incomplete", r.FailedTools)
	}
}
