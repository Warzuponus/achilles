package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/surface"
)

// planFixture is the fake-scanner fixture with two more tools, both the fake
// scanner under real ids: checkov (in the profile; skipped without IaC files) and
// zizmor (opt-in; worth adding when the target has GitHub workflows).
func planFixture(t *testing.T) (cfg, target, vaultPath string) {
	t.Helper()
	cfg, target, vaultPath = fakeScanFixture(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	extra := ""
	for _, tool := range []struct{ id, how string }{{"checkov", "enabled: true"}, {"zizmor", "optIn: zizmor"}} {
		extra += "  - id: " + tool.id + "\n" +
			"    license: MIT\n" +
			"    commercialSafe: true\n" +
			"    " + tool.how + "\n" +
			"    languages: [generic]\n" +
			"    bin: '" + filepath.ToSlash(self) + "'\n" +
			"    format: sarif\n" +
			"    argv: [\"{out}/results.sarif\", \"{src}\"]\n" +
			"    outputFile: \"{out}/results.sarif\"\n"
	}
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	return cfg, target, vaultPath
}

func runPlanned(t *testing.T, args ...string) (model.Scan, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scan.json")
	err := run(append([]string{"--json-report", out}, args...))
	var s model.Scan
	if raw, rerr := os.ReadFile(out); rerr == nil {
		if jerr := json.Unmarshal(raw, &s); jerr != nil {
			t.Fatalf("json report: %v", jerr)
		}
	}
	return s, err
}

func TestRun_ToolPlanSkipsAScannerWithNothingToAnalyze(t *testing.T) {
	cfg, target, vaultPath := planFixture(t)
	plan := filepath.Join(t.TempDir(), "plan.json")
	s, err := runPlanned(t, "--config", cfg, "--vault", vaultPath, "--plan-out", plan, target)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if slices.Contains(s.Tools, "checkov") || !slices.Contains(s.ToolPlan.Skipped(), "checkov") {
		t.Errorf("no IaC files: checkov must be skipped, with the reason; tools %v, plan %+v", s.Tools, s.ToolPlan)
	}
	if !slices.Contains(s.Tools, "fakescan") {
		t.Errorf("a tool with no precondition runs: %v", s.Tools)
	}
	raw, err := os.ReadFile(plan)
	if err != nil || !strings.Contains(string(raw), `"toolPlan"`) {
		t.Errorf("the plan file carries the tool plan: %v", err)
	}

	// --all-tools runs it anyway.
	s, err = runPlanned(t, "--config", cfg, "--vault", vaultPath, "--all-tools", target)
	if err != nil {
		t.Fatalf("run --all-tools: %v", err)
	}
	if !slices.Contains(s.Tools, "checkov") || len(s.ToolPlan.Skipped()) != 0 || !s.ToolPlan.AllTools {
		t.Errorf("--all-tools skips nothing: tools %v, plan %+v", s.Tools, s.ToolPlan)
	}
}

// Without a reason to make a plan, the run is what it always was.
func TestRun_NoToolPlanUnlessAsked(t *testing.T) {
	cfg, target, vaultPath := planFixture(t)
	s, err := runPlanned(t, "--config", cfg, "--vault", vaultPath, target)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s.ToolPlan != nil || !slices.Contains(s.Tools, "checkov") {
		t.Errorf("no plan wanted: tools %v, plan %+v", s.Tools, s.ToolPlan)
	}
}

func TestRun_ThreatContextAddsAnInstalledOptInScanner(t *testing.T) {
	cfg, target, vaultPath := planFixture(t)
	if err := os.MkdirAll(filepath.Join(target, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without a context file the plan only recommends it.
	s, err := runPlanned(t, "--config", cfg, "--vault", vaultPath, "--plan-out", filepath.Join(t.TempDir(), "p.json"), target)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if slices.Contains(s.Tools, "zizmor") || !hasDecision(s.ToolPlan, "zizmor", model.ToolRecommended) {
		t.Errorf("no context: zizmor is recommended, not run; tools %v, plan %+v", s.Tools, s.ToolPlan)
	}

	// With one, it is added.
	if err := os.MkdirAll(filepath.Join(target, ".achilles"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := filepath.Join(target, ".achilles", "threat-context.yaml")
	if err := os.WriteFile(ctx, []byte("businessCritical: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err = runPlanned(t, "--config", cfg, "--vault", vaultPath, target)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !slices.Contains(s.Tools, "zizmor") || !slices.Contains(s.ToolPlan.Added(), "zizmor") {
		t.Errorf("context file + installed scanner: zizmor is added; tools %v, plan %+v", s.Tools, s.ToolPlan)
	}
	if s.ToolPlan.Depth != surface.DepthFull || !hasDecision(s.ToolPlan, "--profile full", model.ToolRecommended) {
		t.Errorf("business critical: depth full, and the full profile is recommended: %+v", s.ToolPlan)
	}
	// The context skipped checkov, so it is listed with the repository's configuration.
	if !slices.Contains(s.RepoConfig, "threat context: .achilles/threat-context.yaml") {
		t.Errorf("repo config: %v", s.RepoConfig)
	}

	// --no-repo-config ignores the file.
	s, err = runPlanned(t, "--config", cfg, "--vault", vaultPath, "--no-repo-config", target)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if slices.Contains(s.Tools, "zizmor") || s.ToolPlan != nil {
		t.Errorf("--no-repo-config: the context file adds nothing; tools %v, plan %+v", s.Tools, s.ToolPlan)
	}

	// A context file that does not parse fails the run, before any scanner runs.
	if err := os.WriteFile(ctx, []byte("busnessCritical: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runPlanned(t, "--config", cfg, "--vault", vaultPath, target); err == nil || !strings.Contains(err.Error(), "threat context") {
		t.Errorf("a misspelled question must fail the run, got %v", err)
	}
}

func hasDecision(p *model.ToolPlan, tool, action string) bool {
	if p == nil {
		return false
	}
	for _, d := range p.Decisions {
		if d.Tool == tool && d.Action == action {
			return true
		}
	}
	return false
}

func TestDecideTools_Rules(t *testing.T) {
	tools := &config.Config{Tools: []config.ToolConfig{
		{ID: "gosec", Enabled: true, Languages: []string{"go"}},
		{ID: "checkov", Enabled: true, Languages: []string{"generic"}},
		{ID: "shellcheck", Profiles: []string{"full"}, Languages: []string{"shell"}},
		{ID: "opengrep", Enabled: true, Languages: []string{"go", "generic"}},
		{ID: "zizmor", OptIn: "zizmor", Languages: []string{"generic"}, Bin: "zizmor"},
	}}
	root := t.TempDir()
	for rel, body := range map[string]string{
		"main.go":                  "package main\n",
		"scripts/release.sh":       "echo hi\n",
		".github/workflows/ci.yml": "on: push\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := &surface.Context{OutOfScope: []string{"scripts/"}, File: ".achilles/threat-context.yaml"}
	m, err := surface.Build(root, surface.Options{Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	installed := func(config.ToolConfig) (bool, string) { return true, "" }
	missing := func(tc config.ToolConfig) (bool, string) { return false, tc.ID + " is not installed" }

	p := decideTools(&options{profile: "full"}, tools, m, installed)
	for _, id := range []string{"gosec", "checkov", "shellcheck"} {
		if !slices.Contains(p.Skipped(), id) {
			t.Errorf("%s should be skipped: %+v", id, p.Decisions)
		}
	}
	if slices.Contains(p.Skipped(), "opengrep") || !slices.Contains(p.Added(), "zizmor") {
		t.Errorf("opengrep is never skipped; zizmor is added: %+v", p.Decisions)
	}

	// Asked for by name: never skipped, and not "added".
	p = decideTools(&options{profile: "full", withTools: "zizmor"}, tools, m, installed)
	if slices.Contains(p.Added(), "zizmor") || slices.Contains(p.Skipped(), "zizmor") {
		t.Errorf("--with zizmor: no plan decision for it: %+v", p.Decisions)
	}

	// Not installed: recommended, not added.
	p = decideTools(&options{profile: "full"}, tools, m, missing)
	if slices.Contains(p.Added(), "zizmor") || !hasDecision(p, "zizmor", model.ToolRecommended) {
		t.Errorf("a scanner that cannot launch is recommended: %+v", p.Decisions)
	}

	// A map that stopped early cannot prove a file is missing: nothing is skipped.
	m.Truncated = true
	if p := decideTools(&options{profile: "full"}, tools, m, installed); len(p.Skipped()) != 0 {
		t.Errorf("truncated map: %+v", p.Decisions)
	}
}
