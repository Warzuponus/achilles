package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/generic"
)

// repoConfigFixture is fakeScanFixture with a scanner that honors two files from
// the scanned repository: .fakeignore, which Achilles passes to it (localConfig),
// and .fakeself, which it would read on its own (repoConfig).
func repoConfigFixture(t *testing.T) (cfg, target, vaultPath string) {
	t.Helper()
	cfg, target, vaultPath = fakeScanFixture(t)
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(b) +
		"    localConfig:\n" +
		"      - file: .fakeignore\n" +
		"        arg: \"--honor-ignore\"\n" +
		"    repoConfig: [.fakeself]\n"
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, target, vaultPath
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A repository's own ignore file can hide a finding. That is its purpose, but the
// repository under review must not be able to do it unseen, or at all when the
// operator says the code is not trusted.
func TestRun_RepositoryScannerConfigIsNamedAndCanBeRefused(t *testing.T) {
	cfg, target, vaultPath := repoConfigFixture(t)
	touch(t, filepath.Join(target, ".fakeignore"))
	md := filepath.Join(t.TempDir(), "report.md")

	// Default: the file is applied (the finding is gone, so the gate passes), and
	// every report says a repository-supplied configuration was in effect.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--fail-on", "high", "--markdown", md, target}); err != nil {
		t.Fatalf("with the repository's ignore file applied the finding is hidden: err = %v", err)
	}
	report, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "fakescan: .fakeignore") || !strings.Contains(string(report), "from the scanned repository") {
		t.Errorf("the report must name the repository's scanner configuration:\n%s", report)
	}

	// --no-repo-config: the file is not passed, so the finding is back and gates.
	err = run([]string{"--config", cfg, "--vault", vaultPath, "--fail-on", "high", "--no-repo-config", "--markdown", md, target})
	var gated *gateError
	if !errors.As(err, &gated) {
		t.Fatalf("--no-repo-config must stop the ignore file hiding the finding: err = %v, want a *gateError", err)
	}
	report, _ = os.ReadFile(md)
	if strings.Contains(string(report), "fakescan: .fakeignore") {
		t.Errorf("a file that was not applied must not be reported as in effect:\n%s", report)
	}
}

// A file the scanner reads by itself cannot be withheld. Under --no-repo-config
// that scanner's result is incomplete: its findings stand, its silence proves nothing.
func TestRun_NoRepoConfigMarksASelfConfiguringScannerIncomplete(t *testing.T) {
	cfg, target, vaultPath := repoConfigFixture(t)
	touch(t, filepath.Join(target, ".fakeself"))
	md := filepath.Join(t.TempDir(), "report.md")

	err := run([]string{"--config", cfg, "--vault", vaultPath, "--no-repo-config", "--strict-tools", target})
	if err == nil || !strings.Contains(err.Error(), "--strict-tools") || !strings.Contains(err.Error(), "fakescan") {
		t.Errorf("err = %v, want a --strict-tools failure naming the scanner", err)
	}

	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--no-repo-config", "--markdown", md, target}); err != nil {
		t.Fatalf("without --strict-tools this is a warning: %v", err)
	}
	report, _ := os.ReadFile(md)
	if !strings.Contains(string(report), "Incomplete scan") || !strings.Contains(string(report), "cmd-injection") {
		t.Errorf("the scan must be reported incomplete and keep the findings it has:\n%s", report)
	}

	// Without the flag the same file is only named.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--strict-tools", "--markdown", md, target}); err != nil {
		t.Fatalf("without --no-repo-config a repository config file does not fail a strict scan: %v", err)
	}
	report, _ = os.ReadFile(md)
	if !strings.Contains(string(report), "fakescan: .fakeself") {
		t.Errorf("the report must name the file:\n%s", report)
	}
}

func TestRepoConfigInEffect_OnlyRegisteredToolsAndPresentFiles(t *testing.T) {
	target := t.TempDir()
	touch(t, filepath.Join(target, ".gitleaks.toml"))
	touch(t, filepath.Join(target, ".trivyignore"))
	touch(t, filepath.Join(target, "osv-scanner.toml"))

	cfg := &config.Config{Tools: []config.ToolConfig{
		{ID: "gitleaks", LocalConfig: []config.LocalConfigRule{{File: ".gitleaks.toml", Arg: "--config=x"}}, RepoConfig: []string{".gitleaks.toml", ".gitleaksignore"}},
		{ID: "trivy", LocalConfig: []config.LocalConfigRule{{File: ".trivyignore", Arg: "--ignorefile=x"}}},
		{ID: "osv-scanner", RepoConfig: []string{"osv-scanner.toml"}}, // not registered below
	}}
	reg := scanner.NewRegistry()
	for _, id := range []string{"gitleaks", "trivy"} {
		if err := reg.Register(generic.New(nil, config.ToolConfig{ID: id}, "")); err != nil {
			t.Fatal(err)
		}
	}

	got := repoConfigInEffect(cfg, reg, target)
	want := []repoConfigUse{
		{Tool: "gitleaks", File: ".gitleaks.toml", SelfRead: true}, // listed both ways: counted once, as self-read
		{Tool: "trivy", File: ".trivyignore", SelfRead: false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("use %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRepoConfigChanged(t *testing.T) {
	inEffect := []string{"gitleaks: .gitleaks.toml", "trivy: .trivyignore"}
	got := repoConfigChanged(inEffect, []string{"src/app.py", "./.gitleaks.toml"})
	if len(got) != 1 || got[0] != "gitleaks: .gitleaks.toml" {
		t.Errorf("got %v, want only the gitleaks file (the diff touches it)", got)
	}
	if got := repoConfigChanged(inEffect, []string{"src/app.py", "docs/.trivyignore"}); len(got) != 0 {
		t.Errorf("a same-named file elsewhere is not the one in effect: %v", got)
	}
}

func TestApplyRepoConfigPolicy(t *testing.T) {
	uses := []repoConfigUse{
		{Tool: "gitleaks", File: ".gitleaks.toml", SelfRead: true},
		{Tool: "gitleaks", File: ".gitleaksignore", SelfRead: true},
		{Tool: "trivy", File: ".trivyignore", SelfRead: false},
	}

	var scan model.Scan
	var out strings.Builder
	if diags := applyRepoConfigPolicy(false, uses, &scan, &out); len(diags) != 0 {
		t.Errorf("without the flag nothing is incomplete: %+v", diags)
	}
	if len(scan.RepoConfig) != 3 || strings.Count(out.String(), "from the scanned repository") != 3 {
		t.Errorf("every file in effect must be recorded and announced: %v\n%s", scan.RepoConfig, out.String())
	}

	scan, out = model.Scan{}, strings.Builder{}
	diags := applyRepoConfigPolicy(true, uses, &scan, &out)
	if len(diags) != 1 || diags[0].Tool != "gitleaks" || diags[0].Stage != "partial" ||
		!strings.Contains(diags[0].Error, ".gitleaks.toml, .gitleaksignore") {
		t.Errorf("want one incomplete diagnostic for gitleaks naming both files, got %+v", diags)
	}
	if len(scan.RepoConfig) != 2 {
		t.Errorf("only the files still in effect are recorded: %v", scan.RepoConfig)
	}
	if !strings.Contains(out.String(), "not applying .trivyignore") {
		t.Errorf("a withheld file must be announced too:\n%s", out.String())
	}
}
