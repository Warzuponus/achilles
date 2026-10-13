package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
)

// withFixture is fakeScanFixture plus an opt-in tool, "extra", that prints its
// report on stdout, reads a configuration file from the repository by itself, and
// has a switch to stop doing so.
func withFixture(t *testing.T) (cfg, target, vaultPath, argsFile string) {
	t.Helper()
	cfg, target, vaultPath = fakeScanFixture(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	extra := "  - id: extra\n" +
		"    license: MIT\n" +
		"    commercialSafe: true\n" +
		"    optIn: extra\n" +
		"    languages: [generic]\n" +
		"    bin: '" + filepath.ToSlash(self) + "'\n" +
		"    format: sarif\n" +
		"    argv: [\"STDOUT\", \"{src}\", \"--record-args\"]\n" +
		"    outputFile: \"{stdout}\"\n" +
		"    successExitCodes: [0]\n" +
		"    noRepoConfigArgs: [\"--no-config\"]\n" +
		"    repoConfig: [extra.yml]\n"
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	argsFile = filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("ACHILLES_FAKE_RECORDED_ARGS", argsFile)
	return cfg, target, vaultPath, argsFile
}

type withReport struct {
	Tools       []string `json:"tools"`
	FailedTools []string `json:"failedTools"`
	RepoConfig  []string `json:"repoConfig"`
	Findings    []struct {
		RuleID string `json:"ruleId"`
	} `json:"findings"`
}

func readWithReport(t *testing.T, path string) withReport {
	t.Helper()
	var r withReport
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// An opt-in scanner runs only when named with --with, and its report is read from
// what it prints.
func TestRun_WithRunsAnOptInScanner(t *testing.T) {
	cfg, target, vaultPath, argsFile := withFixture(t)
	out := filepath.Join(t.TempDir(), "scan.json")

	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if r := readWithReport(t, out); strings.Join(r.Tools, ",") != "fakescan" || len(r.Findings) != 1 {
		t.Fatalf("without --with: tools=%v findings=%d", r.Tools, len(r.Findings))
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("the opt-in scanner ran without being asked for")
	}

	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--with", " Extra ,", target}); err != nil {
		t.Fatalf("run --with: %v", err)
	}
	r := readWithReport(t, out)
	if strings.Join(r.Tools, ",") != "extra,fakescan" || len(r.FailedTools) != 0 {
		t.Errorf("tools=%v failed=%v", r.Tools, r.FailedTools)
	}
	// Both tools report the same line; the report that was printed was read.
	if len(r.Findings) != 2 {
		t.Errorf("%d finding(s), want one from each scanner", len(r.Findings))
	}
}

// A name the registry does not offer is an error before anything runs: a typo
// must not turn into a scan that left the scanner out without saying so.
func TestRun_WithUnknownNameIsAnError(t *testing.T) {
	cfg, target, vaultPath, _ := withFixture(t)
	err := run([]string{"--config", cfg, "--vault", vaultPath, "--with", "extra,zizmorr", target})
	if err == nil || !strings.Contains(err.Error(), "zizmorr") || !strings.Contains(err.Error(), "extra") {
		t.Errorf("err = %v, want one that names the unknown scanner and the ones on offer", err)
	}
}

// A scanner that reads its own configuration from the repository, and can be
// told not to: under --no-repo-config it is told, the file is not in effect, and
// the scanner's result is complete. Without the flag the file is named.
func TestRun_WithScannerThatCanIgnoreItsRepoConfig(t *testing.T) {
	cfg, target, vaultPath, argsFile := withFixture(t)
	if err := os.WriteFile(filepath.Join(target, "extra.yml"), []byte("rules: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "scan.json")

	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--with", "extra", target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	args, _ := os.ReadFile(argsFile)
	if strings.Contains(string(args), "--no-config") {
		t.Errorf("the scanner was told to ignore its configuration without --no-repo-config:\n%s", args)
	}
	if r := readWithReport(t, out); len(r.RepoConfig) != 1 || r.RepoConfig[0] != "extra: extra.yml" {
		t.Errorf("repoConfig = %v, want the file named as in effect", r.RepoConfig)
	}

	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--with", "extra", "--no-repo-config", "--strict-tools", target}); err != nil {
		t.Fatalf("--no-repo-config: %v (the scanner can ignore its configuration, so the scan is complete)", err)
	}
	args, _ = os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--no-config") {
		t.Errorf("the scanner was not told to ignore its configuration:\n%s", args)
	}
	r := readWithReport(t, out)
	if len(r.RepoConfig) != 0 || len(r.FailedTools) != 0 {
		t.Errorf("repoConfig=%v failedTools=%v, want neither: the file is not in effect", r.RepoConfig, r.FailedTools)
	}
}

func TestCheckWith(t *testing.T) {
	reg := &config.Config{Tools: []config.ToolConfig{
		{ID: "a", Enabled: true},
		{ID: "zizmor", OptIn: "zizmor"},
		{ID: "gitleaks-history", OptIn: optInSecretsHistory},
	}}
	o := &options{withTools: "zizmor"}
	if err := checkWith(o, reg); err != nil || !o.optedIn("zizmor") || o.optedIn("other") || o.optedIn("") {
		t.Errorf("err=%v zizmor=%v", err, o.optedIn("zizmor"))
	}
	if o.secretsHistory || o.optedIn(optInSecretsHistory) {
		t.Error("the history scan was turned on by naming another scanner")
	}
	// The history scan can be asked for by its name too; it is the same thing.
	o = &options{withTools: "secrets-history"}
	if err := checkWith(o, reg); err != nil || !o.secretsHistory || !o.optedIn(optInSecretsHistory) {
		t.Errorf("err=%v secretsHistory=%v", err, o.secretsHistory)
	}
	// Nothing asked for, nothing checked.
	if err := checkWith(&options{}, reg); err != nil {
		t.Error(err)
	}
	// A baseline tool is not something --with turns on.
	if err := checkWith(&options{withTools: "a"}, reg); err == nil {
		t.Error("--with accepted the name of a tool that is not opt-in")
	}
}

// The embedded registry's zizmor entry: opt-in, offline, and able to refuse the
// repository's configuration.
func TestEmbeddedRegistry_Zizmor(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var z *config.ToolConfig
	for i := range cfg.Tools {
		if cfg.Tools[i].ID == "zizmor" {
			z = &cfg.Tools[i]
		}
	}
	if z == nil {
		t.Fatal("no zizmor entry")
	}
	if z.Enabled || len(z.Profiles) != 0 || z.OptIn != "zizmor" {
		t.Errorf("zizmor must be opt-in only: enabled=%v profiles=%v optIn=%q", z.Enabled, z.Profiles, z.OptIn)
	}
	argv := strings.Join(z.Argv, " ")
	// Offline always: its online audits would send the repository's action
	// references to the GitHub API, with whatever token is in the environment.
	if !strings.Contains(argv, "--offline") || z.Network == "default" {
		t.Errorf("zizmor must run offline: argv=%q network=%q", argv, z.Network)
	}
	if !strings.Contains(z.Image, "@sha256:") {
		t.Errorf("image %q is not pinned by digest", z.Image)
	}
	if len(z.NothingToScan) == 0 || len(z.IncompleteWhen) == 0 || len(z.SuccessExitCodes) == 0 {
		t.Errorf("zizmor has no guard for an empty or partial run: %+v", z)
	}
	if strings.Join(z.NoRepoConfigArgs, " ") != "--no-config" || len(z.RepoConfig) == 0 {
		t.Errorf("noRepoConfigArgs=%v repoConfig=%v", z.NoRepoConfigArgs, z.RepoConfig)
	}
}
