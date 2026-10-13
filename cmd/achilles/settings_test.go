package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repoWith returns a directory to scan holding the given .achilles.yaml.
func repoWith(t *testing.T, settings string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".achilles.yaml"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRepoSettings_ShapeTheScan(t *testing.T) {
	repo := repoWith(t, "# how this repository is scanned\n"+
		"profile: full\n"+
		"fail-on: High\n"+
		"exclude: [tests, \"*.gen.go\"]\n"+
		"timeout: 12m\n"+
		"baseline: .achilles/baseline.json\n"+
		"issues-max: 5\n"+
		"llm-no-code: true\n")
	o, err := parseFlags([]string{repo})
	if err != nil {
		t.Fatal(err)
	}
	if o.profile != "full" || o.failOn != "high" || o.excludePaths != "tests,*.gen.go" ||
		o.timeout != 12*time.Minute || o.issuesMax != 5 || !o.llmNoCode {
		t.Errorf("settings not applied: profile=%q failOn=%q exclude=%q timeout=%s issuesMax=%d noCode=%v",
			o.profile, o.failOn, o.excludePaths, o.timeout, o.issuesMax, o.llmNoCode)
	}
	// A path in the repository's file is relative to the repository, not to wherever
	// achilles was started.
	if want := filepath.Join(repo, ".achilles", "baseline.json"); o.baselinePath != want {
		t.Errorf("baseline = %q, want %q", o.baselinePath, want)
	}
	want := []string{"baseline", "exclude", "fail-on", "issues-max", "llm-no-code", "profile", "timeout"}
	if o.repoSettings == nil || strings.Join(o.repoSettings.Applied, " ") != strings.Join(want, " ") {
		t.Errorf("applied = %+v, want %v", o.repoSettings, want)
	}

	var out bytes.Buffer
	o.announceSettings(&out)
	if !strings.Contains(out.String(), ".achilles.yaml in the scanned repository sets baseline, exclude, fail-on") ||
		!strings.Contains(out.String(), "--no-repo-config") {
		t.Errorf("the repository's settings must be announced with the way to refuse them:\n%s", out.String())
	}
}

func TestSettings_CommandLineThenSettingsFileThenRepository(t *testing.T) {
	t.Setenv("ACHILLES_LLM_BASE_URL", "")
	repo := repoWith(t, "profile: full\nfail-on: low\ntimeout: 1m\n")
	operator := filepath.Join(t.TempDir(), "team.yaml")
	if err := os.WriteFile(operator, []byte("fail-on: medium\ntimeout: 20m\nllm-base-url: https://gateway.internal/v1\ntriage: true\nllm-model: m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := parseFlags([]string{"--settings", operator, "--timeout", "3m", "--llm-provider", "openrouter", repo})
	if err != nil {
		t.Fatal(err)
	}
	if o.timeout != 3*time.Minute {
		t.Errorf("timeout = %s: the command line must win", o.timeout)
	}
	if o.failOn != "medium" {
		t.Errorf("fail-on = %q: --settings must win over the repository's file", o.failOn)
	}
	if o.profile != "full" {
		t.Errorf("profile = %q: the repository's file sets what nothing else did", o.profile)
	}
	// The operator's file may set anything a flag can, and counts as explicit: a
	// provider preset does not replace the endpoint it names.
	if !o.triageOn || o.llmModel != "m" || o.llmBaseURL != "https://gateway.internal/v1" {
		t.Errorf("operator settings: triage=%v model=%q base=%q", o.triageOn, o.llmModel, o.llmBaseURL)
	}
	if got := strings.Join(o.repoSettings.Overridden, " "); got != "fail-on timeout" {
		t.Errorf("overridden = %q, want the two keys something more trusted set", got)
	}
	var out bytes.Buffer
	o.announceSettings(&out)
	if !strings.Contains(out.String(), "settings from "+operator) || !strings.Contains(out.String(), "also sets fail-on, timeout") {
		t.Errorf("announcement:\n%s", out.String())
	}
}

// The repository under review must not decide where its code is sent, what runs,
// what is written or what is posted. Every flag outside the short list is refused,
// whatever it is: a flag added later is refused until someone decides otherwise.
func TestRepoSettings_OnlyScanShapingKeys(t *testing.T) {
	want := []string{"baseline", "exclude", "fail-on", "issues-group", "issues-max", "issues-min-severity",
		"keep-dismissed", "llm-no-code", "no-default-excludes", "profile", "secrets-history", "timeout", "with"}
	if got := sortedKeys(repoSettingKeys); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the repository may set %v\nthis test expects %v\nWidening the list lets a pull request set that flag: decide that deliberately, then update this test and docs/cli-reference.md", got, want)
	}

	var others []string
	for _, name := range allFlagNames(t) {
		if !repoSettingKeys[name] {
			others = append(others, name)
		}
	}
	if len(others) < 60 {
		t.Fatalf("only %d flags found outside the list; the probe is broken", len(others))
	}
	for _, name := range others {
		_, err := parseFlags([]string{repoWith(t, name+": x\n")})
		refusal := "cannot be set by the scanned repository"
		if name == "settings" {
			refusal = "unknown setting" // not a setting in any file
		}
		if err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%s in the repository's file: err = %v, want a refusal", name, err)
		}
	}

	// The ones that matter most, by name, so the intent survives a refactor.
	for _, name := range []string{"llm-base-url", "llm-provider", "llm-model", "llm-auth", "model-config", "config",
		"runner", "vault", "vault-backend", "triage", "ai", "remediate", "deep-verify", "calibrate", "no-repo-config",
		"strict-tools", "html-report", "sarif-report", "diagnostics", "file-issues", "fix-pr", "pr-comment", "repo",
		"rule-repo", "attest", "mode", "max-cost"} {
		if repoSettingKeys[name] {
			t.Errorf("%s must never be settable by the scanned repository", name)
		}
	}
}

// allFlagNames lists every flag achilles defines.
func allFlagNames(t *testing.T) []string {
	t.Helper()
	fl, _ := defineFlags()
	var names []string
	fl.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	return names
}

func TestSettings_MistakesAreErrors(t *testing.T) {
	cases := map[string]struct{ file, want string }{
		"a typo":               {"fail-om: high\n", `unknown setting "fail-om"`},
		"a bad severity":       {"fail-on: severe\n", "is not a severity"},
		"a bad duration":       {"timeout: soon\n", `"soon" is not a valid value`},
		"a nested mapping":     {"exclude:\n  paths: [a]\n", "must be a plain value or a list"},
		"an empty value":       {"profile:\n", "has no value"},
		"not a mapping":        {"- profile\n", "cannot unmarshal"},
		"a baseline elsewhere": {"baseline: ../../other/baseline.json\n", "must be a path inside the scanned repository"},
		"an absolute baseline": {"baseline: /etc/passwd\n", "must be a path inside the scanned repository"},
	}
	for name, c := range cases {
		_, err := parseFlags([]string{repoWith(t, c.file)})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one containing %q", name, err, c.want)
		}
	}

	// The operator's file is checked the same way, and cannot name another one.
	operator := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(operator, []byte("settings: other.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlags([]string{"--settings", operator, t.TempDir()}); err == nil || !strings.Contains(err.Error(), "unknown setting") {
		t.Errorf("settings inside a settings file: err = %v", err)
	}
	if _, err := parseFlags([]string{"--settings", filepath.Join(t.TempDir(), "missing.yaml"), t.TempDir()}); err == nil {
		t.Error("a --settings file that does not exist must be an error")
	}

	// Two files with the two spellings: nobody can tell which one is meant.
	both := repoWith(t, "profile: full\n")
	if err := os.WriteFile(filepath.Join(both, ".achilles.yml"), []byte("profile: default\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlags([]string{both}); err == nil || !strings.Contains(err.Error(), "keep one") {
		t.Errorf("both spellings: err = %v", err)
	}
}

func TestRepoSettings_RefusedWithNoRepoConfig(t *testing.T) {
	// Even a file that would be an error is simply not read.
	repo := repoWith(t, "fail-on: high\nllm-base-url: https://attacker.example/v1\n")
	o, err := parseFlags([]string{"--no-repo-config", repo})
	if err != nil {
		t.Fatalf("--no-repo-config must ignore the file entirely: %v", err)
	}
	if o.failOn != "" || o.repoSettings != nil {
		t.Errorf("the file was applied: failOn=%q use=%+v", o.failOn, o.repoSettings)
	}
	var out bytes.Buffer
	o.announceSettings(&out)
	if !strings.Contains(out.String(), "--no-repo-config: ignoring .achilles.yaml") {
		t.Errorf("ignoring the file must be said:\n%s", out.String())
	}

	// The operator's own settings file can be what refuses it.
	operator := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(operator, []byte("no-repo-config: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, err = parseFlags([]string{"--settings", operator, repo}); err != nil || o.repoSettings != nil {
		t.Errorf("no-repo-config from --settings: err=%v use=%+v", err, o.repoSettings)
	}
}

// A symbolic link named .achilles.yaml would have achilles read a file of the
// repository's choosing from the machine running the scan.
func TestRepoSettings_SymlinkIsRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("fail-on: low\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repo, ".achilles.yaml")); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	o, err := parseFlags([]string{repo})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v (failOn=%q), want the link refused", err, o.failOn)
	}
}

// Commands that scan nothing do not read a repository's settings.
func TestRepoSettings_NotReadByVaultCommands(t *testing.T) {
	repo := repoWith(t, "this is: [not, valid\n")
	for _, args := range [][]string{{"--rule-health", repo}, {"--metrics", repo}, {"--version", repo}, {"--feedback", "fp1", "--label", "tp", repo}} {
		if _, err := parseFlags(args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// End to end: the repository's file gates and excludes, the reports say so, and
// --no-repo-config takes that power away.
func TestRun_RepoSettingsAreAppliedAndRecorded(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(target, ".achilles.yaml"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	md := filepath.Join(t.TempDir(), "r.md")
	var gated *gateError

	// The repository asks for a gate; the operator set none.
	write("fail-on: high\n")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--markdown", md, target}); !errors.As(err, &gated) {
		t.Fatalf("fail-on from .achilles.yaml: err = %v, want a *gateError", err)
	}
	report, _ := os.ReadFile(md)
	if !strings.Contains(string(report), "achilles: .achilles.yaml") {
		t.Errorf("the report must name the repository's settings file:\n%s", report)
	}

	// The repository excludes the file with the finding. That works, and is on record.
	write("exclude: [\"*.py\"]\n")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--markdown", md, "--fail-on", "high", target}); err != nil {
		t.Fatalf("with the finding excluded by the repository's file: %v", err)
	}
	if report, _ = os.ReadFile(md); !strings.Contains(string(report), "achilles: .achilles.yaml") {
		t.Errorf("an exclusion from the repository must be on record:\n%s", report)
	}

	// For code you do not trust: the file is ignored and the finding gates.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--markdown", md, "--fail-on", "high", "--no-repo-config", target}); !errors.As(err, &gated) {
		t.Fatalf("--no-repo-config: err = %v, want a *gateError", err)
	}
	if report, _ = os.ReadFile(md); strings.Contains(string(report), "achilles: .achilles.yaml") {
		t.Errorf("an ignored file must not be reported as in effect:\n%s", report)
	}
}

// The repository's settings file is recorded in the same form as a scanner's own
// configuration, so a diff that edits it is called out the same way.
func TestRepoSettings_AChangeToTheFileIsFlaggedUnderDiff(t *testing.T) {
	inEffect := []string{"gitleaks: .gitleaks.toml", "achilles: .achilles.yaml"}
	got := repoConfigChanged(inEffect, []string{"src/app.go", ".achilles.yaml"})
	if len(got) != 1 || got[0] != "achilles: .achilles.yaml" {
		t.Errorf("changed = %v, want the settings file flagged", got)
	}
}
