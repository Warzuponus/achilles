package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Warzuponus/achilles/internal/surface"
)

func runInitIn(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	err = runInit(args, &out, &errb)
	return out.String(), errb.String(), err
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInit_GitHubRepository(t *testing.T) {
	repo := gitRepo(t, map[string]string{".github/workflows/ci.yml": "on: push\n", "README.md": "x\n", ".gitignore": "bin/"})
	out, _, err := runInitIn(t, "--no-baseline", repo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "CI: github, it has .github/workflows") {
		t.Errorf("output:\n%s", out)
	}

	// The settings file is a valid settings file: it parses, and the scan accepts it.
	settings := read(t, filepath.Join(repo, ".achilles.yaml"))
	values, err := parseSettings([]byte(settings))
	if err != nil || values["fail-on"] != "high" || values["baseline"] != ".achilles/baseline.json" {
		t.Errorf("settings = %v, err = %v", values, err)
	}
	if _, err := parseFlags([]string{repo}); err != nil {
		t.Errorf("the generated settings are rejected by a scan: %v", err)
	}

	// The workflow parses, scans pull requests and the branch, and needs no secret.
	wf := read(t, filepath.Join(repo, ".github", "workflows", "achilles.yml"))
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(wf), &doc); err != nil {
		t.Fatalf("the generated workflow is not YAML: %v\n%s", err, wf)
	}
	for _, want := range []string{"pull_request:", "branches: [main]", "persist-credentials: false", "with: zizmor", "--diff origin/"} {
		if !strings.Contains(wf, want) {
			t.Errorf("workflow lacks %q:\n%s", want, wf)
		}
	}
	if strings.Contains(wf, "secrets.") || strings.Contains(wf, "__") {
		t.Errorf("the workflow uses a secret or has an unfilled placeholder:\n%s", wf)
	}

	// The threat-context template is written, and parses as an empty context.
	if _, err := surface.ParseContext([]byte(read(t, filepath.Join(repo, ".achilles", "threat-context.yaml")))); err != nil {
		t.Errorf("the threat-context template does not parse: %v", err)
	}

	// .gitignore gains the vault, once, after what was there.
	gi := read(t, filepath.Join(repo, ".gitignore"))
	if !strings.HasPrefix(gi, "bin/\n") || strings.Count(gi, "/.achilles/vault.jsonl*") != 1 {
		t.Errorf(".gitignore:\n%s", gi)
	}

	// Running it again changes nothing and says so.
	out, _, err = runInitIn(t, "--no-baseline", repo)
	if err != nil || strings.Count(out, "kept ") != 3 || strings.Contains(out, "updated  .gitignore") {
		t.Errorf("second run (err %v):\n%s", err, out)
	}
	if read(t, filepath.Join(repo, ".gitignore")) != gi {
		t.Error("a second run changed .gitignore")
	}

	// --force replaces; a file the user edited is otherwise theirs.
	if err := os.WriteFile(filepath.Join(repo, ".achilles.yaml"), []byte("fail-on: low\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runInitIn(t, "--no-baseline", repo); err != nil || read(t, filepath.Join(repo, ".achilles.yaml")) != "fail-on: low\n" {
		t.Errorf("an edited settings file was replaced without --force (err %v)", err)
	}
	if out, _, err := runInitIn(t, "--no-baseline", "--force", repo); err != nil || !strings.Contains(out, "replaced .achilles.yaml") {
		t.Errorf("--force (err %v):\n%s", err, out)
	}
}

func TestInit_GitLabAndNone(t *testing.T) {
	repo := gitRepo(t, map[string]string{".gitlab-ci.yml": "stages: [test]\n"})
	out, _, err := runInitIn(t, "--no-baseline", repo)
	if err != nil || !strings.Contains(out, "CI: gitlab") {
		t.Fatalf("err %v:\n%s", err, out)
	}
	job := read(t, filepath.Join(repo, ".gitlab", "achilles.yml"))
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(job), &doc); err != nil {
		t.Fatalf("the generated GitLab job is not YAML: %v", err)
	}
	for _, want := range []string{"artifacts:", "sast: gl-sast-report.json", "safe.directory", "--diff origin/"} {
		if !strings.Contains(job, want) {
			t.Errorf("GitLab job lacks %q", want)
		}
	}
	if !strings.Contains(out, "local: .gitlab/achilles.yml") {
		t.Errorf("the next steps must say how to include the job:\n%s", out)
	}
	// .gitlab-ci.yml itself is the user's file: never touched.
	if read(t, filepath.Join(repo, ".gitlab-ci.yml")) != "stages: [test]\n" {
		t.Error(".gitlab-ci.yml was modified")
	}

	plain := t.TempDir()
	if out, _, err := runInitIn(t, "--no-baseline", plain); err != nil || strings.Contains(out, "workflow") || strings.Contains(out, "CI:") {
		t.Errorf("no CI found (err %v):\n%s", err, out)
	}
	if !exists(filepath.Join(plain, ".achilles.yaml")) || exists(filepath.Join(plain, ".github")) {
		t.Error("with no CI found, only the settings file is written")
	}
}

func TestInit_DryRunWritesNothing(t *testing.T) {
	repo := gitRepo(t, map[string]string{".github/workflows/ci.yml": "on: push\n"})
	out, _, err := runInitIn(t, "--dry-run", repo)
	if err != nil || !strings.Contains(out, "would write .achilles.yaml") || !strings.Contains(out, "would add the Evidence Vault") {
		t.Fatalf("err %v:\n%s", err, out)
	}
	for _, p := range []string{".achilles.yaml", ".github/workflows/achilles.yml", ".gitignore", ".achilles"} {
		if exists(filepath.Join(repo, filepath.FromSlash(p))) {
			t.Errorf("--dry-run wrote %s", p)
		}
	}
}

func TestInit_UsageErrors(t *testing.T) {
	if _, _, err := runInitIn(t, "--ci", "jenkins", t.TempDir()); err == nil {
		t.Error("an unknown CI must be an error")
	}
	if _, _, err := runInitIn(t, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a directory that does not exist must be an error")
	}
	if _, _, err := runInitIn(t, "a", "b"); err == nil {
		t.Error("two directories must be an error")
	}
	// It is reached by name, like the other subcommands.
	var out, errb bytes.Buffer
	if handled, err := runSubcommand([]string{"init", "--help"}, &out, &errb); !handled || err != nil || !strings.Contains(errb.String(), "achilles init") {
		t.Errorf("handled=%v err=%v help=%q", handled, err, errb.String())
	}
}

// .gitignore that already keeps .achilles/ out is left as it is.
func TestInit_GitignoreAlreadyCoversTheVault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("/.achilles/*\n!/.achilles/baseline.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, _, err := runInitIn(t, "--no-baseline", "--ci", "none", dir); err != nil || strings.Contains(out, ".gitignore") {
		t.Errorf("err %v:\n%s", err, out)
	}
	if got := read(t, filepath.Join(dir, ".gitignore")); got != "/.achilles/*\n!/.achilles/baseline.json" {
		t.Errorf(".gitignore = %q", got)
	}
}

// The point of init: after it, the code as it is passes, and a new finding fails.
func TestInit_SeedsTheBaselineSoOnlyNewFindingsFail(t *testing.T) {
	cfg, target, _ := fakeScanFixture(t) // app.py has one high finding
	out, errOut, err := runInitIn(t, "--config", cfg, "--ci", "none", target)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, errOut)
	}
	if !strings.Contains(out, "Seeding the baseline") || strings.Contains(out, "seed the baseline:") {
		t.Errorf("the baseline should have been seeded:\n%s\n%s", out, errOut)
	}
	var bl struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if err := json.Unmarshal([]byte(read(t, filepath.Join(target, ".achilles", "baseline.json"))), &bl); err != nil || len(bl.Fingerprints) != 1 {
		t.Fatalf("baseline = %+v, err = %v", bl, err)
	}

	// The scan CI will run: settings from .achilles.yaml (fail on high, this baseline).
	vault := filepath.Join(t.TempDir(), "v.jsonl")
	if err := run([]string{"--config", cfg, "--vault", vault, target}); err != nil {
		t.Errorf("the code as it was when init ran must pass: %v", err)
	}
	writeFile(t, filepath.Join(target, "new.py"), "import os\nos.system(other)\n")
	var gated *gateError
	if err := run([]string{"--config", cfg, "--vault", vault, target}); !errors.As(err, &gated) {
		t.Errorf("a new high finding must fail: err = %v", err)
	}
}

// A scan that could not run every scanner must not leave a baseline behind: it
// would miss that scanner's existing findings, and they would fail the first real run.
func TestInit_NoBaselineFromAnIncompleteScan(t *testing.T) {
	_, target, _ := fakeScanFixture(t)
	broken := filepath.Join(t.TempDir(), "tools.yaml")
	reg := "tools:\n  - id: missing\n    license: MIT\n    commercialSafe: true\n    enabled: true\n    languages: [generic]\n" +
		"    bin: no-such-scanner-anywhere\n    format: sarif\n    argv: [\"{out}/r.sarif\", \"{src}\"]\n    outputFile: \"{out}/r.sarif\"\n"
	if err := os.WriteFile(broken, []byte(reg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := runInitIn(t, "--config", broken, "--ci", "none", target)
	if err != nil {
		t.Fatalf("init itself must still succeed: %v", err)
	}
	if exists(filepath.Join(target, ".achilles", "baseline.json")) {
		t.Error("a baseline from an incomplete scan was left behind")
	}
	if !strings.Contains(errOut, "the baseline was not seeded") || !strings.Contains(out, "achilles --write-baseline") {
		t.Errorf("init must say the baseline was not seeded and how to do it:\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
}

func TestActionPin(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	for _, c := range []struct {
		v    versionInfo
		want string
	}{
		{versionInfo{Version: "v0.2.0", Commit: commit}, commit + " # v0.2.0"},
		{versionInfo{Version: "v0.2.0", Commit: commit + "-dirty"}, "v0.2.0 # pin the commit"},
		{versionInfo{Version: "v0.2.0-rc1", Commit: commit}, "main # pin a release"},
		{versionInfo{Version: "dev", Commit: "unknown"}, "main # pin a release"},
	} {
		if got := actionPin(c.v); !strings.HasPrefix(got, c.want) {
			t.Errorf("actionPin(%+v) = %q, want it to start with %q", c.v, got, c.want)
		}
	}
	if imageTag(versionInfo{Version: "v0.2.0"}) != "0.2.0" || imageTag(versionInfo{Version: "dev"}) != "latest" {
		t.Error("imageTag")
	}
}
