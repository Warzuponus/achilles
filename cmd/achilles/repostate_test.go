package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// A pull request that adds a finding and its baseline entry in the same change
// must not pass a diff-scoped scan quietly.
func TestRepoState_ABaselineChangedByTheCommitsUnderReviewIsFlagged(t *testing.T) {
	repo := gitRepo(t, map[string]string{
		"app.py":                  "x = 1\n",
		".achilles/baseline.json": "{}\n",
	})
	git(t, repo, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(repo, filepath.FromSlash("app.py")), "import os\nos.system(cmd)\n")
	git(t, repo, "commit", "-q", "-am", "code only")

	o := &options{diffRef: "main", baselinePath: filepath.Join(repo, ".achilles", "baseline.json")}
	var scan model.Scan
	var out bytes.Buffer
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 0 || out.Len() != 0 {
		t.Fatalf("the baseline was not touched: flagged %v\n%s", scan.RepoConfigChanged, out.String())
	}

	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/baseline.json")), `{"fingerprints":["planted"]}`+"\n")
	git(t, repo, "commit", "-q", "-am", "and the baseline")
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 1 || scan.RepoConfigChanged[0] != "baseline: .achilles/baseline.json" {
		t.Errorf("flagged = %v, want the baseline", scan.RepoConfigChanged)
	}
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "baseline: .achilles/baseline.json") {
		t.Errorf("stderr:\n%s", out.String())
	}

	// Without --diff there is no change under review to compare with.
	scan, o.diffRef = model.Scan{}, ""
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 0 {
		t.Errorf("flagged without --diff: %v", scan.RepoConfigChanged)
	}
}

// A baseline that is not committed (restored from a CI cache, or just written) is
// not part of the change, however different it is from nothing.
func TestRepoState_AnUntrackedBaselineIsNotAChange(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": "x = 1\n"})
	git(t, repo, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/baseline.json")), `{"fingerprints":["a"]}`+"\n")

	o := &options{diffRef: "main", prMini: filepath.Join(repo, ".achilles", "baseline.json")}
	var scan model.Scan
	var out bytes.Buffer
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 0 {
		t.Errorf("flagged = %v, want nothing", scan.RepoConfigChanged)
	}
}

// Feedback in a vault committed with the code can be written by whoever changes
// the code. --calibrate dismisses findings on that feedback with no review, so its
// use is named, a change to it is flagged, and --no-repo-config refuses it.
func TestRepoState_FeedbackFromACommittedVault(t *testing.T) {
	repo := gitRepo(t, map[string]string{
		"app.py":                "x = 1\n",
		".achilles/vault.jsonl": `{"kind":"feedback"}` + "\n",
	})
	vaultPath := filepath.Join(repo, ".achilles", "vault.jsonl")

	// Not in use: nothing to say.
	o := &options{vaultPath: vaultPath, vaultBackend: "file"}
	var scan model.Scan
	var out bytes.Buffer
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfig) != 0 || out.Len() != 0 {
		t.Fatalf("no feature reads the feedback, yet: %v\n%s", scan.RepoConfig, out.String())
	}

	// In use: named.
	o.calibrate = true
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfig) != 1 || scan.RepoConfig[0] != "feedback: .achilles/vault.jsonl" || !o.calibrate {
		t.Errorf("repoConfig = %v calibrate = %v, want the vault named and calibration left on", scan.RepoConfig, o.calibrate)
	}
	if !strings.Contains(out.String(), "--calibrate uses the feedback history in .achilles/vault.jsonl") {
		t.Errorf("stderr:\n%s", out.String())
	}

	// This run appending to the vault is not a change under review...
	git(t, repo, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/vault.jsonl")), `{"kind":"feedback"}`+"\n"+`{"kind":"scan_meta"}`+"\n")
	scan, o.diffRef = model.Scan{}, "main"
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 0 {
		t.Errorf("an uncommitted append was flagged: %v", scan.RepoConfigChanged)
	}
	// ...but a commit that rewrites the history is.
	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/vault.jsonl")), strings.Repeat(`{"kind":"feedback","label":"fp"}`+"\n", 20))
	git(t, repo, "commit", "-q", "-am", "plant feedback")
	scan = model.Scan{}
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 1 || scan.RepoConfigChanged[0] != "feedback: .achilles/vault.jsonl" {
		t.Errorf("flagged = %v, want the vault", scan.RepoConfigChanged)
	}

	// For code you do not trust: the feedback is not used at all.
	o.noRepoConfig, o.ragOn = true, true
	scan = model.Scan{}
	out.Reset()
	applyRepoStatePolicy(o, repo, &scan, &out)
	if o.calibrate || o.ragOn {
		t.Errorf("--no-repo-config left calibrate=%v rag=%v on", o.calibrate, o.ragOn)
	}
	if len(scan.RepoConfig) != 0 || len(scan.RepoConfigChanged) != 0 {
		t.Errorf("refused feedback must not be reported as in effect: %v %v", scan.RepoConfig, scan.RepoConfigChanged)
	}
	if !strings.Contains(out.String(), "--calibrate and --rag off for this run") {
		t.Errorf("stderr:\n%s", out.String())
	}
}

// A vault kept outside the repository, or inside it but not committed, is the
// operator's own: nothing is refused.
func TestRepoState_AVaultThatIsNotCommittedIsTrusted(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": "x = 1\n"})
	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/vault.jsonl")), "{}\n") // present, untracked
	for _, vaultPath := range []string{
		filepath.Join(repo, ".achilles", "vault.jsonl"),
		filepath.Join(t.TempDir(), "vault.jsonl"),
	} {
		o := &options{vaultPath: vaultPath, vaultBackend: "file", calibrate: true, ragOn: true, noRepoConfig: true}
		var scan model.Scan
		var out bytes.Buffer
		applyRepoStatePolicy(o, repo, &scan, &out)
		if !o.calibrate || !o.ragOn || out.Len() != 0 {
			t.Errorf("%s: calibrate=%v rag=%v\n%s", vaultPath, o.calibrate, o.ragOn, out.String())
		}
	}
}

func TestRepoState_GeneratedRulesChangedByTheCommitsUnderReview(t *testing.T) {
	repo := gitRepo(t, map[string]string{
		"app.py":                                "x = 1\n",
		".achilles/generated-rules/rule-a.yaml": "rules: []\n",
	})
	git(t, repo, "checkout", "-q", "-b", "change")
	git(t, repo, "rm", "-q", ".achilles/generated-rules/rule-a.yaml")
	writeFile(t, filepath.Join(repo, filepath.FromSlash(".achilles/generated-rules/keep.txt")), "x\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "drop a rule")

	o := &options{diffRef: "main", ruleRepoDir: filepath.Join(repo, ".achilles", "generated-rules")}
	var scan model.Scan
	var out bytes.Buffer
	applyRepoStatePolicy(o, repo, &scan, &out)
	if len(scan.RepoConfigChanged) != 1 || scan.RepoConfigChanged[0] != "generated rules: .achilles/generated-rules" {
		t.Errorf("flagged = %v, want the rule repository", scan.RepoConfigChanged)
	}
}

// End to end: a change adds a finding and the baseline entry that hides it. The
// gate passes, as the baseline says it should, but not quietly.
func TestRun_DiffThatEditsTheBaselineSaysSo(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, kv := range [][2]string{
		{"GIT_AUTHOR_NAME", "t"}, {"GIT_AUTHOR_EMAIL", "t@example.invalid"},
		{"GIT_COMMITTER_NAME", "t"}, {"GIT_COMMITTER_EMAIL", "t@example.invalid"},
	} {
		t.Setenv(kv[0], kv[1])
	}
	vulnerable, err := os.ReadFile(filepath.Join(target, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(target, ".achilles", "baseline.json")

	writeFile(t, filepath.Join(target, "app.py"), "x = 1\n")
	writeFile(t, baselinePath, "{}\n")
	git(t, target, "init", "-q", "-b", "main")
	git(t, target, "add", "-A")
	git(t, target, "commit", "-q", "-m", "base")

	git(t, target, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(target, "app.py"), string(vulnerable))
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--write-baseline", baselinePath, target}); err != nil {
		t.Fatalf("writing the baseline: %v", err)
	}
	git(t, target, "add", "-A")
	git(t, target, "commit", "-q", "-m", "the finding and its baseline entry")

	md := filepath.Join(t.TempDir(), "r.md")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--diff", "main", "--baseline", baselinePath,
		"--fail-on", "high", "--markdown", md, target}); err != nil {
		t.Fatalf("the baseline covers the finding, so the gate passes: %v", err)
	}
	report, _ := os.ReadFile(md)
	if !strings.Contains(string(report), "baseline: .achilles/baseline.json") {
		t.Errorf("the report must say the change edits the baseline:\n%s", report)
	}
}
