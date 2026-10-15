//go:build integration

// Runs the history scan with the REAL gitleaks, to prove what the hermetic tests
// can only assume: the arguments gitleaks is given, the shape of what it reports
// for a commit, and that the same credential in a file and in a commit get the
// same fingerprint.
//
//	achilles tools install gitleaks   # or have gitleaks on PATH
//	go test -tags integration ./cmd/achilles -run History
//
// Skips when gitleaks is not installed.
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

func TestIntegration_SecretsHistoryWithRealGitleaks(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	t.Setenv("ACHILLES_HOME", t.TempDir())

	// A registry holding only the two gitleaks entries of the embedded one, so no
	// other scanner has to be installed.
	embedded, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var only config.Config
	for _, tc := range embedded.Tools {
		if tc.Bin == "gitleaks" {
			only.Tools = append(only.Tools, tc)
		}
	}
	if len(only.Tools) != 2 {
		t.Fatalf("expected the file and the history entry for gitleaks, got %d", len(only.Tools))
	}
	registry, err := yaml.Marshal(only)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(cfg, registry, 0o600); err != nil {
		t.Fatal(err)
	}

	// Built at run time: this file must hold no credential-shaped literal.
	gone := "ghp_" + "a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8"
	kept := "ghp_" + "z9Y8x7W6v5U4t3S2r1Q0" + "p9O8n7M6l5K4j3I2"

	repo := gitRepo(t, map[string]string{"app.py": "x = 1\n"})
	writeFile(t, filepath.Join(repo, "app.py"), "x = 1\ntoken = \""+gone+"\"\n")
	git(t, repo, "commit", "-q", "-am", "add a token")
	writeFile(t, filepath.Join(repo, "app.py"), "x = 1\n")
	git(t, repo, "commit", "-q", "-am", "remove it")
	writeFile(t, filepath.Join(repo, "settings.py"), "token = \""+kept+"\"\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "a token that stays")

	out := filepath.Join(t.TempDir(), "scan.json")
	type report struct {
		FailedTools []string `json:"failedTools"`
		Findings    []struct {
			RuleID   string `json:"ruleId"`
			Commit   string `json:"commit"`
			Location struct {
				File string `json:"file"`
			} `json:"location"`
		} `json:"findings"`
	}
	scan := func(target string, extra ...string) report {
		t.Helper()
		args := append([]string{"--config", cfg, "--vault", filepath.Join(t.TempDir(), "v.jsonl"), "--json-report", out}, extra...)
		if err := run(append(args, target)); err != nil {
			t.Fatalf("run %v: %v", extra, err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{gone, kept} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("the report contains a credential")
			}
		}
		var r report
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// The files alone: only the token that is still there.
	r := scan(repo)
	if len(r.Findings) != 1 || r.Findings[0].Location.File != "settings.py" || r.Findings[0].Commit != "" {
		t.Fatalf("scan of the files: %+v", r.Findings)
	}

	// With the history: the deleted token too, once, naming its commit. The token
	// that is still in a file is not reported a second time for its commit.
	r = scan(repo, "--secrets-history")
	if len(r.FailedTools) != 0 {
		t.Errorf("failed tools: %v", r.FailedTools)
	}
	var inHistory, inFiles int
	for _, f := range r.Findings {
		if f.Commit != "" {
			inHistory++
			if f.Location.File != "app.py" || len(f.Commit) != 40 {
				t.Errorf("history finding: %+v", f)
			}
		} else {
			inFiles++
		}
	}
	if inHistory != 1 || inFiles != 1 {
		t.Errorf("%d finding(s) in the history and %d in the files, want 1 and 1: %+v", inHistory, inFiles, r.Findings)
	}

	// A shallow clone does not hold the commit that added the deleted token. The
	// scan must say it is incomplete, not report a clean history.
	shallow := filepath.Join(t.TempDir(), "shallow")
	git(t, repo, "clone", "-q", "--depth", "1", "file://"+filepath.ToSlash(repo), shallow)
	r = scan(shallow, "--secrets-history")
	if len(r.FailedTools) != 1 || r.FailedTools[0] != "gitleaks-history" {
		t.Errorf("a shallow clone: failedTools = %v, want the history scan reported incomplete", r.FailedTools)
	}
}
