package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type suppressReport struct {
	Findings []struct {
		RuleID string `json:"ruleId"`
	} `json:"findings"`
	Suppressed []struct {
		RuleID      string `json:"ruleId"`
		Suppression struct {
			File   string `json:"file"`
			Line   int    `json:"line"`
			Reason string `json:"reason"`
			New    bool   `json:"new"`
		} `json:"suppression"`
	} `json:"suppressed"`
	RepoConfigChanged []string `json:"repoConfigChanged"`
}

func readSuppressReport(t *testing.T, path string) suppressReport {
	t.Helper()
	var r suppressReport
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return r
}

const suppressedApp = "import os\nos.system(cmd)  # achilles:ignore cmd-injection -- cmd is built from a fixed table\nprint('x')\n"

// End to end: a finding with a suppression comment beside it does not gate, is not
// sent to the model, and is in the report with the reason. --no-repo-config
// takes the comment's power away.
func TestRun_InlineSuppression(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	if err := os.WriteFile(filepath.Join(target, "app.py"), []byte(suppressedApp), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")

	dir := t.TempDir()
	out, md, sarif := filepath.Join(dir, "scan.json"), filepath.Join(dir, "r.md"), filepath.Join(dir, "r.sarif")
	base := []string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--markdown", md, "--sarif-report", sarif, "--fail-on", "high"}

	if err := run(append(append([]string{}, base...), "--triage", "--llm-auth", "none", "--llm-base-url", srv.URL, "--llm-model", "m", target)); err != nil {
		t.Fatalf("the only finding is suppressed, so the gate passes: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("a suppressed finding was sent to the model (%d call(s))", n)
	}
	r := readSuppressReport(t, out)
	if len(r.Findings) != 0 || len(r.Suppressed) != 1 {
		t.Fatalf("findings=%d suppressed=%d, want 0 and 1", len(r.Findings), len(r.Suppressed))
	}
	s := r.Suppressed[0]
	if s.RuleID != "cmd-injection" || s.Suppression.File != "app.py" || s.Suppression.Line != 2 ||
		s.Suppression.Reason != "cmd is built from a fixed table" || s.Suppression.New {
		t.Errorf("suppressed = %+v", s)
	}
	// Never silent: the Markdown report lists it with its reason, and SARIF marks
	// it suppressed in source.
	if report, _ := os.ReadFile(md); !strings.Contains(string(report), "suppressed by comments in the code") ||
		!strings.Contains(string(report), "cmd is built from a fixed table") {
		t.Errorf("the Markdown report does not list the suppression:\n%s", report)
	}
	if doc, _ := os.ReadFile(sarif); !strings.Contains(string(doc), `"kind": "inSource"`) ||
		!strings.Contains(string(doc), "cmd is built from a fixed table") {
		t.Errorf("the SARIF report does not carry the in-source suppression:\n%s", doc)
	}

	// For code you do not trust, the comment counts for nothing.
	err := run(append(append([]string{}, base...), "--no-repo-config", target))
	var gated *gateError
	if !errors.As(err, &gated) {
		t.Fatalf("--no-repo-config: err = %v, want the gate to fail on the finding", err)
	}
	if r = readSuppressReport(t, out); len(r.Findings) != 1 || len(r.Suppressed) != 0 {
		t.Errorf("--no-repo-config: findings=%d suppressed=%d, want 1 and 0", len(r.Findings), len(r.Suppressed))
	}
}

// A comment that names no reason, or another rule, suppresses nothing.
func TestRun_InlineSuppressionMustNameTheRuleAndAReason(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	out := filepath.Join(t.TempDir(), "scan.json")
	for name, line := range map[string]string{
		"no reason":    "os.system(cmd)  # achilles:ignore cmd-injection",
		"another rule": "os.system(cmd)  # achilles:ignore sql-injection -- not this one",
		"no rule":      "os.system(cmd)  # achilles:ignore -- everything here is fine",
	} {
		if err := os.WriteFile(filepath.Join(target, "app.py"), []byte("import os\n"+line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--fail-on", "high", target})
		var gated *gateError
		if !errors.As(err, &gated) {
			t.Errorf("%s: err = %v, want the finding to gate", name, err)
		}
		if r := readSuppressReport(t, out); len(r.Suppressed) != 0 {
			t.Errorf("%s: the finding was suppressed", name)
		}
	}
}

// On a diff-scoped scan, a suppression the change itself adds is honoured, and
// called out the way a change to a scanner's ignore file is. One that was already
// there is not.
func TestRun_InlineSuppressionAddedByTheChangeIsFlagged(t *testing.T) {
	cfg, _, vaultPath := fakeScanFixture(t)
	target := gitRepo(t, map[string]string{
		"old.py": "import os\nos.system(cmd)  # achilles:ignore cmd-injection -- reviewed last year\n",
		"app.py": "import os\nprint('x')\n",
	})
	git(t, target, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(target, "app.py"), suppressedApp)
	// The old file changes too, but on another line than its suppression.
	writeFile(t, filepath.Join(target, "old.py"), "import os\nos.system(cmd)  # achilles:ignore cmd-injection -- reviewed last year\nprint('new line')\n")
	git(t, target, "commit", "-q", "-am", "add a call and suppress it")

	out := filepath.Join(t.TempDir(), "scan.json")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, "--diff", "main", "--fail-on", "high", target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	r := readSuppressReport(t, out)
	if len(r.Suppressed) != 2 {
		t.Fatalf("suppressed = %+v, want both", r.Suppressed)
	}
	for _, s := range r.Suppressed {
		wantNew := s.Suppression.File == "app.py"
		if s.Suppression.New != wantNew {
			t.Errorf("%s: new = %v, want %v", s.Suppression.File, s.Suppression.New, wantNew)
		}
	}
	if len(r.RepoConfigChanged) != 1 || r.RepoConfigChanged[0] != "suppression: app.py:2" {
		t.Errorf("repoConfigChanged = %v, want the suppression the change added", r.RepoConfigChanged)
	}
}
