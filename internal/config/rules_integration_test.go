//go:build integration

// Tests the Achilles-authored Opengrep rules (configs/rules/achilles-*.yaml) with the
// REAL opengrep: every rule must have test cases in testdata/rules/ (a file with the
// same name as the rule file, any extension), and every "ruleid:" and "ok:"
// annotation there must hold.
//
//	achilles tools install opengrep   # or have opengrep on PATH
//	go test -tags integration ./internal/config -run TestRules
//
// Skips when opengrep is not installed, unless ACHILLES_REQUIRE_OPENGREP=1 (CI).
package config

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRules_AchillesRulesPassTheirTests(t *testing.T) {
	bin, err := exec.LookPath("opengrep")
	if err != nil {
		if home, herr := os.UserHomeDir(); herr == nil {
			for _, dir := range []string{os.Getenv("ACHILLES_HOME"), filepath.Join(home, ".achilles")} {
				for _, name := range []string{"opengrep", "opengrep.exe"} {
					if p := filepath.Join(dir, "bin", name); dir != "" && fileExists(p) {
						bin, err = p, nil
					}
				}
			}
		}
	}
	if err != nil {
		if os.Getenv("ACHILLES_REQUIRE_OPENGREP") == "1" {
			t.Fatal("opengrep is not installed, and ACHILLES_REQUIRE_OPENGREP=1 says this run must test the rules")
		}
		t.Skip("opengrep not installed")
	}

	rulesDir, _ := filepath.Abs(filepath.Join("..", "..", "configs", "rules"))
	testsDir, _ := filepath.Abs(filepath.Join("testdata", "rules"))
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "scan", "--test", "--json", "--config", rulesDir, testsDir)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// With --json, opengrep exits non-zero when a test fails. The report says which,
	// so an exit error matters only when there is no report to read.
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		t.Fatalf("opengrep --test: %v\n%s", err, stderr.String())
	}
	var report struct {
		Results map[string]struct {
			Checks map[string]struct {
				Passed  bool     `json:"passed"`
				Errors  []string `json:"errors"`
				Matches map[string]struct {
					Expected []int `json:"expected_lines"`
					Reported []int `json:"reported_lines"`
				} `json:"matches"`
			} `json:"checks"`
		} `json:"results"`
		ConfigWithErrors []any `json:"config_with_errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("opengrep --test --json: %v\n%s", err, stdout.String())
	}
	if len(report.ConfigWithErrors) > 0 {
		t.Errorf("rule files with errors: %v", report.ConfigWithErrors)
	}

	// Every check opengrep ran must pass.
	checked := map[string]bool{}
	for file, res := range report.Results {
		for id, c := range res.Checks {
			checked[id] = true
			if !c.Passed {
				for target, m := range c.Matches {
					t.Errorf("%s (%s): in %s expected lines %v, reported %v %v",
						id, filepath.Base(file), filepath.Base(target), m.Expected, m.Reported, c.Errors)
				}
			}
		}
	}

	// Every Achilles rule must have been checked: a rule with no test case is a rule
	// nobody has seen fire.
	files, _ := filepath.Glob(filepath.Join(rulesDir, "achilles-*.yaml"))
	if len(files) == 0 {
		t.Fatal("no Achilles rule files found")
	}
	var untested []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID string `yaml:"id"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, r := range doc.Rules {
			if !checked[r.ID] {
				untested = append(untested, r.ID+" ("+filepath.Base(f)+")")
			}
		}
	}
	sort.Strings(untested)
	if len(untested) > 0 {
		t.Errorf("rules with no test case in testdata/rules (add a \"ruleid:\" line for each):\n  %s", strings.Join(untested, "\n  "))
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
