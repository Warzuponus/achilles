package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The vault and the reports quote the code around each finding. When they are
// written inside the scanned directory (the vault is, by default), a scanner that
// reads every file used to find the same issue again in them, one more time on
// every run. They are Achilles' output, not the project's code: always left out.
func TestRun_RepeatedScansDoNotFindAchillesOwnOutput(t *testing.T) {
	cfg, target, _ := fakeScanFixture(t)
	vault := filepath.Join(target, ".achilles", "vault.jsonl")
	md := filepath.Join(target, "achilles-report.md")
	out := filepath.Join(target, "scan.json")
	scan := func(extra ...string) int {
		t.Helper()
		args := append([]string{"--config", cfg, "--vault", vault, "--markdown", md, "--json-report", out}, extra...)
		if err := run(append(args, target)); err != nil {
			t.Fatalf("run: %v", err)
		}
		var r struct {
			Findings []struct {
				Location struct {
					File string `json:"file"`
				} `json:"location"`
			} `json:"findings"`
		}
		b, _ := os.ReadFile(out)
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if f.Location.File != "app.py" {
				t.Errorf("a finding in Achilles' own output: %s", f.Location.File)
			}
		}
		return len(r.Findings)
	}
	for i := 1; i <= 3; i++ {
		if n := scan(); n != 1 {
			t.Fatalf("run %d: %d finding(s), want the one in app.py", i, n)
		}
	}
	// Not a noise pattern a flag can turn off.
	if n := scan("--no-default-excludes"); n != 1 {
		t.Errorf("--no-default-excludes: %d finding(s), want 1", n)
	}
	// The files are really there to be found: the test proves something.
	for _, p := range []string{vault, md, out} {
		if b, err := os.ReadFile(p); err != nil || len(b) == 0 {
			t.Fatalf("%s was not written: %v", p, err)
		}
	}
}
