package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a scanner. Started with ACHILLES_FAKE_SCANNER set and
// arguments `<out-file> <src-dir>`, it writes a SARIF report with one finding per
// line containing "os.system(" under src, the way a real tool is driven by the
// registry. This lets a test run the whole pipeline, on any OS, with no real
// scanner installed. A third argument, --honor-ignore, stands for a repository's
// own ignore file being applied: the scanner then reports nothing.
func TestMain(m *testing.M) {
	if os.Getenv("ACHILLES_FAKE_SCANNER") != "" && len(os.Args) >= 3 && !strings.HasPrefix(os.Args[1], "-") {
		os.Exit(fakeScanner(os.Args[1], os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

func fakeScanner(outFile, src string, extra []string) int {
	for _, a := range extra {
		if a == "--honor-ignore" {
			src = filepath.Join(src, "no-such-directory") // everything is ignored
		}
	}
	if os.Getenv("ACHILLES_FAKE_SCANNER") == "cannot-typecheck" {
		// What gosec does: complain on stderr, then report and exit 0 anyway.
		fmt.Fprintln(os.Stderr, "[fakescan] Error building the SSA representation of the package p: package p has type errors, skipping SSA analysis, no ssa result")
	}
	var results []any
	_ = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(src, p)
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "os.system(") {
				results = append(results, map[string]any{
					"ruleId": "cmd-injection", "level": "error", "message": map[string]any{"text": "shell command built from input"},
					"locations": []any{map[string]any{"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": filepath.ToSlash(rel)},
						"region":           map[string]any{"startLine": i + 1, "snippet": map[string]any{"text": strings.TrimSpace(line)}},
					}}},
				})
			}
		}
		return nil
	})
	doc, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "fakescan"}}, "results": results,
	}}})
	if err := os.WriteFile(outFile, doc, 0o600); err != nil {
		return 2
	}
	return 0
}

// fakeScanFixture writes a registry whose one tool is this test binary, and a
// target with one vulnerable file. It returns the config, target and vault paths.
func fakeScanFixture(t *testing.T) (cfg, target, vaultPath string) {
	t.Helper()
	t.Setenv("ACHILLES_FAKE_SCANNER", "1")
	// Anything a run keeps in the Achilles home (the verdict-cache key) goes to a
	// throwaway directory, never the developer's own.
	t.Setenv("ACHILLES_HOME", t.TempDir())
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg = filepath.Join(dir, "tools.yaml")
	yaml := "tools:\n" +
		"  - id: fakescan\n" +
		"    license: MIT\n" +
		"    commercialSafe: true\n" +
		"    enabled: true\n" +
		"    languages: [generic]\n" +
		"    bin: '" + filepath.ToSlash(self) + "'\n" +
		"    format: sarif\n" +
		"    argv: [\"{out}/results.sarif\", \"{src}\"]\n" +
		"    outputFile: \"{out}/results.sarif\"\n" +
		"    incompleteWhen: [\"skipping SSA analysis\"]\n"
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(dir, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "app.py"), []byte("import os\nos.system(cmd)\nprint('x')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg, target, filepath.Join(dir, "vault.jsonl")
}

// The exit-code contract: 0 clean, 1 gated by --fail-on, 2 any error. The gate
// used to call os.Exit(1) from inside the pipeline, which skipped every deferred
// cleanup and could not be tested at all.
func TestRun_GateIsAnErrorValueNotAnExit(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)

	err := run([]string{"--config", cfg, "--vault", vaultPath, "--fail-on", "high", target})
	var gated *gateError
	if !errors.As(err, &gated) {
		t.Fatalf("a high finding with --fail-on high: err = %v, want a *gateError (exit 1)", err)
	}
	if gated.worst != "high" || gated.threshold != "high" {
		t.Errorf("gateError = %+v", gated)
	}

	// The fake scanner reports level "error" (high): --fail-on critical must pass.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--fail-on", "critical", target}); err != nil {
		t.Errorf("--fail-on critical with only a high finding: err = %v, want nil (exit 0)", err)
	}
	// Flags after the target reach the gate too.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, target, "--fail-on", "high"}); !errors.As(err, &gated) {
		t.Errorf("flag after the target: err = %v, want a *gateError", err)
	}
	// No gate requested: findings alone never fail the run.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, target}); err != nil {
		t.Errorf("no --fail-on: err = %v, want nil", err)
	}
}

// The bug: fix verification re-used the scanners' --timeout context after the AI
// review had run on its own clock. Any run whose scan plus review took longer than
// --timeout had every verification fail with "context deadline exceeded", which is
// every normal --ai run on a real repository.
func TestRun_FixVerificationHasItsOwnClock(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed (verification applies the patch with git apply)")
	}
	cfg, target, vaultPath := fakeScanFixture(t)

	// Three model calls (triage, judge, remediation) at 1.6s each take 4.8s: longer
	// than the 4s --timeout below however fast the scanner is, and the scanner has
	// the whole 4s to itself, which is generous even on a loaded CI machine.
	const perCall = 1600 * time.Millisecond
	diff := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(cmd)\n+subprocess.run([cmd])\n print('x')\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		time.Sleep(perCall)
		var req struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		system := ""
		if len(req.Messages) > 0 {
			system = req.Messages[0].Content
		}
		var reply string
		switch {
		case strings.Contains(system, "adversarial reviewer"):
			reply = `{"refuted":false,"reason":""}`
		case strings.Contains(system, "proposing a fix"):
			b, _ := json.Marshal(map[string]any{"summary": "use an argument list", "diff": diff, "confidence": 0.9})
			reply = string(b)
		default:
			reply = `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"cmd reaches a shell"}`
		}
		content, _ := json.Marshal(reply)
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"message":{"content":` + string(content) + `}}]}`))
	}))
	defer srv.Close()
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")

	err := run([]string{
		"--config", cfg, "--vault", vaultPath,
		"--timeout", "4s", // the scanner is done in well under this; the AI review is not
		"--triage", "--remediate", "--llm-auth", "none", "--llm-base-url", srv.URL, "--llm-model", "m",
		target,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	vaultBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	v := string(vaultBytes)
	if strings.Contains(v, "deadline exceeded") {
		t.Fatal("fix verification ran on an expired clock (\"deadline exceeded\" in the recorded result)")
	}
	if !strings.Contains(v, `"source":"verifyfix"`) {
		t.Fatal("no verification was recorded, so this test proved nothing")
	}
	if !strings.Contains(v, `"status":"verified"`) {
		t.Errorf("the fix removes the finding and should verify; vault has no verified status:\n%s", lastLines(v, 3))
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// A scanner that says it could not analyze part of the target keeps its findings
// but makes the scan incomplete: --strict-tools fails, and the report says so.
func TestRun_ScannerThatCouldNotAnalyzeEverythingMakesTheScanIncomplete(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	t.Setenv("ACHILLES_FAKE_SCANNER", "cannot-typecheck")
	sarifOut := filepath.Join(t.TempDir(), "out.sarif")

	// Default: a partial scan is reported, loudly, but does not fail the run.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--sarif-report", sarifOut, target}); err != nil {
		t.Fatalf("without --strict-tools an incomplete scanner is a warning: %v", err)
	}
	b, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "cmd-injection") {
		t.Error("the findings the scanner did produce must still be reported")
	}
	if !strings.Contains(string(b), `"executionSuccessful":false`) && !strings.Contains(string(b), `"executionSuccessful": false`) {
		t.Error("the SARIF report must say the scan did not complete")
	}

	// --strict-tools: an incomplete scan is not evidence of safety.
	err = run([]string{"--config", cfg, "--vault", vaultPath, "--strict-tools", target})
	if err == nil || !strings.Contains(err.Error(), "--strict-tools") || !strings.Contains(err.Error(), "fakescan") {
		t.Errorf("err = %v, want a --strict-tools failure naming the scanner", err)
	}

	// The same scanner without the complaint is a complete scan.
	t.Setenv("ACHILLES_FAKE_SCANNER", "1")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--strict-tools", target}); err != nil {
		t.Errorf("a scanner that analyzed everything must pass --strict-tools: %v", err)
	}
}
