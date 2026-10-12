package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A rejected key used to end the run with "no report was written": a scan that had
// taken many minutes was thrown away because the step after it failed. The scan is
// now reported as it stands, clearly marked as unreviewed, and the run still fails.
func TestRun_AIReviewFailureStillWritesTheScannersReport(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)

	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer llm.Close()

	var githubCalls atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		githubCalls.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer gh.Close()
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GITHUB_API_URL", gh.URL)
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")

	out := t.TempDir()
	md, html, sarif := filepath.Join(out, "r.md"), filepath.Join(out, "r.html"), filepath.Join(out, "r.sarif")

	err := run([]string{
		"--config", cfg, "--vault", vaultPath,
		"--triage", "--review", "--llm-auth", "none", "--llm-base-url", llm.URL, "--llm-model", "m",
		"--markdown", md, "--html-report", html, "--sarif-report", sarif,
		"--pr-comment", "7", "--file-issues", "--repo", "acme/app",
		"--fail-on", "critical", // the gate alone would pass: the failure must come from the AI review
		target,
	})

	var aborted *triageAbortedError
	if !errors.As(err, &aborted) {
		t.Fatalf("err = %v, want a *triageAbortedError (exit 2)", err)
	}
	if strings.Contains(err.Error(), "no report was written") {
		t.Errorf("the error still claims no report was written: %v", err)
	}

	for name, path := range map[string]string{"Markdown": md, "HTML": html} {
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("%s report was not written: %v", name, readErr)
			continue
		}
		if !strings.Contains(string(b), "cmd-injection") {
			t.Errorf("%s report lost the scanner's finding", name)
		}
		if !strings.Contains(string(b), "did not complete") {
			t.Errorf("%s report must say the AI review did not complete:\n%s", name, b)
		}
	}
	if b, readErr := os.ReadFile(sarif); readErr != nil || !strings.Contains(string(b), "cmd-injection") {
		t.Errorf("SARIF report missing or without the finding: %v", readErr)
	}

	// Unreviewed scanner output is not published as if it had been reviewed.
	if n := githubCalls.Load(); n != 0 {
		t.Errorf("GitHub was called %d time(s) after the AI review failed; nothing must be posted", n)
	}
}
