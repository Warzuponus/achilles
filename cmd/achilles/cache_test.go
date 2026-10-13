package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVerdictCacheSecret_CreatedOncePrivateAndStable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ACHILLES_HOME", home)

	first, err := verdictCacheSecret()
	if err != nil || len(first) != 32 {
		t.Fatalf("secret = %d bytes, err = %v", len(first), err)
	}
	second, err := verdictCacheSecret()
	if err != nil || !bytes.Equal(first, second) {
		t.Errorf("the key must be the same on every run of one machine (err = %v)", err)
	}
	path := filepath.Join(home, verdictCacheKeyFile)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("key file is %04o, want 0600", st.Mode().Perm())
	}

	// A damaged key is an error with a way out, not a silently weaker cache.
	if err := os.WriteFile(path, []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verdictCacheSecret(); err == nil || !strings.Contains(err.Error(), "delete it") {
		t.Errorf("err = %v, want one that says how to recover", err)
	}

	// Another machine (another home) has another key: nothing carries over.
	t.Setenv("ACHILLES_HOME", t.TempDir())
	other, err := verdictCacheSecret()
	if err != nil || bytes.Equal(first, other) {
		t.Errorf("a different home must get a different key (err = %v)", err)
	}
}

// End to end: scanning the same code twice into the same vault asks the model once.
func TestRun_SecondScanOfUnchangedCodeReusesVerdicts(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		reply := `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"cmd reaches a shell"}`
		if strings.Contains(string(body), "adversarial reviewer") {
			reply = `{"refuted":false,"reason":""}`
		}
		content, _ := json.Marshal(reply)
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"finish_reason":"stop","message":{"content":` + string(content) + `}}]}`))
	}))
	defer srv.Close()
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")

	md := filepath.Join(t.TempDir(), "r.md")
	scan := func(extra ...string) {
		t.Helper()
		args := append([]string{"--config", cfg, "--vault", vaultPath, "--triage",
			"--llm-auth", "none", "--llm-base-url", srv.URL, "--llm-model", "m", "--markdown", md}, extra...)
		if err := run(append(args, target)); err != nil {
			t.Fatalf("run: %v", err)
		}
	}

	scan()
	if n := calls.Load(); n != 2 {
		t.Fatalf("first scan made %d model calls, want 2 (review and judge)", n)
	}
	scan()
	if n := calls.Load(); n != 2 {
		t.Errorf("the second scan of unchanged code made %d more model call(s)", n-2)
	}
	report, _ := os.ReadFile(md)
	if !strings.Contains(string(report), "reused from earlier runs") {
		t.Errorf("the report must say the verdict was reused:\n%s", report)
	}

	// The cache can be turned off: the finding is then reviewed again.
	scan("--verdict-cache-days", "0")
	if n := calls.Load(); n != 4 {
		t.Errorf("with the cache off: %d calls in total, want 4", n)
	}

	// Change the code around the finding: a different question, a fresh review.
	if err := os.WriteFile(filepath.Join(target, "app.py"), []byte("import os\nos.system(cmd)\nprint('y')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scan()
	if n := calls.Load(); n != 6 {
		t.Errorf("after the code changed: %d calls in total, want 6", n)
	}
}

// End to end with --remediate: the second scan of unchanged code asks the model
// for nothing, neither the verdict nor the fix, and says the fix was reused.
func TestRun_SecondScanReusesTheFixSuggestion(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)

	var reviews, fixes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reply := `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"cmd reaches a shell"}`
		switch {
		case strings.Contains(string(body), "proposing a fix"):
			fixes.Add(1)
			reply = `{"summary":"Pass the arguments as a list","diff":"","guidance":"Use subprocess.run with a list.","confidence":0.8}`
		case strings.Contains(string(body), "adversarial reviewer"):
			reviews.Add(1)
			reply = `{"refuted":false,"reason":""}`
		default:
			reviews.Add(1)
		}
		content, _ := json.Marshal(reply)
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"finish_reason":"stop","message":{"content":` + string(content) + `}}]}`))
	}))
	defer srv.Close()
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")

	out := filepath.Join(t.TempDir(), "scan.json")
	scan := func(extra ...string) (summary, reusedFrom string) {
		t.Helper()
		args := append([]string{"--config", cfg, "--vault", vaultPath, "--remediate", "--verify-fixes=false",
			"--llm-auth", "none", "--llm-base-url", srv.URL, "--llm-model", "m", "--json-report", out}, extra...)
		if err := run(append(args, target)); err != nil {
			t.Fatalf("run: %v", err)
		}
		var doc struct {
			Findings []struct {
				Remediation *struct {
					Summary    string `json:"summary"`
					ReusedFrom string `json:"reusedFrom"`
				} `json:"remediation"`
			} `json:"findings"`
		}
		b, _ := os.ReadFile(out)
		if err := json.Unmarshal(b, &doc); err != nil || len(doc.Findings) != 1 || doc.Findings[0].Remediation == nil {
			t.Fatalf("report has no fix suggestion (err=%v):\n%s", err, b)
		}
		return doc.Findings[0].Remediation.Summary, doc.Findings[0].Remediation.ReusedFrom
	}

	summary, reused := scan()
	if reviews.Load() != 2 || fixes.Load() != 1 || reused != "" || summary == "" {
		t.Fatalf("first scan: %d review call(s), %d fix call(s), reusedFrom=%q", reviews.Load(), fixes.Load(), reused)
	}
	again, reused := scan()
	if reviews.Load() != 2 || fixes.Load() != 1 {
		t.Errorf("the second scan called the model again: %d review call(s), %d fix call(s) in total", reviews.Load(), fixes.Load())
	}
	if again != summary || reused == "" {
		t.Errorf("second scan: summary=%q reusedFrom=%q, want the first scan's fix marked as reused", again, reused)
	}

	// With the cache off both are asked for again.
	if _, reused = scan("--verdict-cache-days", "0"); reviews.Load() != 4 || fixes.Load() != 2 || reused != "" {
		t.Errorf("with the cache off: %d review call(s), %d fix call(s), reusedFrom=%q", reviews.Load(), fixes.Load(), reused)
	}
}
