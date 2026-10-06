package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// deepEndpoint is an OpenAI-compatible server playing the deep-verification model:
// first turn it reads a.py (or the path in readPath), then it concludes as script says.
type deepEndpoint struct {
	*httptest.Server
	calls    atomic.Int64
	mu       sync.Mutex
	requests []string
}

func newDeepEndpoint(t *testing.T, status int, readPath string, conclusion func(rule string) string) *deepEndpoint {
	t.Helper()
	de := &deepEndpoint{}
	de.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		de.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		de.mu.Lock()
		de.requests = append(de.requests, string(body))
		de.mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, `{"error":{"message":"bad key"}}`, status)
			return
		}
		var req struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		rule, assistant := "", 0
		for _, m := range req.Messages {
			if m.Role == "assistant" {
				assistant++
			}
			for _, line := range strings.Split(m.Content, "\n") {
				if strings.HasPrefix(line, "Rule: ") && rule == "" {
					rule = strings.TrimPrefix(line, "Rule: ")
				}
			}
		}
		reply := `{"action":"read_file","path":"` + readPath + `","start":1,"end":10}`
		if assistant >= 1 {
			reply = conclusion(rule)
		}
		content, _ := json.Marshal(reply)
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"message":{"content":` + string(content) + `}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	t.Cleanup(de.Close)
	return de
}

func deepFixture(t *testing.T) (*model.Scan, vault.Store, string) {
	t.Helper()
	t.Setenv("ACHILLES_LLM_API_KEY", "test-key-not-real")
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")
	llmAuthMode = "key"
	dir := t.TempDir()
	target := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(target, ".achilles"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"a.py":                  "import os\nos.system(cmd)\nprint('x')\n",
		".achilles/vault.jsonl": "VAULT-CONTENT\n",
	} {
		p := filepath.Join(target, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vaultPath := filepath.Join(target, "evidence", "run.log")
	ev, err := vault.NewFileStore(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	// The real vault file, in a directory whose name nothing in the sandbox's name
	// rules would protect: only the explicit deny path can keep it from the model.
	if _, err := ev.Append(vault.Record{RunID: "seed", Kind: vault.KindScanMeta, Payload: json.RawMessage(`"VAULT-CONTENT"`)}); err != nil {
		t.Fatal(err)
	}
	mk := func(tool, rule string, sev model.Severity, v *model.Verdict) model.Finding {
		return model.Finding{Tool: tool, RuleID: rule, Severity: sev, Message: "m", Fingerprint: "fp-" + rule, Verdict: v,
			Location: model.Location{File: "a.py", Region: model.Region{StartLine: 2}}}
	}
	scan := &model.Scan{Target: target, Findings: []model.Finding{
		mk("opengrep", "uncertain-high", model.SeverityHigh, &model.Verdict{Classification: model.ClassUncertain, Confidence: 0.4, Exploitability: model.ExploitUnknown}),
		mk("opengrep", "confirm-crit", model.SeverityCritical, nil),
		mk("gitleaks", "leaked-key", model.SeverityHigh, nil),
		mk("opengrep", "settled-medium", model.SeverityMedium, &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.95}),
		mk("opengrep", "conflict-high", model.SeverityHigh, &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9, Exploitability: model.ExploitReachable, Reasoning: "tainted"}),
	}}
	return scan, ev, vaultPath
}

func deepConclusion(rule string) string {
	switch rule {
	case "confirm-crit":
		return `{"action":"conclude","classification":"true_positive","confidence":0.85,"reasoning":"reaches os.system","evidence":["a.py:2"]}`
	default: // uncertain-high and conflict-high are called false positives, citing what it read
		return `{"action":"conclude","classification":"false_positive","confidence":0.95,"reasoning":"cmd is constant","evidence":["a.py:2"]}`
	}
}

func deepOpts(base, vaultPath string) *options {
	return &options{deepVerify: 3, deepMaxSteps: 4, llmBaseURL: base, llmModel: "m", llmConcurrency: 2, vaultPath: vaultPath}
}

func TestDeepVerifyFindings_SelectsAppliesAndRecords(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", deepConclusion)
	scan, ev, vaultPath := deepFixture(t)
	var out bytes.Buffer

	if err := runDeepVerify(context.Background(), deepOpts(de.URL, vaultPath), ev, "run1", scan, &out); err != nil {
		t.Fatal(err)
	}
	byRule := map[string]model.Finding{}
	for _, f := range scan.Findings {
		byRule[f.RuleID] = f
	}

	// Selected (n=3, most important first): the critical one, then two high.
	if f := byRule["confirm-crit"]; f.Deep == nil || f.Verdict == nil || f.Verdict.Classification != model.ClassTruePositive || f.Severity != model.SeverityCritical {
		t.Errorf("confirm-crit: %+v / %+v", f.Verdict, f.Deep)
	}
	if f := byRule["uncertain-high"]; f.Deep == nil || !f.Dismissed() {
		t.Errorf("uncertain-high should now support dismissal: %+v / %+v", f.Verdict, f.Deep)
	}
	if f := byRule["conflict-high"]; f.Deep == nil || f.Dismissed() || f.Verdict.Classification != model.ClassUncertain {
		t.Errorf("conflict-high must be left uncertain and surfaced: %+v", f.Verdict)
	}
	// Never selected.
	for _, r := range []string{"leaked-key", "settled-medium"} {
		if byRule[r].Deep != nil {
			t.Errorf("%s must not be deep-verified", r)
		}
	}
	// The credential finding's rule name never reached the endpoint.
	for _, req := range de.requests {
		if strings.Contains(req, "leaked-key") {
			t.Error("a credential finding was sent to the model")
		}
	}
	if got := de.calls.Load(); got != 6 {
		t.Errorf("model calls = %d, want 2 per finding", got)
	}

	// Stderr summary, one line.
	line := strings.TrimSpace(out.String())
	for _, want := range []string{"deep verification", "3 finding(s) examined", "3 tool call(s)", "90 token(s)", "1 confirmed", "1 support dismissal", "1 contested"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary lacks %q: %s", want, line)
		}
	}
	if strings.Count(line, "\n") != 0 {
		t.Errorf("summary should be one line: %q", line)
	}

	// The vault holds an llm_call per finding and a merged verdict for each change.
	var calls, verdicts int
	for _, r := range ev.ByRun("run1") {
		if r.Source != "deep-verify" {
			continue
		}
		switch r.Kind {
		case vault.KindLLMCall:
			calls++
			var p struct {
				Task string                 `json:"task"`
				Deep model.DeepVerification `json:"deep"`
			}
			if err := json.Unmarshal(r.Payload, &p); err != nil || p.Task != "deep" || len(p.Deep.Trace) != 1 {
				t.Errorf("llm_call payload: %s (%v)", r.Payload, err)
			}
		case vault.KindVerdict:
			verdicts++
			var v model.Verdict
			if err := json.Unmarshal(r.Payload, &v); err != nil || r.Fingerprint == "" || v.Reasoning == "" {
				t.Errorf("verdict payload: %s (%v)", r.Payload, err)
			}
		}
	}
	if calls != 3 || verdicts != 3 {
		t.Errorf("vault records: %d llm_call, %d verdict; want 3 and 3", calls, verdicts)
	}
	if vaultWrites.failed != 0 {
		t.Errorf("vault write failures: %d (%v)", vaultWrites.failed, vaultWrites.firstErr)
	}

	// The follow-up the lead performs: only the supported dismissal leaves the set.
	if n := scan.PartitionDismissed(); n != 1 || scan.Dismissed[0].RuleID != "uncertain-high" {
		t.Errorf("PartitionDismissed moved %d: %+v", n, scan.Dismissed)
	}
}

func TestDeepVerifyFindings_VaultFileIsNeverShownToTheModel(t *testing.T) {
	for _, readPath := range []string{".achilles/vault.jsonl", "evidence/run.log"} {
		de := newDeepEndpoint(t, 200, readPath, deepConclusion)
		scan, ev, vaultPath := deepFixture(t)
		var out bytes.Buffer
		if err := runDeepVerify(context.Background(), deepOpts(de.URL, vaultPath), ev, "run1", scan, &out); err != nil {
			t.Fatal(err)
		}
		var denied bool
		for _, req := range de.requests {
			if strings.Contains(req, "VAULT-CONTENT") {
				t.Fatalf("%s: the vault's content reached the endpoint", readPath)
			}
			if strings.Contains(req, "access denied") {
				denied = true
			}
		}
		if !denied {
			t.Errorf("%s: the model should have been refused", readPath)
		}
	}
}

func TestDeepVerifyFindings_RefusesWithNoCode(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", deepConclusion)
	scan, ev, vaultPath := deepFixture(t)
	o := deepOpts(de.URL, vaultPath)
	o.llmNoCode = true
	err := runDeepVerify(context.Background(), o, ev, "run1", scan, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--llm-no-code") || !strings.Contains(err.Error(), "NOT run") {
		t.Errorf("err = %v", err)
	}
	if de.calls.Load() != 0 {
		t.Error("no model call may be made")
	}
	for _, f := range scan.Findings {
		if f.Deep != nil {
			t.Error("a refused run must leave findings untouched")
		}
	}
}

func TestDeepVerifyFindings_DryRunCallsNothing(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", deepConclusion)
	scan, ev, vaultPath := deepFixture(t)
	o := deepOpts(de.URL, vaultPath)
	o.dryRun = true
	var out bytes.Buffer
	if err := runDeepVerify(context.Background(), o, ev, "run1", scan, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dry run", "3 of 5", "up to 4 tool call(s)", "upper bound", "No model was called"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run output lacks %q: %s", want, out.String())
		}
	}
	if de.calls.Load() != 0 || len(ev.ByRun("run1")) != 0 {
		t.Error("a dry run must not call the model or write the vault")
	}
}

func TestDeepVerifyFindings_OffMeansOff(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", deepConclusion)
	scan, ev, vaultPath := deepFixture(t)
	o := deepOpts(de.URL, vaultPath)
	o.deepVerify = 0
	if err := runDeepVerify(context.Background(), o, ev, "run1", scan, io.Discard); err != nil || de.calls.Load() != 0 {
		t.Errorf("err = %v, calls = %d", err, de.calls.Load())
	}
	o.deepVerify = -1
	if err := runDeepVerify(context.Background(), o, ev, "run1", scan, io.Discard); err == nil {
		t.Error("a negative count is a usage error")
	}
}

func TestDeepVerifyFindings_NeedsAModel(t *testing.T) {
	scan, ev, vaultPath := deepFixture(t)
	o := deepOpts("http://127.0.0.1:1", vaultPath)
	o.llmModel = ""
	if err := runDeepVerify(context.Background(), o, ev, "run1", scan, io.Discard); err == nil || !strings.Contains(err.Error(), "--llm-model") {
		t.Errorf("err = %v", err)
	}
}

func TestDeepVerifyFindings_EndpointFailureLeavesFindingsAlone(t *testing.T) {
	de := newDeepEndpoint(t, 401, "a.py", deepConclusion)
	scan, ev, vaultPath := deepFixture(t)
	var out bytes.Buffer
	if err := runDeepVerify(context.Background(), deepOpts(de.URL, vaultPath), ev, "run1", scan, &out); err != nil {
		t.Fatalf("deep verification is advisory; a failure must not abort the run: %v", err)
	}
	for _, f := range scan.Findings {
		if f.Deep != nil {
			t.Errorf("%s: no outcome should be recorded for a failed call", f.RuleID)
		}
	}
	if !strings.Contains(out.String(), "failed") {
		t.Errorf("failure not reported: %s", out.String())
	}
	if scan.Findings[0].Verdict.Classification != model.ClassUncertain {
		t.Error("the earlier verdict must be untouched")
	}
}

func TestDeepConfig_DeniesVaultAndStateDirs(t *testing.T) {
	o := &options{deepMaxSteps: 9, vaultPath: "rel/vault.jsonl", ruleRepoDir: ".achilles/generated-rules"}
	cfg := deepConfig(o, "/scan/target")
	if cfg.MaxSteps != 9 {
		t.Errorf("MaxSteps = %d", cfg.MaxSteps)
	}
	var sawState, sawVault bool
	for _, p := range cfg.DenyPaths {
		if !filepath.IsAbs(p) {
			t.Errorf("deny path %q must be absolute", p)
		}
		sawState = sawState || strings.HasSuffix(filepath.ToSlash(p), "/scan/target/.achilles")
		sawVault = sawVault || strings.HasSuffix(filepath.ToSlash(p), "rel/vault.jsonl")
	}
	if !sawState || !sawVault {
		t.Errorf("deny paths = %v", cfg.DenyPaths)
	}
}
