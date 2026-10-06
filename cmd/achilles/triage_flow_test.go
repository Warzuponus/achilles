package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// fakeEndpoint is an OpenAI-compatible server. decide gets the rule named in the
// prompt and whether this is the judge pass, and returns the JSON the "model" sends.
type fakeEndpoint struct {
	*httptest.Server
	calls   atomic.Int64
	mu      sync.Mutex
	prompts []string
}

func newFakeEndpoint(t *testing.T, status int, delay time.Duration, decide func(rule string, judge bool) string) *fakeEndpoint {
	t.Helper()
	fe := &fakeEndpoint{}
	fe.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fe.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		fe.mu.Lock()
		fe.prompts = append(fe.prompts, string(body))
		fe.mu.Unlock()
		time.Sleep(delay)
		if status != http.StatusOK {
			http.Error(w, `{"error":{"message":"bad key"}}`, status)
			return
		}
		var req struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		judge := strings.Contains(req.Messages[0].Content, "adversarial reviewer")
		rule := ""
		for _, line := range strings.Split(req.Messages[len(req.Messages)-1].Content, "\n") {
			if strings.HasPrefix(line, "Rule: ") {
				rule = strings.TrimPrefix(line, "Rule: ")
			}
			if strings.HasPrefix(line, "Finding: ") {
				rule = strings.Fields(strings.TrimPrefix(line, "Finding: "))[0]
			}
		}
		content, _ := json.Marshal(decide(rule, judge))
		_, _ = w.Write([]byte(`{"model":"fake","choices":[{"message":{"content":` + string(content) + `}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	t.Cleanup(fe.Close)
	return fe
}

func verdictFor(rule string, judge bool) string {
	if judge {
		return `{"refuted":false,"reason":""}`
	}
	if strings.HasPrefix(rule, "fp-") {
		return `{"classification":"false_positive","confidence":0.95,"exploitability":"not-reachable","reasoning":"constant input"}`
	}
	return `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"user input reaches the sink"}`
}

func triageFixture(t *testing.T, rules ...string) (*model.Scan, vault.Store) {
	t.Helper()
	t.Setenv("ACHILLES_LLM_API_KEY", "test-key-not-real")
	t.Setenv("ACHILLES_LLM_MAX_RETRIES", "-1")
	llmAuthMode = "key"
	ev, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	scan := &model.Scan{Target: t.TempDir()}
	for i, r := range rules {
		scan.Findings = append(scan.Findings, model.Finding{
			Tool: "opengrep", RuleID: r, Severity: model.SeverityHigh, Message: "m",
			Fingerprint: "fp" + string(rune('a'+i)), CodeContext: "code " + r,
			Location: model.Location{File: "a.py", Region: model.Region{StartLine: i + 1}},
		})
	}
	return scan, ev
}

func TestRunTriage_DismissesConfidentFalsePositivesAndReportsCoverage(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "fp-1", "real-1", "fp-2", "real-2")

	_, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 2 || len(scan.Dismissed) != 2 {
		t.Fatalf("kept %d, dismissed %d; want 2 and 2", len(scan.Findings), len(scan.Dismissed))
	}
	for _, f := range scan.Findings {
		if strings.HasPrefix(f.RuleID, "fp-") {
			t.Errorf("false positive %s stayed in the gate set", f.RuleID)
		}
	}
	if st := scan.Triage; st == nil || st.Total != 4 || st.Triaged != 4 || st.Dismissed != 2 || st.Failed != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestRunTriage_KeepDismissedLeavesEverythingInTheGate(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "fp-1", "real-1")
	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", keepDismissed: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 2 || len(scan.Dismissed) != 0 {
		t.Errorf("kept %d, dismissed %d; want 2 and 0", len(scan.Findings), len(scan.Dismissed))
	}
}

func TestRunTriage_NoCodeNeverDismisses(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "fp-1", "real-1")
	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", noCode: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Dismissed) != 0 {
		t.Error("a model that never saw the code must not dismiss findings")
	}
	for _, p := range fe.prompts {
		if strings.Contains(p, "code fp-1") || strings.Contains(p, "code real-1") {
			t.Errorf("source code reached the endpoint in no-code mode: %s", p)
		}
	}
}

func TestRunTriage_RejectedKeyAbortsInsteadOfFailingEveryFinding(t *testing.T) {
	fe := newFakeEndpoint(t, http.StatusUnauthorized, 0, verdictFor)
	rules := make([]string, 30)
	for i := range rules {
		rules[i] = "real"
	}
	scan, ev := triageFixture(t, rules...)

	_, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", concurrency: 1})
	if err == nil || !strings.Contains(err.Error(), "AI review aborted") {
		t.Fatalf("err = %v, want an abort", err)
	}
	if n := fe.calls.Load(); n > 5 {
		t.Errorf("made %d calls against a rejected key; it should stop almost at once", n)
	}
}

func TestRunTriage_CredentialFindingsAreWithheldAndKept(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1")
	scan.Findings = append(scan.Findings, model.Finding{
		Tool: "gitleaks", RuleID: "generic-api-key", Severity: model.SeverityHigh,
		Message: "found AKIAIOSFODNN7EXAMPLE", Fingerprint: "secret1", CodeContext: "AKIAIOSFODNN7EXAMPLE",
		Location: model.Location{File: ".env"},
	})
	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range fe.prompts {
		if strings.Contains(p, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("a credential reached the endpoint")
		}
	}
	if len(scan.Findings) != 2 {
		t.Errorf("the credential finding must stay in the gate set, have %d findings", len(scan.Findings))
	}
	if st := scan.Triage; st == nil || st.Withheld != 1 || st.Triaged != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestRunTriage_RunningOutOfBudgetIsReportedNotHidden(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 60*time.Millisecond, verdictFor)
	scan, ev := triageFixture(t, "real-1", "real-2", "real-3", "real-4", "real-5", "real-6")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := runTriage(ctx, ev, "run", scan, nil, triageOpts{baseURL: fe.URL, triageModel: "m", concurrency: 1})
	if err != nil {
		t.Fatalf("a spent budget is partial coverage, not an error: %v", err)
	}
	st := scan.Triage
	if st == nil || st.Skipped == 0 || st.Triaged+st.Skipped+st.Failed != st.Total {
		t.Errorf("coverage must account for every finding, got %+v", st)
	}
	if len(scan.Findings) != 6 {
		t.Errorf("unreviewed findings must stay in the gate set, have %d", len(scan.Findings))
	}
}
