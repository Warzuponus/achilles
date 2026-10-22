package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

const tpVerdict = `{"classification":"true_positive","confidence":0.9,"exploitability":"reachable","reasoning":"r"}`

func allPrompts(f *llmtest.Fake) string {
	var sb strings.Builder
	for _, c := range f.Calls {
		for _, m := range c.Messages {
			sb.WriteString(m.Content)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func TestTriage_CredentialFindingNeverReachesTheModel(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{tpVerdict}}
	eng := NewEngine(llm.NewRouter(fake), nil, enrich.New(2), "")
	f := newFinding()
	f.Tool, f.RuleID = "gitleaks", "generic-api-key"
	f.Message = `key = "AKIAIOSFODNN7EXAMPLE"`

	err := eng.Triage(context.Background(), "r", f)
	if !errors.Is(err, ErrWithheld) {
		t.Fatalf("err = %v, want ErrWithheld", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("model was called %d time(s) for a credential finding", len(fake.Calls))
	}
	if f.Verdict != nil {
		t.Error("a withheld finding must have no verdict")
	}
}

func TestTriage_MasksCredentialsInPrompts(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{tpVerdict, `{"refuted":false}`}}
	eng := NewEngine(llm.NewRouter(fake), nil, enrich.New(2), "")
	f := newFinding()
	f.Message = `eval of config token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`

	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	if p := allPrompts(fake); strings.Contains(p, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Errorf("a credential reached the model:\n%s", p)
	}
}

func TestTriage_NoCodeModeSendsNoSource(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{tpVerdict, `{"refuted":false}`}}
	eng := NewEngine(llm.NewRouter(fake), nil, enrich.New(2), "").SetNoCode(true)
	f := newFinding() // CodeContext: eval(user_input)

	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	p := allPrompts(fake)
	if strings.Contains(p, "eval(user_input)") {
		t.Errorf("source code reached the model in --llm-no-code mode:\n%s", p)
	}
	if !strings.Contains(p, "withheld by --llm-no-code") {
		t.Error("the prompt should tell the model the source was withheld")
	}
}

func TestPrompts_TellTheModelCodeIsUntrusted(t *testing.T) {
	f := newFinding()
	v := model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.9}
	for name, msgs := range map[string][]llm.Message{
		"triage":      triageMessages(*f, "code", nil),
		"judge":       judgeMessages(*f, "code", v, false),
		"remediation": remediationMessages(*f, "code"),
	} {
		if !strings.Contains(msgs[0].Content, "UNTRUSTED DATA") {
			t.Errorf("%s system prompt lacks the untrusted-input instruction", name)
		}
	}
}

func TestTriage_NoCodeModeSendsNoEntryPointHints(t *testing.T) {
	dir := t.TempDir()
	src := "package a\nfunc init() { http.HandleFunc(\"/secret-route\", h) }\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	tf := &llmtest.Fake{Responses: []string{`{"classification":"uncertain","confidence":0.5}`}}
	eng := NewEngine(llm.NewRouter(tf), nil, enrich.New(2), dir).SetNoCode(true)
	f := newFinding()
	f.Location.File = "a.go"
	if err := eng.Triage(context.Background(), "r", f); err != nil {
		t.Fatal(err)
	}
	for _, c := range tf.Calls {
		for _, m := range c.Messages {
			if strings.Contains(m.Content, "secret-route") {
				t.Errorf("--llm-no-code must withhold file-derived hints too:\n%s", m.Content)
			}
		}
	}
}

// A scanner-declared credential finding is withheld even when neither its tool
// nor its rule id looks like one (Trivy's "slack-web-hook", "github-pat", ...).
func TestTriage_ScannerDeclaredSecretNeverReachesTheModel(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{tpVerdict}}
	eng := NewEngine(llm.NewRouter(fake), nil, enrich.New(2), "")
	f := newFinding()
	f.Tool, f.RuleID, f.Category = "Trivy", "slack-web-hook", model.CategorySecret

	if err := eng.Triage(context.Background(), "r", f); !errors.Is(err, ErrWithheld) {
		t.Fatalf("err = %v, want ErrWithheld", err)
	}
	if len(fake.Calls) != 0 || f.Verdict != nil {
		t.Errorf("a credential finding reached the model (%d call(s)) or got a verdict", len(fake.Calls))
	}

	// Without the category the same tool and rule would have gone to the model:
	// that is the gap the category closes.
	g := newFinding()
	g.Tool, g.RuleID = "Trivy", "slack-web-hook"
	if g.IsSecret() {
		t.Fatal("precondition: the rule id alone does not look like a credential")
	}
}
