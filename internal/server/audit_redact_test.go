package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// Two kinds of secret, built at run time so this file holds no credential-shaped
// literal: one a pattern mask recognises, and one it cannot (a short password with
// no known prefix), which only withholding protects.
var (
	shapedKey = "AKIA" + "IOSFODNN7EXAMPLE"
	plainPass = "hunter" + "2-Xy7!q"
)

func appendRec(t *testing.T, v vault.Store, kind vault.Kind, fp string, payload any) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Append(vault.Record{RunID: "run1", Kind: kind, Fingerprint: fp, Payload: b}); err != nil {
		t.Fatal(err)
	}
}

// seedSecrets fills a run with everything a real scan leaves in the vault.
func seedSecrets(t *testing.T, tenants *Tenants) model.Finding {
	t.Helper()
	v, err := tenants.Vault("acme")
	if err != nil {
		t.Fatal(err)
	}
	secret := model.Finding{
		Tool: "gitleaks", RuleID: "generic-api-key", Severity: model.SeverityHigh, Fingerprint: "sec1",
		Message:     "generic-api-key has detected secret for file config.py.",
		Location:    model.Location{File: "config.py", Region: model.Region{StartLine: 3}},
		CodeContext: `DB_PASSWORD_VALUE: ` + plainPass, // what gitleaks puts in snippet.text
	}
	code := model.Finding{
		Tool: "opengrep", RuleID: "eval", Severity: model.SeverityHigh, Fingerprint: "code1",
		Message:     "eval on input",
		Location:    model.Location{File: "a.py", Region: model.Region{StartLine: 1}},
		CodeContext: "client = boto3.client('s3', aws_access_key_id='" + shapedKey + "')\neval(user_input)",
	}

	appendRec(t, v, vault.KindScanMeta, "", map[string]any{"target": "/repo/acme", "mode": "oss"})
	// The scanner's raw SARIF: the secret, verbatim, in a snippet.
	appendRec(t, v, vault.KindRawOutput, "", map[string]any{"sarif": map[string]any{"runs": []any{map[string]any{
		"results": []any{map[string]any{"ruleId": "generic-api-key",
			"locations": []any{map[string]any{"physicalLocation": map[string]any{"region": map[string]any{
				"snippet": map[string]any{"text": plainPass}}}}}}},
	}}}})
	appendRec(t, v, vault.KindFinding, secret.Fingerprint, secret)
	appendRec(t, v, vault.KindFinding, code.Fingerprint, code)
	appendRec(t, v, vault.KindLLMCall, code.Fingerprint, map[string]any{
		"task": "triage", "model": "m",
		"response": `{"classification":"true_positive","reasoning":"the key ` + shapedKey + ` is hard-coded next to the eval"}`,
	})
	appendRec(t, v, vault.KindVerdict, code.Fingerprint, model.Verdict{
		Classification: model.ClassTruePositive, Confidence: 0.9,
		Reasoning: "uses " + shapedKey + " then evals input", RefuteEvidence: "aws_access_key_id='" + shapedKey + "'",
	})
	appendRec(t, v, vault.KindRemediation, code.Fingerprint, map[string]any{
		"summary": "s", "diff": "-aws_access_key_id='" + shapedKey + "'\n+aws_access_key_id=os.environ['K']\n",
	})
	return secret
}

// SECURITY.md promises that secrets found in code are redacted before they reach
// the UI or the API. The audit endpoint returned the vault verbatim: raw scanner
// output, credential snippets and LLM transcripts.
func TestAuditExport_ServesNoSecretMaterial(t *testing.T) {
	s, tenants := newServer(t)
	seedSecrets(t, tenants)

	w := do(s.Handler(), "GET", "/runs/run1/audit", "acme", nil)
	if w.Code != 200 {
		t.Fatalf("audit = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, plainPass) {
		t.Error("the audit trail serves a credential a pattern mask cannot recognise (it must be withheld, not masked)")
	}
	if strings.Contains(body, shapedKey) {
		t.Error("the audit trail serves a recognisable key (in a finding, an LLM transcript, a verdict or a diff)")
	}

	var recs []vault.Record
	if err := json.Unmarshal(w.Body.Bytes(), &recs); err != nil {
		t.Fatalf("audit output is not a JSON list of records: %v", err)
	}
	if len(recs) != 7 {
		t.Fatalf("the trail must still list every record, got %d of 7", len(recs))
	}
	kinds := map[vault.Kind]json.RawMessage{}
	for _, r := range recs {
		if r.ID == "" || r.RunID != "run1" || r.Timestamp.IsZero() {
			t.Errorf("record lost its envelope: %+v", r)
		}
		kinds[r.Kind] = r.Payload
	}
	// Raw output is acknowledged, not served.
	var raw map[string]any
	if err := json.Unmarshal(kinds[vault.KindRawOutput], &raw); err != nil || raw["withheld"] == nil || raw["sarif"] != nil {
		t.Errorf("raw_output payload = %s, want a withheld notice", kinds[vault.KindRawOutput])
	}
	// What is not secret is still there to audit.
	if !strings.Contains(body, "eval(user_input)") || !strings.Contains(body, "true_positive") {
		t.Error("redaction removed ordinary content; the trail must stay useful")
	}
	if !strings.Contains(body, `"fingerprint":"code1"`) && !strings.Contains(body, `"fingerprint": "code1"`) {
		t.Error("fingerprints link the records and must survive")
	}
}

func TestRunPage_WithholdsCredentialSnippets(t *testing.T) {
	s, tenants := newServer(t)
	seedSecrets(t, tenants)

	w := do(s.Handler(), "GET", "/runs/run1", "acme", nil)
	if w.Code != 200 {
		t.Fatalf("run page = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, plainPass) {
		t.Error("the run page shows a credential finding's matched text")
	}
	if strings.Contains(body, shapedKey) {
		t.Error("the run page shows a key from a code finding's context")
	}
	if !strings.Contains(body, "withheld") {
		t.Error("the page should say the snippet was withheld, not show an unexplained gap")
	}
	if !strings.Contains(body, "eval(user_input)") {
		t.Error("ordinary code context must still be shown")
	}
}

func TestRedactValue_KeepsIdentifiersAndWalksEverythingElse(t *testing.T) {
	longHash := strings.Repeat("ab12", 10) // 40 chars: the long-token mask would blank it
	doc := map[string]any{
		"fingerprint": longHash,
		"note":        "token " + longHash,
		"nested":      map[string]any{"list": []any{"key " + shapedKey, 7, true, nil}},
	}
	out := redactValue("", doc).(map[string]any)
	if out["fingerprint"] != longHash {
		t.Errorf("fingerprint was masked: %v", out["fingerprint"])
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), shapedKey) || strings.Contains(out["note"].(string), longHash) {
		t.Errorf("a string value escaped the mask: %s", b)
	}
}

func TestRedactPayload_NeverServesWhatItCannotParse(t *testing.T) {
	got := redactPayload(vault.KindLLMCall, json.RawMessage(`not json `+plainPass))
	if strings.Contains(string(got), plainPass) || !strings.Contains(string(got), "withheld") {
		t.Errorf("an unparseable payload must be withheld, got %s", got)
	}
}
