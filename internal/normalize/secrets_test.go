package normalize

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// Built at run time so this file holds no credential-shaped literal.
var (
	testSecretA = "hunter" + "2-Xy7!q-first"
	testSecretB = "hunter" + "2-Xy7!q-second"
)

// trivyDoc is the shape Trivy emits: one driver, every rule tagged with its class.
func trivyDoc() []byte {
	rule := func(id, class string) map[string]any {
		return map[string]any{"id": id, "properties": map[string]any{"tags": []string{class, "security", "HIGH"}}}
	}
	result := func(id, msg, uri string, line int) map[string]any {
		return map[string]any{"ruleId": id, "level": "error", "message": map[string]any{"text": msg},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": uri},
				"region":           map[string]any{"startLine": line, "snippet": map[string]any{"text": "line " + id}},
			}}}}
	}
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "Trivy", "rules": []any{
			rule("github-pat", "secret"), rule("slack-web-hook", "secret"),
			rule("DSA-5678-1", "vulnerability"), rule("AVD-DS-0002", "misconfiguration"),
		}}},
		"results": []any{
			result("github-pat", "Artifact: deploy.sh\nType: \nSecret GitHub Personal Access Token\nSeverity: CRITICAL\nMatch: ****", "deploy.sh", 4),
			result("slack-web-hook", "Artifact: notify.py\nType: \nSecret Slack Webhook\nSeverity: MEDIUM\nMatch: ****", "notify.py", 9),
			result("DSA-5678-1", "Package: libfoo\nInstalled Version: 1.0\nVulnerability DSA-5678-1", "Dockerfile", 1),
			result("AVD-DS-0002", "Artifact: Dockerfile\nType: dockerfile\nVulnerability DS002", "Dockerfile", 3),
		},
	}}}
	b, _ := json.Marshal(doc)
	return b
}

// The bug: Trivy's secret rules ("github-pat", "slack-web-hook", ...) match none of
// the keyword heuristics, so the line holding the credential was sent to the model
// and a verdict could dismiss it.
func TestTrivy_FindingsAreClassifiedByWhatTrivySaysTheyAre(t *testing.T) {
	fs, err := Normalize("sarif", "trivy", trivyDoc())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 {
		t.Fatalf("want 4 findings, got %d", len(fs))
	}
	for _, f := range fs[:2] {
		if f.Category != model.CategorySecret || !f.IsSecret() {
			t.Errorf("%s: category %q, IsSecret %v; a Trivy secret must be a credential finding", f.RuleID, f.Category, f.IsSecret())
		}
		if f.IsDependencyAdvisory() {
			t.Errorf("%s is not a dependency advisory", f.RuleID)
		}
		if f.CodeContext != "" {
			t.Errorf("%s keeps its snippet %q; a credential finding's snippet is never kept", f.RuleID, f.CodeContext)
		}
	}
	if vuln := fs[2]; vuln.Category != model.CategoryDependency || !vuln.IsDependencyAdvisory() || vuln.IsSecret() {
		t.Errorf("a Trivy vulnerability with a non-CVE id must still be a dependency advisory: %+v", vuln)
	}
	if mis := fs[3]; mis.Category != "" || mis.IsSecret() || mis.IsDependencyAdvisory() {
		t.Errorf("a misconfiguration is an ordinary finding the AI may review: %+v", mis)
	}
	if fs[3].CodeContext == "" {
		t.Error("ordinary findings keep their snippet")
	}
}

func TestTrivy_SecretIsRecognisedFromTheMessageWhenTagsAreMissing(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":"github-pat"}]}},
	  "results":[{"ruleId":"github-pat","level":"error",
	  "message":{"text":"Artifact: deploy.sh\nType: \nSecret GitHub Personal Access Token\nSeverity: CRITICAL\nMatch: ****"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"deploy.sh"},"region":{"startLine":4}}}]}]}]}`
	fs, err := Normalize("sarif", "trivy", []byte(doc))
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if !fs[0].IsSecret() {
		t.Error("a Trivy result labelled Secret in its message is a credential finding")
	}
}

func TestCategory_VulnerabilityTagOnAnotherToolIsNotADependency(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"somesast","rules":[
	  {"id":"sqli","properties":{"tags":["vulnerability","security"]}}]}},
	  "results":[{"ruleId":"sqli","level":"error","message":{"text":"m"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	fs, _ := Normalize("sarif", "x", []byte(doc))
	if len(fs) != 1 || fs[0].IsDependencyAdvisory() {
		t.Errorf("only Trivy's \"vulnerability\" tag means a vulnerable package: %+v", fs)
	}
}

func gitleaksDoc(secrets ...string) []byte {
	var results []any
	for i, s := range secrets {
		results = append(results, map[string]any{"ruleId": "generic-api-key",
			"message": map[string]any{"text": "generic-api-key has detected secret for file config.py."},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": "config.py"},
				"region":           map[string]any{"startLine": i + 1, "snippet": map[string]any{"text": s}},
			}}}})
	}
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "gitleaks"}}, "results": results}}})
	return b
}

// The snippet is dropped, but only after the fingerprint was taken from it: two
// different secrets in one file must stay two findings.
func TestSecretSnippetIsDroppedAfterFingerprinting(t *testing.T) {
	fs, err := Normalize("sarif", "gitleaks", gitleaksDoc(testSecretA, testSecretB))
	if err != nil || len(fs) != 2 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	for _, f := range fs {
		if f.CodeContext != "" {
			t.Errorf("credential snippet kept: %q", f.CodeContext)
		}
		if b, _ := json.Marshal(f); bytes.Contains(b, []byte("hunter")) {
			t.Errorf("the stored finding record would contain the secret: %s", b)
		}
	}
	if fs[0].Fingerprint == fs[1].Fingerprint {
		t.Error("two different secrets collapsed into one fingerprint")
	}
	again, _ := Normalize("sarif", "gitleaks", gitleaksDoc(testSecretA, testSecretB))
	if again[0].Fingerprint != fs[0].Fingerprint {
		t.Error("the fingerprint must be stable across runs")
	}
}

// --- ScrubRaw ---

func mixedDoc() ([]byte, []model.Finding) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"mixed","rules":[
	  {"id":"hardcoded-password","properties":{"tags":["secret"]}},{"id":"eval"}]}},
	  "results":[
	   {"ruleId":"hardcoded-password","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":
	     {"artifactLocation":{"uri":"c.py"},"region":{"startLine":1,"snippet":{"text":"` + testSecretA + `"}},
	      "contextRegion":{"startLine":1,"snippet":{"text":"x = ` + testSecretA + `"}}}}]},
	   {"ruleId":"eval","level":"warning","message":{"text":"m"},"locations":[{"physicalLocation":
	     {"artifactLocation":{"uri":"a.py"},"region":{"startLine":7,"snippet":{"text":"eval(user_input)"}}}}]}
	  ]}]}`
	fs, err := Normalize("sarif", "mixed", []byte(doc))
	if err != nil {
		panic(err)
	}
	return []byte(doc), fs
}

func TestScrubRaw_RemovesCredentialSnippetsAndKeepsTheRest(t *testing.T) {
	doc, fs := mixedDoc()
	out := ScrubRaw("sarif", doc, fs)
	if bytes.Contains(out, []byte(testSecretA)) {
		t.Fatalf("the secret is still in the stored output:\n%s", out)
	}
	if !bytes.Contains(out, []byte("eval(user_input)")) {
		t.Error("the code finding's snippet must be kept")
	}
	// Still a SARIF log that normalizes to the same findings.
	again, err := Normalize("sarif", "mixed", out)
	if err != nil || len(again) != 2 || again[1].RuleID != "eval" || again[1].Location.Region.StartLine != 7 {
		t.Errorf("scrubbed output is no longer usable SARIF: %v %+v", err, again)
	}
}

func TestScrubRaw_LeavesOutputWithNoCredentialsByteForByte(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[{"ruleId":"G204","level":"error",
	  "message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1,"snippet":{"text":"exec.Command(x)"}}}}]}]}]}`)
	fs, _ := Normalize("sarif", "gosec", doc)
	if out := ScrubRaw("sarif", doc, fs); !bytes.Equal(out, doc) {
		t.Error("output with nothing to remove must be stored exactly as the tool wrote it")
	}
}

func TestScrubRaw_BlanksEverySnippetWhenResultsCannotBeMatchedToFindings(t *testing.T) {
	doc, fs := mixedDoc()
	out := ScrubRaw("sarif", doc, fs[:1]) // one finding for two results: alignment is lost
	if bytes.Contains(out, []byte(testSecretA)) || bytes.Contains(out, []byte("eval(user_input)")) {
		t.Errorf("when in doubt every snippet goes:\n%s", out)
	}
}

func TestScrubRaw_NonSARIFAndUnparseableOutput(t *testing.T) {
	secret := []model.Finding{{Tool: "bandit", RuleID: "B105", CWE: []string{"CWE-259"}}}
	key := "AKIA" + "IOSFODNN7EXAMPLE"

	out := ScrubRaw("bandit", []byte(`{"results":[{"code":"aws = '`+key+`'","line_number":3}]}`), secret)
	if bytes.Contains(out, []byte(key)) || !bytes.Contains(out, []byte(`"line_number":3`)) {
		t.Errorf("non-SARIF output must be pattern-masked and stay JSON: %s", out)
	}

	out = ScrubRaw("bandit", []byte("not json: "+testSecretA), secret)
	if strings.Contains(string(out), testSecretA) || !strings.Contains(string(out), "withheld") {
		t.Errorf("output that cannot be parsed must be withheld, never stored as is: %s", out)
	}
}
