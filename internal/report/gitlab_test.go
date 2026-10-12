package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
)

var gitlabMeta = GitLabMeta{
	Version: "v0.2.0",
	Start:   time.Date(2026, 10, 12, 9, 30, 0, 0, time.FixedZone("CEST", 2*3600)),
	End:     time.Date(2026, 10, 12, 9, 31, 5, 0, time.FixedZone("CEST", 2*3600)),
}

func gitlabScan() model.Scan {
	return model.Scan{
		Target: "/repo",
		Tools:  []string{"gosec", "opengrep", "gitleaks", "osv-scanner"},
		Findings: []model.Finding{
			{
				ID: "id-1", Tool: "gosec", RuleID: "G204", CWE: []string{"CWE-78", "cwe-078", "CWE-88: argument injection"},
				Message:  "Subprocess launched with variable. Review how cmd is built.",
				Location: model.Location{File: "./cmd/run.go", Region: model.Region{StartLine: 41, EndLine: 43}},
				Severity: model.SeverityHigh, Fingerprint: "fp-1",
				Verdict: &model.Verdict{Classification: model.ClassTruePositive, Confidence: 0.9,
					Exploitability: model.ExploitReachable, Reasoning: "cmd comes from the request"},
				Remediation: &model.Remediation{
					Summary: "Pass arguments as a list", Guidance: "Never build a shell string from input.",
					Diff:         "--- a/cmd/run.go\n+++ b/cmd/run.go\n@@ -41,1 +41,1 @@\n-old\n+new\n",
					Verification: &model.FixVerification{Status: model.FixVerified},
				},
			},
			{
				ID: "id-2", Tool: "opengrep", RuleID: "python.lang.security.dangerous-system-call",
				Message:  "os.system called with user input",
				Location: model.Location{File: `app\views.py`, Region: model.Region{StartLine: 7}},
				Severity: model.SeverityMedium, Fingerprint: "fp-2",
				Remediation: &model.Remediation{Summary: "Use subprocess.run", Diff: "--- a\n+++ b\n",
					Verification: &model.FixVerification{Status: model.FixNotFixed}},
			},
			{
				ID: "id-3", Tool: "gitleaks", RuleID: "generic-api-key", Category: model.CategorySecret,
				Message:  "Detected key AKIAIOSFODNN7EXAMPLE in config. token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
				Location: model.Location{File: "config/prod.env", Region: model.Region{StartLine: 3}},
				Severity: model.SeverityCritical, Fingerprint: "fp-3",
			},
			{
				ID: "id-4", Tool: "osv-scanner", RuleID: "GHSA-aaaa-bbbb-cccc", Category: model.CategoryDependency,
				Message:  "lodash 4.17.20 is vulnerable",
				Location: model.Location{File: "package-lock.json"},
				Severity: model.SeverityHigh, Fingerprint: "fp-4",
			},
			{
				ID: "id-5", Tool: "opengrep", RuleID: "generated.rule", Shadow: true,
				Message:  "found by a rule still under observation",
				Location: model.Location{File: "a.py", Region: model.Region{StartLine: 1}},
				Severity: model.SeverityHigh, Fingerprint: "fp-5",
			},
		},
	}
}

func decodeGitLab(t *testing.T, write func(*bytes.Buffer) error) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	return doc
}

// checkGitLabSecurityReport holds a document to the constraints of GitLab's
// security report schema, as published in versions 15.0.0 through 15.2.5 of
// gitlab-org/security-products/security-report-schemas: required properties,
// enumerations, patterns and length limits for every property Achilles writes.
func checkGitLabSecurityReport(t *testing.T, doc map[string]any, scanType string) {
	t.Helper()
	str := func(m map[string]any, key string, required bool) string {
		t.Helper()
		v, ok := m[key]
		if !ok {
			if required {
				t.Errorf("required property %q is missing", key)
			}
			return ""
		}
		s, isString := v.(string)
		if !isString {
			t.Errorf("%q must be a string, got %T", key, v)
		}
		if required && s == "" {
			t.Errorf("%q must not be empty", key)
		}
		return s
	}
	obj := func(m map[string]any, key string) map[string]any {
		t.Helper()
		o, ok := m[key].(map[string]any)
		if !ok {
			t.Errorf("required object %q is missing", key)
			return map[string]any{}
		}
		return o
	}
	oneOf := func(what, got string, allowed ...string) {
		t.Helper()
		for _, a := range allowed {
			if got == a {
				return
			}
		}
		t.Errorf("%s = %q, must be one of %v", what, got, allowed)
	}

	if v := str(doc, "version", true); !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(v) {
		t.Errorf("version %q", v)
	}
	if s := str(doc, "schema", false); !strings.HasPrefix(s, "https://") {
		t.Errorf("schema %q", s)
	}

	scan := obj(doc, "scan")
	oneOf("scan.type", str(scan, "type", true), scanType)
	oneOf("scan.status", str(scan, "status", true), "success", "failure")
	stamp := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
	for _, k := range []string{"start_time", "end_time"} {
		if v := str(scan, k, true); !stamp.MatchString(v) {
			t.Errorf("scan.%s = %q, want yyyy-mm-ddThh:mm:ss with no zone", k, v)
		}
	}
	for _, k := range []string{"analyzer", "scanner"} {
		tool := obj(scan, k)
		str(tool, "id", true)
		str(tool, "name", true)
		str(tool, "version", true)
		str(obj(tool, "vendor"), "name", true)
		if u, ok := tool["url"]; ok && !regexp.MustCompile(`^https?://.+`).MatchString(u.(string)) {
			t.Errorf("scan.%s.url %q", k, u)
		}
	}
	if msgs, ok := scan["messages"]; ok {
		for _, m := range msgs.([]any) {
			oneOf("message level", str(m.(map[string]any), "level", true), "info", "warn", "fatal")
			str(m.(map[string]any), "value", true)
		}
	}

	vulns, ok := doc["vulnerabilities"].([]any)
	if !ok {
		t.Fatalf("vulnerabilities must be an array, got %T", doc["vulnerabilities"])
	}
	ids := map[string]bool{}
	for _, raw := range vulns {
		v := raw.(map[string]any)
		id := str(v, "id", true)
		if ids[id] {
			t.Errorf("vulnerability id %q is not unique", id)
		}
		ids[id] = true
		if n := str(v, "name", false); len(n) > 255 {
			t.Errorf("name is %d bytes, at most 255", len(n))
		}
		if s := str(v, "solution", false); len(s) > 7000 {
			t.Errorf("solution is %d bytes, at most 7000", len(s))
		}
		oneOf("severity", str(v, "severity", true), "Info", "Unknown", "Low", "Medium", "High", "Critical")
		loc := obj(v, "location")
		if scanType == "secret_detection" {
			str(obj(loc, "commit"), "sha", true)
		}
		for _, k := range []string{"start_line", "end_line"} {
			if n, ok := loc[k]; ok {
				if f, isNum := n.(float64); !isNum || f < 1 {
					t.Errorf("location.%s = %v", k, n)
				}
			}
		}
		idents, _ := v["identifiers"].([]any)
		if len(idents) < 1 || len(idents) > 20 {
			t.Errorf("%d identifiers; the schema needs at least one and GitLab keeps at most 20", len(idents))
		}
		for _, i := range idents {
			im := i.(map[string]any)
			str(im, "type", true)
			str(im, "name", true)
			str(im, "value", true)
			if u, ok := im["url"]; ok && !regexp.MustCompile(`^https?://.+`).MatchString(u.(string)) {
				t.Errorf("identifier url %q", u)
			}
		}
		if flags, ok := v["flags"]; ok {
			for _, f := range flags.([]any) {
				fm := f.(map[string]any)
				oneOf("flag type", str(fm, "type", true), "flagged-as-likely-false-positive")
				str(fm, "origin", true)
				str(fm, "description", true)
			}
		}
		if details, ok := v["details"]; ok {
			for key, d := range details.(map[string]any) {
				dm := d.(map[string]any)
				oneOf("details."+key+".type", str(dm, "type", true), "text")
				str(dm, "name", true)
				str(dm, "value", false)
			}
		}
	}
	if rems, ok := doc["remediations"]; ok {
		for _, r := range rems.([]any) {
			rm := r.(map[string]any)
			str(rm, "summary", true)
			if _, err := base64.StdEncoding.DecodeString(str(rm, "diff", true)); err != nil {
				t.Errorf("remediation diff is not base64: %v", err)
			}
			fixes, _ := rm["fixes"].([]any)
			if len(fixes) == 0 {
				t.Error("a remediation must name the vulnerabilities it fixes")
			}
			for _, f := range fixes {
				if id := str(f.(map[string]any), "id", true); !ids[id] {
					t.Errorf("remediation refers to %q, which is not a vulnerability in this report", id)
				}
			}
		}
	}
}

func TestGitLabSAST_ConformsAndCarriesTheFindingsInCode(t *testing.T) {
	doc := decodeGitLab(t, func(b *bytes.Buffer) error { return WriteGitLabSAST(b, gitlabScan(), gitlabMeta) })
	checkGitLabSecurityReport(t, doc, "sast")

	if doc["version"] != GitLabSchemaVersion || !strings.HasSuffix(doc["schema"].(string), "/v"+GitLabSchemaVersion+"/dist/sast-report-format.json") {
		t.Errorf("version %v schema %v", doc["version"], doc["schema"])
	}
	scan := doc["scan"].(map[string]any)
	// Times are UTC without a zone: 09:30 at +02:00 is 07:30.
	if scan["start_time"] != "2026-10-12T07:30:00" || scan["end_time"] != "2026-10-12T07:31:05" {
		t.Errorf("times: %v .. %v", scan["start_time"], scan["end_time"])
	}
	if v := scan["scanner"].(map[string]any)["version"]; v != "0.2.0" {
		t.Errorf("scanner version = %v, want the version without its v", v)
	}
	if scan["status"] != "success" || scan["messages"] != nil {
		t.Errorf("a complete scan: status %v messages %v", scan["status"], scan["messages"])
	}

	// The secret, the dependency advisory and the shadow finding are not SAST findings.
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 2 {
		t.Fatalf("%d vulnerabilities, want the 2 findings in code", len(vulns))
	}
	first := vulns[0].(map[string]any)
	if first["name"] != "Subprocess launched with variable" || first["severity"] != "High" {
		t.Errorf("name %q severity %q", first["name"], first["severity"])
	}
	loc := first["location"].(map[string]any)
	if loc["file"] != "cmd/run.go" || loc["start_line"] != 41.0 || loc["end_line"] != 43.0 {
		t.Errorf("location = %v", loc)
	}
	// The reporting tool's rule is the primary identifier; CWEs follow, once each.
	var idents []string
	for _, i := range first["identifiers"].([]any) {
		im := i.(map[string]any)
		idents = append(idents, im["type"].(string)+"="+im["value"].(string))
	}
	if got := strings.Join(idents, " "); got != "gosec_rule_id=G204 cwe=78 cwe=88" {
		t.Errorf("identifiers = %s", got)
	}
	details := first["details"].(map[string]any)
	if review := details["ai_review"].(map[string]any)["value"]; review != "true positive, confidence 0.90, reachable" {
		t.Errorf("ai_review = %q", review)
	}
	if !strings.Contains(first["solution"].(string), "Pass arguments as a list") {
		t.Errorf("solution = %q", first["solution"])
	}
	// A Windows path is written the way GitLab links files.
	if f := vulns[1].(map[string]any)["location"].(map[string]any)["file"]; f != "app/views.py" {
		t.Errorf("file = %v", f)
	}

	// Only the patch that passed re-scanning is offered as a remediation.
	rems, _ := doc["remediations"].([]any)
	if len(rems) != 1 {
		t.Fatalf("%d remediations, want only the verified one", len(rems))
	}
	rem := rems[0].(map[string]any)
	diff, _ := base64.StdEncoding.DecodeString(rem["diff"].(string))
	if !strings.Contains(string(diff), "+new") || rem["fixes"].([]any)[0].(map[string]any)["id"] != first["id"] {
		t.Errorf("remediation = %v (diff %q)", rem, diff)
	}
}

func TestGitLabSecretDetection_NeverCarriesTheSecret(t *testing.T) {
	meta := gitlabMeta
	var buf bytes.Buffer
	if err := WriteGitLabSecretDetection(&buf, gitlabScan(), meta); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"} {
		if strings.Contains(buf.String(), leak) {
			t.Fatalf("the report contains the credential %s:\n%s", leak, buf.String())
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	checkGitLabSecurityReport(t, doc, "secret_detection")
	if !strings.HasSuffix(doc["schema"].(string), "/secret-detection-report-format.json") {
		t.Errorf("schema = %v", doc["schema"])
	}
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("%d vulnerabilities, want the one credential finding", len(vulns))
	}
	v := vulns[0].(map[string]any)
	if v["name"] != "Possible credential (gitleaks generic-api-key)" || v["severity"] != "Critical" {
		t.Errorf("name %q severity %q", v["name"], v["severity"])
	}
	// No commit is known: the placeholder GitLab's own analyzer uses for files.
	if sha := v["location"].(map[string]any)["commit"].(map[string]any)["sha"]; sha != "0000000" {
		t.Errorf("commit sha = %v", sha)
	}

	meta.Commit = "4f2a9c1"
	doc = decodeGitLab(t, func(b *bytes.Buffer) error { return WriteGitLabSecretDetection(b, gitlabScan(), meta) })
	if sha := doc["vulnerabilities"].([]any)[0].(map[string]any)["location"].(map[string]any)["commit"].(map[string]any)["sha"]; sha != "4f2a9c1" {
		t.Errorf("commit sha = %v, want the scanned commit", sha)
	}
}

// With nothing to report, the document is still a complete, valid report: GitLab
// reads an absent or null list as a broken artifact, not as a clean scan.
func TestGitLab_EmptyAndIncompleteScans(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitLabSAST(&buf, model.Scan{}, GitLabMeta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"vulnerabilities": []`) {
		t.Errorf("an empty scan must write an empty array:\n%s", buf.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	checkGitLabSecurityReport(t, doc, "sast")
	if v := doc["scan"].(map[string]any)["scanner"].(map[string]any)["version"]; v != "0.0.0" {
		t.Errorf("an unknown version must still be a version: %v", v)
	}

	// A scanner that did not run: the report says the scan failed and why.
	s := gitlabScan()
	s.FailedTools = []string{"gosec"}
	doc = decodeGitLab(t, func(b *bytes.Buffer) error { return WriteGitLabSAST(b, s, gitlabMeta) })
	checkGitLabSecurityReport(t, doc, "sast")
	scan := doc["scan"].(map[string]any)
	msgs, _ := scan["messages"].([]any)
	if scan["status"] != "failure" || len(msgs) != 1 || !strings.Contains(msgs[0].(map[string]any)["value"].(string), "gosec failed") {
		t.Errorf("status %v messages %v", scan["status"], msgs)
	}
	if len(doc["vulnerabilities"].([]any)) != 2 {
		t.Error("the findings of the scanners that did run must still be reported")
	}

	buf.Reset()
	if err := WriteGitLabCodeQuality(&buf, model.Scan{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("an empty Code Quality report is an empty array, got %s", buf.String())
	}
}

// A finding kept in the gate although the AI review dismissed it (--keep-dismissed)
// is marked the way GitLab marks a likely false positive.
func TestGitLabSAST_DismissedButKeptIsFlagged(t *testing.T) {
	s := gitlabScan()
	s.Findings[0].Verdict = &model.Verdict{Classification: model.ClassFalsePositive, Confidence: 0.97,
		Exploitability: model.ExploitNotReachable, Reasoning: "the command is a constant"}
	if !s.Findings[0].Dismissed() {
		t.Fatal("test setup: the verdict should dismiss the finding")
	}
	doc := decodeGitLab(t, func(b *bytes.Buffer) error { return WriteGitLabSAST(b, s, gitlabMeta) })
	checkGitLabSecurityReport(t, doc, "sast")
	vulns := doc["vulnerabilities"].([]any)
	flags, _ := vulns[0].(map[string]any)["flags"].([]any)
	if len(flags) != 1 || flags[0].(map[string]any)["description"] != "the command is a constant" {
		t.Errorf("flags = %v", flags)
	}
	if _, ok := vulns[1].(map[string]any)["flags"]; ok {
		t.Error("a finding without a dismissing verdict must not be flagged")
	}
}

func TestGitLab_IDsAreStableAndUnique(t *testing.T) {
	s := gitlabScan()
	// The same finding reported twice at the same place must still get two ids.
	s.Findings = append(s.Findings, s.Findings[0])
	ids := func() []string {
		doc := decodeGitLab(t, func(b *bytes.Buffer) error { return WriteGitLabSAST(b, s, gitlabMeta) })
		checkGitLabSecurityReport(t, doc, "sast")
		var out []string
		for _, v := range doc["vulnerabilities"].([]any) {
			out = append(out, v.(map[string]any)["id"].(string))
		}
		return out
	}
	first, second := ids(), ids()
	if strings.Join(first, " ") != strings.Join(second, " ") {
		t.Errorf("ids differ between two runs over the same scan:\n%v\n%v", first, second)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for _, id := range first {
		if !uuid.MatchString(id) {
			t.Errorf("id %q does not have the shape of a UUID", id)
		}
	}
}

// Text from a scanner or a model is bounded and cannot smuggle control characters.
func TestGitLab_UntrustedTextIsBounded(t *testing.T) {
	s := model.Scan{Findings: []model.Finding{{
		ID: "x", Tool: "opengrep", RuleID: strings.Repeat("r", 600),
		Message:  strings.Repeat("An endless sentence with no stop ", 400) + "\x1b[31mred\x00",
		Location: model.Location{File: "a.py", Region: model.Region{StartLine: 2}},
		Severity: model.Severity("weird"), Fingerprint: "fp",
		Remediation: &model.Remediation{Summary: strings.Repeat("s", 9000)},
	}}}
	var buf bytes.Buffer
	if err := WriteGitLabSAST(&buf, s, gitlabMeta); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `\u001b`) || strings.Contains(buf.String(), `\u0000`) {
		t.Error("control characters reached the report")
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	checkGitLabSecurityReport(t, doc, "sast")
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	if v["severity"] != "Unknown" {
		t.Errorf("an unrecognized severity must be Unknown, got %v", v["severity"])
	}
	if n := len(v["description"].(string)); n > gitlabMaxDescription {
		t.Errorf("description is %d bytes", n)
	}
}

func TestGitLabCodeQuality_EveryFindingThatCounts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitLabCodeQuality(&buf, gitlabScan()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") || strings.Contains(buf.String(), "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("the report contains a credential:\n%s", buf.String())
	}
	var issues []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &issues); err != nil {
		t.Fatalf("not a JSON array: %v", err)
	}
	// Code, credential and dependency findings; not the shadow one.
	if len(issues) != 4 {
		t.Fatalf("%d issues, want 4", len(issues))
	}
	prints := map[string]bool{}
	for _, is := range issues {
		for _, k := range []string{"description", "check_name", "fingerprint", "severity"} {
			if s, _ := is[k].(string); s == "" {
				t.Errorf("%q is required: %v", k, is)
			}
		}
		switch is["severity"] {
		case "info", "minor", "major", "critical", "blocker":
		default:
			t.Errorf("severity %v is not one GitLab accepts", is["severity"])
		}
		loc := is["location"].(map[string]any)
		if p, _ := loc["path"].(string); p == "" || strings.HasPrefix(p, "./") || strings.Contains(p, `\`) {
			t.Errorf("path %q must be relative with forward slashes", p)
		}
		if begin, _ := loc["lines"].(map[string]any)["begin"].(float64); begin < 1 {
			t.Errorf("lines.begin = %v, must be a line number", begin)
		}
		prints[is["fingerprint"].(string)] = true
	}
	if len(prints) != len(issues) {
		t.Error("fingerprints must be unique")
	}
	if issues[0]["severity"] != "critical" || issues[2]["severity"] != "blocker" || issues[1]["severity"] != "major" {
		t.Errorf("severities: %v %v %v", issues[0]["severity"], issues[1]["severity"], issues[2]["severity"])
	}
	if d := issues[0]["description"].(string); !strings.HasSuffix(d, "[gosec G204]") {
		t.Errorf("description = %q, want the tool and rule named", d)
	}

	// A line shift does not change a fingerprint; GitLab would otherwise show the
	// same finding as one fixed and one new.
	moved := gitlabScan()
	moved.Findings[0].Location.Region.StartLine = 99
	buf.Reset()
	_ = WriteGitLabCodeQuality(&buf, moved)
	var after []map[string]any
	_ = json.Unmarshal(buf.Bytes(), &after)
	if after[0]["fingerprint"] != issues[0]["fingerprint"] {
		t.Error("the fingerprint changed when the finding only moved")
	}
}
