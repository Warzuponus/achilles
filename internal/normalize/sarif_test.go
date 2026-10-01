package normalize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func loadSample(t *testing.T) []model.Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sample.sarif"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings, err := FromSARIF("fallback", data)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	return findings
}

func TestFromSARIF_Count(t *testing.T) {
	findings := loadSample(t)
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
}

func TestFromSARIF_UsesDriverName(t *testing.T) {
	findings := loadSample(t)
	if findings[0].Tool != "opengrep" {
		t.Errorf("want tool=opengrep (from driver), got %q", findings[0].Tool)
	}
}

func TestFromSARIF_MapsFields(t *testing.T) {
	f := loadSample(t)[0]

	if f.RuleID != "achilles.python.dangerous-eval" {
		t.Errorf("ruleID: got %q", f.RuleID)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity: want high (SARIF error), got %q", f.Severity)
	}
	if f.Location.File != "app/handlers.py" || f.Location.Region.StartLine != 42 {
		t.Errorf("location: got %s:%d", f.Location.File, f.Location.Region.StartLine)
	}
	if f.CodeContext != "eval(user_input)" {
		t.Errorf("code context: got %q", f.CodeContext)
	}
}

func TestFromSARIF_SeverityMapping(t *testing.T) {
	f := loadSample(t)[1]
	if f.Severity != model.SeverityMedium {
		t.Errorf("severity: want medium (SARIF warning), got %q", f.Severity)
	}
}

func TestFromSARIF_CWEExtraction(t *testing.T) {
	f := loadSample(t)[0]
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-95" {
		t.Errorf("cwe: want [CWE-95], got %v", f.CWE)
	}
}

// gosec publishes a rule's CWE as a SARIF taxonomy relationship with a BARE
// numeric id, not as a "CWE-nnn" tag. Reading only the inline form dropped the
// CWE from every gosec finding, which also made cross-tool correlation (which
// keys on CWE) inert on Go codebases.
func TestFromSARIF_CWEFromTaxonomyRelationship(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[
	  {"id":"G104","relationships":[{"kinds":["superset"],"target":{"id":"703","toolComponent":{"name":"CWE"}}}]}]}},
	  "results":[{"ruleId":"G104","level":"warning","message":{"text":"Errors unhandled"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]}]}`)
	fs, err := FromSARIF("gosec", doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if len(fs[0].CWE) != 1 || fs[0].CWE[0] != "CWE-703" {
		t.Errorf("cwe: want [CWE-703] from the taxonomy relationship, got %v", fs[0].CWE)
	}
}

func TestFromSARIF_IgnoresNonCWETaxonomies(t *testing.T) {
	// A relationship to some other taxonomy must not be relabelled as a CWE.
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[
	  {"id":"R1","relationships":[
	    {"target":{"id":"1234","toolComponent":{"name":"OWASP"}}},
	    {"target":{"id":"not-a-number","toolComponent":{"name":"CWE"}}}]}]}},
	  "results":[{"ruleId":"R1","message":{"text":"x"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`)
	fs, err := FromSARIF("t", doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs[0].CWE) != 0 {
		t.Errorf("want no CWEs, got %v", fs[0].CWE)
	}
}

func TestFromSARIF_CWEDedupesAcrossSources(t *testing.T) {
	// Same CWE inline AND as a relationship should yield one entry.
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[
	  {"id":"R1","properties":{"tags":["CWE-89"]},
	   "relationships":[{"target":{"id":"89","toolComponent":{"name":"cwe"}}}]}]}},
	  "results":[{"ruleId":"R1","message":{"text":"x"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`)
	fs, err := FromSARIF("t", doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs[0].CWE) != 1 || fs[0].CWE[0] != "CWE-89" {
		t.Errorf("want a single deduped [CWE-89], got %v", fs[0].CWE)
	}
}

func TestFromSARIF_PrefersToolFingerprint(t *testing.T) {
	f := loadSample(t)[0]
	if f.Fingerprint != "abc123def456" {
		t.Errorf("fingerprint: want tool-provided abc123def456, got %q", f.Fingerprint)
	}
}

func TestFromSARIF_FallbackFingerprintIsStable(t *testing.T) {
	// Second finding has no tool fingerprint → we compute one; it must be
	// deterministic across parses.
	a := loadSample(t)[1].Fingerprint
	b := loadSample(t)[1].Fingerprint
	if a == "" {
		t.Fatal("expected a computed fallback fingerprint")
	}
	if a != b {
		t.Errorf("fallback fingerprint not stable: %q vs %q", a, b)
	}
}

func TestFromSARIF_LevelInheritedFromRuleDefault(t *testing.T) {
	// A result with no level must inherit the rule's defaultConfiguration.level
	// (how Opengrep encodes severity).
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep",
	  "rules":[{"id":"r1","defaultConfiguration":{"level":"error"}}]}},
	  "results":[{"ruleId":"r1","message":{"text":"m"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}]}]}`
	f, err := FromSARIF("x", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if f[0].Severity != model.SeverityHigh {
		t.Errorf("want high (inherited error), got %q", f[0].Severity)
	}
}

func TestFromSARIF_Empty(t *testing.T) {
	findings, err := FromSARIF("x", []byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(findings))
	}
}

func TestFromSARIF_BadJSON(t *testing.T) {
	if _, err := FromSARIF("x", []byte(`not json`)); err == nil {
		t.Error("expected error on malformed JSON")
	}
}
