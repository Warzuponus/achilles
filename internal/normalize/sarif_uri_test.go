package normalize

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// artifactLocation.uri is a URI reference, not a file path. Taken literally, an
// encoded or file: URI names a file that does not exist, so the code around the
// finding cannot be read and diff or baseline matching misses it.
func TestFromSARIF_ArtifactURIBecomesAPath(t *testing.T) {
	cases := []struct{ name, uri, baseID, want string }{
		{"plain relative path", "src/app.py", "", "src/app.py"},
		{"percent-encoded space", "src/my%20file.py", "", "src/my file.py"},
		{"percent-encoded unicode", "src/caf%C3%A9.py", "", "src/café.py"},
		{"a literal percent that is not an escape", "notes/100%done.txt", "", "notes/100%done.txt"},
		{"absolute file URI", "file:///repo/src/a.py", "", "/repo/src/a.py"},
		{"file URI with an encoded space", "file:///repo/my%20dir/a.py", "", "/repo/my dir/a.py"},
		{"windows file URI", "file:///C:/repo/src/a.go", "", "C:/repo/src/a.go"},
		{"relative to a base that is a subdirectory", "handlers/a.py", "SRC", "src/handlers/a.py"},
		{"base chain", "a.py", "PKG", "src/pkg/a.py"},
		{"base that is the mount point is not applied", "src/a.py", "ROOT", "src/a.py"},
		{"unknown base", "src/a.py", "NOPE", "src/a.py"},
	}
	for _, c := range cases {
		doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "t"}},
			"originalUriBaseIds": map[string]any{
				"ROOT": map[string]any{"uri": "file:///mnt/src/"},
				"SRC":  map[string]any{"uri": "src/", "uriBaseId": "ROOT"},
				"PKG":  map[string]any{"uri": "pkg/", "uriBaseId": "SRC"},
			},
			"results": []any{map[string]any{
				"ruleId": "r", "message": map[string]any{"text": "m"},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": c.uri, "uriBaseId": c.baseID},
					"region":           map[string]any{"startLine": 3},
				}}},
			}},
		}}}
		data, _ := json.Marshal(doc)
		fs, err := FromSARIF("t", data)
		if err != nil || len(fs) != 1 {
			t.Fatalf("%s: %v (%d findings)", c.name, err, len(fs))
		}
		if got := fs[0].Location.File; got != c.want {
			t.Errorf("%s: File = %q, want %q", c.name, got, c.want)
		}
	}
}

// A result may name its rule only by index, or through a rule reference. It used
// to get an empty rule id, and so no severity from the rule and no CWE.
func TestFromSARIF_RuleNamedByIndexOrReference(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[
	  {"id":"first","defaultConfiguration":{"level":"note"}},
	  {"id":"sql-injection","defaultConfiguration":{"level":"error"},"properties":{"tags":["CWE-89"]}}
	]}},"results":[
	  {"ruleIndex":1,"message":{"text":"by index"}},
	  {"rule":{"index":1},"message":{"text":"by reference index"}},
	  {"rule":{"id":"sql-injection"},"message":{"text":"by reference id"}},
	  {"ruleIndex":7,"message":{"text":"index out of range"}}
	]}]}`
	fs, err := FromSARIF("t", []byte(doc))
	if err != nil || len(fs) != 4 {
		t.Fatalf("%v (%d findings)", err, len(fs))
	}
	for _, f := range fs[:3] {
		if f.RuleID != "sql-injection" {
			t.Errorf("%s: RuleID = %q, want sql-injection", f.Message, f.RuleID)
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("%s: severity = %s, want the rule's (high)", f.Message, f.Severity)
		}
		if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
			t.Errorf("%s: CWE = %v, want the rule's", f.Message, f.CWE)
		}
	}
	if fs[3].RuleID != "" {
		t.Errorf("an out-of-range index must not pick a rule: %q", fs[3].RuleID)
	}
}

// SARIF requires a region to say where it starts, so "region": {} is invalid. A
// finding with no line is written with no region.
func TestSARIFRegion_IsOmittedWhenThereIsNoLine(t *testing.T) {
	b, err := json.Marshal(model.SarifPhysicalLocation{ArtifactLocation: model.SarifArtifactLocation{URI: "go.mod"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "region") {
		t.Errorf("an empty region was written: %s", b)
	}
	b, _ = json.Marshal(model.SarifPhysicalLocation{
		ArtifactLocation: model.SarifArtifactLocation{URI: "a.go"},
		Region:           model.SarifRegion{StartLine: 4},
	})
	if !strings.Contains(string(b), `"region":{"startLine":4}`) {
		t.Errorf("a real region must be written, and without an empty snippet: %s", b)
	}
}
