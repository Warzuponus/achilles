package normalize

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNormalize_Dispatch(t *testing.T) {
	sarif, err := os.ReadFile(filepath.Join("testdata", "sample.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	bandit, err := os.ReadFile(filepath.Join("testdata", "bandit.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Empty format defaults to SARIF (historical behavior).
	if _, err := Normalize("", "x", sarif); err != nil {
		t.Errorf("empty format should default to sarif: %v", err)
	}
	// Explicit sarif + bandit dispatch to their normalizers.
	if _, err := Normalize("sarif", "x", sarif); err != nil {
		t.Errorf("sarif dispatch: %v", err)
	}
	fs, err := Normalize("bandit", "bandit", bandit)
	if err != nil || len(fs) != 2 {
		t.Errorf("bandit dispatch: got %d findings, err=%v", len(fs), err)
	}
	// Case-insensitive.
	if _, err := Normalize("SARIF", "x", sarif); err != nil {
		t.Errorf("format match should be case-insensitive: %v", err)
	}
	// Unknown, non-empty format is an explicit error (not a silent sarif parse).
	if _, err := Normalize("nonsense", "x", sarif); err == nil {
		t.Error("unknown format should error")
	}
}

// osv-scanner 2.4.0 repeats some results word for word. One copy is kept; the
// same rule and text at another line, or with another message, is another finding.
func TestNormalize_DropsExactDuplicates(t *testing.T) {
	result := func(line int, msg string) string {
		return `{"ruleId":"CVE-2020-14343","level":"warning","message":{"text":"` + msg + `"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"requirements.txt"},` +
			`"region":{"startLine":` + strconv.Itoa(line) + `}}}]}`
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"osv-scanner"}},"results":[` +
		strings.Join([]string{
			result(3, "pyyaml 5.3.1 is vulnerable"),
			result(3, "pyyaml 5.3.1 is vulnerable"),
			result(3, "pyyaml 5.3.1 is vulnerable"),
			result(7, "pyyaml 5.3.1 is vulnerable"),
			result(3, "pyyaml 5.3.1 is vulnerable (dev dependency)"),
		}, ",") + `]}]}`
	fs, err := Normalize("sarif", "osv-scanner", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		for _, f := range fs {
			t.Logf("%s:%d %s", f.Location.File, f.Location.Region.StartLine, f.Message)
		}
		t.Fatalf("got %d findings, want 3 (one of the three identical ones, the one at line 7, the one with another message)", len(fs))
	}
}

// Opengrep reports a taint sink once per source that reaches it, with the copies
// numbered in matchBasedId. At one exact span they are one finding; the same rule at
// another span of the same line is another.
func TestNormalize_DropsOpengrepCopiesOfOneSink(t *testing.T) {
	result := func(id string, startCol, endCol int) string {
		return `{"ruleId":"achilles.javascript.sql-injection","level":"error","message":{"text":"sql"},` +
			`"fingerprints":{"matchBasedId/v1":"` + id + `"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"routes/search.ts"},` +
			`"region":{"startLine":23,"startColumn":` + strconv.Itoa(startCol) + `,"endLine":23,"endColumn":` + strconv.Itoa(endCol) + `}}}]}`
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep"}},"results":[` +
		strings.Join([]string{
			result("abc_0", 28, 160),
			result("abc_1", 28, 160),
			result("abc_2", 28, 160),
			result("def_0", 170, 200),
		}, ",") + `]}]}`
	fs, err := Normalize("sarif", "opengrep", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 (one of the three copies at 28-160, and the one at 170-200)", len(fs))
	}
	if fs[0].Fingerprint != "abc_0" {
		t.Errorf("kept fingerprint %q, want the first copy's, abc_0", fs[0].Fingerprint)
	}
}
