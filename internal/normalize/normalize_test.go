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
