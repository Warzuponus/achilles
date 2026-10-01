package normalize

import (
	"os"
	"path/filepath"
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
