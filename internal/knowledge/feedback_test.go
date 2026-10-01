package knowledge

import (
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/vault"
)

func newVault(t *testing.T) *vault.FileStore {
	t.Helper()
	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFeedback_RecordAndHistory(t *testing.T) {
	fs := NewFeedbackStore(newVault(t))
	if err := fs.Record("r1", Feedback{Fingerprint: "fp1", Tool: "opengrep", RuleID: "eval", Label: LabelFP, Note: "constant input"}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Record("r2", Feedback{Fingerprint: "fp1", Tool: "opengrep", RuleID: "eval", Label: LabelTP}); err != nil {
		t.Fatal(err)
	}
	fs.Record("r1", Feedback{Fingerprint: "other", Tool: "gosec", RuleID: "g101", Label: LabelTP})

	hist := fs.History("fp1")
	if len(hist) != 2 {
		t.Fatalf("History(fp1): want 2, got %d", len(hist))
	}
	if hist[0].Label != LabelFP || hist[0].Note != "constant input" {
		t.Errorf("first feedback wrong: %+v", hist[0])
	}
	if n := len(fs.All()); n != 3 {
		t.Errorf("All: want 3, got %d", n)
	}
}
