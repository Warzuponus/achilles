package research

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// admit writes an admitted rule with a given creation date, as the synthesizer
// would (created uses the "2006-01-02" layout).
func admit(t *testing.T, repo *RuleRepo, id string, created time.Time) {
	t.Helper()
	rule := GeneratedRule{
		ID:       id,
		Language: "python",
		RuleYAML: "rules:\n  - id: " + id + "\n    pattern: eval(...)\n    message: eval\n    severity: ERROR\n    languages: [python]\n",
		Provenance: Provenance{
			SourceCitation: "https://example.com/cve",
			IssueTitle:     "eval injection",
			Created:        created.Format(admittedCreatedFmt),
		},
	}
	if err := repo.Admit("run1", rule, ValidationResult{Parses: true, MatchesVulnerable: true}); err != nil {
		t.Fatal(err)
	}
}

func yamlCount(t *testing.T, dir string) int {
	t.Helper()
	if dir == "" {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml" {
			n++
		}
	}
	return n
}

func TestProvision_PartitionsByAge(t *testing.T) {
	repoDir := t.TempDir()
	repo := NewRuleRepo(repoDir, nil)
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

	admit(t, repo, "gen-old", now.AddDate(0, 0, -30)) // 30d old → active
	admit(t, repo, "gen-new", now.AddDate(0, 0, -1))  // 1d old  → shadow

	// A baseline rules dir with one in-house rule (always active).
	baseline := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseline, "base.yaml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	set, cleanup, err := repo.Provision(baseline, 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if set.ActiveGenerated != 1 {
		t.Errorf("ActiveGenerated: got %d, want 1 (gen-old)", set.ActiveGenerated)
	}
	if set.Shadow != 1 {
		t.Errorf("Shadow: got %d, want 1 (gen-new)", set.Shadow)
	}
	// Active dir = baseline (1) + active generated (1) = 2 rule files.
	if got := yamlCount(t, set.ActiveDir); got != 2 {
		t.Errorf("active dir rule files: got %d, want 2", got)
	}
	if got := yamlCount(t, set.ShadowDir); got != 1 {
		t.Errorf("shadow dir rule files: got %d, want 1", got)
	}
}

func TestProvision_NoShadowWhenAllAged(t *testing.T) {
	repo := NewRuleRepo(t.TempDir(), nil)
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	admit(t, repo, "gen-old", now.AddDate(0, 0, -30))

	set, cleanup, err := repo.Provision("", 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if set.Shadow != 0 || set.ShadowDir != "" {
		t.Errorf("expected no shadow set, got Shadow=%d ShadowDir=%q", set.Shadow, set.ShadowDir)
	}
	if set.ActiveGenerated != 1 || yamlCount(t, set.ActiveDir) != 1 {
		t.Errorf("expected 1 active generated rule, got %d (dir files=%d)", set.ActiveGenerated, yamlCount(t, set.ActiveDir))
	}
}

func TestProvision_MissingDateDefaultsActive(t *testing.T) {
	repo := NewRuleRepo(t.TempDir(), nil)
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	// Admit with an empty Created → unparseable → should default to active.
	rule := GeneratedRule{ID: "gen-nodate", Language: "python", RuleYAML: "rules: []\n"}
	if err := repo.Admit("run1", rule, ValidationResult{Parses: true}); err != nil {
		t.Fatal(err)
	}
	set, cleanup, err := repo.Provision("", 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if set.ActiveGenerated != 1 || set.Shadow != 0 {
		t.Errorf("undated rule should be active: ActiveGenerated=%d Shadow=%d", set.ActiveGenerated, set.Shadow)
	}
}
