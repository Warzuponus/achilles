package research

import (
	"context"
	"testing"
)

func mineSeeds(n int) []Issue {
	seeds := make([]Issue, n)
	for i := range seeds {
		seeds[i] = Issue{Title: "confirmed-" + string(rune('a'+i)), Citation: "internal: fp", Language: "python"}
	}
	return seeds
}

func TestMiner_AdmitsValidatedRules(t *testing.T) {
	repo := NewRuleRepo(t.TempDir(), nil)
	// Validator says: parses, matches vulnerable, not patched → admissible.
	m := NewMiner(fakeSynth{}, fakeValidator{res: ValidationResult{Parses: true, MatchesVulnerable: true}}, repo, 10)

	sum, err := m.Mine(context.Background(), "run1", mineSeeds(3))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Seeds != 3 || sum.Admitted != 3 || sum.Quarantined != 0 {
		t.Fatalf("want 3 seeds/3 admitted/0 quarantined, got %+v", sum)
	}
	if repo.Count("admitted") == 0 {
		t.Error("admitted rules should be written to the repo")
	}
}

func TestMiner_QuarantinesBadRules(t *testing.T) {
	repo := NewRuleRepo(t.TempDir(), nil)
	// Matches the patched fixture too → overbroad → not admissible.
	m := NewMiner(fakeSynth{}, fakeValidator{res: ValidationResult{Parses: true, MatchesVulnerable: true, MatchesPatched: true}}, repo, 10)

	sum, _ := m.Mine(context.Background(), "run1", mineSeeds(2))
	if sum.Admitted != 0 || sum.Quarantined != 2 {
		t.Errorf("bad rules should be quarantined, got %+v", sum)
	}
	if repo.Count("admitted") != 0 {
		t.Error("no rules should be admitted")
	}
}

func TestMiner_RespectsMax(t *testing.T) {
	repo := NewRuleRepo(t.TempDir(), nil)
	m := NewMiner(fakeSynth{}, fakeValidator{res: ValidationResult{Parses: true, MatchesVulnerable: true}}, repo, 2)
	sum, _ := m.Mine(context.Background(), "run1", mineSeeds(5))
	if sum.Seeds != 2 {
		t.Errorf("max=2 should cap seeds processed, got %d", sum.Seeds)
	}
}
