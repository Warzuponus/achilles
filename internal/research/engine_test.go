package research

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/vault"
)

// --- fakes ---

type fakeAgent struct {
	issues map[string][]Issue // by target key
	calls  int
}

func (a *fakeAgent) Research(_ context.Context, t Target) ([]Issue, error) {
	a.calls++
	return a.issues[t.Key()], nil
}

type fakeSynth struct{}

func (fakeSynth) Synthesize(_ context.Context, i Issue) (GeneratedRule, error) {
	return GeneratedRule{ID: ruleID(i.Title, i.Title), Language: "python", RuleYAML: "rules: []", Provenance: Provenance{SourceCitation: i.Citation}}, nil
}

type fakeValidator struct{ res ValidationResult }

func (v fakeValidator) Validate(context.Context, GeneratedRule) (ValidationResult, error) {
	return v.res, nil
}

func newRepo(t *testing.T) *RuleRepo {
	t.Helper()
	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return NewRuleRepo(t.TempDir(), v)
}

func TestEngine_AdmitsPassingRule(t *testing.T) {
	agent := &fakeAgent{issues: map[string][]Issue{
		"pypi|flask@2.0.1": {{Title: "eval RCE", Citation: "CVE-1", Language: "python"}},
	}}
	repo := newRepo(t)
	eng := NewEngine(agent, fakeSynth{}, fakeValidator{ValidationResult{Parses: true, MatchesVulnerable: true}}, repo, 0)

	sum, err := eng.Run(context.Background(), "run1", []Target{{Tech: "flask", Version: "2.0.1", Ecosystem: "pypi"}})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Admitted != 1 || sum.Quarantined != 0 || sum.RulesGenerated != 1 {
		t.Errorf("summary wrong: %+v", sum)
	}
	if repo.Count("admitted") != 1 {
		t.Errorf("admitted rule not written: %d", repo.Count("admitted"))
	}
}

func TestEngine_QuarantinesFailingRule(t *testing.T) {
	agent := &fakeAgent{issues: map[string][]Issue{
		"pypi|flask@2.0.1": {{Title: "bad", Citation: "CVE-2", Language: "python"}},
	}}
	repo := newRepo(t)
	// Matches the patched fixture too → false positive → must be quarantined.
	eng := NewEngine(agent, fakeSynth{}, fakeValidator{ValidationResult{Parses: true, MatchesVulnerable: true, MatchesPatched: true}}, repo, 0)

	sum, _ := eng.Run(context.Background(), "run1", []Target{{Tech: "flask", Version: "2.0.1", Ecosystem: "pypi"}})
	if sum.Admitted != 0 || sum.Quarantined != 1 {
		t.Errorf("failing rule should be quarantined: %+v", sum)
	}
	if repo.Count("admitted") != 0 || repo.Count("quarantine") != 1 {
		t.Errorf("repo dirs wrong: admitted=%d quarantine=%d", repo.Count("admitted"), repo.Count("quarantine"))
	}
}

func TestEngine_DedupsTargets(t *testing.T) {
	agent := &fakeAgent{issues: map[string][]Issue{}}
	eng := NewEngine(agent, fakeSynth{}, fakeValidator{}, newRepo(t), 0)

	dup := Target{Tech: "flask", Version: "2.0.1", Ecosystem: "pypi"}
	sum, _ := eng.Run(context.Background(), "r", []Target{dup, dup, dup})
	if sum.TargetsResearched != 1 {
		t.Errorf("duplicate targets should be researched once, got %d", sum.TargetsResearched)
	}
	if agent.calls != 1 {
		t.Errorf("agent should be called once, got %d", agent.calls)
	}
}

func TestEngine_BudgetCap(t *testing.T) {
	agent := &fakeAgent{issues: map[string][]Issue{}}
	eng := NewEngine(agent, fakeSynth{}, fakeValidator{}, newRepo(t), 2)

	targets := []Target{
		{Tech: "a", Ecosystem: "pypi"}, {Tech: "b", Ecosystem: "pypi"},
		{Tech: "c", Ecosystem: "pypi"}, {Tech: "d", Ecosystem: "pypi"},
	}
	sum, _ := eng.Run(context.Background(), "r", targets)
	if sum.TargetsResearched != 2 {
		t.Errorf("budget cap should limit to 2, got %d", sum.TargetsResearched)
	}
}
