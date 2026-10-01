package correlate

import (
	"reflect"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// f builds a finding with the fields correlation actually keys on.
func f(tool, rule string, line int, sev model.Severity, cwe ...string) model.Finding {
	return model.Finding{
		Tool: tool, RuleID: rule, Severity: sev, CWE: cwe,
		Fingerprint: tool + ":" + rule,
		Location:    model.Location{File: "app/db.go", Region: model.Region{StartLine: line}},
	}
}

func TestClusters_MergesSameLocationAndCWEAcrossTools(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityMedium, "CWE-89"),
		f("gosec", "G201", 42, model.SeverityHigh, "CWE-89"),
	}
	got := Clusters(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 cluster, got %d (%+v)", len(got), got)
	}
	// The high-severity gosec report is the representative worth triaging.
	if got[0].Rep != 1 {
		t.Errorf("rep should be the highest-severity member (index 1), got %d", got[0].Rep)
	}
	if !reflect.DeepEqual(got[0].Members, []int{0}) {
		t.Errorf("members = %v, want [0]", got[0].Members)
	}
	if Saved(got) != 1 {
		t.Errorf("Saved = %d, want 1", Saved(got))
	}
}

func TestClusters_DoesNotMergeDifferentCWE(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityHigh, "CWE-89"),
		f("gosec", "G401", 42, model.SeverityHigh, "CWE-327"),
	}
	if got := Clusters(fs); len(got) != 0 {
		t.Errorf("same line but different CWE must not merge, got %+v", got)
	}
}

func TestClusters_DoesNotMergeDifferentLines(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityHigh, "CWE-89"),
		f("gosec", "G201", 43, model.SeverityHigh, "CWE-89"),
	}
	if got := Clusters(fs); len(got) != 0 {
		t.Errorf("different lines must not merge, got %+v", got)
	}
}

func TestClusters_DoesNotMergeSameTool(t *testing.T) {
	// One tool reporting twice at one line is two instances, not cross-tool
	// overlap — merging them would copy a verdict between distinct defects.
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityHigh, "CWE-89"),
		f("opengrep", "sqli-2", 42, model.SeverityHigh, "CWE-89"),
	}
	if got := Clusters(fs); len(got) != 0 {
		t.Errorf("same-tool findings must not merge, got %+v", got)
	}
}

func TestClusters_SameToolRepeatDoesNotBlockCrossToolMerge(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityMedium, "CWE-89"),
		f("opengrep", "sqli-dup", 42, model.SeverityMedium, "CWE-89"),
		f("gosec", "G201", 42, model.SeverityMedium, "CWE-89"),
	}
	got := Clusters(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 cluster, got %d (%+v)", len(got), got)
	}
	// First-seen per tool: opengrep index 0 + gosec index 2. Index 1 is left to
	// be triaged on its own.
	if got[0].Rep != 0 || !reflect.DeepEqual(got[0].Members, []int{2}) {
		t.Errorf("cluster = %+v, want rep 0 members [2]", got[0])
	}
}

func TestClusters_SkipsIneligibleFindings(t *testing.T) {
	cases := []struct {
		name string
		fs   []model.Finding
	}{
		{"no CWE", []model.Finding{
			f("opengrep", "r1", 42, model.SeverityHigh),
			f("gosec", "r2", 42, model.SeverityHigh),
		}},
		{"no line number", []model.Finding{
			f("opengrep", "r1", 0, model.SeverityHigh, "CWE-89"),
			f("gosec", "r2", 0, model.SeverityHigh, "CWE-89"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Clusters(tc.fs); len(got) != 0 {
				t.Errorf("must not cluster on too little evidence, got %+v", got)
			}
		})
	}
}

func TestClusters_NeverClustersShadowFindings(t *testing.T) {
	// A shadow finding is report-only (§9.4). Keeping it out of clusters means
	// the shadow window's semantics can't be perturbed by correlation.
	shadow := f("opengrep", "gen.rule", 42, model.SeverityHigh, "CWE-89")
	shadow.Shadow = true
	fs := []model.Finding{shadow, f("gosec", "G201", 42, model.SeverityHigh, "CWE-89")}
	if got := Clusters(fs); len(got) != 0 {
		t.Errorf("shadow findings must not cluster, got %+v", got)
	}
}

func TestClusters_CWEOrderAndCaseDoNotMatter(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "r1", 42, model.SeverityHigh, "CWE-89", "cwe-564"),
		f("gosec", "r2", 42, model.SeverityHigh, "CWE-564", "CWE-89"),
	}
	if got := Clusters(fs); len(got) != 1 {
		t.Errorf("the CWE set should be order- and case-insensitive, got %+v", got)
	}
}

func TestClusters_TieOnSeverityPicksLowestIndex(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "r1", 42, model.SeverityHigh, "CWE-89"),
		f("gosec", "r2", 42, model.SeverityHigh, "CWE-89"),
		f("trivy", "r3", 42, model.SeverityHigh, "CWE-89"),
	}
	got := Clusters(fs)
	if len(got) != 1 || got[0].Rep != 0 {
		t.Fatalf("tie should resolve to the earliest index, got %+v", got)
	}
	if !reflect.DeepEqual(got[0].Members, []int{1, 2}) {
		t.Errorf("members = %v, want [1 2]", got[0].Members)
	}
	if Saved(got) != 2 {
		t.Errorf("Saved = %d, want 2", Saved(got))
	}
}

func TestClusters_Deterministic(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "a", 10, model.SeverityLow, "CWE-89"),
		f("gosec", "b", 20, model.SeverityHigh, "CWE-327"),
		f("trivy", "c", 10, model.SeverityLow, "CWE-89"),
		f("checkov", "d", 20, model.SeverityCritical, "CWE-327"),
	}
	want := Clusters(fs)
	for i := 0; i < 20; i++ {
		if got := Clusters(fs); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d differed:\n got %+v\nwant %+v", i, got, want)
		}
	}
	// Clusters are ordered by representative index.
	for i := 1; i < len(want); i++ {
		if want[i-1].Rep >= want[i].Rep {
			t.Errorf("clusters not ordered by rep index: %+v", want)
		}
	}
}

func TestAnnotate_RecordsSiblingsBothWays(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityMedium, "CWE-89"),
		f("gosec", "G201", 42, model.SeverityHigh, "CWE-89"),
		f("gitleaks", "key", 99, model.SeverityHigh, "CWE-798"),
	}
	Annotate(fs, Clusters(fs))

	if want := []string{"gosec:G201"}; !reflect.DeepEqual(fs[0].Correlated, want) {
		t.Errorf("fs[0].Correlated = %v, want %v", fs[0].Correlated, want)
	}
	if want := []string{"opengrep:sqli"}; !reflect.DeepEqual(fs[1].Correlated, want) {
		t.Errorf("fs[1].Correlated = %v, want %v", fs[1].Correlated, want)
	}
	if fs[2].Correlated != nil {
		t.Errorf("an uncorrelated finding must stay unannotated, got %v", fs[2].Correlated)
	}
}

func TestAnnotate_DoesNotTouchIdentityFields(t *testing.T) {
	// Correlation is descriptive: baselines, --file-issues, and feedback are all
	// fingerprint-keyed, so annotation must not perturb identity.
	fs := []model.Finding{
		f("opengrep", "sqli", 42, model.SeverityMedium, "CWE-89"),
		f("gosec", "G201", 42, model.SeverityHigh, "CWE-89"),
	}
	before := make([]model.Finding, len(fs))
	copy(before, fs)

	Annotate(fs, Clusters(fs))

	for i := range fs {
		if fs[i].ID != before[i].ID || fs[i].Fingerprint != before[i].Fingerprint ||
			fs[i].Severity != before[i].Severity || fs[i].Shadow != before[i].Shadow {
			t.Errorf("finding %d identity changed: %+v -> %+v", i, before[i], fs[i])
		}
	}
}

func TestClusters_EmptyInput(t *testing.T) {
	if got := Clusters(nil); len(got) != 0 {
		t.Errorf("nil input should yield no clusters, got %+v", got)
	}
	if Saved(nil) != 0 {
		t.Error("Saved(nil) should be 0")
	}
}
