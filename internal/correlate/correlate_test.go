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
	if Saved(fs, got) != 1 {
		t.Errorf("Saved = %d, want 1", Saved(fs, got))
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
	if Saved(fs, got) != 2 {
		t.Errorf("Saved = %d, want 2", Saved(fs, got))
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
	if Saved(nil, nil) != 0 {
		t.Error("Saved(nil, nil) should be 0")
	}
}

// The key used to be the identical SET of CWEs, so two tools describing one defect
// with slightly different ids never clustered: gosec says CWE-78, Opengrep says
// CWE-77 and CWE-78, and each got its own pair of model calls.
func TestClusters_MergesOverlappingAndRelatedCWEs(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"one shared CWE among several", []string{"CWE-78"}, []string{"CWE-77", "CWE-78"}, true},
		{"parent and child", []string{"CWE-78"}, []string{"CWE-77"}, true},
		{"two children of one parent", []string{"CWE-259"}, []string{"CWE-321"}, true},
		{"weak hash and weak cryptography", []string{"CWE-328"}, []string{"CWE-327"}, true},
		{"unrelated weaknesses on one line", []string{"CWE-89"}, []string{"CWE-306"}, false},
		{"injection kinds are not one family", []string{"CWE-89"}, []string{"CWE-78"}, false},
	}
	for _, c := range cases {
		fs := []model.Finding{
			f("opengrep", "r1", 42, model.SeverityHigh, c.a...),
			f("gosec", "r2", 42, model.SeverityHigh, c.b...),
		}
		if got := len(Clusters(fs)) == 1; got != c.want {
			t.Errorf("%s: clustered = %v, want %v", c.name, got, c.want)
		}
	}
}

// Sharing is transitive at one place: A and B share one CWE, B and C another.
func TestClusters_SharedLabelsChainWithinOneLine(t *testing.T) {
	fs := []model.Finding{
		f("opengrep", "a", 42, model.SeverityLow, "CWE-22"),
		f("gosec", "b", 42, model.SeverityHigh, "CWE-22", "CWE-73"),
		f("bandit", "c", 42, model.SeverityMedium, "CWE-73"),
		f("trivy", "d", 42, model.SeverityHigh, "CWE-798"), // same line, another defect
	}
	got := Clusters(fs)
	want := []Cluster{{Rep: 1, Members: []int{0, 2}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestClusters_CredentialsAndAdvisories(t *testing.T) {
	secret := func(tool, rule string, line int) model.Finding {
		x := f(tool, rule, line, model.SeverityHigh)
		x.Category = model.CategorySecret
		return x
	}
	advisory := func(tool, id, file string) model.Finding {
		return model.Finding{Tool: tool, RuleID: id, Severity: model.SeverityHigh, Category: model.CategoryDependency,
			Fingerprint: tool + ":" + id, Location: model.Location{File: file}}
	}
	fs := []model.Finding{
		secret("gitleaks", "aws-access-token", 7),
		secret("trivy", "aws-access-key-id", 7), // same line, another tool's name for it
		secret("trivy", "github-pat", 9),        // another line: another credential
		advisory("osv-scanner", "CVE-2024-1234", "go.mod"),
		advisory("trivy", "cve-2024-1234", "go.mod"),                // same advisory, same manifest, no line
		advisory("trivy", "CVE-2024-9999", "go.mod"),                // another advisory
		advisory("trivy", "CVE-2024-1234", "web/package-lock.json"), // same id, another manifest
	}
	got := Clusters(fs)
	want := []Cluster{{Rep: 0, Members: []int{1}}, {Rep: 3, Members: []int{4}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// Neither kind is ever sent to a model, so nothing is saved by clustering them.
	if Saved(fs, got) != 0 {
		t.Errorf("Saved = %d, want 0: credentials and advisories are not triaged", Saved(fs, got))
	}
	if Size(got) != 4 {
		t.Errorf("Size = %d, want 4", Size(got))
	}
}
