package research

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

// advisoryServer answers like the public advisory services: 200 for an id it
// knows, 404 otherwise. It counts requests and can be told to fail.
func advisoryServer(t *testing.T, known ...string) (*HTTPGrounder, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	var calls atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		for _, id := range known {
			if strings.HasSuffix(r.URL.Path, "/"+id) {
				_, _ = w.Write([]byte(`{"id":"` + id + `"}`))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return &HTTPGrounder{Client: srv.Client(), OSVBase: srv.URL, CVEBase: srv.URL}, &calls, &down
}

func TestAdvisoryIDs(t *testing.T) {
	got := AdvisoryIDs("see cve-2021-44228 and https://github.com/advisories/GHSA-JFH8-C2JP-5V3Q, also CVE-2021-44228 again, GO-2021-0113")
	want := []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "GO-2021-0113"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
	if ids := AdvisoryIDs("https://example.com/blog/a-vulnerability-in-flask"); len(ids) != 0 {
		t.Errorf("a URL with no advisory id has nothing to check: %v", ids)
	}
}

// "Citation-mandatory" used to mean the citation field was not empty, so an
// invented CVE id passed. The cited advisory now has to exist.
func TestLLMAgent_KeepsOnlyIssuesWhoseAdvisoryExists(t *testing.T) {
	g, calls, _ := advisoryServer(t, "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q")
	fake := &llmtest.Fake{Responses: []string{`{"issues":[
	  {"title":"real cve","description":"x","citation":"CVE-2021-44228","language":"java"},
	  {"title":"invented cve","description":"x","citation":"CVE-2023-12345","language":"java"},
	  {"title":"real ghsa in a url","description":"x","citation":"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q","language":"java"},
	  {"title":"a url with no id","description":"x","citation":"https://example.com/blog/log4j-is-bad","language":"java"},
	  {"title":"no citation","description":"x","citation":"","language":"java"}
	]}`}}

	issues, err := NewLLMAgent(fake).WithGrounder(g).Research(context.Background(), Target{Tech: "log4j", Version: "2.14", Ecosystem: "maven"})
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, i := range issues {
		titles = append(titles, i.Title)
	}
	if strings.Join(titles, "|") != "real cve|real ghsa in a url" {
		t.Errorf("kept %v, want only the two issues whose advisory exists", titles)
	}
	if calls.Load() == 0 {
		t.Error("no lookup was made")
	}
}

// If the lookup cannot be made, nothing from the target is used: an unverified
// issue must not slip through because a service was down.
func TestLLMAgent_LookupFailureFailsClosed(t *testing.T) {
	g, _, down := advisoryServer(t, "CVE-2021-44228")
	down.Store(true)
	fake := &llmtest.Fake{Responses: []string{`{"issues":[{"title":"real cve","description":"x","citation":"CVE-2021-44228","language":"java"}]}`}}
	issues, err := NewLLMAgent(fake).WithGrounder(g).Research(context.Background(), Target{Tech: "log4j"})
	if err == nil || len(issues) != 0 {
		t.Errorf("issues=%v err=%v, want an error and nothing kept", issues, err)
	}
}

func TestHTTPGrounder_FallsBackToTheCVEServiceForCVEIDsOnly(t *testing.T) {
	var osv, cve atomic.Int32
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { osv.Add(1); http.NotFound(w, r) }))
	defer osvSrv.Close()
	cveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cve.Add(1)
		if strings.HasSuffix(r.URL.Path, "/api/cve/CVE-2020-0001") {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer cveSrv.Close()
	g := &HTTPGrounder{Client: &http.Client{Timeout: 5 * time.Second}, OSVBase: osvSrv.URL, CVEBase: cveSrv.URL}

	if ok, err := g.Resolve(context.Background(), "CVE-2020-0001"); err != nil || !ok {
		t.Errorf("a CVE the first service lacks must be found in the second: ok=%v err=%v", ok, err)
	}
	if ok, err := g.Resolve(context.Background(), "GHSA-aaaa-bbbb-cccc"); err != nil || ok {
		t.Errorf("an unknown GHSA: ok=%v err=%v, want not found", ok, err)
	}
	if osv.Load() != 2 || cve.Load() != 1 {
		t.Errorf("lookups: osv=%d cve=%d, want 2 and 1 (only CVE ids go to the CVE service)", osv.Load(), cve.Load())
	}
}

// The gate checks a rule against the examples the same model wrote. An empty
// patched example made "does not match the patched code" true for any rule.
func TestFixtureProblem(t *testing.T) {
	good := GeneratedRule{RuleYAML: "rules: []", VulnerableSnippet: "eval(x)", PatchedSnippet: "ast.literal_eval(x)"}
	if p := FixtureProblem(good); p != "" {
		t.Errorf("a rule with two different fixtures is fine: %q", p)
	}
	for name, r := range map[string]GeneratedRule{
		"no patched fixture":         {RuleYAML: "r", VulnerableSnippet: "eval(x)", PatchedSnippet: "  \n"},
		"no vulnerable fixture":      {RuleYAML: "r", VulnerableSnippet: "", PatchedSnippet: "ok()"},
		"patched same as vulnerable": {RuleYAML: "r", VulnerableSnippet: "eval(x)\n", PatchedSnippet: "  eval(x)"},
		"empty rule":                 {RuleYAML: " ", VulnerableSnippet: "eval(x)", PatchedSnippet: "ok()"},
	} {
		if FixtureProblem(r) == "" {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

type scriptedValidator struct {
	res   ValidationResult
	calls int
}

func (v *scriptedValidator) Validate(context.Context, GeneratedRule) (ValidationResult, error) {
	v.calls++
	return v.res, nil
}

func TestJudge_RejectsDegenerateAndOverbroadRules(t *testing.T) {
	passing := ValidationResult{Parses: true, MatchesVulnerable: true}
	good := GeneratedRule{RuleYAML: "r", VulnerableSnippet: "eval(x)", PatchedSnippet: "ok(x)"}

	v := &scriptedValidator{res: passing}
	if _, ok, reason := Judge(context.Background(), v, good); !ok {
		t.Errorf("a sound rule must be admitted: %s", reason)
	}

	// No patched fixture: rejected before the engine is even run.
	v = &scriptedValidator{res: passing}
	if _, ok, reason := Judge(context.Background(), v, GeneratedRule{RuleYAML: "r", VulnerableSnippet: "eval(x)"}); ok || v.calls != 0 || !strings.Contains(reason, "patched") {
		t.Errorf("ok=%v calls=%d reason=%q, want a rejection naming the patched fixture, with no engine run", ok, v.calls, reason)
	}

	// Matches ordinary code: too broad.
	broad := passing
	broad.MatchesControl = true
	if _, ok, reason := Judge(context.Background(), &scriptedValidator{res: broad}, good); ok || !strings.Contains(reason, "too broad") {
		t.Errorf("ok=%v reason=%q, want a rule that matches ordinary code rejected", ok, reason)
	}
}

func TestControlSnippets_CoverEveryLanguageTheValidatorKnows(t *testing.T) {
	for lang := range langExt {
		if strings.TrimSpace(controlSnippets[lang]) == "" {
			t.Errorf("no control snippet for %s: an over-broad %s rule would not be caught", lang, lang)
		}
	}
}

// A rule mined from a finding of a rule pack Achilles did not write is stored with
// that origin, and can be left out when rules are loaded (--mode commercial).
func TestProvision_ExcludesRulesByOrigin(t *testing.T) {
	dir := t.TempDir()
	repo := NewRuleRepo(dir, nil)
	admit := func(id, origin string) {
		t.Helper()
		rule := GeneratedRule{ID: id, RuleYAML: "rules: []\n", Provenance: Provenance{Origin: origin, Created: "2020-01-01"}}
		if err := repo.Admit("run", rule, ValidationResult{Parses: true, MatchesVulnerable: true}); err != nil {
			t.Fatal(err)
		}
	}
	admit("gen.ours", "")
	admit("gen.from-community", OriginExternalRule)

	// The origin is recorded next to the rule.
	b, err := os.ReadFile(filepath.Join(repo.AdmittedDir(), "gen.from-community.meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta ruleMeta
	if json.Unmarshal(b, &meta) != nil || meta.Provenance.Origin != OriginExternalRule {
		t.Fatalf("origin not stored: %s", b)
	}

	set, done, err := repo.Provision("", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if set.ActiveGenerated != 2 || set.Excluded != 0 {
		t.Errorf("by default both rules load: %+v", set)
	}
	done()

	repo.ExcludeOrigins(OriginExternalRule)
	set, done, err = repo.Provision("", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if set.ActiveGenerated != 1 || set.Excluded != 1 {
		t.Errorf("excluded origin: %+v, want 1 active and 1 excluded", set)
	}
	if _, err := os.Stat(filepath.Join(set.ActiveDir, "gen.from-community.yaml")); err == nil {
		t.Error("the excluded rule was copied into the active rule set")
	}
	if _, err := os.Stat(filepath.Join(repo.AdmittedDir(), "gen.from-community.yaml")); err != nil {
		t.Error("exclusion must not delete the rule from the repository")
	}
}
