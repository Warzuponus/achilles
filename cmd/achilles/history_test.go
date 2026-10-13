package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
)

const (
	histSHA1 = "689bd12734c6a21c4431adae399f29b9d181649b"
	histSHA2 = "b46276dfc79202de8e333a751ca1d4cba321a809"
)

func historyRegistry() *config.Config {
	return &config.Config{Tools: []config.ToolConfig{
		{ID: "fakescan", Enabled: true},
		{ID: "fakescan-history", OptIn: optInSecretsHistory},
	}}
}

func TestCollapseHistory(t *testing.T) {
	inTree := model.Finding{Tool: "gitleaks", RuleID: "github-pat", Fingerprint: "fp-live", Location: model.Location{File: "app.py"}}
	scan := model.Scan{Findings: []model.Finding{
		inTree,
		// The same credential, as the commit that added it: nothing new.
		{Tool: "gitleaks", RuleID: "github-pat", Fingerprint: "fp-live", Commit: histSHA1, CommitDate: "2026-01-01T00:00:00Z", Message: "live"},
		// A credential that is gone from the files, in three commits, newest first.
		{Tool: "gitleaks", RuleID: "aws-access-token", Fingerprint: "fp-gone", Commit: histSHA2, CommitDate: "2026-03-01T00:00:00Z", Message: "third."},
		{Tool: "gitleaks", RuleID: "aws-access-token", Fingerprint: "fp-gone", Commit: histSHA1, CommitDate: "2026-01-01T00:00:00Z", Message: "first."},
		{Tool: "gitleaks", RuleID: "aws-access-token", Fingerprint: "fp-gone", Commit: "cccccccccccc", CommitDate: "2026-02-01T00:00:00Z", Message: "second."},
		// Another tool's finding with the same fingerprint string is another finding.
		{Tool: "trivy", RuleID: "github-pat", Fingerprint: "fp-live", Commit: histSHA2, Message: "other tool"},
		{Tool: "gosec", RuleID: "G204", Fingerprint: "fp-code"},
	}}
	var out bytes.Buffer
	collapseHistory(&scan, &out)

	var got []string
	for _, f := range scan.Findings {
		got = append(got, f.Tool+"/"+f.RuleID+"@"+f.Commit)
	}
	want := []string{"gitleaks/github-pat@", "gitleaks/aws-access-token@" + histSHA1, "trivy/github-pat@" + histSHA2, "gosec/G204@"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("kept:\n  %v\nwant:\n  %v", got, want)
	}
	// The earliest commit is the one kept, and it says there were more.
	if m := scan.Findings[1].Message; !strings.HasPrefix(m, "first.") || !strings.Contains(m, "2 more time(s)") {
		t.Errorf("message = %q", m)
	}
	for _, s := range []string{"2 credential(s) found only in the history", "1 more are still in the files", "2 repeat(s)"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("summary lacks %q: %s", s, out.String())
		}
	}

	// Nothing from the history: nothing is said and nothing changes.
	plain := model.Scan{Findings: []model.Finding{inTree}}
	out.Reset()
	collapseHistory(&plain, &out)
	if len(plain.Findings) != 1 || out.Len() != 0 {
		t.Errorf("a scan without history findings was touched: %d finding(s), %q", len(plain.Findings), out.String())
	}
}

// gitleaks reports a clean history, with exit code 0, when git could not read the
// history at all. Everything that can be known beforehand is checked beforehand.
func TestPlanHistoryScan(t *testing.T) {
	repo := gitRepo(t, map[string]string{"app.py": "x = 1\n", "sub/z.py": "z = 1\n"})

	// Not asked for: nothing happens, whatever the target is.
	var out bytes.Buffer
	if d := planHistoryScan(&options{}, historyRegistry(), t.TempDir(), &out); d != nil || out.Len() != 0 {
		t.Errorf("without the flag: %v %q", d, out.String())
	}

	// A full clone, scanned from its root: runs, nothing to report.
	o := &options{secretsHistory: true}
	if d := planHistoryScan(o, historyRegistry(), repo, &out); len(d) != 0 || !o.secretsHistory {
		t.Errorf("a full clone: diags=%v stillOn=%v", d, o.secretsHistory)
	}

	// Not a repository: the scanner is not run, and that is a failed tool.
	o = &options{secretsHistory: true}
	d := planHistoryScan(o, historyRegistry(), t.TempDir(), &out)
	if len(d) != 1 || d[0].Tool != "fakescan-history" || d[0].Stage != "run" || o.secretsHistory {
		t.Errorf("not a repository: diags=%+v stillOn=%v", d, o.secretsHistory)
	}

	// --diff with a ref this checkout does not have: the range would resolve to nothing.
	o = &options{secretsHistory: true, diffRef: "no-such-branch"}
	d = planHistoryScan(o, historyRegistry(), repo, &out)
	if len(d) != 1 || d[0].Stage != "run" || !strings.Contains(d[0].Error, "no-such-branch") || o.secretsHistory {
		t.Errorf("unknown ref: diags=%+v stillOn=%v", d, o.secretsHistory)
	}
	o = &options{secretsHistory: true, diffRef: "main"}
	if d = planHistoryScan(o, historyRegistry(), repo, &out); len(d) != 0 || !o.secretsHistory {
		t.Errorf("a ref that exists: diags=%+v", d)
	}

	// A directory inside the repository: runs, but says what it actually covers.
	o = &options{secretsHistory: true}
	d = planHistoryScan(o, historyRegistry(), filepath.Join(repo, "sub"), &out)
	if len(d) != 1 || d[0].Stage != "partial" || !strings.Contains(d[0].Error, "sub") || !o.secretsHistory {
		t.Errorf("subdirectory: diags=%+v stillOn=%v", d, o.secretsHistory)
	}

	// A shallow clone holds one commit. The scan runs and is reported as incomplete.
	writeFile(t, filepath.Join(repo, "app.py"), "x = 2\n")
	git(t, repo, "commit", "-q", "-am", "second")
	shallow := filepath.Join(t.TempDir(), "shallow")
	git(t, repo, "clone", "-q", "--depth", "1", "file://"+filepath.ToSlash(repo), shallow)
	o = &options{secretsHistory: true}
	d = planHistoryScan(o, historyRegistry(), shallow, &out)
	if len(d) != 1 || d[0].Stage != "partial" || !strings.Contains(d[0].Error, "shallow") || !o.secretsHistory {
		t.Errorf("shallow clone: diags=%+v stillOn=%v", d, o.secretsHistory)
	}

	// A registry with no history scanner cannot do what was asked.
	o = &options{secretsHistory: true}
	d = planHistoryScan(o, &config.Config{Tools: []config.ToolConfig{{ID: "fakescan", Enabled: true}}}, repo, &out)
	if len(d) != 1 || d[0].Stage != "run" || o.secretsHistory {
		t.Errorf("no history scanner registered: diags=%+v stillOn=%v", d, o.secretsHistory)
	}
}

// The embedded registry has the history scanner, opt-in, limited by --diff, and
// guarded against gitleaks' silent failure.
func TestEmbeddedRegistry_HistoryScannerIsOptInAndGuarded(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var hist *config.ToolConfig
	for i := range cfg.Tools {
		if cfg.Tools[i].OptIn == optInSecretsHistory {
			hist = &cfg.Tools[i]
		}
	}
	if hist == nil {
		t.Fatal("no tool is marked optIn: secrets-history")
	}
	if hist.Enabled || len(hist.Profiles) != 0 {
		t.Errorf("%s must run only when asked for: enabled=%v profiles=%v", hist.ID, hist.Enabled, hist.Profiles)
	}
	if hist.RunsInProfile("default") || hist.RunsInProfile("full") {
		t.Errorf("%s runs in a profile", hist.ID)
	}
	if !strings.Contains(hist.DiffArg, "{diff}..HEAD") {
		t.Errorf("diffArg = %q, want the commits since the ref", hist.DiffArg)
	}
	if len(hist.IncompleteWhen) == 0 || len(hist.SuccessExitCodes) == 0 {
		t.Errorf("%s has no guard against a run that scanned nothing: incompleteWhen=%v successExitCodes=%v",
			hist.ID, hist.IncompleteWhen, hist.SuccessExitCodes)
	}
	if len(hist.RepoConfig) == 0 {
		t.Errorf("%s reads the repository's own gitleaks configuration; that must be declared", hist.ID)
	}
}

// historyFixture is fakeScanFixture with a second, opt-in tool that plays the
// history scanner, inside a git repository. It returns the registry, the target
// and the vault path, and prepares the results that tool will report.
func historyFixture(t *testing.T, results []map[string]any) (cfg, target, vaultPath, argsFile string) {
	t.Helper()
	cfg, _, vaultPath = fakeScanFixture(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	extra := "  - id: fakescan-history\n" +
		"    license: MIT\n" +
		"    commercialSafe: true\n" +
		"    optIn: secrets-history\n" +
		"    languages: [generic]\n" +
		"    bin: '" + filepath.ToSlash(self) + "'\n" +
		"    format: sarif\n" +
		"    argv: [\"{out}/results.sarif\", \"{src}\", \"--history\"]\n" +
		"    diffArg: \"--log-opts={diff}..HEAD\"\n" +
		"    outputFile: \"{out}/results.sarif\"\n"
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// The target is a repository with a clean first commit on main and the
	// vulnerable file added on a branch.
	target = gitRepo(t, map[string]string{"README.md": "hello\n"})
	git(t, target, "checkout", "-q", "-b", "change")
	writeFile(t, filepath.Join(target, "app.py"), vulnApp)
	git(t, target, "add", "-A")
	git(t, target, "commit", "-q", "-m", "add the app")

	dir := t.TempDir()
	prepared, _ := json.Marshal(results)
	resultsFile := filepath.Join(dir, "history.json")
	if err := os.WriteFile(resultsFile, prepared, 0o600); err != nil {
		t.Fatal(err)
	}
	argsFile = filepath.Join(dir, "args.txt")
	t.Setenv("ACHILLES_FAKE_HISTORY_RESULTS", resultsFile)
	t.Setenv("ACHILLES_FAKE_HISTORY_ARGS", argsFile)
	return cfg, target, vaultPath, argsFile
}

func historyResult(rule, file string, line int, snippet, sha string) map[string]any {
	return map[string]any{
		"ruleId": rule, "level": "error", "message": map[string]any{"text": rule + " at commit " + sha},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": file},
			"region":           map[string]any{"startLine": line, "snippet": map[string]any{"text": snippet}},
		}}},
		"partialFingerprints": map[string]any{"commitSha": sha, "date": "2026-10-13T03:57:18Z"},
	}
}

// End to end: the history scanner runs only when asked for, is limited to the
// commits under review, and a finding it makes in a file the branch added and then
// deleted survives the diff filter and gates.
func TestRun_SecretsHistory(t *testing.T) {
	cfg, target, vaultPath, argsFile := historyFixture(t, []map[string]any{
		// In a file that is not in the tree, and so not in the net diff.
		historyResult("leaked-token", "tmp.env", 1, "token-that-was-deleted", histSHA1),
		// The finding the file scanner also makes in app.py: the same matched text.
		historyResult("cmd-injection", "app.py", 2, "os.system(cmd)", histSHA2),
	})
	out := filepath.Join(t.TempDir(), "scan.json")
	type report struct {
		Tools    []string `json:"tools"`
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Commit   string `json:"commit"`
			Message  string `json:"message"`
			Location struct {
				File string `json:"file"`
			} `json:"location"`
		} `json:"findings"`
	}
	read := func() report {
		t.Helper()
		var r report
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Without the flag the history scanner is not part of the scan.
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out, target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if r := read(); len(r.Findings) != 1 || strings.Join(r.Tools, ",") != "fakescan" {
		t.Fatalf("without --secrets-history: tools=%v findings=%d", r.Tools, len(r.Findings))
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("the history scanner ran without being asked for")
	}

	// With it, on a diff-scoped scan.
	err := run([]string{"--config", cfg, "--vault", vaultPath, "--json-report", out,
		"--secrets-history", "--diff", "main", "--fail-on", "high", target})
	var gated *gateError
	if !errors.As(err, &gated) {
		t.Fatalf("err = %v, want the gate to fail on the findings", err)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--log-opts=main..HEAD") {
		t.Errorf("the history scanner was not limited to the commits under review; it was given:\n%s", args)
	}
	r := read()
	if strings.Join(r.Tools, ",") != "fakescan,fakescan-history" {
		t.Errorf("tools = %v", r.Tools)
	}
	var history, files int
	for _, f := range r.Findings {
		switch {
		case f.Commit != "":
			history++
			if f.RuleID != "leaked-token" || f.Location.File != "tmp.env" || !strings.Contains(f.Message, "689bd12") {
				t.Errorf("history finding = %+v", f)
			}
		default:
			files++
		}
	}
	// tmp.env is not in the net diff, and the finding is kept. The app.py finding is
	// reported once, as the one in the file.
	if history != 1 || files != 1 {
		t.Errorf("%d finding(s) from the history and %d from the files, want 1 and 1: %+v", history, files, r.Findings)
	}
}
