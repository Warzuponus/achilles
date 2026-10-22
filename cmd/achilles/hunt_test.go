package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/deep"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

const huntApp = "from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n@app.route('/run')\ndef run():\n    os.system(request.args['c'])\n"

func huntFixture(t *testing.T) (*model.Scan, vault.Store, string) {
	t.Helper()
	scan, ev, vaultPath := deepFixture(t)
	if err := os.WriteFile(filepath.Join(scan.Target, "web.py"), []byte(huntApp), 0o600); err != nil {
		t.Fatal(err)
	}
	return scan, ev, vaultPath
}

func huntOpts(base, vaultPath string) *options {
	return &options{hunt: 2, huntMaxSteps: 4, llmBaseURL: base, llmModel: "m", llmConcurrency: 1, vaultPath: vaultPath}
}

// The hunt reads web.py (already shown), then reports two candidates: one at a
// line it was shown, one a scanner already reported at a.py:2.
func huntReport(string) string {
	return `{"action":"report","candidates":[` +
		`{"location":"web.py:7","class":"command-injection","severity":"high","title":"query parameter reaches os.system","reasoning":"no check","route":["web.py:5 route","web.py:7 os.system"]},` +
		`{"location":"a.py:2","class":"command-injection","severity":"high","title":"same as the scanner"}]}`
}

func TestRunHunt_AddsReviewableCandidates(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", huntReport)
	scan, ev, vaultPath := huntFixture(t)
	before := len(scan.Findings)
	var out bytes.Buffer
	if err := runHunt(context.Background(), huntOpts(de.URL, vaultPath), ev, "run1", scan, &out); err != nil {
		t.Fatal(err)
	}
	if got := len(scan.Findings) - before; got != 1 {
		t.Fatalf("added %d finding(s), want 1 (the other is next to a scanner finding)\n%s", got, out.String())
	}
	f := scan.Findings[len(scan.Findings)-1]
	if f.Tool != deep.HuntTool || !f.Hunted || f.RuleID != "hunt/command-injection" || f.Location.File != "web.py" ||
		f.Location.Region.StartLine != 7 || f.Fingerprint == "" || len(f.Flow) != 2 || f.Verdict != nil {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(out.String(), "1 candidate(s) added for review, 1 already reported by a scanner") {
		t.Errorf("summary: %s", out.String())
	}
	recorded := false
	for _, r := range ev.ByRun("run1") {
		if r.Source == "hunt" {
			recorded = true
		}
	}
	if !recorded {
		t.Error("every hunt is recorded in the vault")
	}

	// Without a review that confirms it, the candidate is moved apart.
	if n := scan.PartitionUnconfirmedHunts(); n != 1 || len(scan.Hunted) != 1 || len(scan.Findings) != before {
		t.Errorf("partition moved %d; findings %d, hunted %d", n, len(scan.Findings), len(scan.Hunted))
	}
}

func TestRunHunt_FingerprintSurvivesTheLineMoving(t *testing.T) {
	scan, _, _ := huntFixture(t)
	a := sourceLine(scan.Target, "web.py", 7)
	if a != "os.system(request.args['c'])" {
		t.Fatalf("line = %q", a)
	}
	if err := os.WriteFile(filepath.Join(scan.Target, "web.py"), []byte("# new first line\n"+huntApp), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := sourceLine(scan.Target, "web.py", 8); b != a {
		t.Errorf("moved line = %q", b)
	}
	if sourceLine(scan.Target, "../outside.py", 1) != "" {
		t.Error("a path outside the target must not be read")
	}
}

func TestRunHunt_RefusesWithNoCode(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", huntReport)
	scan, ev, vaultPath := huntFixture(t)
	o := huntOpts(de.URL, vaultPath)
	o.llmNoCode = true
	if err := runHunt(context.Background(), o, ev, "run1", scan, io.Discard); err == nil || !strings.Contains(err.Error(), "NOT run") {
		t.Errorf("err = %v", err)
	}
	if de.calls.Load() != 0 {
		t.Error("no model call may be made")
	}
}

func TestRunHunt_DryRunCountsSeedsAndCallsNothing(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", huntReport)
	scan, ev, vaultPath := huntFixture(t)
	o := huntOpts(de.URL, vaultPath)
	o.dryRun = true
	var out bytes.Buffer
	if err := runHunt(context.Background(), o, ev, "run1", scan, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hunt mode would start from 1 entry point(s)") || de.calls.Load() != 0 {
		t.Errorf("dry run: %s (calls %d)", out.String(), de.calls.Load())
	}
}

func TestRunHunt_OffAndNoSeeds(t *testing.T) {
	de := newDeepEndpoint(t, 200, "a.py", huntReport)
	scan, ev, vaultPath := deepFixture(t) // no entry point in it
	o := huntOpts(de.URL, vaultPath)
	var out bytes.Buffer
	if err := runHunt(context.Background(), o, ev, "run1", scan, &out); err != nil || !strings.Contains(out.String(), "no entry point") {
		t.Errorf("err = %v, out = %s", err, out.String())
	}
	o.hunt = 0
	if err := runHunt(context.Background(), o, ev, "run1", scan, &out); err != nil || de.calls.Load() != 0 {
		t.Error("--hunt 0 is off")
	}
	o.hunt = -1
	if err := runHunt(context.Background(), o, ev, "run1", scan, io.Discard); err == nil {
		t.Error("a negative --hunt is an error")
	}
}

func TestValidateLLM_HuntNeedsTriageAndCode(t *testing.T) {
	o, _ := parseFlags([]string{"--hunt", "3", "."})
	if err := o.validateLLM(); err == nil || !strings.Contains(err.Error(), "needs --triage") {
		t.Errorf("--hunt alone: %v", err)
	}
	o, _ = parseFlags([]string{"--triage", "--hunt", "3", "--llm-no-code", "--llm-model", "m", "."})
	if err := o.validateLLM(); err == nil || !strings.Contains(err.Error(), "--llm-no-code") {
		t.Errorf("--hunt with --llm-no-code: %v", err)
	}
}
