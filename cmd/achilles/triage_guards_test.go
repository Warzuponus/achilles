package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// seedNoisyRule labels n distinct findings of opengrep/rule as false positives.
func seedNoisyRule(t *testing.T, ev vault.Store, rule string, n int) {
	t.Helper()
	fb := knowledge.NewFeedbackStore(ev)
	for i := 0; i < n; i++ {
		if err := fb.Record("seed", knowledge.Feedback{
			Fingerprint: fmt.Sprintf("old-%d", i), Tool: "opengrep", RuleID: rule, Label: knowledge.LabelFP,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// Feedback history must never take a finding out of the gate unless the operator
// asked for that: by default every finding still goes to the model.
func TestRunTriage_CalibrationIsOffByDefault(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1")
	scan.Findings[0].Severity = model.SeverityMedium
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m"}); err != nil {
		t.Fatal(err)
	}
	if fe.calls.Load() == 0 {
		t.Fatal("the finding was never sent to the model")
	}
	if len(scan.Dismissed) != 0 || len(scan.Findings) != 1 {
		t.Errorf("without --calibrate, 20 fp labels must not dismiss anything: kept %d, dismissed %d",
			len(scan.Findings), len(scan.Dismissed))
	}
	if scan.Triage.AutoResolved != 0 {
		t.Errorf("AutoResolved = %d, want 0", scan.Triage.AutoResolved)
	}
}

func TestRunTriage_CalibrateResolvesANoisyRuleAndSaysSo(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1", "real-2")
	scan.Findings[0].Severity = model.SeverityMedium // eligible
	scan.Findings[1].Severity = model.SeverityMedium // different rule, no feedback
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", calibrate: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Dismissed) != 1 || scan.Dismissed[0].RuleID != "real-1" {
		t.Fatalf("dismissed = %+v, want only real-1", scan.Dismissed)
	}
	if p := scan.Dismissed[0].Provenance; p == nil || p.PromptVersion != "calibration" {
		t.Errorf("the verdict must be attributed to calibration, not to a model: %+v", p)
	}
	if scan.Triage.AutoResolved != 1 {
		t.Errorf("AutoResolved = %d, want 1 (reports use it to say no model reviewed these)", scan.Triage.AutoResolved)
	}
	if len(scan.Findings) != 1 || scan.Findings[0].RuleID != "real-2" {
		t.Errorf("the rule with no feedback must still be reviewed and kept: %+v", scan.Findings)
	}
}

func TestRunTriage_CalibrateNeverTouchesAHighSeverityFinding(t *testing.T) {
	fe := newFakeEndpoint(t, 200, 0, verdictFor)
	scan, ev := triageFixture(t, "real-1") // the fixture's findings are high severity
	seedNoisyRule(t, ev, "real-1", 20)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m", calibrate: true}); err != nil {
		t.Fatal(err)
	}
	if len(scan.Dismissed) != 0 || scan.Triage.AutoResolved != 0 {
		t.Errorf("a high-severity finding must be reviewed however noisy its rule: dismissed %d, auto-resolved %d",
			len(scan.Dismissed), scan.Triage.AutoResolved)
	}
	if fe.calls.Load() == 0 {
		t.Error("it should have gone to the model instead")
	}
}

// A known CVE in a dependency is not sent to the model and stays in the gate.
func TestRunTriage_DependencyAdvisoriesAreKeptAsReported(t *testing.T) {
	// The fake endpoint calls anything whose rule starts with "fp-" a confident
	// false positive; give it every chance to dismiss the advisory.
	fe := newFakeEndpoint(t, 200, 0, func(string, bool) string {
		return `{"classification":"false_positive","confidence":0.99,"exploitability":"not-reachable","reasoning":"no usage shown"}`
	})
	scan, ev := triageFixture(t, "fp-code")
	scan.Findings = append(scan.Findings,
		model.Finding{Tool: "osv-scanner", RuleID: "GHSA-j8r2-6x86-q33q", Severity: model.SeverityHigh,
			Message: "requests 2.19.1", Fingerprint: "adv1", Location: model.Location{File: "requirements.txt"}},
		model.Finding{Tool: "Trivy", RuleID: "CVE-2024-3094", Severity: model.SeverityCritical,
			Message: "xz 5.6.0", Fingerprint: "adv2", Location: model.Location{File: "Dockerfile", Region: model.Region{StartLine: 1}}},
	)

	if _, err := runTriage(context.Background(), ev, "run", scan, nil,
		triageOpts{baseURL: fe.URL, triageModel: "m"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range fe.prompts {
		if strings.Contains(p, "GHSA-j8r2-6x86-q33q") || strings.Contains(p, "CVE-2024-3094") {
			t.Errorf("an advisory reached the model: %s", p)
		}
	}
	if len(scan.Dismissed) != 1 || scan.Dismissed[0].RuleID != "fp-code" {
		t.Fatalf("dismissed = %+v, want only the code finding", scan.Dismissed)
	}
	if len(scan.Findings) != 2 {
		t.Fatalf("both advisories must stay in the gate, kept %d", len(scan.Findings))
	}
	for _, f := range scan.Findings {
		if f.Verdict != nil {
			t.Errorf("%s must carry no verdict: %+v", f.RuleID, f.Verdict)
		}
	}
	st := scan.Triage
	if st.Advisories != 2 || st.Triaged != 1 || st.Skipped != 0 || st.Failed != 0 {
		t.Errorf("stats = %+v; advisories are their own bucket, not \"not reached\"", st)
	}
}

// Under --runner docker a tool with no image (Opengrep) used to be handed to
// `docker run` with an empty image name and fail on every scan, while the docs said
// it runs as a local binary. It now does, and says so.
func TestRunnerFor_ToolWithoutAnImageRunsLocallyAndSaysSo(t *testing.T) {
	docker := xexec.DockerRunner{Network: "none"}

	var warn strings.Builder
	got := runnerFor(config.ToolConfig{ID: "opengrep", Bin: "opengrep"}, docker, &warn)
	if _, local := got.(xexec.LocalRunner); !local {
		t.Errorf("no image under the docker runner: got %T, want LocalRunner", got)
	}
	if !strings.Contains(warn.String(), "opengrep") || !strings.Contains(warn.String(), "not in a container") {
		t.Errorf("falling back to a local binary must be announced; got %q", warn.String())
	}

	warn.Reset()
	got = runnerFor(config.ToolConfig{ID: "gosec", Bin: "gosec", Image: "ghcr.io/securego/gosec:2"}, docker, &warn)
	if _, isDocker := got.(xexec.DockerRunner); !isDocker || warn.Len() != 0 {
		t.Errorf("a tool with an image stays in its container, silently: got %T, %q", got, warn.String())
	}

	// --runner local is never changed.
	got = runnerFor(config.ToolConfig{ID: "opengrep", Bin: "opengrep"}, xexec.LocalRunner{}, &warn)
	if _, local := got.(xexec.LocalRunner); !local || warn.Len() != 0 {
		t.Errorf("local runner: got %T, %q", got, warn.String())
	}
}

// The target's inventory was computed by walking the whole tree in up to six
// places per run. It is computed once and shared, and forgotten between runs.
func TestInventoryOf_WalksOncePerRun(t *testing.T) {
	resetInventory()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := inventoryOf(dir)
	if err != nil || len(first.Languages) == 0 {
		t.Fatalf("inventory: %+v, %v", first, err)
	}
	// A file added mid-run is not seen: the first walk is the answer for the run.
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	same, _ := inventoryOf(dir)
	if len(same.Languages) != len(first.Languages) {
		t.Errorf("the tree was walked again within one run: %v then %v", first.Languages, same.Languages)
	}
	// The next run starts fresh.
	resetInventory()
	next, _ := inventoryOf(dir)
	if len(next.Languages) != len(first.Languages)+1 {
		t.Errorf("a new run must walk the tree again: %v", next.Languages)
	}
}
