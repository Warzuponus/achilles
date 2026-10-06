package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/verifyfix"
)

type stubVerifier map[string]verifyfix.Result // keyed by fingerprint

func (s stubVerifier) Verify(_ context.Context, f model.Finding, _ string) verifyfix.Result {
	return s[f.Fingerprint]
}

func fixFinding(fp, diff string) model.Finding {
	f := model.Finding{Tool: "fake", RuleID: "r", Fingerprint: fp}
	if diff != "" {
		f.Remediation = &model.Remediation{Summary: "s", Diff: diff, Confidence: 0.9}
	}
	return f
}

func TestVerifyScanFixes_StoresResultsAndSkipsNonDiffs(t *testing.T) {
	shadow := fixFinding("sh", "--- a/x\n+++ b/x\n")
	shadow.Shadow = true
	scan := &model.Scan{Findings: []model.Finding{
		fixFinding("ok", "--- a/x\n+++ b/x\n"),
		fixFinding("bad", "--- a/y\n+++ b/y\n"),
		fixFinding("nodiff", ""),
		shadow,
	}}
	scan.Findings[2].Remediation = &model.Remediation{Guidance: "prose only"}
	v := stubVerifier{
		"ok":  {Status: verifyfix.Verified},
		"bad": {Status: verifyfix.NotFixed, Detail: "still there"},
	}
	st, err := vault.NewFileStore(filepath.Join(t.TempDir(), "v.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	verifyScanFixes(context.Background(), v, scan, st, "run1")

	if !scan.Findings[0].Remediation.IsVerified() {
		t.Error("first fix should be verified")
	}
	if got := scan.Findings[1].Remediation.Verification; got == nil || got.Status != verifyfix.NotFixed || got.Detail != "still there" {
		t.Errorf("second fix verification = %+v", got)
	}
	if scan.Findings[2].Remediation.Verification != nil || scan.Findings[3].Remediation.Verification != nil {
		t.Error("prose-only and shadow remediations must not be verified")
	}
	recs := st.ByRun("run1")
	if len(recs) != 2 {
		t.Fatalf("vault records = %d, want 2", len(recs))
	}
	var rem model.Remediation
	if err := json.Unmarshal(recs[0].Payload, &rem); err != nil || rem.Verification == nil {
		t.Errorf("vault payload should be the remediation with its verification: %v %s", err, recs[0].Payload)
	}
}

func TestVerifyRemediations_OffDoesNothing(t *testing.T) {
	scan := &model.Scan{Findings: []model.Finding{fixFinding("a", "--- a/x\n+++ b/x\n")}}
	o := &options{verifyFixes: false}
	if err := verifyRemediations(context.Background(), o, t.TempDir(), scanner.NewRegistry(), scan, nil, "r"); err != nil {
		t.Fatal(err)
	}
	if scan.Findings[0].Remediation.Verification != nil {
		t.Error("--verify-fixes=false must not verify")
	}
}

func TestVerifySummary(t *testing.T) {
	got := verifySummary(map[model.FixVerificationStatus]int{model.FixVerified: 3, model.FixNotFixed: 1, model.FixPatchFailed: 2})
	want := "fix verification: 3 verified, 1 not fixed, 2 patch failed"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// ----- end to end through the real verifier, a fake scanner and git apply -----

const verifyTestFormat = "cmd-verifyfix-test"

func init() {
	normalize.Register(verifyTestFormat, func(_ string, data []byte) ([]model.Finding, error) {
		var fs []model.Finding
		return fs, json.Unmarshal(data, &fs)
	})
}

type markerScanner struct{}

func (markerScanner) ID() string                     { return "marker" }
func (markerScanner) Meta() scanner.ScannerMeta      { return scanner.ScannerMeta{ID: "marker"} }
func (markerScanner) Applicable(scanner.Target) bool { return true }
func (markerScanner) Run(_ context.Context, t scanner.Target) (scanner.RawResult, error) {
	var out []model.Finding
	b, _ := os.ReadFile(filepath.Join(t.Path, "app.txt"))
	for i, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "BAD") {
			out = append(out, model.Finding{Tool: "marker", RuleID: "bad", Fingerprint: model.ComputeFingerprint("marker", "bad", "app.txt", line),
				Location: model.Location{File: "app.txt", Region: model.Region{StartLine: i + 1}}})
		}
	}
	data, _ := json.Marshal(out)
	return scanner.RawResult{Tool: "marker", Format: verifyTestFormat, Data: data}, nil
}

func TestVerifyRemediations_EndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.txt"), []byte("one\nBAD line\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := scanner.NewRegistry()
	if err := reg.Register(markerScanner{}); err != nil {
		t.Fatal(err)
	}
	good := "--- a/app.txt\n+++ b/app.txt\n@@ -1,3 +1,3 @@\n one\n-BAD line\n+good line\n three\n"
	noop := "--- a/app.txt\n+++ b/app.txt\n@@ -1,3 +1,3 @@\n-one\n+uno\n BAD line\n three\n"
	f1 := fixFinding("fp-good", good)
	f2 := fixFinding("fp-noop", noop)
	for _, f := range []*model.Finding{&f1, &f2} {
		f.Tool, f.RuleID = "marker", "bad"
		f.Location = model.Location{File: "app.txt", Region: model.Region{StartLine: 2}}
		f.Fingerprint = model.ComputeFingerprint("marker", "bad", "app.txt", "BAD line")
	}
	f1.Fingerprint = "fp-good" // distinct ids; matching is by rule+line window too
	scan := &model.Scan{Findings: []model.Finding{f1, f2}}

	if err := verifyRemediations(context.Background(), &options{verifyFixes: true}, root, reg, scan, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := scan.Findings[0].Remediation.Verification; got == nil || got.Status != verifyfix.Verified {
		t.Errorf("good fix: %+v", got)
	}
	if got := scan.Findings[1].Remediation.Verification; got == nil || got.Status != verifyfix.NotFixed {
		t.Errorf("no-op fix: %+v", got)
	}
}

func TestSelectFixes_OnlyVerifiedDiffsAreApplied(t *testing.T) {
	mk := func(fp string, v *model.FixVerification) model.Finding {
		f := fixFinding(fp, "--- a/x\n+++ b/x\n")
		f.Remediation.Verification = v
		return f
	}
	findings := []model.Finding{
		mk("ok", &model.FixVerification{Status: model.FixVerified}),
		mk("nf", &model.FixVerification{Status: model.FixNotFixed, Detail: "still\nreported"}),
		mk("new", &model.FixVerification{Status: model.FixIntroducesNew}),
		mk("sk", &model.FixVerification{Status: model.FixSkipped}),
		fixFinding("prose", ""),
	}
	fixes, notes := selectFixes(findings)
	if len(fixes) != 1 || fixes[0].fp != "ok" || !fixes[0].verified {
		t.Fatalf("fixes = %+v", fixes)
	}
	if len(notes) != 3 {
		t.Fatalf("every declined diff must be reported, got %v", notes)
	}
	for _, want := range []string{"(nf)", "not_fixed", "still reported", "(new)", "introduces_new", "(sk)", "skipped"} {
		if !strings.Contains(strings.Join(notes, "\n"), want) {
			t.Errorf("notes missing %q:\n%s", want, strings.Join(notes, "\n"))
		}
	}
}

func TestSelectFixes_NoVerificationAppliesWithNote(t *testing.T) {
	fixes, notes := selectFixes([]model.Finding{mk0("a"), mk0("b")})
	if len(fixes) != 2 || fixes[0].verified {
		t.Fatalf("fixes = %+v", fixes)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "2 diff(s) were not re-scanned") {
		t.Errorf("notes = %v", notes)
	}
}

func mk0(fp string) model.Finding { return fixFinding(fp, "--- a/x\n+++ b/x\n") }
