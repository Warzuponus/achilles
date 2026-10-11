package generic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/config"
	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// fakeRunner stands in for a real tool: it records the command it was given and
// writes canned SARIF to whatever host path is mounted as "out". This lets us
// exercise the full generic scan→read path without the actual binary.
type fakeRunner struct {
	sarif  []byte
	gotCmd xexec.Command
}

func (f *fakeRunner) Run(_ context.Context, c xexec.Command) (xexec.Result, error) {
	f.gotCmd = c
	for _, m := range c.Mounts {
		if m.Name == "out" {
			_ = os.WriteFile(filepath.Join(m.HostPath, "results.sarif"), f.sarif, 0o644)
		}
	}
	return xexec.Result{ExitCode: 1}, nil // non-zero exit == "found issues"
}

func testCfg() config.ToolConfig {
	return config.ToolConfig{
		ID:         "gosec",
		Languages:  []string{"go"},
		Bin:        "gosec",
		Format:     "sarif",
		Argv:       []string{"-fmt=sarif", "-out={out}/results.sarif", "{src}/..."},
		OutputFile: "{out}/results.sarif",
	}
}

func TestRun_ReadsToolOutput(t *testing.T) {
	fr := &fakeRunner{sarif: []byte(`{"version":"2.1.0","runs":[]}`)}
	s := New(fr, testCfg(), "")

	raw, err := s.Run(context.Background(), scanner.Target{Path: "/some/src"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(raw.Data) != `{"version":"2.1.0","runs":[]}` {
		t.Errorf("did not read back tool SARIF: %q", raw.Data)
	}
	if raw.Tool != "gosec" || raw.Format != "sarif" {
		t.Errorf("raw meta wrong: tool=%q format=%q", raw.Tool, raw.Format)
	}

	// The src mount must be the target path and marked read-only.
	var sawSrcRO bool
	for _, m := range fr.gotCmd.Mounts {
		if m.Name == "src" && m.HostPath == "/some/src" && m.ReadOnly {
			sawSrcRO = true
		}
	}
	if !sawSrcRO {
		t.Errorf("expected read-only src mount at /some/src, got %+v", fr.gotCmd.Mounts)
	}
}

func TestRun_NoOutputFileIsError(t *testing.T) {
	// Runner that writes nothing → missing output file → error (not silent success).
	nopRunner := &fakeRunner{sarif: nil}
	cfg := testCfg()
	// Point the tool at a file the fake won't create.
	cfg.Argv = []string{"noop"}
	s := New(nopRunner, cfg, "")
	// Overwrite the "out" write by using a runner that writes nothing:
	s.runner = writeNothingRunner{}
	if _, err := s.Run(context.Background(), scanner.Target{Path: "/x"}); err == nil {
		t.Error("want error when the tool produced no output file")
	}
}

type writeNothingRunner struct{}

func (writeNothingRunner) Run(context.Context, xexec.Command) (xexec.Result, error) {
	return xexec.Result{ExitCode: 2, Stderr: []byte("boom")}, nil
}

func TestApplicable(t *testing.T) {
	s := New(&fakeRunner{}, testCfg(), "") // languages: [go]

	cases := []struct {
		name string
		tgt  scanner.Target
		want bool
	}{
		{"empty path", scanner.Target{}, false},
		{"matching lang", scanner.Target{Path: "/x", Languages: []string{"go"}}, true},
		{"non-matching lang", scanner.Target{Path: "/x", Languages: []string{"python"}}, false},
		{"unknown target langs", scanner.Target{Path: "/x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Applicable(tc.tgt); got != tc.want {
				t.Errorf("Applicable=%v want %v", got, tc.want)
			}
		})
	}
}

// A language-agnostic tool (SCA/secrets/IaC) declares "generic" and must apply to
// any target — otherwise populating Target.Languages would wrongly skip it.
func TestApplicable_GenericIsWildcard(t *testing.T) {
	cfg := testCfg()
	cfg.ID = "trivy"
	cfg.Languages = []string{"generic"}
	s := New(&fakeRunner{}, cfg, "")

	for _, langs := range [][]string{{"go"}, {"python", "ruby"}, nil} {
		if !s.Applicable(scanner.Target{Path: "/x", Languages: langs}) {
			t.Errorf("generic tool should apply to target langs %v", langs)
		}
	}
}

func TestRun_PassesNetworkPolicy(t *testing.T) {
	fr := &fakeRunner{sarif: []byte(`{}`)}
	cfg := testCfg()
	cfg.Network = "default" // tool that needs egress (e.g. SCA/NuGet restore)
	_, _ = New(fr, cfg, "").Run(context.Background(), scanner.Target{Path: "/x"})
	if fr.gotCmd.Network != "default" {
		t.Errorf("network policy not passed to runner: got %q", fr.gotCmd.Network)
	}
}

func TestRun_ArgvPlaceholdersPreserved(t *testing.T) {
	fr := &fakeRunner{sarif: []byte(`{}`)}
	s := New(fr, testCfg(), "")
	_, _ = s.Run(context.Background(), scanner.Target{Path: "/x"})
	joined := strings.Join(fr.gotCmd.Args, " ")
	if !strings.Contains(joined, "{out}") || !strings.Contains(joined, "{src}") {
		t.Errorf("argv placeholders should reach the runner for resolution: %q", joined)
	}
}

// A target's own ignore file is honored: the rule's arg is appended only when
// the file is present in the target.
func TestRun_LocalConfigAppendedWhenPresent(t *testing.T) {
	cfg := testCfg()
	cfg.LocalConfig = []config.LocalConfigRule{{File: ".trivyignore", Arg: "--ignorefile={src}/.trivyignore"}}

	// Present → appended.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".trivyignore"), []byte("CVE-x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{sarif: []byte(`{}`)}
	_, _ = New(fr, cfg, "").Run(context.Background(), scanner.Target{Path: dir})
	if !strings.Contains(strings.Join(fr.gotCmd.Args, " "), "--ignorefile={src}/.trivyignore") {
		t.Errorf("expected local-config arg when file present; args=%v", fr.gotCmd.Args)
	}

	// Absent → not appended.
	fr2 := &fakeRunner{sarif: []byte(`{}`)}
	_, _ = New(fr2, cfg, "").Run(context.Background(), scanner.Target{Path: t.TempDir()})
	if strings.Contains(strings.Join(fr2.gotCmd.Args, " "), "ignorefile") {
		t.Errorf("local-config arg must not be appended when file absent; args=%v", fr2.gotCmd.Args)
	}
}

// checkingRunner is a fakeRunner that can also answer "is this binary on PATH?",
// as the local runner does.
type checkingRunner struct {
	fakeRunner
	have map[string]bool
}

func (c *checkingRunner) Has(bin string) bool { return c.have[bin] }

// gosec exits 0 with an empty report when `go` is missing — the scan would look
// clean. A declared prerequisite that is absent must be a loud tool failure.
func TestRun_MissingPrerequisiteIsAToolFailure(t *testing.T) {
	cfg := testCfg()
	cfg.Requires = []string{"go"}
	cr := &checkingRunner{fakeRunner: fakeRunner{sarif: []byte(`{"version":"2.1.0","runs":[]}`)}, have: map[string]bool{}}
	_, err := New(cr, cfg, "").Run(context.Background(), scanner.Target{Path: "/some/src"})
	if err == nil || !strings.Contains(err.Error(), "needs `go` on PATH") {
		t.Fatalf("err = %v, want a missing-prerequisite failure", err)
	}
	if cr.gotCmd.Bin != "" {
		t.Error("the tool must not be run when a prerequisite is missing")
	}

	cr.have["go"] = true
	if _, err := New(cr, cfg, "").Run(context.Background(), scanner.Target{Path: "/some/src"}); err != nil {
		t.Errorf("with the prerequisite present the tool should run: %v", err)
	}
}

// Runners that cannot check (docker) are not asked: the image carries the tools.
func TestRun_RunnerWithoutHasSkipsPrerequisiteCheck(t *testing.T) {
	cfg := testCfg()
	cfg.Requires = []string{"go"}
	fr := &fakeRunner{sarif: []byte(`{"version":"2.1.0","runs":[]}`)}
	if _, err := New(fr, cfg, "").Run(context.Background(), scanner.Target{Path: "/some/src"}); err != nil {
		t.Errorf("docker-style runner must not be blocked: %v", err)
	}
}

// noReportRunner is a tool that exits without writing its report, printing msg.
type noReportRunner struct{ stderr string }

func (n noReportRunner) Run(context.Context, xexec.Command) (xexec.Result, error) {
	return xexec.Result{ExitCode: 128, Stderr: []byte(n.stderr)}, nil
}

func TestRun_NothingToScanIsAnEmptyResultNotAFailure(t *testing.T) {
	cfg := testCfg()
	cfg.ID = "osv-scanner"
	cfg.NothingToScan = []string{"No package sources found"}

	raw, err := New(noReportRunner{stderr: "Scanning dir /x\nNo package sources found, --help for usage information.\n"}, cfg, "").
		Run(context.Background(), scanner.Target{Path: "/x"})
	if err != nil {
		t.Fatalf("a tree with nothing to scan must not be a failure: %v", err)
	}
	if !strings.Contains(string(raw.Data), `"results":[]`) || raw.Tool != "osv-scanner" {
		t.Errorf("want an empty SARIF result for osv-scanner, got %s (tool %q)", raw.Data, raw.Tool)
	}
}

func TestRun_MissingReportStillFailsWithoutTheMarker(t *testing.T) {
	cfg := testCfg()
	cfg.NothingToScan = []string{"No package sources found"}
	_, err := New(noReportRunner{stderr: "panic: something real broke"}, cfg, "").
		Run(context.Background(), scanner.Target{Path: "/x"})
	if err == nil {
		t.Fatal("a tool that wrote no report for any other reason must still fail")
	}
}

// reportingRunner writes a valid report, exits 0, and prints stderr: a tool that
// looks entirely successful.
type reportingRunner struct{ sarif, stderr string }

func (r reportingRunner) Run(_ context.Context, c xexec.Command) (xexec.Result, error) {
	for _, m := range c.Mounts {
		if m.Name == "out" {
			_ = os.WriteFile(filepath.Join(m.HostPath, "results.sarif"), []byte(r.sarif), 0o644)
		}
	}
	return xexec.Result{ExitCode: 0, Stderr: []byte(r.stderr)}, nil
}

// gosec, when a package will not type-check, exits 0 and writes a valid report
// with whatever its syntax-only rules found. Every analysis that needs types is
// skipped, and the only trace is a log line. That must not read as a full scan.
func TestRun_IncompleteWhenKeepsFindingsAndSaysWhy(t *testing.T) {
	cfg := testCfg()
	cfg.IncompleteWhen = []string{"skipping SSA analysis"}
	const sarif = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[{"ruleId":"G401","message":{"text":"m"}}]}]}`
	stderr := "[gosec] Checking package: a\n" +
		"[gosec] Error building the SSA representation of the package a: package a has type errors, skipping SSA analysis, no ssa result\n" +
		"[gosec] Error building the SSA representation of the package b: package b has type errors, skipping SSA analysis, no ssa result\n"

	raw, err := New(reportingRunner{sarif: sarif, stderr: stderr}, cfg, "").Run(context.Background(), scanner.Target{Path: "/x"})
	if err != nil {
		t.Fatalf("the tool ran and reported; that is not a run error: %v", err)
	}
	if !strings.Contains(string(raw.Data), "G401") {
		t.Error("the findings the tool did produce must be kept")
	}
	if !strings.Contains(raw.Incomplete, "package a has type errors") {
		t.Errorf("Incomplete should quote the tool's own first complaint, got %q", raw.Incomplete)
	}
	if !strings.Contains(raw.Incomplete, "1 more") {
		t.Errorf("Incomplete should count the other affected packages, got %q", raw.Incomplete)
	}
}

func TestRun_CompleteRunIsNotMarkedIncomplete(t *testing.T) {
	cfg := testCfg()
	cfg.IncompleteWhen = []string{"skipping SSA analysis"}
	raw, err := New(reportingRunner{sarif: `{"version":"2.1.0","runs":[]}`, stderr: "[gosec] Checking package: a\n"}, cfg, "").
		Run(context.Background(), scanner.Target{Path: "/x"})
	if err != nil || raw.Incomplete != "" {
		t.Errorf("a clean log must not mark the run incomplete: %q err=%v", raw.Incomplete, err)
	}
	// And a tool with no such phrases configured is never marked.
	raw, _ = New(reportingRunner{sarif: `{"version":"2.1.0","runs":[]}`, stderr: "skipping SSA analysis"}, testCfg(), "").
		Run(context.Background(), scanner.Target{Path: "/x"})
	if raw.Incomplete != "" {
		t.Errorf("no incompleteWhen configured: %q", raw.Incomplete)
	}
}
