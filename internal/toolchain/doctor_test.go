package toolchain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeDoctor(have map[string]string, env map[string]string) Doctor {
	return Doctor{
		GOOS: "linux", GOARCH: "amd64", BinDir: "/home/u/.achilles/bin",
		Look: func(bin string) (string, Source, error) {
			if _, ok := have[bin]; ok {
				return "/fake/" + bin, SourcePATH, nil
			}
			return "", "", errors.New("not found")
		},
		Version: func(_ context.Context, path string, _ []string) (string, error) {
			return have[filepath.Base(path)], nil
		},
		Getenv:     func(k string) string { return env[k] },
		DockerInfo: func(context.Context) string { return "" },
	}
}

func TestDoctorStates(t *testing.T) {
	d := fakeDoctor(map[string]string{
		"opengrep": "1.25.0",
		"gosec":    "Version: 2.20.0\nGit tag: v2.20.0",
		"trivy":    "Version: 0.99.0",
		"gitleaks": "garbage",
		"go":       "",
	}, nil)
	r := d.Diagnose(context.Background())
	got := map[string]ToolStatus{}
	for _, s := range r.Tools {
		got[s.Name] = s
	}
	for name, want := range map[string]string{
		"opengrep":    StateOK,
		"gosec":       StateOutdated,
		"trivy":       StateNewer,
		"gitleaks":    StateUnknownVer,
		"osv-scanner": StateMissing,
	} {
		if got[name].State != want {
			t.Errorf("%s: state %q, want %q", name, got[name].State, want)
		}
	}
	if got["osv-scanner"].Fix != "achilles tools install osv-scanner" {
		t.Errorf("fix = %q", got["osv-scanner"].Fix)
	}
	if got["gosec"].Fix != "achilles tools install gosec" {
		t.Errorf("outdated fix = %q", got["gosec"].Fix)
	}
	if !r.Failed() {
		t.Error("a missing default-profile tool must fail the doctor")
	}
	var buf bytes.Buffer
	r.Write(&buf)
	out := buf.String()
	for _, s := range []string{"FAIL", "achilles tools install osv-scanner", "pinned 2.4.0"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestDoctorAllPresentPasses(t *testing.T) {
	have := map[string]string{"go": "", "docker": ""}
	for _, tool := range Tools() {
		have[tool.Bin] = "version " + tool.Version
	}
	r := fakeDoctor(have, nil).Diagnose(context.Background())
	if r.Failed() {
		t.Fatalf("unexpected failure: %+v", r.Tools)
	}
	for _, s := range r.Tools {
		if s.State != StateOK {
			t.Errorf("%s: %s", s.Name, s.State)
		}
	}
	if !r.Docker.Found || !strings.Contains(r.Docker.Detail, "not reachable") {
		t.Errorf("docker: %+v", r.Docker)
	}
}

func TestDoctorGosecWithoutGoWarns(t *testing.T) {
	have := map[string]string{}
	for _, tool := range Tools() {
		have[tool.Bin] = tool.Version
	}
	r := fakeDoctor(have, nil).Diagnose(context.Background())
	if r.Go.Found {
		t.Fatal("go should be missing")
	}
	for _, s := range r.Tools {
		if s.Name == "gosec" && len(s.Notes) == 0 {
			t.Error("gosec without go on PATH should carry a warning")
		}
	}
}

func TestDoctorNoAssetPlatform(t *testing.T) {
	d := fakeDoctor(nil, nil)
	d.GOOS, d.GOARCH = "linux", "riscv64"
	r := d.Diagnose(context.Background())
	for _, s := range r.Tools {
		if s.State != StateUnsupported || !strings.Contains(s.Fix, "install manually") {
			t.Errorf("%s: %s / %q", s.Name, s.State, s.Fix)
		}
	}
	if !r.Failed() {
		t.Error("required tools without an asset must fail the doctor")
	}
}

func TestDoctorNeverPrintsKey(t *testing.T) {
	const secret = "sk-super-secret-value"
	d := fakeDoctor(nil, map[string]string{
		"ACHILLES_LLM_API_KEY":  secret,
		"ACHILLES_LLM_BASE_URL": "https://user:" + secret + "@llm.example.com/v1?token=" + secret,
	})
	r := d.Diagnose(context.Background())
	var buf bytes.Buffer
	r.Write(&buf)
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("doctor output leaked a secret:\n%s", buf.String())
	}
	if r.LLMKeyVar != "ACHILLES_LLM_API_KEY" || r.LLMBase != "https://llm.example.com/v1" {
		t.Errorf("llm = %q %q", r.LLMKeyVar, r.LLMBase)
	}
	r = fakeDoctor(nil, nil).Diagnose(context.Background())
	if r.LLMKeyVar != "" || r.LLMBase != DefaultLLMBaseURL {
		t.Errorf("defaults: %q %q", r.LLMKeyVar, r.LLMBase)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.2.3", "1.2.3", 0}, {"1.2.3", "1.10.0", -1}, {"2.0.0", "1.99.99", 1}, {"1.2", "1.2.0", 0}} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if ParseVersion("osv-scanner version: 2.4.0\ncommit: abc") != "2.4.0" {
		t.Error("ParseVersion")
	}
}

func TestLookBinPrefersManagedDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvHome, home)
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "achilles-fake-tool"
	file := exeName(runtime.GOOS, name)
	if err := os.WriteFile(filepath.Join(binDir, file), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Same name earlier on PATH: the managed copy still wins.
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, file), []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("PATH", other)

	p, src, err := LookBin(name)
	if err != nil || src != SourceManaged || p != filepath.Join(binDir, file) {
		t.Fatalf("got %q %q %v", p, src, err)
	}

	os.Remove(filepath.Join(binDir, file))
	p, src, err = LookBin(name)
	if err != nil || src != SourcePATH || filepath.Dir(p) != other {
		t.Fatalf("PATH fallback: got %q %q %v", p, src, err)
	}

	if _, _, err := LookBin("achilles-no-such-tool"); err == nil {
		t.Error("want error for unknown tool")
	}
}

func TestDoctorReportsCommunityRules(t *testing.T) {
	d := fakeDoctor(nil, nil)
	var buf bytes.Buffer
	d.Rules = func() InstalledRules { return InstalledRules{} }
	d.Diagnose(context.Background()).Write(&buf)
	if !strings.Contains(buf.String(), "not installed (fix: achilles tools install rules)") {
		t.Errorf("missing-rules output:\n%s", buf.String())
	}
	buf.Reset()
	d.Rules = func() InstalledRules { return InstalledRules{Installed: true, Dir: "/x/rules", Files: 42} }
	r := d.Diagnose(context.Background())
	r.Write(&buf)
	if !strings.Contains(buf.String(), "42 rule files in /x/rules") {
		t.Errorf("installed-rules output:\n%s", buf.String())
	}
	if r.Failed() && !strings.Contains(buf.String(), "FAIL") {
		t.Error("inconsistent")
	}
}
