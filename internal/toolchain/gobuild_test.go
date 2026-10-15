package toolchain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeGo answers `go env -json` with settings and, for `go install`, writes a
// binary into GOBIN (unless installErr is set). It records every call.
type fakeGo struct {
	settings   string
	installErr error
	calls      []fakeGoCall
}

type fakeGoCall struct {
	dir  string
	env  []string
	args []string
}

func (f *fakeGo) run(_ context.Context, dir string, env []string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, fakeGoCall{dir, env, args})
	switch args[0] {
	case "env":
		return []byte(f.settings), nil
	case "install":
		if f.installErr != nil {
			return []byte("go: downloading github.com/x/y v1.0.0\nverifying module: checksum mismatch"), f.installErr
		}
		gobin := envValue(env, "GOBIN")
		return nil, os.WriteFile(filepath.Join(gobin, exeName(runtime.GOOS, "gosec")), []byte("built"), 0o755)
	}
	return nil, errors.New("unexpected go command")
}

func envValue(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val // the last one wins, as in exec
		}
	}
	return v
}

func gosecTool(t *testing.T) Tool {
	t.Helper()
	tool, err := Lookup("gosec")
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func TestBuildFromSource(t *testing.T) {
	// Settings that would exempt modules from the checksum database, or change
	// what gets built, must not reach the build.
	t.Setenv("GONOSUMDB", "github.com/*")
	t.Setenv("GOFLAGS", "-mod=vendor")
	t.Setenv("GOINSECURE", "*")
	f := &fakeGo{settings: `{"GOPROXY":"https://proxy.example.com","GOSUMDB":"sum.golang.org","GOVERSION":"go1.27.1"}`}
	in := &Installer{BinDir: filepath.Join(t.TempDir(), "bin"), Go: "go", goRunner: f.run}
	got, err := in.buildFromSource(context.Background(), gosecTool(t), runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(in.BinDir, exeName(runtime.GOOS, "gosec")) {
		t.Errorf("installed at %s", got)
	}
	if b, _ := os.ReadFile(got); string(b) != "built" {
		t.Errorf("installed file = %q", b)
	}
	if names := dirEntries(t, in.BinDir); len(names) != 1 {
		t.Errorf("leftovers in the bin dir: %v", names)
	}

	if len(f.calls) != 2 {
		t.Fatalf("go was run %d times, want 2 (env, install)", len(f.calls))
	}
	if envValue(f.calls[0].env, "GOTOOLCHAIN") != "local" {
		t.Error("go env did not pin the toolchain to the Go on PATH")
	}
	inst := f.calls[1]
	want := map[string]string{
		"GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-trimpath", "GOWORK": "off",
		"CGO_ENABLED": "0", "GOPROXY": "https://proxy.example.com", "GOSUMDB": "sum.golang.org",
		"GONOSUMDB": "", "GOINSECURE": "",
	}
	for k, v := range want {
		if got := envValue(inst.env, k); got != v {
			t.Errorf("install env %s = %q, want %q", k, got, v)
		}
	}
	args := strings.Join(inst.args, " ")
	if !strings.HasSuffix(args, " github.com/securego/gosec/v2/cmd/gosec@v2.27.1") {
		t.Errorf("install args = %s", args)
	}
	if !strings.Contains(args, "-X main.Version=2.27.1") || !strings.Contains(args, "-X main.GitTag=v2.27.1") {
		t.Errorf("the pinned version is not stamped into the build: %s", args)
	}
	if inst.dir == "" {
		t.Error("go install ran in the current directory, where a go.mod or go.work could steer it")
	}
}

func TestBuildFromSource_RefusesWithoutTheChecksumDatabase(t *testing.T) {
	f := &fakeGo{settings: `{"GOPROXY":"direct","GOSUMDB":"off","GOVERSION":"go1.27.1"}`}
	in := &Installer{BinDir: t.TempDir(), Go: "go", goRunner: f.run}
	_, err := in.buildFromSource(context.Background(), gosecTool(t), runtime.GOOS)
	if err == nil || !strings.Contains(err.Error(), "GOSUMDB=off") {
		t.Fatalf("err = %v, want a GOSUMDB=off refusal", err)
	}
	for _, c := range f.calls {
		if c.args[0] == "install" {
			t.Error("built anyway")
		}
	}
}

// A failed build falls back to the pinned, checksum-verified download.
func TestInstall_FallsBackToTheDownloadWhenTheBuildFails(t *testing.T) {
	raw := []byte("prebuilt")
	in, url := serve(t, raw)
	f := &fakeGo{settings: `{"GOPROXY":"direct","GOSUMDB":"sum.golang.org","GOVERSION":"go1.27.1"}`, installErr: errors.New("exit status 1")}
	in.Go, in.goRunner = "go", f.run
	var log strings.Builder
	in.Log = &log
	tool := gosecTool(t)
	tool.Assets = map[string]Asset{platformKey(runtime.GOOS, runtime.GOARCH): {URL: url, Archive: Raw, SHA256: sum(raw)}}
	got, err := in.Install(context.Background(), tool, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(got); string(b) != "prebuilt" {
		t.Errorf("installed %q, want the download", b)
	}
	if !strings.Contains(log.String(), "checksum mismatch") || !strings.Contains(log.String(), "prebuilt binary instead") {
		t.Errorf("the fallback was not explained:\n%s", log.String())
	}
	if names := dirEntries(t, in.BinDir); len(names) != 1 {
		t.Errorf("leftovers in the bin dir: %v", names)
	}
}

// Without Go, or for a tool with no GoPackage, nothing is built.
func TestInstall_DownloadsWhenNotBuilding(t *testing.T) {
	raw := []byte("prebuilt")
	for _, c := range []struct {
		name   string
		goPath string
		pkg    string
	}{{"no go", "", "github.com/securego/gosec/v2/cmd/gosec"}, {"not a Go tool", "go", ""}} {
		in, url := serve(t, raw)
		f := &fakeGo{}
		in.Go, in.goRunner = c.goPath, f.run
		tool := gosecTool(t)
		tool.GoPackage = c.pkg
		tool.Assets = map[string]Asset{platformKey(runtime.GOOS, runtime.GOARCH): {URL: url, Archive: Raw, SHA256: sum(raw)}}
		if _, err := in.Install(context.Background(), tool, runtime.GOOS, runtime.GOARCH); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: ran go %v", c.name, f.calls)
		}
	}
}

func TestOlderGo(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"go1.26.3", "go1.27.1", true},
		{"go1.27.1", "go1.27.2", false}, // same release line
		{"go1.27.1", "go1.26.7", false},
		{"go1.27rc1", "go1.28.0", true},
		{"go1.27.1 X:fieldtrack", "go1.27.1", false},
		{"devel +abc", "go1.27.1", false}, // unparsable is never older
		{"", "go1.27.1", false},
	} {
		if got := olderGo(c.a, c.b); got != c.want {
			t.Errorf("olderGo(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestBuiltWithGo(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if v := BuiltWithGo(self); !strings.HasPrefix(v, "go") {
		t.Errorf("BuiltWithGo(test binary) = %q", v)
	}
	notGo := filepath.Join(t.TempDir(), "x")
	os.WriteFile(notGo, []byte("#!/bin/sh\n"), 0o600)
	if v := BuiltWithGo(notGo); v != "" {
		t.Errorf("BuiltWithGo(shell script) = %q", v)
	}
}

func TestDoctorFlagsAGosecBuiltWithAnOlderGo(t *testing.T) {
	have := map[string]string{"go": ""}
	for _, tool := range Tools() {
		have[tool.Bin] = tool.Version
	}
	d := fakeDoctor(have, nil)
	d.GoVersion = func(context.Context, string) string { return "go1.27.1" }
	built := "go1.26.3"
	d.BuiltWith = func(string) string { return built }
	st := map[string]ToolStatus{}
	for _, s := range d.Diagnose(context.Background()).Tools {
		st[s.Name] = s
	}
	g := st["gosec"]
	if !strings.Contains(strings.Join(g.Notes, " "), "built with go1.26.3 but type-checks with go1.27.1") ||
		g.Fix != "achilles tools install --force gosec   (builds it with your Go)" {
		t.Errorf("stale gosec not flagged: %+v", g)
	}
	if n := st["trivy"].Notes; len(n) != 0 {
		t.Errorf("a tool that is not built with Go was checked: %v", n)
	}

	built = "go1.27.0"
	for _, s := range d.Diagnose(context.Background()).Tools {
		if s.Name == "gosec" && (len(s.Notes) != 0 || s.Fix != "") {
			t.Errorf("a gosec built with the same Go release line was flagged: %+v", s)
		}
	}
}
