package main

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	bi := func(mainVer string, kv ...string) *debug.BuildInfo {
		b := &debug.BuildInfo{Main: debug.Module{Version: mainVer}}
		for i := 0; i+1 < len(kv); i += 2 {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return b
	}
	cases := []struct {
		name                string
		ver, commit, date   string
		info                *debug.BuildInfo
		wantVer, wantCommit string
		wantDate            string
	}{
		{"ldflags win", "0.2.0", "abc123", "2026-01-02T03:04:05Z", bi("v9.9.9"), "v0.2.0", "abc123", "2026-01-02T03:04:05Z"},
		{"go install module version", "", "", "", bi("v0.1.0"), "v0.1.0", "unknown", "unknown"},
		{"checkout build uses vcs stamp", "", "", "", bi("(devel)", "vcs.revision", "deadbeef", "vcs.time", "2026-02-02T00:00:00Z"), "dev", "deadbeef", "2026-02-02T00:00:00Z"},
		{"dirty tree", "", "", "", bi("(devel)", "vcs.revision", "deadbeef", "vcs.modified", "true"), "dev", "deadbeef-dirty", "unknown"},
		{"ldflags commit is trusted even when the VCS stamp says modified", "0.2.0", "abc123", "2026-01-02T03:04:05Z", bi("v9.9.9", "vcs.revision", "deadbeef", "vcs.modified", "true"), "v0.2.0", "abc123", "2026-01-02T03:04:05Z"},
		{"no build info", "", "", "", nil, "dev", "unknown", "unknown"},
		{"git describe stays as is", "6e842d6-dirty", "", "", nil, "6e842d6-dirty", "unknown", "unknown"},
		{"v prefix kept", "v1.0.0", "c", "d", nil, "v1.0.0", "c", "d"},
	}
	for _, c := range cases {
		got := resolveVersion(c.ver, c.commit, c.date, c.info)
		if got.Version != c.wantVer || got.Commit != c.wantCommit || got.Date != c.wantDate {
			t.Errorf("%s: got %+v", c.name, got)
		}
		if got.GoVersion != runtime.Version() || got.OS != runtime.GOOS || got.Arch != runtime.GOARCH {
			t.Errorf("%s: runtime fields wrong: %+v", c.name, got)
		}
	}
}

func TestPrintVersionAndFlag(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)
	out := buf.String()
	for _, want := range []string{"achilles ", "commit:", "built:", "go:", runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(out, want) {
			t.Errorf("version output lacks %q:\n%s", want, out)
		}
	}
	o, err := parseFlags([]string{"--version"})
	if err != nil || !o.showVersion {
		t.Fatalf("--version not parsed: %v %+v", err, o)
	}
}
