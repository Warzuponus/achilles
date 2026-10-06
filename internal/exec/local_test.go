package exec

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The local runner must find tools installed by `achilles tools install`
// ($ACHILLES_HOME/bin) and prefer them over PATH.
func TestLocalRunnerPrefersManagedBinDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fixtures")
	}
	home, onPath := t.TempDir(), t.TempDir()
	t.Setenv("ACHILLES_HOME", home)
	t.Setenv("PATH", onPath+string(os.PathListSeparator)+"/usr/bin:/bin")
	script := func(dir, out string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "achfaketool"), []byte("#!/bin/sh\necho "+out+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script(onPath, "from-path")

	r := LocalRunner{}
	res, err := r.Run(context.Background(), Command{Bin: "achfaketool"})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "from-path" {
		t.Fatalf("PATH only: %q %v", res.Stdout, err)
	}

	script(filepath.Join(home, "bin"), "from-managed")
	res, err = r.Run(context.Background(), Command{Bin: "achfaketool"})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "from-managed" {
		t.Fatalf("managed dir should win: %q %v", res.Stdout, err)
	}
	if !r.Has("achfaketool") || r.Has("achilles-definitely-absent") {
		t.Error("Has() wrong")
	}
}

func TestLocalEnvForcesUTF8OnlyForOpengrep(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	if got := localEnv("/x/opengrep"); len(got) != 1 || got[0] != "LC_ALL=C.UTF-8" {
		t.Errorf("opengrep with no locale: %v", got)
	}
	if got := localEnv("gitleaks"); got != nil {
		t.Errorf("other tools untouched: %v", got)
	}
	t.Setenv("LANG", "en_US.UTF-8")
	if got := localEnv("opengrep"); got != nil {
		t.Errorf("existing UTF-8 locale must be left alone: %v", got)
	}
}
