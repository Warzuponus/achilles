package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunSubcommandPassesThroughScans(t *testing.T) {
	for _, argv := range [][]string{nil, {"."}, {"--profile", "full", "."}, {"./version"}, {"--version"}} {
		var out, errb bytes.Buffer
		if handled, err := runSubcommand(argv, &out, &errb); handled || err != nil {
			t.Errorf("%v: handled=%v err=%v, want a pass-through", argv, handled, err)
		}
	}
}

func TestVersionSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	handled, err := runSubcommand([]string{"version"}, &out, &errb)
	if !handled || err != nil || !strings.HasPrefix(out.String(), "achilles ") {
		t.Fatalf("handled=%v err=%v out=%q", handled, err, out.String())
	}
}

func TestToolsSubcommandErrors(t *testing.T) {
	t.Setenv("ACHILLES_HOME", t.TempDir())
	cases := [][]string{
		{"tools"},
		{"tools", "frobnicate"},
		{"tools", "install", "no-such-tool"},
	}
	for _, argv := range cases {
		var out, errb bytes.Buffer
		handled, err := runSubcommand(argv, &out, &errb)
		if !handled || err == nil {
			t.Errorf("%v: handled=%v err=%v, want a handled error", argv, handled, err)
		}
	}
}

func TestToolsList(t *testing.T) {
	t.Setenv("ACHILLES_HOME", t.TempDir())
	var out, errb bytes.Buffer
	if handled, err := runSubcommand([]string{"tools", "list"}, &out, &errb); !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	for _, name := range []string{"opengrep", "gosec", "osv-scanner", "trivy", "gitleaks"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("list lacks %s:\n%s", name, out.String())
		}
	}
}

func TestDoctorFailsWhenScannersMissing(t *testing.T) {
	// Empty managed dir + empty PATH: nothing can be found, so doctor must fail
	// and name the fix.
	t.Setenv("ACHILLES_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	var out, errb bytes.Buffer
	handled, err := runSubcommand([]string{"doctor"}, &out, &errb)
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v, want a failure", handled, err)
	}
	if !strings.Contains(out.String(), "achilles tools install") {
		t.Errorf("doctor output lacks the fix command:\n%s", out.String())
	}
}
