package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	c, err := Load(filepath.Join("testdata", "tools.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Tools) != 3 {
		t.Fatalf("want 3 tools, got %d", len(c.Tools))
	}

	gosec := c.Tools[1]
	if gosec.ID != "gosec" || !gosec.CommercialSafe || !gosec.Enabled {
		t.Errorf("gosec parsed wrong: %+v", gosec)
	}
	if gosec.OutputFile != "{out}/results.sarif" {
		t.Errorf("gosec outputFile: %q", gosec.OutputFile)
	}
	if len(gosec.Argv) == 0 {
		t.Error("gosec argv should be non-empty")
	}

	// ToLicense projection feeds the policy gate.
	lic := c.Tools[2].ToLicense()
	if lic.ID != "brakeman" || lic.CommercialSafe {
		t.Errorf("brakeman license projection wrong: %+v", lic)
	}
}

func TestLoad_Missing(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Error("want error for missing file")
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	f := writeTemp(t, "tools:\n  - {id: a, enabled: false}\n  - {id: a, enabled: false}\n")
	if _, err := Load(f); err == nil {
		t.Error("want error for duplicate id")
	}
}

func TestValidate_EnabledGenericNeedsArgv(t *testing.T) {
	f := writeTemp(t, "tools:\n  - {id: a, enabled: true}\n")
	if _, err := Load(f); err == nil {
		t.Error("want error: enabled generic tool without argv")
	}
}

func TestValidate_ProfileGenericNeedsArgv(t *testing.T) {
	f := writeTemp(t, "tools:\n  - {id: a, profiles: [full]}\n")
	if _, err := Load(f); err == nil {
		t.Error("want error: profile-tagged generic tool without argv")
	}
}

func TestRunsInProfile(t *testing.T) {
	baseline := ToolConfig{Enabled: true}
	heavy := ToolConfig{Profiles: []string{"full"}}
	off := ToolConfig{}

	if !baseline.RunsInProfile("default") || !baseline.RunsInProfile("full") {
		t.Error("baseline (enabled) should run in every profile")
	}
	if heavy.RunsInProfile("default") {
		t.Error("full-only tool must NOT run in the default profile")
	}
	if !heavy.RunsInProfile("full") {
		t.Error("full-only tool should run under --profile full")
	}
	if off.RunsInProfile("default") || off.RunsInProfile("full") {
		t.Error("untagged tool should run in no profile")
	}
}

func TestValidate_BespokeWithoutArgvOK(t *testing.T) {
	f := writeTemp(t, "tools:\n  - {id: a, enabled: true, bespoke: true}\n")
	if _, err := Load(f); err != nil {
		t.Errorf("bespoke tool without argv should be OK, got %v", err)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
