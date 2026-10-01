package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadModelRouting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "models.yaml")
	yaml := `tasks:
  triage:
    model: gpt-4o-mini
  judge:
    model: gpt-4o
    baseURL: https://alt.example/v1
  remediation:
    model: gpt-4o
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	mr, err := LoadModelRouting(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mr.Tasks) != 3 {
		t.Fatalf("want 3 tasks, got %d", len(mr.Tasks))
	}
	if mr.Tasks["triage"].Model != "gpt-4o-mini" {
		t.Errorf("triage model: got %q", mr.Tasks["triage"].Model)
	}
	if mr.Tasks["judge"].BaseURL != "https://alt.example/v1" {
		t.Errorf("judge baseURL: got %q", mr.Tasks["judge"].BaseURL)
	}
}

func TestLoadModelRouting_MissingFile(t *testing.T) {
	if _, err := LoadModelRouting(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing model-config should error")
	}
}
