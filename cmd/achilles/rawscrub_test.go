package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Warzuponus/achilles/internal/scanner"
)

// sarifScanner is a scanner that returns a fixed SARIF document.
type sarifScanner struct {
	id   string
	data []byte
}

func (s sarifScanner) ID() string                     { return s.id }
func (s sarifScanner) Meta() scanner.ScannerMeta      { return scanner.ScannerMeta{ID: s.id} }
func (s sarifScanner) Applicable(scanner.Target) bool { return true }
func (s sarifScanner) Run(context.Context, scanner.Target) (scanner.RawResult, error) {
	return scanner.RawResult{Tool: s.id, Format: "sarif", Data: s.data}, nil
}

// What a scan keeps of a secret scanner's report (the vault's raw_output record,
// --sarif-out) must not contain the secrets it found.
func TestRunScanners_RawOutputKeptForStorageHoldsNoCredential(t *testing.T) {
	secret := "hunter" + "2-Xy7!q" // built at run time: no credential-shaped literal
	doc, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "gitleaks"}},
		"results": []any{map[string]any{"ruleId": "generic-api-key",
			"message": map[string]any{"text": "generic-api-key has detected secret for file config.py."},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": "config.py"},
				"region":           map[string]any{"startLine": 3, "snippet": map[string]any{"text": secret}},
			}}}}},
	}}})

	results := runScanners(context.Background(), []scanner.Scanner{sarifScanner{id: "gitleaks", data: doc}}, scanner.Target{Path: t.TempDir()})
	if len(results) != 1 || results[0].err != nil || results[0].normErr != nil {
		t.Fatalf("results = %+v", results)
	}
	r := results[0]
	if bytes.Contains(r.raw.Data, []byte(secret)) {
		t.Errorf("the raw output a scan stores still holds the secret:\n%s", r.raw.Data)
	}
	if len(r.findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(r.findings))
	}
	f := r.findings[0]
	if f.CodeContext != "" {
		t.Errorf("the finding keeps the secret as its snippet: %q", f.CodeContext)
	}
	if f.Fingerprint == "" || f.Location.File != "config.py" || f.Location.Region.StartLine != 3 {
		t.Errorf("the finding itself must be intact: %+v", f)
	}
	if b, _ := json.Marshal(f); bytes.Contains(b, []byte(secret)) {
		t.Errorf("the finding record would carry the secret into the vault: %s", b)
	}
}
