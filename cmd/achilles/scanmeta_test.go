package main

import "testing"

func TestScanMetaPayload_LabelAndCommit(t *testing.T) {
	plain := scanMetaPayload("/abs/code", "", "", "oss", "default", []string{"gosec"})
	if plain["target"] != "/abs/code" {
		t.Errorf("without a label the scanned path is the target: %v", plain)
	}
	if _, ok := plain["commit"]; ok {
		t.Errorf("no commit key expected without --source-commit: %v", plain)
	}
	got := scanMetaPayload("/tmp/ws/app", "https://example.com/acme/app.git", "abc123", "oss", "default", nil)
	if got["target"] != "https://example.com/acme/app.git" || got["commit"] != "abc123" {
		t.Errorf("label/commit not recorded: %v", got)
	}
}
