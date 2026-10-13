package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End to end: scan, then ask the MCP server about that scan the way a client does.
func TestMCP_ServesAScanOverStdio(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vaultPath, target}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_scans","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"min_severity":"high"}}}`,
	}, "\n") + "\n"
	var stdout, stderr bytes.Buffer
	if err := runMCP([]string{"--vault", vaultPath}, strings.NewReader(in), &stdout, &stderr); err != nil {
		t.Fatalf("mcp: %v", err)
	}

	// stdout is the protocol channel: one JSON message per line and nothing else.
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d line(s) on stdout, want one reply per request:\n%s", len(lines), stdout.String())
	}
	var replies []map[string]any
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout carries a line that is not JSON: %q", line)
		}
		replies = append(replies, m)
	}
	if !strings.Contains(stderr.String(), "read-only") {
		t.Errorf("the human-readable start-up line belongs on stderr:\n%s", stderr.String())
	}
	if replies[0]["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "achilles" {
		t.Errorf("initialize = %v", replies[0])
	}

	text := func(reply map[string]any) map[string]any {
		t.Helper()
		res := reply["result"].(map[string]any)
		if res["isError"] == true {
			t.Fatalf("tool error: %v", res)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(res["content"].([]any)[0].(map[string]any)["text"].(string)), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	scans := text(replies[1])["scans"].([]any)
	if len(scans) != 1 || scans[0].(map[string]any)["findings"] != 1.0 {
		t.Errorf("scans = %v", scans)
	}
	findings := text(replies[2])["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
	if f := findings[0].(map[string]any); f["ruleId"] != "cmd-injection" || f["file"] != "app.py" || f["severity"] != "high" {
		t.Errorf("finding = %v", f)
	}

	// Serving it changed nothing.
	after, _ := os.ReadFile(vaultPath)
	if !bytes.Equal(before, after) {
		t.Error("the vault file changed while it was being served")
	}
}

// A client may start the server before anything was scanned. That is not an error,
// it creates no file, and the tools say there is nothing yet.
func TestMCP_NoVaultYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing", "vault.jsonl")
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}` + "\n"
	var stdout, stderr bytes.Buffer
	if err := runMCP([]string{"--vault", path}, strings.NewReader(in), &stdout, &stderr); err != nil {
		t.Fatalf("mcp: %v", err)
	}
	if !strings.Contains(stderr.String(), "no vault at") {
		t.Errorf("stderr should say there is no vault yet:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"isError":true`) || !strings.Contains(stdout.String(), "no scans yet") {
		t.Errorf("the tool should say there is nothing to read yet:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Dir(path)); err == nil {
		t.Error("serving a vault that does not exist created its directory")
	}
}

func TestMCP_UsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runMCP([]string{"some-target"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Error("a positional argument must be an error: the server scans nothing")
	}
	if err := runMCP([]string{"--vault-backend", "sqlite"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Error("an unknown backend must be an error")
	}
	if stdout.Len() != 0 {
		t.Errorf("an error was written to the protocol channel: %s", stdout.String())
	}
	// The subcommand is reached by name, like the others.
	stdout.Reset()
	if handled, err := runSubcommand([]string{"mcp", "--help"}, &stdout, &stderr); !handled || err != nil {
		t.Errorf("handled=%v err=%v", handled, err)
	}
	if !strings.Contains(stderr.String(), "list_scans") || stdout.Len() != 0 {
		t.Errorf("--help should describe the tools on stderr:\n%s", stderr.String())
	}
}
