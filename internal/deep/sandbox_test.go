package deep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const outsideMarker = "OUTSIDE-MARKER-7731"
const secretMarker = "SECRET-MARKER-4410"

// fixture builds <tmp>/repo (the scan root) from files, plus <tmp>/outside with a
// file that must never be reachable through the sandbox. It returns both paths.
func fixture(t *testing.T, files map[string]string) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "repo")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, content string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(outside, "outside.txt"), outsideMarker+"\n")
	write(filepath.Join(outside, "sub", "deep.txt"), outsideMarker+" deep\n")
	for name, content := range files {
		write(filepath.Join(root, filepath.FromSlash(name)), content)
	}
	return root, outside
}

func newSB(t *testing.T, root string, lim Limits, deny ...string) *Sandbox {
	t.Helper()
	sb, err := NewSandbox(root, lim, deny...)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func mustDeny(t *testing.T, label string, r Result) {
	t.Helper()
	if !strings.HasPrefix(r.Text, "access denied") || !r.Denied {
		t.Errorf("%s: want an access-denied refusal, got %q (denied=%v)", label, r.Text, r.Denied)
	}
	if strings.Contains(r.Text, outsideMarker) || strings.Contains(r.Text, secretMarker) {
		t.Errorf("%s: refusal leaked protected content: %q", label, r.Text)
	}
}

func TestSandbox_RejectsTraversalAndAbsolutePaths(t *testing.T) {
	root, outside := fixture(t, map[string]string{"a/b.txt": "inside\n"})
	sb := newSB(t, root, Limits{})

	bad := []string{
		"../outside/outside.txt",
		"a/../../outside/outside.txt",
		"a/../..",
		"..",
		`..\outside\outside.txt`,
		`a\..\..\outside\outside.txt`,
		filepath.Join(outside, "outside.txt"), // absolute, built at run time
		"/etc/hostname",
		`C:\Windows\win.ini`,
		"c:relative",
		"a/b.txt\x00../../x",
		strings.Repeat("a/", 400) + "x",
	}
	for _, p := range bad {
		label := fmt.Sprintf("%q", p)
		mustDeny(t, "read_file "+label, sb.ReadFile(p, 1, 10))
		mustDeny(t, "list_dir "+label, sb.ListDir(p))
		mustDeny(t, "grep in "+label, sb.Grep(context.Background(), "marker", "", p))
	}
	// A normal path still works, including with a leading ./ and mixed separators.
	for _, p := range []string{"a/b.txt", "./a/b.txt", "a//b.txt", `a\b.txt`} {
		if r := sb.ReadFile(p, 1, 10); !strings.Contains(r.Text, "inside") {
			t.Errorf("read_file %q: %q", p, r.Text)
		}
	}
}

func TestSandbox_SymlinkEscapeIsRefused(t *testing.T) {
	root, outside := fixture(t, map[string]string{"ok.txt": "ok\n", "real/inner.txt": "inner-text\n"})
	link(t, filepath.Join(outside, "outside.txt"), filepath.Join(root, "file_link"))
	link(t, outside, filepath.Join(root, "dir_link"))
	link(t, "../outside", filepath.Join(root, "rel_dir_link"))
	link(t, filepath.Join(root, "real"), filepath.Join(root, "inside_dir_link"))
	link(t, filepath.Join(root, "real", "inner.txt"), filepath.Join(root, "inside_file_link"))
	sb := newSB(t, root, Limits{})

	for _, p := range []string{"file_link", "dir_link/outside.txt", "dir_link/sub/deep.txt", "rel_dir_link/outside.txt"} {
		mustDeny(t, "read_file "+p, sb.ReadFile(p, 1, 5))
	}
	for _, p := range []string{"dir_link", "rel_dir_link", "dir_link/sub"} {
		mustDeny(t, "list_dir "+p, sb.ListDir(p))
		mustDeny(t, "grep in "+p, sb.Grep(context.Background(), ".", "", p))
	}

	// A search from the root must not walk through the links either.
	for _, r := range []Result{
		sb.Grep(context.Background(), "OUTSIDE", "", ""),
		sb.FindReferences(context.Background(), "OUTSIDE", ""),
	} {
		if strings.Contains(r.Text, outsideMarker) {
			t.Fatalf("a search followed a symlink out of the root: %q", r.Text)
		}
	}
	// The listing shows links but not where they lead.
	list := sb.ListDir(".")
	if !strings.Contains(list.Text, "dir_link@") || strings.Contains(list.Text, outsideMarker) {
		t.Errorf("list_dir: %q", list.Text)
	}

	// Links that stay inside the root are fine.
	if r := sb.ReadFile("inside_file_link", 1, 5); !strings.Contains(r.Text, "inner-text") || r.Denied {
		t.Errorf("an in-root file link should read: %q", r.Text)
	}
	if r := sb.ReadFile("inside_dir_link/inner.txt", 1, 5); !strings.Contains(r.Text, "inner-text") {
		t.Errorf("an in-root directory link should read: %q", r.Text)
	}
}

func TestSandbox_SymlinkToProtectedFileIsRefused(t *testing.T) {
	root, _ := fixture(t, map[string]string{
		".env":            "TOKEN=" + secretMarker + "\n",
		".git/config":     "[core] " + secretMarker + "\n",
		"keys/prod.pem":   secretMarker + "\n",
		"harmless/it.txt": "fine\n",
	})
	// The link has an innocent name; its target is protected. Resolution must catch it.
	link(t, filepath.Join(root, ".env"), filepath.Join(root, "notes.txt"))
	link(t, filepath.Join(root, ".git"), filepath.Join(root, "history"))
	link(t, filepath.Join(root, "keys"), filepath.Join(root, "docs"))
	sb := newSB(t, root, Limits{})

	mustDeny(t, "link to .env", sb.ReadFile("notes.txt", 1, 5))
	mustDeny(t, "link to .git", sb.ReadFile("history/config", 1, 5))
	mustDeny(t, "link to .git dir", sb.ListDir("history"))
	mustDeny(t, "link to a dir holding a key", sb.ReadFile("docs/prod.pem", 1, 5))
	if r := sb.Grep(context.Background(), secretMarker, "", ""); strings.Contains(r.Text, secretMarker) {
		t.Errorf("grep surfaced protected content: %q", r.Text)
	}
}

func TestSandbox_SecretBearingFilesAreRefused(t *testing.T) {
	protected := []string{
		".env", ".env.local", ".env.production", "app/.env", "app/.ENV",
		"certs/server.pem", "certs/SERVER.PEM", "certs/tls.key", "id_rsa", "id_rsa.pub", "home/.ssh/id_ed25519", "id_ecdsa",
		"store.p12", "store.pfx", "ks.jks", ".netrc", "_netrc", ".npmrc", ".pypirc", ".htpasswd", ".pgpass",
		"credentials", "credentials.json", "aws/credentials", "gcp/service-account.json", "service-account-prod.json",
		"client_secret_123.json", "secrets.yaml", "secrets.yml", "secret.json",
		"infra/terraform.tfstate", "infra/terraform.tfstate.backup", "infra/prod.tfvars", "infra/prod.auto.tfvars.json",
		".terraform/providers.json", ".git/config", ".git/HEAD", "sub/.git/config",
		".achilles/vault.jsonl", ".achilles/anything.txt", "vault.jsonl", "run.vault.jsonl",
		".aws/config", ".kube/config", ".docker/config.json", "kubeconfig", ".git-credentials",
	}
	files := map[string]string{"main.go": "package main // visible\n"}
	for _, p := range protected {
		files[p] = "line1 " + secretMarker + "\n"
	}
	root, _ := fixture(t, files)
	sb := newSB(t, root, Limits{})

	for _, p := range protected {
		mustDeny(t, "read_file "+p, sb.ReadFile(p, 1, 5))
	}
	// Directories that are protected are refused whole.
	for _, d := range []string{".git", ".achilles", ".terraform", "home/.ssh", ".aws", ".kube"} {
		mustDeny(t, "list_dir "+d, sb.ListDir(d))
	}
	// Listings omit protected entries, grep and find_references never match inside them.
	list := sb.ListDir(".")
	for _, n := range []string{".env", ".git", ".achilles", "credentials", "kubeconfig", "vault.jsonl", ".netrc", "id_rsa"} {
		for _, line := range strings.Split(list.Text, "\n") {
			if strings.HasPrefix(line, n) {
				t.Errorf("list_dir shows protected entry %q: %q", n, list.Text)
			}
		}
	}
	for _, r := range []Result{
		sb.Grep(context.Background(), "SECRET-MARKER", "", ""),
		sb.Grep(context.Background(), "SECRET-MARKER", "*.pem", ""),
		sb.Grep(context.Background(), "line1", ".env*", ""),
		sb.FindReferences(context.Background(), "line1", ""),
	} {
		if strings.Contains(r.Text, secretMarker) {
			t.Errorf("search surfaced protected content: %q", r.Text)
		}
	}
	if r := sb.ReadFile("main.go", 1, 5); !strings.Contains(r.Text, "visible") {
		t.Errorf("ordinary file unreadable: %q", r.Text)
	}
}

func TestSandbox_ExtraDenyPath(t *testing.T) {
	root, _ := fixture(t, map[string]string{
		"state/evidence.dat":    secretMarker + "\n",
		"state/nested/more.dat": secretMarker + "\n",
		"other.txt":             "fine\n",
	})
	sb := newSB(t, root, Limits{}, filepath.Join(root, "state"))
	mustDeny(t, "denied dir file", sb.ReadFile("state/evidence.dat", 1, 5))
	mustDeny(t, "denied dir", sb.ListDir("state"))
	if r := sb.Grep(context.Background(), "SECRET", "", ""); strings.Contains(r.Text, secretMarker) {
		t.Errorf("grep entered a denied directory: %q", r.Text)
	}
	if r := sb.ReadFile("other.txt", 1, 5); !strings.Contains(r.Text, "fine") {
		t.Errorf("ordinary file unreadable: %q", r.Text)
	}
}

func TestSandbox_NotFoundAndKinds(t *testing.T) {
	root, _ := fixture(t, map[string]string{"d/f.txt": "x\n"})
	sb := newSB(t, root, Limits{})
	if r := sb.ReadFile("nope.txt", 1, 5); !strings.HasPrefix(r.Text, "not found") || r.Denied {
		t.Errorf("missing file: %q", r.Text)
	}
	if r := sb.ReadFile("d", 1, 5); !strings.Contains(r.Text, "directory") {
		t.Errorf("read_file on a directory: %q", r.Text)
	}
	if r := sb.ListDir("d/f.txt"); !strings.Contains(r.Text, "not a directory") {
		t.Errorf("list_dir on a file: %q", r.Text)
	}
	if err := os.WriteFile(filepath.Join(root, "bin.dat"), []byte("ab\x00cd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := sb.ReadFile("bin.dat", 1, 5); !strings.Contains(r.Text, "binary") {
		t.Errorf("binary file: %q", r.Text)
	}
	if r := sb.Run(context.Background(), Action{Action: "rm_rf"}); !strings.Contains(r.Text, "unknown tool") {
		t.Errorf("unknown action: %q", r.Text)
	}
	if _, err := NewSandbox(filepath.Join(root, "missing"), Limits{}); err == nil {
		t.Error("a missing root must be an error")
	}
	if _, err := NewSandbox(filepath.Join(root, "d", "f.txt"), Limits{}); err == nil {
		t.Error("a file as root must be an error")
	}
}

func TestSandbox_ReadFileCaps(t *testing.T) {
	var big strings.Builder
	for i := 1; i <= 500; i++ {
		fmt.Fprintf(&big, "line %d\n", i)
	}
	root, _ := fixture(t, map[string]string{
		"big.txt":  big.String(),
		"long.txt": strings.Repeat("x", 5000) + "\nshort\n",
		"wide.txt": strings.Repeat(strings.Repeat("y", 100)+"\n", 400),
	})
	sb := newSB(t, root, Limits{})

	r := sb.ReadFile("big.txt", 0, 0)
	if n := strings.Count(r.Text, "\n    "); n > 200 || !strings.Contains(r.Text, "lines 1-200") || !strings.Contains(r.Text, "continue with start=201") {
		t.Errorf("default window: %d numbered lines\n%s", n, r.Text[:min(len(r.Text), 200)])
	}
	r = sb.ReadFile("big.txt", 10, 5000) // asks for far more than the cap
	if !strings.Contains(r.Text, "lines 10-209") {
		t.Errorf("end must be clamped to 200 lines: %q", r.Text[:80])
	}
	r = sb.ReadFile("big.txt", 495, 520)
	if !strings.Contains(r.Text, "line 500") || !strings.Contains(r.Text, "[end of file]") {
		t.Errorf("tail read: %q", r.Text)
	}
	r = sb.ReadFile("big.txt", 900, 910)
	if !strings.Contains(r.Text, "past the end") {
		t.Errorf("past the end: %q", r.Text)
	}

	r = sb.ReadFile("long.txt", 1, 2)
	if !strings.Contains(r.Text, "[line truncated]") || strings.Count(r.Text, "x") > 300 || !strings.Contains(r.Text, "short") {
		t.Errorf("long line not capped: %d x's", strings.Count(r.Text, "x"))
	}

	r = sb.ReadFile("wide.txt", 1, 200) // 200 lines * ~108 bytes > 16KB
	if len(r.Text) > 16<<10+200 || !strings.Contains(r.Text, "[output limit reached; continue with start=") {
		t.Errorf("byte cap: len=%d tail=%q", len(r.Text), r.Text[max(0, len(r.Text)-120):])
	}
}

func TestSandbox_GrepCaps(t *testing.T) {
	files := map[string]string{
		"many.txt":                 strings.Repeat("needle here\n", 100),
		"src/a.go":                 "package a\nfunc Handler() {}\n",
		"src/b.py":                 "def x(): Handler()\n",
		"node_modules/dep/x.js":    "needle in a dependency\n",
		"vendor/v.go":              "needle in vendor\n",
		"sub/deep/needle_file.txt": "needle\n",
	}
	root, _ := fixture(t, files)
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), []byte("needle\x00needle"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb := newSB(t, root, Limits{})
	ctx := context.Background()

	r := sb.Grep(ctx, "needle", "many.txt", "")
	if n := strings.Count(r.Text, "many.txt:"); n != 40 || !strings.Contains(r.Text, "stopped after 40 matches") {
		t.Errorf("match cap: %d matches\n%s", n, r.Text[max(0, len(r.Text)-200):])
	}
	r = sb.Grep(ctx, "needle", "", "sub")
	if !strings.Contains(r.Text, "sub/deep/needle_file.txt:1:") {
		t.Errorf("subdir grep: %q", r.Text)
	}
	r = sb.Grep(ctx, "needle", "*.js", "")
	if strings.Contains(r.Text, "node_modules") || strings.Contains(r.Text, "vendor") || strings.Contains(r.Text, "blob.bin") {
		t.Errorf("dependency trees and binaries must be skipped: %q", r.Text)
	}
	r = sb.Grep(ctx, "Handler", "*.go", "")
	if !strings.Contains(r.Text, "src/a.go:2:") || strings.Contains(r.Text, "b.py") {
		t.Errorf("path_glob by base name: %q", r.Text)
	}
	r = sb.Grep(ctx, "Handler", "src/*.py", "")
	if !strings.Contains(r.Text, "src/b.py:1:") || strings.Contains(r.Text, "a.go") {
		t.Errorf("path_glob with a directory: %q", r.Text)
	}
	r = sb.Grep(ctx, "Handler", "**/*.go", "")
	if !strings.Contains(r.Text, "src/a.go") {
		t.Errorf("path_glob with **/: %q", r.Text)
	}
	if r := sb.Grep(ctx, "zzz-no-such-thing", "", ""); !strings.HasPrefix(r.Text, "No matches") {
		t.Errorf("no match: %q", r.Text)
	}
	if r := sb.Grep(ctx, "x", "[", ""); !strings.Contains(r.Text, "not a valid glob") {
		t.Errorf("bad glob: %q", r.Text)
	}
}

func TestSandbox_GrepPatternGuards(t *testing.T) {
	root, _ := fixture(t, map[string]string{"a.txt": strings.Repeat("a", 100000) + "!\n"})
	sb := newSB(t, root, Limits{})
	ctx := context.Background()

	for _, p := range []string{"", "   ", "(", "[a-", "a{1001}", "(?=x)", strings.Repeat("a", 201)} {
		if r := sb.Grep(ctx, p, "", ""); !strings.HasPrefix(r.Text, "grep:") {
			t.Errorf("pattern %q should be rejected, got %q", p[:min(len(p), 20)], r.Text)
		}
	}
	// Classic catastrophic-backtracking patterns are linear under RE2.
	start := time.Now()
	for _, p := range []string{`(a+)+$`, `(a*)*b`, `(a|aa)+$`, `^(([a-z])+.)+[A-Z]([a-z])+$`} {
		sb.Grep(ctx, p, "", "")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("ReDoS-shaped patterns took %v", d)
	}
}

func TestSandbox_SearchHonorsContextAndFileCaps(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = "hit\n"
	}
	root, _ := fixture(t, files)
	sb := newSB(t, root, Limits{GrepMaxFiles: 10})
	r := sb.Grep(context.Background(), "hit", "", "")
	if strings.Count(r.Text, "hit") != 10 || !strings.Contains(r.Text, "stopped after 10 files") {
		t.Errorf("file cap: %q", r.Text)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := newSB(t, root, Limits{}).Grep(ctx, "hit", "", ""); !strings.HasPrefix(r.Text, "No matches") {
		t.Errorf("cancelled search: %q", r.Text)
	}
	sb = newSB(t, root, Limits{GrepMaxScanBytes: 8})
	if r := sb.Grep(context.Background(), "hit", "", ""); !strings.Contains(r.Text, "byte limit") {
		t.Errorf("byte cap: %q", r.Text)
	}
}

func TestSandbox_ListDirCap(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 150; i++ {
		files[fmt.Sprintf("many/f%03d.txt", i)] = "x"
	}
	root, _ := fixture(t, files)
	r := newSB(t, root, Limits{}).ListDir("many")
	if n := strings.Count(r.Text, ".txt"); n != 100 || !strings.Contains(r.Text, "[50 more entries not shown]") {
		t.Errorf("list cap: %d entries\n%s", n, r.Text[max(0, len(r.Text)-100):])
	}
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := newSB(t, root, Limits{}).ListDir("empty"); !strings.Contains(r.Text, "(empty)") {
		t.Errorf("empty dir: %q", r.Text)
	}
}

func TestSandbox_FindReferences(t *testing.T) {
	root, _ := fixture(t, map[string]string{
		"a.go": "func sanitize(x string) {}\nsanitize(input)\nresanitized := 1\nunsanitize()\n",
	})
	sb := newSB(t, root, Limits{})
	ctx := context.Background()
	r := sb.FindReferences(ctx, "sanitize", "")
	if !strings.Contains(r.Text, "a.go:1:") || !strings.Contains(r.Text, "a.go:2:") ||
		strings.Contains(r.Text, "a.go:3:") || strings.Contains(r.Text, "a.go:4:") {
		t.Errorf("whole-word matching: %q", r.Text)
	}
	for _, s := range []string{"", ".*", "a b", "x(", strings.Repeat("a", 101), "a\nb"} {
		if r := sb.FindReferences(ctx, s, ""); !strings.HasPrefix(r.Text, "find_references:") {
			t.Errorf("symbol %q should be rejected: %q", s, r.Text)
		}
	}
	// A symbol with a metacharacter in it is matched literally.
	if r := sb.FindReferences(ctx, "a.b", ""); !strings.HasPrefix(r.Text, "No matches") {
		t.Errorf("literal dot: %q", r.Text)
	}
}

func TestSandbox_RedactsEverythingShown(t *testing.T) {
	awsKey := "AKI" + "A" + strings.Repeat("Q", 16)
	ghTok := "ghp_" + strings.Repeat("a1", 20)
	begin, end := "-----BEGIN "+"RSA PRIVATE KEY-----", "-----END "+"RSA PRIVATE KEY-----"
	body := strings.Join([]string{
		"line one",                         // 1
		"aws = " + awsKey,                  // 2
		`password = "hunter2-hunter2"`,     // 3
		begin,                              // 4
		"MIIEowIBAAKCAQEA-" + secretMarker, // 5
		"second-key-line-" + secretMarker,  // 6
		end,                                // 7
		"token: " + ghTok,                  // 8
		"after the key, needle",            // 9
		"zero\u200bwidth \x1b[31mred\x1b[0m text", // 10
	}, "\n") + "\n"
	root, _ := fixture(t, map[string]string{"cfg.txt": body})
	sb := newSB(t, root, Limits{})
	ctx := context.Background()

	check := func(label, text string) {
		t.Helper()
		for _, leak := range []string{awsKey, ghTok, "hunter2-hunter2", secretMarker, "MIIEow", begin, end} {
			if strings.Contains(text, leak) {
				t.Errorf("%s leaked %q:\n%s", label, leak, text)
			}
		}
		if strings.ContainsAny(text, "\x1b\u200b") {
			t.Errorf("%s kept control/format characters: %q", label, text)
		}
	}
	whole := sb.ReadFile("cfg.txt", 1, 20)
	check("read_file", whole.Text)
	// Line numbers survive the key block being masked.
	if !strings.Contains(whole.Text, "    9  after the key, needle") || !strings.Contains(whole.Text, "   10  zerowidth [31mred[0m text") {
		t.Errorf("line numbers shifted or text mangled:\n%s", whole.Text)
	}
	// Starting inside a key block must still mask its body.
	check("read_file mid-key", sb.ReadFile("cfg.txt", 5, 6).Text)
	check("grep", sb.Grep(ctx, "aws|password|token|PRIVATE|second|MIIE", "", "").Text)
	check("find_references", sb.FindReferences(ctx, "aws", "").Text)
	check("run", sb.Run(ctx, Action{Action: ActionReadFile, Path: "cfg.txt", Start: 1, End: 20}).Text)

	// Matching runs on the REDACTED line, so a pattern cannot probe masked characters.
	for _, p := range []string{"AKIAQ", "hunter2", secretMarker, "MIIEow", "ghp_a1"} {
		if r := sb.Grep(ctx, p, "", ""); !strings.HasPrefix(r.Text, "No matches") {
			t.Errorf("grep %q matched masked text: %q", p, r.Text)
		}
	}
	if r := sb.Grep(ctx, "needle", "", ""); !strings.Contains(r.Text, "cfg.txt:9:") {
		t.Errorf("text after the key block must be searchable: %q", r.Text)
	}
}

func TestSandbox_RunCapsEveryTool(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 100; i++ {
		files[fmt.Sprintf("d/%s%03d.txt", strings.Repeat("n", 90), i)] = "x"
	}
	root, _ := fixture(t, files)
	sb := newSB(t, root, Limits{CallMaxBytes: 500})
	r := sb.Run(context.Background(), Action{Action: ActionListDir, Path: "d"})
	if len(r.Text) > 500+len("\n[output truncated at the per-call limit]") || !strings.Contains(r.Text, "per-call limit") {
		t.Errorf("per-call cap not applied: len=%d", len(r.Text))
	}
}

func TestSandbox_RaceFreeConcurrentUse(t *testing.T) {
	root, _ := fixture(t, map[string]string{"a.txt": "alpha\n", "b/c.txt": "alpha beta\n"})
	sb := newSB(t, root, Limits{})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				sb.Grep(context.Background(), "alpha", "", "")
				sb.ReadFile("b/c.txt", 1, 3)
				sb.ListDir(".")
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
