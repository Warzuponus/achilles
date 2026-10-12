package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// What Context reads is sent to a model and shown in reports. A scanner's report
// about a hostile repository must not be able to point it at a file outside the
// scanned tree.
func TestContext_NeverReadsOutsideTheScannedTree(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	const secret = "OUTSIDE-THE-TREE-do-not-read"
	outside := filepath.Join(base, "credentials")
	if err := os.WriteFile(outside, []byte("line one\n"+secret+"\nline three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "app.py"), []byte("import os\neval(x)\nprint(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	finding := func(file string) model.Finding {
		return model.Finding{CodeContext: "tool snippet", Location: model.Location{File: file, Region: model.Region{StartLine: 2}}}
	}
	en := New(2)

	cases := map[string]string{
		"dot-dot path":             filepath.Join("..", "credentials"),
		"dot-dot with slashes":     "src/../../credentials",
		"absolute path elsewhere":  outside,
		"absolute dot-dot in root": filepath.Join(root, "..", "credentials"),
	}
	// A symlink inside the repository that points out of it. Creating one needs a
	// privilege on Windows; the other cases still run there.
	link := filepath.Join(root, "src", "notes.txt")
	if err := os.Symlink(outside, link); err == nil {
		cases["symlink out of the tree"] = "src/notes.txt"
		cases["symlink, absolute"] = link
	} else {
		t.Logf("symlink case not run: %v", err)
	}
	dirLink := filepath.Join(root, "up")
	if err := os.Symlink(base, dirLink); err == nil {
		cases["symlinked directory out of the tree"] = "up/credentials"
	}

	for name, file := range cases {
		got := en.Context(finding(file), root)
		if strings.Contains(got, secret) {
			t.Errorf("%s: Context read a file outside the scanned tree:\n%s", name, got)
		}
		if got != "tool snippet" {
			t.Errorf("%s: want the fallback to the tool's own snippet, got %q", name, got)
		}
	}

	// Files inside the tree still work, by relative path, URI-style path and absolute path.
	for _, file := range []string{"src/app.py", filepath.Join("src", "app.py"), filepath.Join(root, "src", "app.py")} {
		if got := en.Context(finding(file), root); !strings.Contains(got, "eval(x)") || !strings.Contains(got, "import os") {
			t.Errorf("Context(%q) did not read the file inside the tree: %q", file, got)
		}
	}

	// With no root there is nothing to confine to, so nothing is read.
	if got := en.Context(finding(filepath.Join(root, "src", "app.py")), ""); got != "tool snippet" {
		t.Errorf("no root: got %q, want the tool snippet", got)
	}
}
