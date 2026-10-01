package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "package main\n")
	write(t, dir, "app.py", "print(1)\n")
	write(t, dir, "go.mod", "module x\n\ngo 1.26\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.1.0 // indirect\n)\n")
	write(t, dir, "requirements.txt", "flask==2.0.1\nrequests>=2.28.0\n# comment\n")
	write(t, dir, "package.json", `{"dependencies":{"express":"^4.18.2"},"devDependencies":{"jest":"29.0.0"}}`)

	inv, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	wantLangs := map[string]bool{"go": true, "python": true}
	for _, l := range inv.Languages {
		delete(wantLangs, l)
	}
	if len(wantLangs) != 0 {
		t.Errorf("missing languages: %v (got %v)", wantLangs, inv.Languages)
	}

	got := map[string]string{} // name -> version
	eco := map[string]string{}
	for _, d := range inv.Dependencies {
		got[d.Name] = d.Version
		eco[d.Name] = d.Ecosystem
	}
	for name, ver := range map[string]string{
		"github.com/foo/bar": "v1.2.3", "flask": "2.0.1", "requests": "2.28.0",
		"express": "4.18.2", "jest": "29.0.0",
	} {
		if got[name] != ver {
			t.Errorf("dep %s: want %q, got %q", name, ver, got[name])
		}
	}
	if eco["flask"] != "pypi" || eco["express"] != "npm" || eco["github.com/foo/bar"] != "go" {
		t.Errorf("ecosystem mislabeled: %v", eco)
	}
}

func TestScan_SkipsVendorDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "node_modules"), "junk.py", "x")
	write(t, dir, "real.go", "package main")

	inv, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range inv.Languages {
		if l == "python" {
			t.Error("should not detect python from node_modules")
		}
	}
}
