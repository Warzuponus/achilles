package verifyfix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `build`, `dist`, `target` and `out` are left out of the copy as build output,
// but they are also ordinary names for directories of source. A finding there used
// to be reported "skipped: in a directory excluded from the verification copy".
func TestVerify_FindingInABuildNamedSourceDirIsVerified(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{
		"src/build/gen.py":         "import os\nos.system(cmd)  # VULN\nprint('x')\n",
		"src/build/node_modules/x": "nested dependency tree: still not copied\n",
		"dist/bundle.js":           "unrelated build output: still not copied\n",
		"app.py":                   "ok\n",
	})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection"}}
	diff := "--- a/src/build/gen.py\n+++ b/src/build/gen.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(cmd)  # VULN\n+subprocess.run([cmd])\n print('x')\n"
	tmp := t.TempDir()

	res := newVerifier(t, root, sc, Options{TempDir: tmp}).Verify(context.Background(),
		orig("fake", "cmd-injection", "src/build/gen.py", "os.system(cmd)  # VULN", 2), diff)
	if res.Status != Verified {
		t.Fatalf("status = %s (%s), want verified", res.Status, res.Detail)
	}
	leftovers(t, tmp)
}

func TestCopyTree_KeepsOnlyTheBulkyDirOnThePathToTheFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app.py":                    "x\n",
		"svc/target/src/Main.java":  "m\n",
		"svc/target/node_modules/a": "n\n",
		"other/target/classes/A":    "c\n",
		"build/out.txt":             "o\n",
		".git/config":               "g\n",
	})
	dst := t.TempDir()
	if err := copyTree(root, dst, DefaultMaxCopyBytes, DefaultMaxCopyFiles, "svc/target/src/Main.java"); err != nil {
		t.Fatal(err)
	}
	var got []string
	_ = filepath.WalkDir(dst, func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			r, _ := filepath.Rel(dst, p)
			got = append(got, filepath.ToSlash(r))
		}
		return nil
	})
	want := "app.py svc/target/src/Main.java"
	if strings.Join(got, " ") != want {
		t.Errorf("copied %v, want %q", got, want)
	}
}

func TestVerify_FindingInVersionControlDirIsNeverCopied(t *testing.T) {
	root := writeTree(t, map[string]string{".achilles/x.py": "VULN\n", "app.py": "ok\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "r"}}
	res := newVerifier(t, root, sc, Options{}).Verify(context.Background(), orig("fake", "r", ".achilles/x.py", "VULN", 1),
		"--- a/.achilles/x.py\n+++ b/.achilles/x.py\n@@ -1 +1 @@\n-VULN\n+ok\n")
	if res.Status == Verified {
		t.Fatalf("a fix inside a never-copied directory must not verify: %s (%s)", res.Status, res.Detail)
	}
}

// With ReuseCopies the target is copied once and each patch is undone by putting
// the one file it may touch back. Every verification must still start from the
// original content: fix A must not be visible when fix B is checked.
func TestVerify_ReusedCopyIsRestoredBetweenFixes(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{
		"a.py": "import os\nos.system(a)  # VULN-A\nprint('a')\n",
		"b.py": "import os\nos.system(b)  # VULN-B\nprint('b')\n",
	})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN-A": "inj-a", "VULN-B": "inj-b"}}
	tmp := t.TempDir()
	v := newVerifier(t, root, sc, Options{TempDir: tmp, ReuseCopies: true})

	fixA := "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(a)  # VULN-A\n+subprocess.run([a])\n print('a')\n"
	fixB := "--- a/b.py\n+++ b/b.py\n@@ -1,3 +1,3 @@\n import os\n-os.system(b)  # VULN-B\n+subprocess.run([b])\n print('b')\n"
	noFix := "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n import os\n os.system(a)  # VULN-A\n-print('a')\n+print('changed, but the finding is still there')\n"

	if res := v.Verify(context.Background(), orig("fake", "inj-a", "a.py", "os.system(a)  # VULN-A", 2), fixA); res.Status != Verified {
		t.Fatalf("fix A: %s (%s)", res.Status, res.Detail)
	}
	ents, _ := os.ReadDir(tmp)
	if len(ents) != 1 {
		t.Fatalf("want one copy kept for reuse, found %d", len(ents))
	}
	kept := filepath.Join(tmp, ents[0].Name())
	if b, _ := os.ReadFile(filepath.Join(kept, "a.py")); !strings.Contains(string(b), "VULN-A") {
		t.Fatalf("the kept copy still carries fix A:\n%s", b)
	}

	// B is checked in the same copy. If A's patch had leaked, the scanner would no
	// longer report inj-a there, which the comparison would not notice; so check
	// the file directly above, and here that B verifies and no second copy is made.
	if res := v.Verify(context.Background(), orig("fake", "inj-b", "b.py", "os.system(b)  # VULN-B", 2), fixB); res.Status != Verified {
		t.Fatalf("fix B: %s (%s)", res.Status, res.Detail)
	}
	// A patch that does not remove the finding is still caught in a reused copy.
	if res := v.Verify(context.Background(), orig("fake", "inj-a", "a.py", "os.system(a)  # VULN-A", 2), noFix); res.Status == Verified {
		t.Fatalf("a patch that leaves the finding in place verified in a reused copy: %s", res.Detail)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 1 {
		t.Errorf("three verifications made %d copies, want 1", len(ents))
	}
	if b, _ := os.ReadFile(filepath.Join(root, "a.py")); !strings.Contains(string(b), "VULN-A") {
		t.Error("the original target was modified")
	}

	v.Close()
	leftovers(t, tmp)
}

// A patch that does not apply leaves the copy untouched, so it can still be reused;
// and a custom applier, which is not known to honor the scope rule, never reuses.
func TestVerify_ReuseAfterAFailedPatchAndNeverWithACustomApplier(t *testing.T) {
	needGit(t)
	root := writeTree(t, map[string]string{"app.py": "import os\nos.system(cmd)  # VULN\nprint('x')\n"})
	sc := &fakeScanner{id: "fake", rules: map[string]string{"VULN": "cmd-injection"}}
	tmp := t.TempDir()
	v := newVerifier(t, root, sc, Options{TempDir: tmp, ReuseCopies: true})
	f := orig("fake", "cmd-injection", "app.py", "os.system(cmd)  # VULN", 2)

	bad := "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n-this line is not in the file\n+x\n print('x')\n"
	if res := v.Verify(context.Background(), f, bad); res.Status != PatchFailed {
		t.Fatalf("status = %s, want patch_failed", res.Status)
	}
	if res := v.Verify(context.Background(), f, fixDiff); res.Status != Verified {
		t.Fatalf("after a failed patch the copy must still be usable: %s (%s)", res.Status, res.Detail)
	}
	v.Close()
	leftovers(t, tmp)

	custom := newVerifier(t, root, sc, Options{TempDir: tmp, ReuseCopies: true,
		Apply: func(_ context.Context, dir, _ string) error {
			return os.WriteFile(filepath.Join(dir, "app.py"), []byte("ok\n"), 0o644)
		}})
	if res := custom.Verify(context.Background(), f, fixDiff); res.Status != Verified {
		t.Fatalf("custom applier: %s (%s)", res.Status, res.Detail)
	}
	leftovers(t, tmp) // nothing kept: a custom applier gets a fresh copy every time
}
