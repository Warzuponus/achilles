package deep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Evidence was checked against the set of files a tool had touched. A model could
// grep one token in auth.go and then cite auth.go:999 as the sanitizer: the file
// was "seen", so the citation counted, and a cited dismissal needs only one.
func TestFilterEvidence_LineMustHaveBeenShown(t *testing.T) {
	seen := map[string]bool{"auth.go": true, "db.go": true}
	lines := map[string]map[int]bool{
		"auth.go": {10: true, 11: true, 12: true, 40: true},
		"db.go":   {},
	}
	kept, dropped := filterEvidence([]string{
		"auth.go:11",    // shown
		"auth.go:10-12", // every line of the range shown
		"auth.go:999",   // file read, line never shown
		"auth.go:12-40", // ends are shown, the middle is not
		"auth.go:40-10", // backwards
		"db.go:5",       // file seen (a grep ran), nothing of it shown
		"other.go:1",    // never read at all
		"./auth.go:40",  // same line, written differently
	}, seen, lines)

	want := []string{"auth.go:11", "auth.go:10-12", "auth.go:40"}
	if strings.Join(kept, " ") != strings.Join(want, " ") {
		t.Errorf("kept %v, want %v", kept, want)
	}
	if dropped != 5 {
		t.Errorf("dropped = %d, want 5", dropped)
	}
}

func TestSandbox_ReportsExactlyTheLinesItShowed(t *testing.T) {
	root := t.TempDir()
	var body strings.Builder
	for i := 1; i <= 30; i++ {
		body.WriteString("line\n")
	}
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.go"), []byte("x\nneedle here\ny\nneedle again\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := NewSandbox(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	res := sb.ReadFile("a.go", 5, 9)
	if len(res.Lines) != 5 || res.Lines[0] != (Shown{"a.go", 5}) || res.Lines[4] != (Shown{"a.go", 9}) {
		t.Errorf("ReadFile(5..9) reported %v", res.Lines)
	}

	g := sb.Grep(context.Background(), "needle", "", "")
	if len(g.Lines) != 2 || g.Lines[0] != (Shown{"b.go", 2}) || g.Lines[1] != (Shown{"b.go", 4}) {
		t.Errorf("Grep reported %v, want b.go lines 2 and 4", g.Lines)
	}

	// A result cut down by the byte budget: only lines delivered whole count.
	header, _, _ := strings.Cut(res.Text, "\n")
	firstTwo := strings.SplitAfterN(res.Text, "\n", 4)
	delivered := firstTwo[0] + firstTwo[1] + firstTwo[2] // header + two full lines
	if got := res.shownIn(delivered + "    7  li"); len(got) != 2 || got[1].Line != 6 {
		t.Errorf("after truncation mid-line: %v, want lines 5 and 6 only", got)
	}
	if got := res.shownIn(delivered + "\n[truncated: budget]"); len(got) != 2 {
		t.Errorf("after truncation with a notice appended: %v, want 2 lines", got)
	}
	if got := res.shownIn(header); len(got) != 0 {
		t.Errorf("only the header was delivered: %v, want nothing shown", got)
	}
	if got := res.shownIn(res.Text); len(got) != 5 {
		t.Errorf("untruncated: %d lines, want 5", len(got))
	}
}

// End to end through a session: what a tool call shows is what can be cited.
func TestSession_OnlyShownLinesCanBeCited(t *testing.T) {
	root := t.TempDir()
	var body strings.Builder
	for i := 1; i <= 200; i++ {
		body.WriteString("code\n")
	}
	if err := os.WriteFile(filepath.Join(root, "auth.go"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := NewSandbox(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	sess := &session{sb: sb, remaining: DefaultTotalBytes, seen: map[string]bool{}, lines: map[string]map[int]bool{}}
	sess.run(context.Background(), Action{Action: "read_file", Path: "auth.go", Start: 20, End: 25})

	kept, dropped := filterEvidence([]string{"auth.go:22", "auth.go:150"}, sess.seen, sess.lines)
	if len(kept) != 1 || kept[0] != "auth.go:22" || dropped != 1 {
		t.Errorf("kept %v, dropped %d: a line outside what read_file returned must not count", kept, dropped)
	}
}
