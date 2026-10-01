package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A scan (CLI) and a long-running achillesd are separate processes sharing one
// vault file. Two FileStore instances over the same path model that: each has its
// own memory, and they only meet on disk.

func openTwo(t *testing.T) (*FileStore, *FileStore) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v.jsonl")
	a, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestFileStore_ReaderSeesAnotherInstancesAppends(t *testing.T) {
	scanner, server := openTwo(t)
	if got := len(server.All()); got != 0 {
		t.Fatalf("precondition: %d records", got)
	}
	rec, err := scanner.Append(Record{RunID: "r1", Kind: KindFinding, Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	if got := server.ByRun("r1"); len(got) != 1 || got[0].ID != rec.ID {
		t.Errorf("server ByRun = %+v, want the scanner's record", got)
	}
	if got := server.ByFingerprint("fp"); len(got) != 1 {
		t.Errorf("server ByFingerprint = %d records", len(got))
	}
	if _, ok := server.Get(rec.ID); !ok {
		t.Error("server Get missed the scanner's record")
	}
}

func TestFileStore_TwoWritersNeverCollideOnID(t *testing.T) {
	a, b := openTwo(t)
	var wg sync.WaitGroup
	for _, s := range []*FileStore{a, b} {
		wg.Add(1)
		go func(s *FileStore) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				// Identical content on purpose: only the sequence can tell them apart.
				if _, err := s.Append(Record{RunID: "r", Kind: KindFinding, Timestamp: time.Unix(1, 0).UTC()}); err != nil {
					t.Error(err)
					return
				}
			}
		}(s)
	}
	wg.Wait()
	for name, s := range map[string]*FileStore{"a": a, "b": b} {
		all := s.All()
		if len(all) != 80 {
			t.Errorf("%s sees %d records, want 80", name, len(all))
		}
		seen := map[string]bool{}
		for _, r := range all {
			if seen[r.ID] {
				t.Fatalf("%s: duplicate record ID %s", name, r.ID)
			}
			seen[r.ID] = true
		}
	}
}

func TestFileStore_ReaderSurvivesAnotherInstancesPurge(t *testing.T) {
	a, b := openTwo(t)
	old := time.Now().Add(-48 * time.Hour).UTC()
	for i := 0; i < 3; i++ {
		if _, err := a.Append(Record{RunID: "old", Kind: KindFinding, Timestamp: old.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Append(Record{RunID: "new", Kind: KindFinding}); err != nil {
		t.Fatal(err)
	}
	if n := len(b.All()); n != 4 {
		t.Fatalf("b sees %d, want 4", n)
	}
	if n, err := a.Purge(time.Now().Add(-24 * time.Hour)); err != nil || n != 3 {
		t.Fatalf("purge = %d, %v", n, err)
	}
	all := b.All()
	if len(all) != 1 || all[0].RunID != "new" {
		t.Errorf("b after a's purge sees %+v, want only the new record", all)
	}
	// And b can keep writing on top of the rewritten file.
	if _, err := b.Append(Record{RunID: "later", Kind: KindFinding}); err != nil {
		t.Fatal(err)
	}
	if n := len(a.All()); n != 2 {
		t.Errorf("a sees %d, want 2", n)
	}
}

func TestFileStore_IgnoresPartialTrailingLine(t *testing.T) {
	a, b := openTwo(t)
	if _, err := a.Append(Record{RunID: "r", Kind: KindFinding}); err != nil {
		t.Fatal(err)
	}
	if err := appendRaw(a.path, `{"id":"half","runId":"r"`); err != nil { // no newline: a write in flight
		t.Fatal(err)
	}
	if n := len(b.All()); n != 1 {
		t.Errorf("b sees %d records, want only the 1 complete line", n)
	}
	if err := appendRaw(a.path, "}\n"); err != nil {
		t.Fatal(err)
	}
	if n := len(b.All()); n != 2 {
		t.Errorf("after the line completes b sees %d, want 2", n)
	}
}

// TestFileStore_RealProcessesAppendConcurrently re-executes the test binary as
// writer processes, so the lock is exercised across real OS processes, not just
// across instances in one.
func TestFileStore_RealProcessesAppendConcurrently(t *testing.T) {
	if p := os.Getenv("VAULT_TEST_WRITER_PATH"); p != "" {
		s, err := NewFileStore(p)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 30; i++ {
			if _, err := s.Append(Record{RunID: "r", Kind: KindFinding, Timestamp: time.Unix(1, 0).UTC()}); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	path := filepath.Join(t.TempDir(), "v.jsonl")
	var cmds []*exec.Cmd
	for i := 0; i < 3; i++ {
		c := exec.Command(os.Args[0], "-test.run=^TestFileStore_RealProcessesAppendConcurrently$")
		c.Env = append(os.Environ(), "VAULT_TEST_WRITER_PATH="+path)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("writer process: %v", err)
		}
	}
	s, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	all := s.All()
	if len(all) != 90 {
		t.Fatalf("got %d records, want 90", len(all))
	}
	seen := map[string]bool{}
	for _, r := range all {
		if seen[r.ID] {
			t.Fatalf("duplicate ID %s across processes", r.ID)
		}
		seen[r.ID] = true
	}
}
