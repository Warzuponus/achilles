package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.jsonl")
	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return fs, path
}

func TestAppendAndGet(t *testing.T) {
	fs, _ := newTestStore(t)
	rec, err := fs.Append(Record{RunID: "run1", Kind: KindScanMeta, Payload: json.RawMessage(`{"target":"x"}`)})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("expected an assigned ID")
	}
	if rec.Timestamp.IsZero() {
		t.Fatal("expected an assigned timestamp")
	}
	got, ok := fs.Get(rec.ID)
	if !ok || got.RunID != "run1" {
		t.Errorf("Get: ok=%v run=%q", ok, got.RunID)
	}
}

func TestByRun(t *testing.T) {
	fs, _ := newTestStore(t)
	fs.Append(Record{RunID: "a", Kind: KindRawOutput})
	fs.Append(Record{RunID: "b", Kind: KindRawOutput})
	fs.Append(Record{RunID: "a", Kind: KindFinding})
	if n := len(fs.ByRun("a")); n != 2 {
		t.Errorf("ByRun(a): want 2, got %d", n)
	}
	if n := len(fs.ByRun("b")); n != 1 {
		t.Errorf("ByRun(b): want 1, got %d", n)
	}
}

func TestDistinctIDsForIdenticalPayload(t *testing.T) {
	fs, _ := newTestStore(t)
	r1, _ := fs.Append(Record{RunID: "a", Kind: KindFinding, Payload: json.RawMessage(`{"x":1}`)})
	r2, _ := fs.Append(Record{RunID: "a", Kind: KindFinding, Payload: json.RawMessage(`{"x":1}`)})
	if r1.ID == r2.ID {
		t.Error("identical payloads at different positions must get distinct IDs")
	}
}

func TestPersistenceReload(t *testing.T) {
	fs, path := newTestStore(t)
	fs.Append(Record{RunID: "a", Kind: KindScanMeta})
	fs.Append(Record{RunID: "a", Kind: KindFinding})

	// Reopen: records must survive as an on-disk audit log.
	fs2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n := len(fs2.ByRun("a")); n != 2 {
		t.Errorf("after reload: want 2 records, got %d", n)
	}
}

func TestPurge(t *testing.T) {
	fs, path := newTestStore(t)
	fs.Append(Record{RunID: "a", Kind: KindFinding, Timestamp: time.Now().Add(-48 * time.Hour)})
	fs.Append(Record{RunID: "a", Kind: KindFinding, Timestamp: time.Now()})

	n, err := fs.Purge(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d, want 1", n)
	}
	if got := len(fs.ByRun("a")); got != 1 {
		t.Errorf("one record should remain, got %d", got)
	}
	// Purge must persist (the on-disk log is rewritten).
	fs2, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(fs2.ByRun("a")); got != 1 {
		t.Errorf("purge not persisted: reopened store has %d", got)
	}
}

func TestCorrectionReferencesPrev(t *testing.T) {
	// Immutability model: a correction is a NEW record pointing at the old one.
	fs, _ := newTestStore(t)
	orig, _ := fs.Append(Record{RunID: "a", Kind: KindVerdict, Fingerprint: "fp1", Payload: json.RawMessage(`{"tp":true}`)})
	corr, _ := fs.Append(Record{RunID: "a", Kind: KindVerdict, Fingerprint: "fp1", PrevID: orig.ID, Payload: json.RawMessage(`{"tp":false}`)})
	if corr.PrevID != orig.ID {
		t.Errorf("correction should reference original %q, got %q", orig.ID, corr.PrevID)
	}
	// Both remain in the log; nothing is overwritten.
	if n := len(fs.ByRun("a")); n != 2 {
		t.Errorf("want both records retained, got %d", n)
	}
}

func appendRaw(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(s)
	return err
}
