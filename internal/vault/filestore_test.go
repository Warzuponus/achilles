package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestAppendCreatesOwnerOnlyFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := filepath.Join(t.TempDir(), "tenants", "acme")
	path := filepath.Join(dir, "vault.jsonl")
	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, err := fs.Append(Record{RunID: "r", Kind: KindRawOutput}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
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

// The vault holds findings, code and prompts and is created 0600. Retention rewrote
// it through os.Create, which made the replacement world-readable.
func TestPurge_KeepsTheVaultPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	fs, path := newTestStore(t)
	fs.Append(Record{RunID: "a", Kind: KindFinding, Timestamp: time.Now().Add(-48 * time.Hour)})
	fs.Append(Record{RunID: "a", Kind: KindFinding, Timestamp: time.Now()})

	// A leftover temp file from an interrupted purge, with loose permissions, must
	// not lend them to the new vault.
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := fs.Purge(time.Now().Add(-24 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v", n, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("vault is %04o after a purge, want 0600", perm)
	}
}

func quietWarn(t *testing.T) *[]string {
	t.Helper()
	var got []string
	old := Warn
	Warn = func(msg string) { got = append(got, msg) }
	t.Cleanup(func() { Warn = old })
	return &got
}

// One undecodable line used to make every open fail, and with it every Append:
// recording stopped for good until someone repaired the file by hand.
func TestFileStore_ADamagedLineDoesNotBrickTheVault(t *testing.T) {
	warnings := quietWarn(t)
	fs, path := newTestStore(t)
	if _, err := fs.Append(Record{RunID: "a", Kind: KindFinding}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"id\":\"torn\",\"run\n") // a damaged line in the middle
	f.Close()
	if _, err := fs.Append(Record{RunID: "a", Kind: KindVerdict}); err != nil {
		t.Fatalf("Append after a damaged line: %v", err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("open a vault with one damaged line: %v", err)
	}
	if got := len(reopened.ByRun("a")); got != 2 {
		t.Errorf("want both intact records, got %d", got)
	}
	if reopened.Skipped() != 1 {
		t.Errorf("Skipped() = %d, want 1", reopened.Skipped())
	}
	if _, err := reopened.Append(Record{RunID: "a", Kind: KindFeedback}); err != nil {
		t.Errorf("the reopened vault must accept writes: %v", err)
	}
	if len(*warnings) == 0 || !strings.Contains((*warnings)[0], "damaged line") {
		t.Errorf("skipping a line must be announced, got %q", *warnings)
	}
}

// A crash or a full disk mid-write leaves a fragment with no newline at the end.
// The next record must not be glued onto it and lost with it.
func TestFileStore_AppendAfterATornWriteKeepsTheNewRecord(t *testing.T) {
	quietWarn(t)
	fs, path := newTestStore(t)
	if _, err := fs.Append(Record{RunID: "a", Kind: KindFinding}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"id":"torn","runID":"a","ki`) // no newline: the write was cut off
	f.Close()

	// A different process picks up where the crashed one left off.
	other, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := other.Append(Record{RunID: "a", Kind: KindVerdict, Source: "after-the-crash"})
	if err != nil {
		t.Fatal(err)
	}

	final, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := final.Get(rec.ID); !ok || got.Source != "after-the-crash" {
		t.Errorf("the record written after the torn one was lost (found=%v)", ok)
	}
	if n := len(final.ByRun("a")); n != 2 || final.Skipped() != 1 {
		t.Errorf("records=%d skipped=%d, want 2 intact and 1 skipped", n, final.Skipped())
	}
}

// Every record says which format it was written in, so a later build can tell what
// it is reading. Records from before versioning read back as 0.
func TestFileStore_RecordsCarryTheSchemaVersion(t *testing.T) {
	warnings := quietWarn(t)
	fs, path := newTestStore(t)
	rec, err := fs.Append(Record{RunID: "a", Kind: KindFinding})
	if err != nil {
		t.Fatal(err)
	}
	if rec.V != SchemaVersion {
		t.Errorf("Append returned V=%d, want %d", rec.V, SchemaVersion)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"v":1`) {
		t.Errorf("the version is not on disk: %s", raw)
	}

	// An old, unversioned line and one from a newer build.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"id":"old","runId":"a","kind":"finding","ts":"2026-01-01T00:00:00Z"}` + "\n")
	f.WriteString(`{"v":99,"id":"future","runId":"a","kind":"finding","ts":"2026-01-01T00:00:00Z"}` + "\n")
	f.Close()

	re, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if old, ok := re.Get("old"); !ok || old.V != 0 {
		t.Errorf("an unversioned record must read back as version 0: %+v (found=%v)", old, ok)
	}
	if fut, ok := re.Get("future"); !ok || fut.V != 99 {
		t.Errorf("a newer record is still read, as far as it can be: %+v (found=%v)", fut, ok)
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "newer Achilles") {
		t.Errorf("reading a newer record format must be announced once, got %q", *warnings)
	}
}
