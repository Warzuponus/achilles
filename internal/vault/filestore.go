package vault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// FileStore is a JSONL-backed, append-only Evidence Vault. Records are written
// one JSON object per append and never rewritten through this API, so the file
// itself is the audit log. It is not tamper-evident: there is no hash chain or
// signature, so anyone who can write the file can change it. Protect it with file
// permissions (it is created 0600) like any other record you rely on.
//
// Several processes may share one file on a local filesystem — typically a scan
// writing while achillesd serves the War Room. Writers serialize on a sidecar
// lock file (the vault itself can't carry the lock: Purge replaces it by rename),
// and every operation first folds in whatever other processes appended since it
// last looked. Network filesystems (NFS and friends) don't give flock the needed
// guarantees; use a database backend for those.
type FileStore struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	records []Record
	byID    map[string]Record

	// Read position: the file we last read (to notice Purge's rename) and how many
	// bytes of it are already folded into records. offset only ever advances past
	// complete lines, so a writer caught mid-append is picked up next time.
	seen   os.FileInfo
	offset int64

	// skipped counts lines that could not be decoded (see refresh).
	skipped int
	// warnedNewer: the notice about records from a newer build was given.
	warnedNewer bool

	health readHealth
}

// LastReadErr and ReadFailures report reads that could not refresh from disk (the
// file became unreadable after it was opened). Such a read still serves the
// records already loaded, so it is stale rather than empty.
func (fs *FileStore) LastReadErr() error { return fs.health.LastReadErr() }
func (fs *FileStore) ReadFailures() int  { return fs.health.ReadFailures() }

// Warn receives the one-line notice a FileStore gives when it has to skip a
// damaged line. It defaults to stderr; tests replace it.
var Warn = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

// Skipped reports how many damaged lines this store has passed over.
func (fs *FileStore) Skipped() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.skipped
}

// NewFileStore opens (or creates on first append) a vault at path, loading any
// existing records.
func NewFileStore(path string) (*FileStore, error) {
	fs := &FileStore{
		path: path,
		now:  func() time.Time { return time.Now().UTC() },
		byID: map[string]Record{},
	}
	if err := fs.refresh(); err != nil {
		return nil, err
	}
	return fs, nil
}

// refresh folds in records appended by other processes since the last call, or
// reloads from scratch if the file was replaced (Purge) or truncated. The caller
// holds fs.mu.
func (fs *FileStore) refresh() error {
	f, err := os.Open(fs.path)
	if err != nil {
		if os.IsNotExist(err) {
			fs.reset()
			return nil
		}
		return fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat vault: %w", err)
	}
	if fs.seen == nil || !os.SameFile(fs.seen, fi) || fi.Size() < fs.offset {
		fs.reset()
	}
	fs.seen = fi
	if _, err := f.Seek(fs.offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek vault: %w", err)
	}

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break // a trailing fragment has no newline yet: leave it for next time
			}
			return fmt.Errorf("read vault: %w", err)
		}
		fs.offset += int64(len(line))
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			// One damaged line (a write torn by a crash or a full disk, a stray
			// edit) must not take the vault down: failing here made every later
			// open and every later Append fail too, so a single bad line stopped
			// all recording until someone repaired the file by hand. Skip it, say
			// so once, and keep everything that is intact.
			fs.skipped++
			if fs.skipped == 1 {
				Warn(fmt.Sprintf("achilles: vault %s: skipping a damaged line ending at byte %d (%v); the other records are intact",
					fs.path, fs.offset, err))
			}
			continue
		}
		if rec.V > SchemaVersion && !fs.warnedNewer {
			fs.warnedNewer = true
			Warn(fmt.Sprintf("achilles: vault %s holds records written by a newer Achilles (record format %d; this build understands %d). "+
				"They are read as far as this build understands them; upgrade to be sure nothing is misread", fs.path, rec.V, SchemaVersion))
		}
		fs.records = append(fs.records, rec)
		fs.byID[rec.ID] = rec
	}
	return nil
}

func (fs *FileStore) reset() {
	fs.records, fs.byID, fs.seen, fs.offset, fs.skipped = nil, map[string]Record{}, nil, 0, 0
}

// lock takes the cross-process write lock and brings memory up to date; the
// returned func releases it. The caller holds fs.mu.
func (fs *FileStore) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(fs.path), 0o700); err != nil {
		return nil, fmt.Errorf("vault dir: %w", err)
	}
	lf, err := os.OpenFile(fs.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	if err := lockFile(lf); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("lock vault: %w", err)
	}
	unlock := func() { unlockFile(lf); _ = lf.Close() }
	if err := fs.refresh(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// Append stores r immutably. It never updates an existing record.
func (fs *FileStore) Append(r Record) (Record, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	unlock, err := fs.lock()
	if err != nil {
		return Record{}, err
	}
	defer unlock()

	if r.Timestamp.IsZero() {
		r.Timestamp = fs.now()
	}
	r.V = SchemaVersion
	// The sequence is the count AFTER folding in other writers' records, so IDs
	// stay unique across processes.
	r.ID = computeID(r, len(fs.records))

	// Owner-only: records hold raw scanner output, including any secrets found in code.
	f, err := os.OpenFile(fs.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Record{}, fmt.Errorf("open vault for append: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(r)
	if err != nil {
		return Record{}, fmt.Errorf("marshal record: %w", err)
	}
	// If an earlier write was cut short, the file ends in a fragment with no
	// newline. Appending straight after it would glue this record onto the
	// fragment and lose both; end the fragment's line first so only it is lost.
	if fi, err := f.Stat(); err == nil && fi.Size() > fs.offset {
		line = append([]byte{'\n'}, line...)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("write record: %w", err)
	}

	// Fold our own line back in through the normal read path so offset/seen stay
	// consistent with the file.
	if err := fs.refresh(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Get returns a record by ID.
func (fs *FileStore) Get(id string) (Record, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.health.noteRead(fs.refresh()) // on a read error serve what we have, and say so
	r, ok := fs.byID[id]
	return r, ok
}

// ByRun returns all records for a run in insertion order.
func (fs *FileStore) ByRun(runID string) []Record {
	return fs.filter(func(r Record) bool { return r.RunID == runID })
}

// ByFingerprint returns all records for a finding fingerprint in insertion order.
func (fs *FileStore) ByFingerprint(fp string) []Record {
	return fs.filter(func(r Record) bool { return r.Fingerprint == fp })
}

// All returns every record in insertion order.
func (fs *FileStore) All() []Record {
	return fs.filter(func(Record) bool { return true })
}

// Purge deletes records older than the cutoff and rewrites the log (retention).
// Distinct from the append-only guarantee: this is coarse time-based expiry, not
// record mutation — records within the window are copied unchanged.
func (fs *FileStore) Purge(before time.Time) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	unlock, err := fs.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()

	kept := make([]Record, 0, len(fs.records))
	deleted := 0
	for _, r := range fs.records {
		if r.Timestamp.Before(before) {
			deleted++
			continue
		}
		kept = append(kept, r)
	}
	if deleted == 0 {
		return 0, nil
	}

	// 0600 like the vault itself: os.Create would make the replacement 0644
	// (before umask), turning a private file of findings and prompts into one any
	// local user can read the first time retention runs.
	tmp := fs.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("purge open: %w", err)
	}
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" { // a leftover .tmp keeps its old mode
		f.Close()
		return 0, fmt.Errorf("purge chmod: %w", err)
	}
	for _, r := range kept {
		line, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return 0, err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			return 0, err
		}
	}
	if err := f.Sync(); err != nil { // the old file is about to be replaced: have the new one on disk first
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, fs.path); err != nil {
		return 0, fmt.Errorf("purge rename: %w", err)
	}

	// The file is a new inode now; re-read it rather than patching memory.
	fs.reset()
	if err := fs.refresh(); err != nil {
		return 0, err
	}
	return deleted, nil
}

func (fs *FileStore) filter(keep func(Record) bool) []Record {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.health.noteRead(fs.refresh()) // on a read error serve what we have, and say so
	var out []Record
	for _, r := range fs.records {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}
