package vault

import "sync"

// The Store read methods (Get, ByRun, ByFingerprint, All) return no error: they
// were designed for an in-memory file store that cannot fail once open. A database
// backend can, and then "the query failed" and "there is nothing there" came back
// as the same empty slice: a PostgreSQL outage read as "No scans recorded", an
// empty feedback history and an empty War Room.
//
// Rather than change every read call site, a store that can fail on read records
// it here, and the callers that turn "empty" into a statement to the user (the
// War Room pages, --metrics, --rule-health, the end of a scan) ask.

// readHealth is embedded in stores whose reads can fail.
type readHealth struct {
	mu       sync.Mutex
	last     error // the most recent read's error; nil if it succeeded
	failures int   // how many reads have failed since the store was opened
}

// noteRead records the outcome of one read.
func (h *readHealth) noteRead(err error) {
	h.mu.Lock()
	h.last = err
	if err != nil {
		h.failures++
	}
	h.mu.Unlock()
}

// LastReadErr is the error of the most recent read, or nil.
func (h *readHealth) LastReadErr() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

// ReadFailures is the number of reads that have failed since the store was opened.
func (h *readHealth) ReadFailures() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failures
}

// ReadReporter is implemented by stores whose reads can fail.
type ReadReporter interface {
	LastReadErr() error
	ReadFailures() int
}

// ReadErr returns the error of s's most recent read, or nil: for the caller that
// has just read and is about to present the result. A store that cannot fail on
// read reports nil.
func ReadErr(s Store) error {
	if r, ok := s.(ReadReporter); ok {
		return r.LastReadErr()
	}
	return nil
}

// ReadFailures returns how many of s's reads have failed since it was opened.
func ReadFailures(s Store) int {
	if r, ok := s.(ReadReporter); ok {
		return r.ReadFailures()
	}
	return 0
}
