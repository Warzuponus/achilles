package enrich

import "sync"

// fileCache holds the contents of files already read for context.
//
// Context is called more than once per finding (the cost estimate, the review, the
// fix suggestion, each re-ask) and findings cluster in files, so the same file was
// read from disk again and again: a file with forty findings was read well over a
// hundred times. The scanned tree does not change during a run, so one read each
// is enough.
//
// It is bounded: when the cached bytes pass the cap the cache is emptied and
// starts again. That is crude next to an LRU, and cannot grow without limit on a
// repository with thousands of large files.
type fileCache struct {
	mu    sync.Mutex
	files map[string]cached
	bytes int
}

type cached struct {
	data []byte
	err  error
}

const maxCacheBytes = 64 << 20

func newFileCache() *fileCache { return &fileCache{files: map[string]cached{}} }

// read returns the file's contents through load, remembering the result (errors
// too: an unreadable file stays unreadable for the run, and each failed attempt
// would otherwise repeat the system calls).
func (c *fileCache) read(key string, load func() ([]byte, error)) ([]byte, error) {
	if c == nil {
		return load()
	}
	c.mu.Lock()
	if hit, ok := c.files[key]; ok {
		c.mu.Unlock()
		return hit.data, hit.err
	}
	c.mu.Unlock()

	data, err := load()

	c.mu.Lock()
	if c.bytes+len(data) > maxCacheBytes {
		c.files, c.bytes = map[string]cached{}, 0
	}
	if len(data) <= maxCacheBytes {
		c.files[key] = cached{data: data, err: err}
		c.bytes += len(data)
	}
	c.mu.Unlock()
	return data, err
}
