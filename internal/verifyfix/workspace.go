package verifyfix

import (
	"fmt"
	"os"
	"path/filepath"
)

// workspace is one private copy of the target in which a patch is applied and the
// scanner re-run.
//
// A fresh copy per fix is the simple design, and on a large repository the
// expensive one: up to 200 MiB and 50,000 files copied for every proposed fix.
// With Options.ReuseCopies a copy is put back after use and handed to the next
// fix, so a run makes one copy per concurrent verification instead of one per fix.
//
// Reuse is sound because of the scope rule: a patch that gets as far as being
// applied can only have changed the finding's own file, and cannot have created,
// deleted, renamed or re-moded anything. So putting that one file back restores
// the copy. If putting it back fails for any reason the copy is thrown away.
type workspace struct {
	dir    string
	pooled bool // may be returned to the pool after use

	// The one file a patch may change, as it was before the patch.
	savedPath string
	savedData []byte
	savedMode os.FileMode
	saved     bool
}

// workspace returns a copy of the target for verifying a fix to file.
func (v *Verifier) workspace(file string) (*workspace, error) {
	// A finding inside a normally-excluded directory needs a copy that includes
	// it. Such a copy is not what other fixes expect, so it is never pooled.
	keep := ""
	if file != "" && inDir(file, bulkyDirs) {
		keep = file
	}
	reuse := v.opts.ReuseCopies && keep == ""
	if reuse {
		v.mu.Lock()
		if n := len(v.pool); n > 0 {
			ws := v.pool[n-1]
			v.pool = v.pool[:n-1]
			v.mu.Unlock()
			return ws, nil
		}
		v.mu.Unlock()
	}

	tmp, err := os.MkdirTemp(v.opts.TempDir, "achilles-verifyfix-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	if err := copyTree(v.target, tmp, v.opts.MaxCopyBytes, v.opts.MaxCopyFiles, keep); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("copy target: %w", err)
	}
	return &workspace{dir: tmp, pooled: reuse}, nil
}

// remember saves the file a patch is about to change, so restore can undo it.
func (ws *workspace) remember(file string) error {
	ws.saved = false
	if file == "" {
		return fmt.Errorf("no file to remember")
	}
	p := filepath.Join(ws.dir, filepath.FromSlash(file))
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", file)
	}
	data, err := os.ReadFile(p) // #nosec G304 -- inside our own temp copy; file passed the scope rule
	if err != nil {
		return err
	}
	ws.savedPath, ws.savedData, ws.savedMode, ws.saved = p, data, info.Mode().Perm(), true
	return nil
}

// restore puts the remembered file back exactly as it was.
func (ws *workspace) restore() error {
	if !ws.saved {
		return fmt.Errorf("nothing was remembered")
	}
	ws.saved = false
	// Remove first: the patch may have replaced the file rather than rewritten it.
	if err := os.Remove(ws.savedPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(ws.savedPath, ws.savedData, ws.savedMode) // #nosec G306 G304 -- restoring a file in our own temp copy with the mode it had
}

// release returns a workspace to the pool if it can be trusted to be pristine
// again, and removes it otherwise.
func (v *Verifier) release(ws *workspace) {
	if ws == nil {
		return
	}
	if ws.pooled && ws.restore() == nil {
		v.mu.Lock()
		if !v.closed {
			v.pool = append(v.pool, ws)
			v.mu.Unlock()
			return
		}
		v.mu.Unlock()
	}
	_ = os.RemoveAll(ws.dir)
}

// Close removes the copies kept for reuse. A Verifier must not be used afterwards.
// It is a no-op without Options.ReuseCopies.
func (v *Verifier) Close() {
	v.mu.Lock()
	pool := v.pool
	v.pool, v.closed = nil, true
	v.mu.Unlock()
	for _, ws := range pool {
		_ = os.RemoveAll(ws.dir)
	}
}
