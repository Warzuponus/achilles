package verifyfix

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// neverCopied directories are left out of every verification copy, whatever is
// inside them: version control state and Achilles' own. A patch must never be able
// to reach .git, and a finding there is not source code.
var neverCopied = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".achilles": true,
}

// bulkyDirs are left out because they are usually large and are not what a patch
// edits: dependency trees, caches and build output. Usually, not always: `build`,
// `dist`, `target` and `out` are also ordinary names for directories of source
// (src/build/, a Maven module called target). So when the finding being verified
// is inside one, that directory is copied after all (see copyTree's keep).
var bulkyDirs = map[string]bool{
	"node_modules": true, "vendor": true,
	"dist": true, "build": true, "target": true, "out": true,
	".next": true, ".nuxt": true, ".gradle": true, ".terraform": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
}

// errTooLarge marks a target over the copy caps; it is a "skipped" result, not a
// failure.
var errTooLarge = errors.New("target too large")

// copyTree copies the regular files under src into dst, skipping neverCopied and
// bulkyDirs, symlinks and special files. keep is the slash-separated relative path
// of a file that must be in the copy: a bulky directory on the way to it is copied.
// It stops with errTooLarge once the byte or file cap is exceeded. Permission bits
// are preserved.
func copyTree(src, dst string, maxBytes int64, maxFiles int, keep string) error {
	var bytes int64
	var files int
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if neverCopied[d.Name()] {
				return filepath.SkipDir
			}
			if bulkyDirs[d.Name()] && !strings.HasPrefix(keep, filepath.ToSlash(rel)+"/") {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		if !d.Type().IsRegular() {
			return nil // symlink, socket, device: never followed or recreated
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		bytes += info.Size()
		if bytes > maxBytes || files > maxFiles {
			return fmt.Errorf("%w: over %d MiB or %d files", errTooLarge, maxBytes>>20, maxFiles)
		}
		return copyFile(p, filepath.Join(dst, rel), info.Mode().Perm())
	})
}

// inDir reports whether rel (slash-separated) has a directory from set on its path.
func inDir(rel string, set map[string]bool) bool {
	segs := strings.Split(rel, "/")
	for _, s := range segs[:len(segs)-1] {
		if set[s] {
			return true
		}
	}
	return false
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- walking the operator's own scan target
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm|0o600) // #nosec G304 -- dst is inside our own temp copy; the relative path comes from a walk of regular files only
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
