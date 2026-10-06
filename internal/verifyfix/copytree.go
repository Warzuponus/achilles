package verifyfix

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// skipDirs are never copied: version control, dependency trees, tool state and
// build output. They are large, are not what a patch edits, and (for .git) must
// never be reachable from a patch.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, ".achilles": true,
	"dist": true, "build": true, "target": true, "out": true,
	".next": true, ".nuxt": true, ".gradle": true, ".terraform": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
}

// errTooLarge marks a target over the copy caps; it is a "skipped" result, not a
// failure.
var errTooLarge = errors.New("target too large")

// copyTree copies the regular files under src into dst, skipping skipDirs and
// symlinks and special files. It stops with errTooLarge once the byte or file cap
// is exceeded. Permission bits are preserved.
func copyTree(src, dst string, maxBytes int64, maxFiles int) error {
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
			if skipDirs[d.Name()] {
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
