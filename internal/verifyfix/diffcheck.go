package verifyfix

import (
	"fmt"
	"path"
	"strings"
)

// checkDiff rejects a diff that is unsafe to hand to `git apply`, or too large. It
// is a gate in front of git's own path checks, not a replacement for them: the diff
// comes from an LLM that read untrusted code, so it is treated as hostile.
//
// Rejected: absolute paths, any ".." segment, any ".git" segment, quoted/escaped
// paths, backslashes, binary patches, symlink modes, and diffs over the size or
// file-count caps.
func checkDiff(diff string, maxBytes, maxFiles int) error {
	if strings.TrimSpace(diff) == "" {
		return fmt.Errorf("empty diff")
	}
	if len(diff) > maxBytes {
		return fmt.Errorf("diff is %d bytes, over the %d byte cap", len(diff), maxBytes)
	}
	if strings.ContainsRune(diff, 0) {
		return fmt.Errorf("diff contains a NUL byte")
	}

	files := map[string]bool{}
	for _, line := range strings.Split(diff, "\n") {
		line = strings.TrimRight(line, "\r")
		var paths []string
		switch {
		case strings.HasPrefix(line, "GIT binary patch"), strings.HasPrefix(line, "Binary files "):
			return fmt.Errorf("binary patches are not accepted")
		case strings.HasPrefix(line, "new file mode 120000"), strings.HasPrefix(line, "old mode 120000"),
			strings.HasPrefix(line, "new mode 120000"), strings.HasPrefix(line, "deleted file mode 120000"):
			return fmt.Errorf("symlink changes are not accepted")
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			p := line[4:]
			if i := strings.IndexByte(p, '\t'); i >= 0 {
				p = p[:i] // a timestamp may follow the path after a tab
			}
			paths = []string{p}
		case strings.HasPrefix(line, "diff --git "):
			paths = strings.Fields(line[len("diff --git "):])
		case strings.HasPrefix(line, "rename from "):
			paths = []string{line[len("rename from "):]}
		case strings.HasPrefix(line, "rename to "):
			paths = []string{line[len("rename to "):]}
		case strings.HasPrefix(line, "copy from "):
			paths = []string{line[len("copy from "):]}
		case strings.HasPrefix(line, "copy to "):
			paths = []string{line[len("copy to "):]}
		}
		for _, p := range paths {
			if p == "/dev/null" {
				continue
			}
			if err := checkPath(p); err != nil {
				return err
			}
			files[stripPrefix(p)] = true
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("diff names no files")
	}
	if len(files) > maxFiles {
		return fmt.Errorf("diff touches %d files, over the %d file cap", len(files), maxFiles)
	}
	return nil
}

// stripPrefix drops the leading a/ or b/ git adds to a path.
func stripPrefix(p string) string {
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

// checkPath validates one path as written in a diff header, both as written and
// after the one-component strip `git apply` performs, so neither reading escapes.
func checkPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty path in diff header")
	}
	if strings.HasPrefix(p, `"`) || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("unsupported or escaped path %q in diff header", p)
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || (len(p) > 1 && p[1] == ':') {
		return fmt.Errorf("absolute path %q in diff header", p)
	}
	for _, cand := range []string{p, stripPrefix(p)} {
		if cand == "" || path.IsAbs(cand) {
			return fmt.Errorf("absolute or empty path %q in diff header", p)
		}
		for _, seg := range strings.Split(cand, "/") {
			switch strings.ToLower(seg) {
			case "..":
				return fmt.Errorf("path %q in diff header escapes the repository", p)
			case ".git":
				return fmt.Errorf("path %q in diff header touches .git", p)
			}
		}
	}
	return nil
}
