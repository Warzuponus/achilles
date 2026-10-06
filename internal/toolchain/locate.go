package toolchain

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Source says where a binary was found.
type Source string

const (
	SourceManaged Source = "managed" // $ACHILLES_HOME/bin (installed by `achilles tools install`)
	SourcePATH    Source = "PATH"
)

// LookBin resolves an executable name. Precedence (documented in
// docs/getting-started.md): the managed bin directory FIRST, then PATH. The
// managed copy is the pinned, checksum-verified one the user explicitly asked
// for; PATH is the fallback. Returns exec.ErrNotFound-wrapping errors like
// exec.LookPath.
func LookBin(name string) (path string, src Source, err error) {
	if dir, derr := BinDir(); derr == nil && filepath.Base(name) == name {
		cand := filepath.Join(dir, exeName(runtime.GOOS, name))
		if isExecutableFile(cand) {
			return cand, SourceManaged, nil
		}
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", "", err
	}
	return p, SourcePATH, nil
}

func isExecutableFile(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return st.Mode().Perm()&0o111 != 0
}
