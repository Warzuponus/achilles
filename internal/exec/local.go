package exec

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/toolchain"
)

// LocalRunner runs the tool binary directly on the host. Placeholders resolve
// to host paths. Useful for development and for environments where the tool is
// already installed.
type LocalRunner struct{}

// Has reports whether an executable can be found (used for tool prerequisites):
// in the managed tool directory ($ACHILLES_HOME/bin, populated by
// `achilles tools install`) or on PATH — see toolchain.LookBin.
func (LocalRunner) Has(bin string) bool {
	_, _, err := toolchain.LookBin(bin)
	return err == nil
}

func (LocalRunner) Run(ctx context.Context, c Command) (Result, error) {
	hostPath := map[string]string{}
	for _, m := range c.Mounts {
		hostPath[m.Name] = m.HostPath
	}
	args := resolveArgs(c.Args, func(n string) string { return hostPath[n] }, mountNames(c.Mounts))
	// Managed tools win over PATH (toolchain.LookBin). When nothing resolves, keep
	// the bare name so the error is the usual "executable file not found".
	bin := c.Bin
	if p, _, err := toolchain.LookBin(bin); err == nil {
		bin = p
	}
	return runOSEnv(ctx, bin, args, localEnv(c.Bin))
}

// localEnv returns extra environment for a local tool run. Opengrep is a Python
// program that decodes rule files with the process locale: under a non-UTF-8 locale
// (LANG unset, as in many containers and CI jobs) it crashes with a
// UnicodeDecodeError on any rule file containing a non-ASCII character, which the
// community rule pack has. Force a UTF-8 locale for it only when none is set.
func localEnv(bin string) []string {
	if strings.TrimSuffix(filepath.Base(bin), ".exe") != "opengrep" {
		return nil
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); strings.Contains(v, "utf-8") || strings.Contains(v, "utf8") {
			return nil
		}
	}
	return []string{"LC_ALL=C.UTF-8"}
}
