package exec

import (
	"context"
	osexec "os/exec"
)

// LocalRunner runs the tool binary directly on the host. Placeholders resolve
// to host paths. Useful for development and for environments where the tool is
// already installed.
type LocalRunner struct{}

// Has reports whether an executable is on PATH (used for tool prerequisites).
func (LocalRunner) Has(bin string) bool {
	_, err := osexec.LookPath(bin)
	return err == nil
}

func (LocalRunner) Run(ctx context.Context, c Command) (Result, error) {
	hostPath := map[string]string{}
	for _, m := range c.Mounts {
		hostPath[m.Name] = m.HostPath
	}
	args := resolveArgs(c.Args, func(n string) string { return hostPath[n] }, mountNames(c.Mounts))
	return runOS(ctx, c.Bin, args)
}
