//go:build !unix && !windows

package exec

import "os/exec"

// isolate is a no-op where process groups are not available.
func isolate(*exec.Cmd) {}

// killTree kills the command itself; its children cannot be reached here.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
