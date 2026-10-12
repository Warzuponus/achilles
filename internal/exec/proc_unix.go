//go:build unix

package exec

import (
	"os/exec"
	"syscall"
)

// isolate starts the command in its own process group, so killTree can end the
// tool together with everything it spawned.
//
// A side effect is that the tool no longer receives the terminal's Ctrl-C itself
// (that goes to the foreground group, which is now only Achilles). Achilles
// handles the interrupt, cancels the context, and killTree does the rest.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree kills the command's whole process group. Several scanners are thin
// launchers around a worker process (Opengrep runs a core binary); killing only
// the launcher leaves the worker running and holding the output pipes open.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
