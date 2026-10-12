//go:build windows

package exec

import (
	"os/exec"
	"strconv"
	"syscall"
)

// isolate starts the command in its own process group. As on unix, the tool then
// no longer sees the console's Ctrl-C directly; Achilles handles the interrupt,
// cancels the context, and killTree ends the tool.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// killTree ends the command and every process it started. Process.Kill ends only
// the one process, which leaves a launcher's worker running and holding the output
// pipes open; `taskkill /T` walks the tree.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if err := exec.Command("taskkill", "/T", "/F", "/PID", pid).Run(); err != nil { // #nosec G204 -- fixed binary; the argument is an integer pid
		return cmd.Process.Kill()
	}
	return nil
}
