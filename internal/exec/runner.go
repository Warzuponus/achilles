// Package exec runs external scanner tools, either directly (local binary) or
// inside a pinned container. Callers describe a Command with logical mounts and
// path placeholders; each Runner resolves those placeholders for its execution
// model. This keeps scanner adapters agnostic to how the tool is launched.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Mount is a host path exposed to the command under a logical name. Adapters
// reference it in Args as "{name}".
type Mount struct {
	Name     string
	HostPath string
	ReadOnly bool
}

// Command is a tool invocation. Args may contain "{name}" placeholders that
// resolve to each Mount's path (host path for local, container path for docker).
type Command struct {
	// Bin is the executable to run. For container images whose entrypoint is
	// already the tool, leave Bin empty.
	Bin string
	// Image is the container image for this command (docker runner). Empty
	// falls back to the runner's default. Ignored by the local runner.
	Image string
	// Network is the per-command docker network policy ("none" | "default" |
	// a named network). Empty falls back to the runner's default. Tools that need
	// egress (SCA advisory DBs, .NET NuGet restore) set "default"; everything else
	// stays "none" for containment. Ignored by the local runner.
	Network string
	Args    []string
	Mounts  []Mount
}

// Result captures a finished command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes a Command.
type Runner interface {
	Run(ctx context.Context, c Command) (Result, error)
}

func resolveArgs(args []string, replace func(name string) string, names []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		for _, n := range names {
			a = strings.ReplaceAll(a, "{"+n+"}", replace(n))
		}
		out[i] = a
	}
	return out
}

func mountNames(mounts []Mount) []string {
	names := make([]string, len(mounts))
	for i, m := range mounts {
		names[i] = m.Name
	}
	return names
}

// killGrace is how long a cancelled command gets, after it has been killed, to let
// go of its output pipes before we stop waiting for it. A variable so tests can
// shorten it.
var killGrace = 5 * time.Second

// runOpts are the optional parts of running a command.
type runOpts struct {
	extraEnv []string // extra KEY=VALUE environment entries
	onCancel func()   // extra cleanup when the context ends (docker: kill the container)
}

// runOSEnv runs a command with extra KEY=VALUE environment entries (nil = inherit as is).
func runOSEnv(ctx context.Context, name string, args []string, extraEnv []string) (Result, error) {
	return runCmd(ctx, name, args, runOpts{extraEnv: extraEnv})
}

// runCmd runs a command to completion, or until ctx ends.
//
// When ctx ends (--timeout, or Ctrl-C) the command really has to stop, and so does
// our wait for it. The default CommandContext behaviour gives neither: it kills
// only the one process, and Wait then blocks until every process that inherited
// the output pipes has exited. A scanner that is a launcher around a worker
// (Opengrep) or a client for something running elsewhere (docker) therefore kept
// running, and the scan hung past its own timeout. So the command gets its own
// process group, cancellation kills the whole group (plus onCancel), and WaitDelay
// bounds the wait for the pipes.
func runCmd(ctx context.Context, name string, args []string, o runOpts) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(o.extraEnv) > 0 {
		cmd.Env = append(os.Environ(), o.extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	isolate(cmd)
	cmd.Cancel = func() error {
		if o.onCancel != nil {
			o.onCancel()
		}
		return killTree(cmd)
	}
	cmd.WaitDelay = killGrace
	err := cmd.Run()

	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil && ctx.Err() != nil {
		// Killed because the context ended. That is a failed run, never an exit
		// code for the adapter to interpret: a tool cut off mid-scan may have
		// written half a report, and half a report must not read as a clean one.
		why := "interrupted"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			why = "timed out"
		}
		return res, fmt.Errorf("run %s: %s: %w", name, why, ctx.Err())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // non-zero exit is not a Runner error; the adapter judges it
		}
		return res, fmt.Errorf("run %s: %w", name, err)
	}
	return res, nil
}
