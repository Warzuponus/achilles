package exec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	osexec "os/exec"
	"path"
	"time"
)

// DockerRunner runs the tool inside a pinned container image. Each mount is
// bind-mounted under /mnt/<name>; placeholders resolve to those container
// paths. This is the production execution model (reproducible, isolated).
type DockerRunner struct {
	// Image is the container reference. Pin to a digest in production.
	Image string
	// Network sets --network (e.g. "none" to deny egress during a scan).
	// Empty leaves Docker's default.
	Network string
}

func (r DockerRunner) Run(ctx context.Context, c Command) (Result, error) {
	containerPath := func(name string) string { return path.Join("/mnt", name) }

	image := c.Image
	if image == "" {
		image = r.Image
	}

	// Per-command network overrides the runner default. "default" means Docker's
	// normal bridge (no flag); "none"/named are passed through as --network.
	network := c.Network
	if network == "" {
		network = r.Network
	}

	// The container is named so it can be killed. Killing the `docker run` client
	// does not stop the container: it would keep scanning (and keep its mounts
	// busy) after a timeout or Ctrl-C, with nothing left to collect the result.
	name := containerName()
	args := []string{"run", "--rm", "--name", name}
	if network != "" && network != "default" {
		args = append(args, "--network", network)
	}
	for _, m := range c.Mounts {
		spec := m.HostPath + ":" + containerPath(m.Name)
		if m.ReadOnly {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
	}
	args = append(args, image)
	// Note: c.Bin is deliberately NOT passed in docker mode — scanner images set
	// the tool as their ENTRYPOINT, so passing the binary again would double it
	// (e.g. `gosec gosec ...`). c.Bin is used only by the local runner.
	args = append(args, resolveArgs(c.Args, containerPath, mountNames(c.Mounts))...)

	return runCmd(ctx, "docker", args, runOpts{onCancel: func() { killContainer(name) }})
}

// containerName returns a unique name for one tool container.
func containerName() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("achilles-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return "achilles-" + hex.EncodeToString(b[:])
}

// killContainer stops a tool container by name. It runs on its own short clock:
// the context that would normally bound it is the one that just ended. Errors are
// ignored: the container may already be gone, which is the outcome we want.
func killContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = osexec.CommandContext(ctx, "docker", "kill", name).Run()
}
