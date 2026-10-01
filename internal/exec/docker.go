package exec

import (
	"context"
	"path"
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

	args := []string{"run", "--rm"}
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

	return runOS(ctx, "docker", args)
}
