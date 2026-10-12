package exec

import (
	"slices"
	"strings"
	"testing"
)

func flagValue(args []string, flag string) (values []string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			values = append(values, args[i+1])
		}
	}
	return values
}

// A tool container processes a repository that may be hostile, and some tools run
// code from it. It gets no more privilege than a scanner needs.
func TestDockerRunner_ContainersAreConfined(t *testing.T) {
	cmd := Command{
		Image: "example/tool:1", Bin: "tool", Args: []string{"scan", "--out={out}/r.sarif", "{src}"},
		Mounts: []Mount{{Name: "src", HostPath: "/repo", ReadOnly: true}, {Name: "out", HostPath: "/tmp/out"}},
	}
	args, err := DockerRunner{Network: "none"}.runArgs(cmd, "achilles-test")
	if err != nil {
		t.Fatal(err)
	}

	if got := flagValue(args, "--security-opt"); !slices.Contains(got, "no-new-privileges") {
		t.Errorf("--security-opt = %v, want no-new-privileges", got)
	}
	if got := flagValue(args, "--cap-drop"); !slices.Equal(got, []string{"ALL"}) {
		t.Errorf("--cap-drop = %v, want ALL", got)
	}
	// Exactly one capability comes back, the one needed to read the source and
	// write the report across the bind mounts. Adding another is a decision.
	if got := flagValue(args, "--cap-add"); !slices.Equal(got, []string{"DAC_OVERRIDE"}) {
		t.Errorf("--cap-add = %v, want only DAC_OVERRIDE", got)
	}
	if got := flagValue(args, "--pids-limit"); len(got) != 1 {
		t.Errorf("--pids-limit = %v, want a limit", got)
	}
	if slices.Contains(args, "--privileged") {
		t.Error("a tool container must never be privileged")
	}
	if got := flagValue(args, "--network"); !slices.Equal(got, []string{"none"}) {
		t.Errorf("--network = %v, want none", got)
	}
	if got := flagValue(args, "-v"); !slices.Equal(got, []string{"/repo:/mnt/src:ro", "/tmp/out:/mnt/out"}) {
		t.Errorf("mounts = %v: the source must be read-only", got)
	}

	// Every option comes before the image; the tool's own arguments after it, with
	// the placeholders resolved to container paths and the binary name not repeated.
	i := slices.Index(args, "example/tool:1")
	if i < 0 {
		t.Fatalf("image missing from %v", args)
	}
	if tail := args[i+1:]; !slices.Equal(tail, []string{"scan", "--out=/mnt/out/r.sarif", "/mnt/src"}) {
		t.Errorf("tool arguments = %v", tail)
	}
	for _, a := range args[:i] {
		if a == "scan" || strings.Contains(a, "r.sarif") {
			t.Errorf("a tool argument appears before the image: %v", args)
		}
	}

	// The escape hatch turns the confinement flags off and nothing else.
	loose, err := DockerRunner{Network: "none", Unconfined: true}.runArgs(cmd, "achilles-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"--cap-drop", "--cap-add", "--security-opt", "--pids-limit"} {
		if slices.Contains(loose, f) {
			t.Errorf("Unconfined still passes %s", f)
		}
	}
	if got := flagValue(loose, "--network"); !slices.Equal(got, []string{"none"}) {
		t.Errorf("Unconfined must not change the network policy: %v", got)
	}
}
