package main

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// Injected at link time by release builds (see .goreleaser.yaml and `make release`):
//
//	-ldflags "-X main.version=v0.1.0 -X main.commit=<sha> -X main.date=<RFC3339>"
//
// All three are empty in a plain `go build`; then buildInfo falls back to what the
// Go toolchain embedded (so `go install ...@v0.1.0` still reports v0.1.0).
var (
	version string
	commit  string
	date    string
)

var semverStart = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// versionInfo is what `achilles --version` prints.
type versionInfo struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	OS, Arch  string
}

// resolveVersion merges link-time values with runtime/debug build info. Link-time
// values win; the module version is used for `go install pkg@vX.Y.Z`; the VCS
// stamp fills commit/date for `go build` inside a checkout.
func resolveVersion(ldVersion, ldCommit, ldDate string, bi *debug.BuildInfo) versionInfo {
	v := versionInfo{
		Version: ldVersion, Commit: ldCommit, Date: ldDate,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	var dirty bool
	if bi != nil {
		if v.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if v.Commit == "" {
					v.Commit = s.Value
				}
			case "vcs.time":
				if v.Date == "" {
					v.Date = s.Value
				}
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	if v.Version == "" {
		v.Version = "dev"
	} else if semverStart.MatchString(v.Version) {
		v.Version = "v" + v.Version // goreleaser's {{.Version}} has no leading v
	}
	if v.Commit == "" {
		v.Commit = "unknown"
	} else if dirty && !strings.HasSuffix(v.Commit, "-dirty") {
		v.Commit += "-dirty"
	}
	if v.Date == "" {
		v.Date = "unknown"
	}
	return v
}

func currentVersion() versionInfo {
	bi, _ := debug.ReadBuildInfo()
	return resolveVersion(version, commit, date, bi)
}

func printVersion(w io.Writer) {
	v := currentVersion()
	fmt.Fprintf(w, "achilles %s\n", v.Version)
	fmt.Fprintf(w, "  commit:   %s\n", v.Commit)
	fmt.Fprintf(w, "  built:    %s\n", v.Date)
	fmt.Fprintf(w, "  go:       %s\n", v.GoVersion)
	fmt.Fprintf(w, "  platform: %s/%s\n", v.OS, v.Arch)
}
