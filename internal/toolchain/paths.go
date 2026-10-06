// Package toolchain installs and locates the third-party scanners Achilles
// orchestrates (Opengrep, gosec, osv-scanner, Trivy, Gitleaks).
//
// It has three parts: a pinned manifest of upstream release assets with sha256
// digests (manifest.go), an installer that downloads, verifies (fail closed) and
// extracts exactly one binary into the managed bin directory (install.go), and a
// locator/doctor that finds installed tools (locate.go, doctor.go).
package toolchain

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// EnvHome overrides the Achilles home directory (default ~/.achilles).
const EnvHome = "ACHILLES_HOME"

// Home returns the Achilles home directory: $ACHILLES_HOME, else ~/.achilles.
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return filepath.Abs(h)
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot determine home directory; set " + EnvHome)
	}
	return filepath.Join(u, ".achilles"), nil
}

// BinDir is where `achilles tools install` puts scanner binaries.
func BinDir() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "bin"), nil
}

// RulesDir is an optional directory of extra Opengrep rule YAML that is merged
// with the embedded baseline rules (see internal/config).
func RulesDir() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "rules"), nil
}

// exeName appends ".exe" on Windows.
func exeName(goos, name string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

// platformKey is the manifest key for a platform.
func platformKey(goos, goarch string) string { return goos + "/" + goarch }

// CurrentPlatform is the manifest key for the running platform.
func CurrentPlatform() string { return platformKey(runtime.GOOS, runtime.GOARCH) }
