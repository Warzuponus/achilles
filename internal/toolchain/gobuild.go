package toolchain

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// goEnvControlled are the Go settings a source build sets itself. Anything the
// user's environment says about them is dropped: a GOFLAGS of -mod=vendor, a
// GONOSUMDB or GOPRIVATE pattern, or GOINSECURE would each change what is built
// or skip the checksum database for some of the modules that go into it.
var goEnvControlled = map[string]bool{
	"GOENV": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "GOBIN": true, "GOWORK": true,
	"GO111MODULE": true, "CGO_ENABLED": true, "GOOS": true, "GOARCH": true,
	"GOPROXY": true, "GOSUMDB": true, "GONOSUMDB": true, "GONOSUMCHECK": true,
	"GOPRIVATE": true, "GONOPROXY": true, "GOINSECURE": true,
}

// goSettings is what a source build keeps from the user's Go configuration.
type goSettings struct {
	GOPROXY   string
	GOSUMDB   string
	GOVERSION string
}

// buildFromSource builds the pinned version of t with the Go at in.Go and
// installs it into BinDir.
//
// Integrity: `go install pkg@version` checks every module it downloads, the
// tool's and each dependency's, against the Go checksum database, so a module
// that is not byte-for-byte what was first published under that version fails
// the build. The user's GOPROXY and GOSUMDB are kept (a company mirror is
// common), but GOSUMDB=off is refused, and the settings that would exempt
// modules from the check are dropped. GOTOOLCHAIN=local makes it build with the
// very Go that is on PATH: the point is a tool built with the Go it scans with.
func (in *Installer) buildFromSource(ctx context.Context, t Tool, goos string) (string, error) {
	if in.BinDir == "" {
		return "", errors.New("no install directory")
	}
	if !versionRe.MatchString(t.Version) {
		return "", fmt.Errorf("pinned version %q is not a plain release version", t.Version)
	}
	s, err := in.goSettings(ctx)
	if err != nil {
		return "", err
	}
	if s.GOSUMDB == "off" {
		return "", errors.New("GOSUMDB=off: the source could not be checked against the Go checksum database")
	}
	if err := ensureDir(in.BinDir); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(in.BinDir, ".gobuild-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	env := append(goEnvWithout(os.Environ()),
		"GOENV=off", // the go env file can set any of the above; ignore it
		"GOTOOLCHAIN=local",
		"GOFLAGS=-trimpath",
		"GOWORK=off",
		"GO111MODULE=on",
		"CGO_ENABLED=0",
		"GOBIN="+tmp,
		"GOPROXY="+s.GOPROXY,
		"GOSUMDB="+s.GOSUMDB,
	)
	args := []string{"install"}
	if ld := t.goLDFlags(); ld != "" {
		args = append(args, "-ldflags="+ld)
	}
	args = append(args, t.GoPackage+"@v"+t.Version)
	in.logf("%s %s: building it with %s (%s)", t.Name, t.Version, s.GOVERSION, in.Go)
	if out, err := in.runGo(ctx, tmp, env, args...); err != nil {
		return "", fmt.Errorf("go install: %v: %s", err, lastLines(out, 6))
	}

	built := filepath.Join(tmp, exeName(goos, t.Bin))
	st, err := os.Stat(built)
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("go install produced no %s", filepath.Base(built))
	}
	final := filepath.Join(in.BinDir, exeName(goos, t.Bin))
	if err := os.Rename(built, final); err != nil {
		return "", fmt.Errorf("install %s: %w", final, err)
	}
	return final, nil
}

// versionRe is a release version as the manifest pins it (no leading "v").
var versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// goLDFlags stamps the pinned version into the tool's version variables.
func (t Tool) goLDFlags() string {
	if len(t.GoVersionVars) == 0 {
		return ""
	}
	names := make([]string, 0, len(t.GoVersionVars))
	for n := range t.GoVersionVars {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := []string{"-s", "-w"}
	for _, n := range names {
		v := strings.NewReplacer("{v}", t.Version, "{tag}", "v"+t.Version).Replace(t.GoVersionVars[n])
		parts = append(parts, "-X", n+"="+v)
	}
	return strings.Join(parts, " ")
}

// goSettings reads the user's GOPROXY and GOSUMDB (from the environment or the
// go env file) and the Go version, with the toolchain pinned to the one on PATH.
func (in *Installer) goSettings(ctx context.Context) (goSettings, error) {
	env := append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := in.runGo(ctx, "", env, "env", "-json", "GOPROXY", "GOSUMDB", "GOVERSION")
	if err != nil {
		return goSettings{}, fmt.Errorf("go env: %v: %s", err, lastLines(out, 3))
	}
	var s goSettings
	if err := json.Unmarshal(out, &s); err != nil {
		return goSettings{}, fmt.Errorf("go env: %w", err)
	}
	if s.GOVERSION == "" {
		return goSettings{}, errors.New("go env reported no GOVERSION")
	}
	return s, nil
}

// runGo runs the Go at in.Go. Tests replace it with in.goRunner.
func (in *Installer) runGo(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	if in.goRunner != nil {
		return in.goRunner(ctx, dir, env, args...)
	}
	cmd := exec.CommandContext(ctx, in.Go, args...) // #nosec G204 -- in.Go is the go executable found on PATH; args are fixed or from the manifest
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return append(stdout.Bytes(), stderr.Bytes()...), err
	}
	return stdout.Bytes(), nil // stderr carries download progress, not the answer
}

// goEnvWithout drops the Go settings a source build controls.
func goEnvWithout(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if goEnvControlled[strings.ToUpper(k)] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// BuiltWithGo returns the Go version a Go binary was built with ("go1.26.2"),
// or "" when the file is not a Go binary or carries no build information.
func BuiltWithGo(path string) string {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	return bi.GoVersion
}

// olderGo reports whether Go version a ("go1.26.2") is an older release line
// (major.minor) than b. Unparsable versions are never older.
func olderGo(a, b string) bool {
	am, an, ok1 := goMinor(a)
	bm, bn, ok2 := goMinor(b)
	if !ok1 || !ok2 {
		return false
	}
	return am < bm || (am == bm && an < bn)
}

// goMinorString is a version's release line: "go1.27.1" -> "Go 1.27".
func goMinorString(v string) string {
	if major, minor, ok := goMinor(v); ok {
		return fmt.Sprintf("Go %d.%d", major, minor)
	}
	return v
}

func goMinor(v string) (major, minor int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "go")
	v, _, _ = strings.Cut(v, " ") // "go1.27.1 X:fieldtrack"
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	// "1.27rc1" -> 27: the leading digits
	minorDigits := parts[1]
	if i := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorDigits = minorDigits[:i]
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(minorDigits)
	return major, minor, err1 == nil && err2 == nil
}

// LocalGoVersion is the version of the Go at goPath ("go1.27.1"), with the
// toolchain pinned to that Go, or "" when it cannot be run.
func LocalGoVersion(ctx context.Context, goPath string) string {
	if goPath == "" {
		return ""
	}
	in := &Installer{Go: goPath}
	s, err := in.goSettings(ctx)
	if err != nil {
		return ""
	}
	return s.GOVERSION
}

// StaleGoBuild reports whether the Go binary at path was built with an older
// Go release line than goVersion, and with which: such a gosec cannot read code
// that uses what the newer standard library added.
func StaleGoBuild(path, goVersion string) (builtWith string, stale bool) {
	builtWith = BuiltWithGo(path)
	return builtWith, builtWith != "" && goVersion != "" && olderGo(builtWith, goVersion)
}
