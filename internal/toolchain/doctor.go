package toolchain

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Tool states reported by Diagnose.
const (
	StateOK          = "ok"
	StateMissing     = "missing"
	StateOutdated    = "outdated" // older than the pinned version
	StateNewer       = "newer"    // newer than the pinned version (accepted)
	StateUnknownVer  = "unknown-version"
	StateUnsupported = "no-asset" // not installed and upstream publishes no pinned asset for this platform
)

// ToolStatus is the doctor's verdict on one scanner.
type ToolStatus struct {
	Name     string
	Required bool   // needed by the default profile
	State    string // one of the State* constants
	Path     string
	Source   Source
	Version  string // as reported by the binary ("" if not probed or unparsable)
	Pinned   string
	Fix      string   // exact command or instruction; empty when OK
	Notes    []string // extra warnings (e.g. missing prerequisite)
}

// Report is the full doctor output.
type Report struct {
	Platform  string
	BinDir    string
	Tools     []ToolStatus
	Go        Prereq
	Docker    Prereq
	LLMKeyVar string // env var that holds a key ("" = none set); the key itself is never read into the report
	LLMBase   string // resolved base URL, credentials stripped
	Rules     InstalledRules
	RulesPack RuleSet
}

// Prereq is a looked-up helper executable.
type Prereq struct {
	Found  bool
	Path   string
	Detail string
}

// Failed reports whether a default-profile tool is missing (the doctor's exit
// status). Outdated tools warn but do not fail: they still scan.
func (r Report) Failed() bool {
	for _, t := range r.Tools {
		if t.Required && (t.State == StateMissing || t.State == StateUnsupported) {
			return true
		}
	}
	return false
}

// Doctor gathers a Report. The function fields exist so tests can run it
// hermetically; NewDoctor wires the real ones.
type Doctor struct {
	GOOS, GOARCH string
	Look         func(bin string) (path string, src Source, err error)
	Version      func(ctx context.Context, path string, args []string) (string, error)
	Getenv       func(string) string
	DockerInfo   func(ctx context.Context) string // "" = daemon not reachable
	Rules        func() InstalledRules            // nil = not checked
	BinDir       string
	// GoVersion reports the version of the go at a path ("go1.27.1"; "" =
	// unknown), and BuiltWith the Go a binary was built with. nil = not checked.
	GoVersion func(ctx context.Context, goPath string) string
	BuiltWith func(path string) string
}

// NewDoctor returns a Doctor for the running machine.
func NewDoctor() Doctor {
	bd, _ := BinDir()
	return Doctor{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Look:       LookBin,
		Version:    ProbeVersion,
		Getenv:     os.Getenv,
		DockerInfo: dockerInfo,
		Rules:      InstalledCommunityRules,
		BinDir:     bd,
		GoVersion:  LocalGoVersion,
		BuiltWith:  BuiltWithGo,
	}
}

// DefaultLLMBaseURL mirrors the --llm-base-url default in cmd/achilles/flags.go.
const DefaultLLMBaseURL = "https://api.openai.com/v1"

// Diagnose inspects every pinned tool and the surrounding environment.
func (d Doctor) Diagnose(ctx context.Context) Report {
	r := Report{Platform: platformKey(d.GOOS, d.GOARCH), BinDir: d.BinDir, RulesPack: communityRules}
	if d.Rules != nil {
		r.Rules = d.Rules()
	}

	goPath, _, goErr := d.Look("go")
	r.Go = Prereq{Found: goErr == nil, Path: goPath}
	if r.Go.Found && d.GoVersion != nil {
		r.Go.Detail = d.GoVersion(ctx, goPath)
	}
	if dp, _, err := d.Look("docker"); err == nil {
		detail := "CLI found, daemon not reachable"
		if v := d.DockerInfo(ctx); v != "" {
			detail = "daemon " + v
		}
		r.Docker = Prereq{Found: true, Path: dp, Detail: detail}
	}

	for _, t := range Tools() {
		r.Tools = append(r.Tools, d.diagnoseTool(ctx, t, r.Go))
	}

	for _, k := range []string{"ACHILLES_LLM_API_KEY", "OPENAI_API_KEY"} {
		if d.Getenv(k) != "" {
			r.LLMKeyVar = k
			break
		}
	}
	base := d.Getenv("ACHILLES_LLM_BASE_URL")
	if base == "" {
		base = DefaultLLMBaseURL
	}
	r.LLMBase = stripURLCredentials(base)
	return r
}

func (d Doctor) diagnoseTool(ctx context.Context, t Tool, goTool Prereq) ToolStatus {
	haveGo := goTool.Found
	st := ToolStatus{Name: t.Name, Required: t.Default, Pinned: t.Version}
	path, src, err := d.Look(t.Bin)
	if err != nil {
		if _, ok := t.Asset(d.GOOS, d.GOARCH); ok {
			st.State = StateMissing
			st.Fix = "achilles tools install " + t.Name
		} else {
			st.State = StateUnsupported
			st.Fix = fmt.Sprintf("no pinned %s download for %s/%s; install manually (%s)", t.Name, d.GOOS, d.GOARCH, t.Manual)
		}
		return st
	}
	st.Path, st.Source = path, src

	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, verr := d.Version(vctx, path, t.VersionArgs)
	st.Version = ParseVersion(out)
	switch {
	case verr != nil && st.Version == "":
		st.State = StateUnknownVer
		st.Notes = append(st.Notes, "could not run it to read its version: "+verr.Error())
	case st.Version == "":
		st.State = StateUnknownVer
		first, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
		if len(first) > 60 {
			first = first[:60]
		}
		st.Notes = append(st.Notes, fmt.Sprintf("no version number in its output (%q); likely a dev build", first))
		if _, ok := t.Asset(d.GOOS, d.GOARCH); ok {
			st.Fix = "achilles tools install " + t.Name + "   (installs the pinned build; it then takes precedence over this one)"
		}
	default:
		switch c := compareVersions(st.Version, t.Version); {
		case c == 0:
			st.State = StateOK
		case c < 0:
			st.State = StateOutdated
		default:
			st.State = StateNewer
		}
	}
	if st.State == StateOutdated {
		if _, ok := t.Asset(d.GOOS, d.GOARCH); ok {
			st.Fix = "achilles tools install " + t.Name
		}
	}

	// A Go tool built with an older Go than the one it type-checks with cannot
	// read what the newer standard library uses (gosec 2.27.1's release binary,
	// built with Go 1.26, fails on any Go 1.27 package importing math/rand/v2).
	if t.GoPackage != "" && d.BuiltWith != nil && goTool.Detail != "" {
		if built := d.BuiltWith(path); built != "" && olderGo(built, goTool.Detail) {
			st.Notes = append(st.Notes, fmt.Sprintf(
				"built with %s but type-checks with %s: it cannot read Go code that uses what %s added, and reports such packages as incomplete",
				built, goTool.Detail, goMinorString(goTool.Detail)))
			if st.Fix == "" {
				st.Fix = "achilles tools install --force " + t.Name + "   (builds it with your Go)"
			}
		}
	}

	for _, req := range t.Requires {
		if req == "go" && !haveGo {
			st.Notes = append(st.Notes, "needs `go` on PATH (it type-checks through the Go toolchain); without it gosec fails on Go targets")
		}
	}
	return st
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// ParseVersion extracts the first X.Y.Z from a tool's version output.
func ParseVersion(s string) string { return semverRe.FindString(s) }

// compareVersions compares dotted numeric versions: -1, 0, +1.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ProbeVersion runs `path args...` and returns its combined output.
func ProbeVersion(ctx context.Context, path string, args []string) (string, error) {
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	return string(out), err
}

func dockerInfo(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// stripURLCredentials drops userinfo and the query string so a base URL that
// embeds a token is never printed.
func stripURLCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparsable URL)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Write renders the report for humans.
func (r Report) Write(w io.Writer) {
	fmt.Fprintf(w, "achilles doctor — %s\nManaged tool directory: %s\n\n", r.Platform, r.BinDir)
	fmt.Fprintln(w, "Scanners (default profile)")
	r.writeTools(w, true)
	optIn := false
	for _, t := range r.Tools {
		optIn = optIn || !t.Required
	}
	if optIn {
		// Missing is fine here: these run only when a scan asks for them.
		fmt.Fprintln(w, "\nOpt-in scanners (run only with --with <name>; nothing needs them otherwise)")
		r.writeTools(w, false)
	}
	r.writeRest(w)
}

// writeTools prints the default-profile tools (required) or the opt-in ones.
func (r Report) writeTools(w io.Writer, required bool) {
	for _, t := range r.Tools {
		if t.Required != required {
			continue
		}
		ver := t.Version
		if ver == "" {
			ver = "-"
		}
		where := ""
		if t.Path != "" {
			where = fmt.Sprintf("%s (%s)", t.Path, t.Source)
		}
		fmt.Fprintf(w, "  %-12s %-15s %-8s (pinned %s)  %s\n", t.Name, t.State, ver, t.Pinned, where)
		if t.Fix != "" {
			label := "fix"
			if !required {
				label = "install" // not a problem: nothing runs it unless asked
			}
			fmt.Fprintf(w, "      %s: %s\n", label, t.Fix)
		}
		for _, n := range t.Notes {
			fmt.Fprintf(w, "      warning: %s\n", n)
		}
	}
}

// writeRest prints everything after the scanners.
func (r Report) writeRest(w io.Writer) {
	fmt.Fprintln(w, "\nPrerequisites")
	if r.Go.Found {
		ver := ""
		if r.Go.Detail != "" {
			ver = " (" + r.Go.Detail + ")"
		}
		fmt.Fprintf(w, "  go           found  %s%s   (gosec needs it)\n", r.Go.Path, ver)
	} else {
		fmt.Fprintln(w, "  go           NOT FOUND  (gosec cannot scan Go code without it: https://go.dev/dl/)")
	}
	if r.Docker.Found {
		fmt.Fprintf(w, "  docker       found  %s   (%s; optional: --runner docker)\n", r.Docker.Path, r.Docker.Detail)
	} else {
		fmt.Fprintln(w, "  docker       not found   (optional: only needed for --runner docker)")
	}

	fmt.Fprintln(w, "\nCommunity rules (optional; more Opengrep coverage on top of the built-in Achilles rules)")
	if r.Rules.Installed {
		fmt.Fprintf(w, "  %s  installed: %d rule files in %s\n", r.RulesPack.DirName(), r.Rules.Files, r.Rules.Dir)
	} else {
		fmt.Fprintf(w, "  %s  not installed (fix: achilles tools install rules)\n", r.RulesPack.DirName())
	}
	fmt.Fprintf(w, "      license: %s; not loaded under --mode commercial\n", r.RulesPack.License)

	fmt.Fprintln(w, "\nLLM (optional: --triage, --ai)")
	if r.LLMKeyVar != "" {
		fmt.Fprintf(w, "  API key      set (%s)\n", r.LLMKeyVar)
	} else {
		fmt.Fprintln(w, "  API key      not set (ACHILLES_LLM_API_KEY)")
	}
	fmt.Fprintf(w, "  base URL     %s\n", r.LLMBase)

	if r.Failed() {
		fmt.Fprintln(w, "\nResult: FAIL — required scanner(s) missing. Fix:")
		for _, t := range r.Tools {
			if t.Required && (t.State == StateMissing || t.State == StateUnsupported) {
				fmt.Fprintf(w, "  %s\n", t.Fix)
			}
		}
		fmt.Fprintln(w, "  or install everything at once: achilles tools install")
	} else {
		fmt.Fprintln(w, "\nResult: OK — all default-profile scanners are present.")
	}
}
