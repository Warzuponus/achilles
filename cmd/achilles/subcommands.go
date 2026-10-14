package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/toolchain"
)

// runSubcommand handles `achilles version | doctor | tools ...`. handled is false
// when argv is an ordinary scan invocation (flags and/or a target path), in which
// case the caller carries on. A scan target that is literally named "version",
// "doctor" or "tools" must be written ./version etc.
func runSubcommand(argv []string, stdout, stderr io.Writer) (handled bool, err error) {
	if len(argv) == 0 {
		return false, nil
	}
	switch argv[0] {
	case "version":
		printVersion(stdout)
		return true, nil
	case "doctor":
		return true, runDoctor(argv[1:], stdout)
	case "tools":
		return true, runTools(argv[1:], stdout, stderr)
	case "mcp":
		return true, runMCP(argv[1:], os.Stdin, stdout, stderr)
	case "init":
		return true, runInit(argv[1:], stdout, stderr)
	}
	return false, nil
}

const toolsUsage = `usage: achilles tools <command>

  list                     show the pinned scanners and community rules, whether upstream
                           publishes one for this platform, and where each is installed
  install [--force] [name...]
                           download, sha256-verify and install pinned scanners into
                           $ACHILLES_HOME/bin (default ~/.achilles/bin) and, as the name
                           "rules", the community Opengrep rule pack into
                           $ACHILLES_HOME/rules; no names = every scanner plus the rules
  doctor                   same as 'achilles doctor'
`

func runTools(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, toolsUsage)
		if len(args) == 0 {
			return errors.New("tools: missing command")
		}
		return nil
	}
	switch args[0] {
	case "list":
		return runToolsList(stdout)
	case "install":
		return runToolsInstall(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout)
	}
	fmt.Fprint(stderr, toolsUsage)
	return fmt.Errorf("tools: unknown command %q", args[0])
}

func runDoctor(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep := toolchain.NewDoctor().Diagnose(ctx)
	rep.Write(stdout)
	if rep.Failed() {
		return errors.New("doctor: required scanner(s) missing (see above)")
	}
	return nil
}

func runToolsList(stdout io.Writer) error {
	fmt.Fprintf(stdout, "%-12s %-13s %-10s %s\n", "TOOL", "PINNED", "DOWNLOAD", "INSTALLED")
	for _, t := range toolchain.Tools() {
		dl := "yes"
		if _, ok := t.Asset(runtime.GOOS, runtime.GOARCH); !ok {
			dl = "none"
		}
		where := "-"
		if p, src, err := toolchain.LookBin(t.Bin); err == nil {
			where = fmt.Sprintf("%s (%s)", p, src)
		}
		fmt.Fprintf(stdout, "%-12s %-13s %-10s %s\n", t.Name, t.Version, dl, where)
	}
	rs := toolchain.CommunityRules()
	rules := "-"
	if ir := toolchain.InstalledCommunityRules(); ir.Installed {
		rules = fmt.Sprintf("%s (%d rule files)", ir.Dir, ir.Files)
	}
	fmt.Fprintf(stdout, "%-12s %-13s %-10s %s\n", "rules", rs.ShortSHA(), "yes", rules)
	if dir, err := toolchain.BinDir(); err == nil {
		fmt.Fprintf(stdout, "\nplatform %s/%s; managed directory %s\n", runtime.GOOS, runtime.GOARCH, dir)
	}
	return nil
}

func runToolsInstall(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tools install", flag.ContinueOnError)
	force := fs.Bool("force", false, "reinstall even if the pinned version is already installed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var selected []toolchain.Tool
	wantRules := fs.NArg() == 0
	var optional []string
	if fs.NArg() == 0 {
		// No names: what the default scan needs. An opt-in scanner is installed by name.
		for _, t := range toolchain.Tools() {
			if t.Default {
				selected = append(selected, t)
			} else {
				optional = append(optional, t.Name)
			}
		}
	} else {
		for _, name := range fs.Args() {
			if name == "rules" {
				wantRules = true
				continue
			}
			t, err := toolchain.Lookup(name)
			if err != nil {
				return err
			}
			selected = append(selected, t)
		}
	}

	binDir, err := toolchain.BinDir()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	in := &toolchain.Installer{BinDir: binDir, Log: stdout}
	var failed []string
	for _, t := range selected {
		if !*force {
			if v := installedPinnedVersion(ctx, t); v != "" {
				fmt.Fprintf(stdout, "%s %s: already installed (use --force to reinstall)\n", t.Name, v)
				continue
			}
		}
		path, err := in.Install(ctx, t, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			fmt.Fprintf(stderr, "achilles: %v\n", err)
			failed = append(failed, t.Name)
			continue
		}
		vctx, vcancel := context.WithTimeout(ctx, 15*time.Second)
		out, verr := toolchain.ProbeVersion(vctx, path, t.VersionArgs)
		vcancel()
		if v := toolchain.ParseVersion(out); v != "" {
			fmt.Fprintf(stdout, "%s %s: installed %s\n", t.Name, v, path)
		} else {
			fmt.Fprintf(stdout, "%s: installed %s (warning: could not read its version: %v)\n", t.Name, path, verr)
		}
	}
	if wantRules {
		if err := installCommunityRules(ctx, in, *force, stdout, stderr); err != nil {
			failed = append(failed, "rules")
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("tools install: failed: %s", strings.Join(failed, ", "))
	}
	if len(optional) > 0 {
		fmt.Fprintf(stdout, "\nOpt-in scanners are installed by name: achilles tools install %s\n", strings.Join(optional, " "))
	}
	fmt.Fprintln(stdout, "\nNext: achilles doctor")
	return nil
}

// installedPinnedVersion returns the version when the MANAGED copy of t already
// reports the pinned version, else "".
func installedPinnedVersion(ctx context.Context, t toolchain.Tool) string {
	path, src, err := toolchain.LookBin(t.Bin)
	if err != nil || src != toolchain.SourceManaged {
		return ""
	}
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _ := toolchain.ProbeVersion(vctx, path, t.VersionArgs)
	if v := toolchain.ParseVersion(out); v == t.Version {
		return v
	}
	return ""
}

// installCommunityRules fetches the pinned opengrep-rules pack (download-on-demand:
// it is never embedded or committed) into $ACHILLES_HOME/rules.
func installCommunityRules(ctx context.Context, in *toolchain.Installer, force bool, stdout, stderr io.Writer) error {
	rs := toolchain.CommunityRules()
	if cur := toolchain.InstalledCommunityRules(); cur.Installed && !force {
		fmt.Fprintf(stdout, "rules %s: already installed, %d rule files (use --force to reinstall)\n", rs.ShortSHA(), cur.Files)
		return nil
	}
	root, err := toolchain.RulesDir()
	if err != nil {
		fmt.Fprintf(stderr, "achilles: %v\n", err)
		return err
	}
	got, err := in.InstallRules(ctx, rs, root)
	if err != nil {
		fmt.Fprintf(stderr, "achilles: %v\n", err)
		return err
	}
	fmt.Fprintf(stdout, "rules %s: installed %d rule files in %s\n", rs.ShortSHA(), got.Files, got.Dir)
	fmt.Fprintf(stdout, "  note: these rules are %s. They are loaded alongside the built-in Achilles rules\n", rs.License)
	fmt.Fprintln(stdout, "  and are skipped under --mode commercial (the Commons Clause forbids selling them).")
	return nil
}
