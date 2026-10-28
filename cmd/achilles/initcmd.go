package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/surface"
	"github.com/Warzuponus/achilles/internal/toolchain"
)

//go:embed templates/settings.yaml
var settingsTemplate string

//go:embed templates/github.yml
var githubTemplate string

//go:embed templates/gitlab.yml
var gitlabTemplate string

const initUsage = `usage: achilles init [--ci auto|github|gitlab|none] [--no-baseline] [--force] [--dry-run] [DIR]

Sets a repository up for Achilles in one step:

  .achilles.yaml                  how the repository is scanned (fail on high, use the baseline)
  .achilles/threat-context.yaml   what the code is (business critical? internet facing? ...),
                                  its crown jewels and out-of-scope paths: picks the scan depth,
                                  the scanners and the review order (every question starts
                                  commented out; answer the ones you can)
  .achilles/baseline.json         the findings in the code today, so CI fails only on new ones
                                  (seeded by a scan when the default scanners are installed)
  .github/workflows/achilles.yml  a pull-request and default-branch scan (GitHub), or
  .gitlab/achilles.yml            the same for GitLab, to include from .gitlab-ci.yml
  .gitignore                      keeps the Evidence Vault (local state) out of git

Existing files are left alone unless --force is given. DIR defaults to the
current directory.
`

// initFile is one file init writes, and what happened to it.
type initFile struct {
	path    string // relative to the repository
	content string
	note    string // what it is for, printed next to it
}

// runInit sets a repository up: settings, CI, .gitignore, and a seeded baseline.
func runInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("achilles init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, initUsage) }
	ci := fs.String("ci", "auto", "CI to write a workflow for: auto | github | gitlab | none")
	noBaseline := fs.Bool("no-baseline", false, "do not scan now to seed the baseline")
	force := fs.Bool("force", false, "overwrite files that already exist")
	dryRun := fs.Bool("dry-run", false, "print what would be written, and write nothing")
	config := fs.String("config", "", "tool registry for the seeding scan (default: the one built in)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("achilles init takes one directory, got %d arguments", fs.NArg())
	}
	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("achilles init: %s is not a directory", dir)
	}

	kind, why := *ci, "as asked"
	if kind == "auto" {
		kind, why = detectCI(dir)
	}
	files := []initFile{
		{path: ".achilles.yaml", content: settingsTemplate, note: "how this repository is scanned"},
		{path: surface.ContextFiles[0], content: surface.ContextTemplate, note: "what this code is and what matters most in it: answer what you can"},
	}
	switch kind {
	case "github":
		files = append(files, initFile{path: ".github/workflows/achilles.yml",
			content: fillTemplate(githubTemplate, dir), note: "scans pull requests and " + defaultBranch(dir)})
	case "gitlab":
		files = append(files, initFile{path: ".gitlab/achilles.yml",
			content: fillTemplate(gitlabTemplate, dir), note: "include it from .gitlab-ci.yml (see the comment at its top)"})
	case "none":
	default:
		return fmt.Errorf("--ci %q: want auto, github, gitlab or none", kind)
	}

	fmt.Fprintf(stdout, "Setting up Achilles in %s", absOr(dir))
	if kind != "none" {
		fmt.Fprintf(stdout, " (CI: %s, %s)", kind, why)
	}
	fmt.Fprintln(stdout)

	// Every file is written through a root on the repository: a .github that is a
	// symbolic link to somewhere else does not get a workflow written there.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	var wrote []string
	for _, f := range files {
		target := filepath.FromSlash(f.path)
		_, statErr := root.Stat(target)
		exists := statErr == nil
		switch {
		case exists && !*force:
			fmt.Fprintf(stdout, "  kept     %s (already there; --force to replace it)\n", f.path)
			continue
		case *dryRun:
			fmt.Fprintf(stdout, "  would write %s — %s\n", f.path, f.note)
			continue
		}
		if err := root.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		// These files are meant to be committed and read by CI: 0644 on purpose.
		if err := root.WriteFile(target, []byte(f.content), 0o644); err != nil { // #nosec G306 -- committed repository files
			return err
		}
		verb := "wrote   "
		if exists {
			verb = "replaced"
		}
		fmt.Fprintf(stdout, "  %s %s — %s\n", verb, f.path, f.note)
		wrote = append(wrote, f.path)
	}

	if !*dryRun && gitOutput(dir, "check-ignore", surface.ContextFiles[0]) != "" {
		fmt.Fprintf(stdout, "  NOTE     .gitignore ignores %s; add the line !/%s after the rule that ignores it, so it is committed\n",
			surface.ContextFiles[0], surface.ContextFiles[0])
	}

	added, err := ignoreVault(root, *dryRun)
	if err != nil {
		return err
	}
	switch {
	case added && *dryRun:
		fmt.Fprintln(stdout, "  would add the Evidence Vault to .gitignore")
	case added:
		fmt.Fprintln(stdout, "  updated  .gitignore — the Evidence Vault is local state, not something to commit")
		wrote = append(wrote, ".gitignore")
	}

	seeded := false
	if !*noBaseline && !*dryRun {
		seeded = seedBaseline(dir, *config, stdout, stderr)
		if seeded {
			wrote = append(wrote, ".achilles/baseline.json")
		}
	}

	fmt.Fprintln(stdout, "\nNext:")
	step := 1
	next := func(format string, a ...any) {
		fmt.Fprintf(stdout, "  %d. "+format+"\n", append([]any{step}, a...)...)
		step++
	}
	if !seeded && !*dryRun {
		next("install the scanners and seed the baseline:\n       achilles tools install\n       achilles --write-baseline .achilles/baseline.json %s", dir)
	}
	if kind == "gitlab" {
		next("add to .gitlab-ci.yml:\n       include:\n         - local: .gitlab/achilles.yml")
	}
	if len(wrote) > 0 {
		next("review and commit: git add %s", strings.Join(wrote, " "))
	}
	next("scan any time: achilles %s   (add --ai with an LLM key for verdicts and fixes; see docs/llm-and-agents.md)", dir)
	return nil
}

// detectCI chooses the CI to write a workflow for, and says why.
func detectCI(dir string) (kind, why string) {
	if isDir(filepath.Join(dir, ".github", "workflows")) {
		return "github", "it has .github/workflows"
	}
	if exists(filepath.Join(dir, ".gitlab-ci.yml")) {
		return "gitlab", "it has .gitlab-ci.yml"
	}
	remote := strings.ToLower(gitOutput(dir, "remote", "get-url", "origin"))
	switch {
	case strings.Contains(remote, "github.com"):
		return "github", "its origin is on github.com"
	case strings.Contains(remote, "gitlab"):
		return "gitlab", "its origin is a GitLab server"
	}
	return "none", "no GitHub or GitLab setup found"
}

// defaultBranch is the branch CI should scan on push: the remote's default, else
// the current branch, else main.
func defaultBranch(dir string) string {
	if ref := gitOutput(dir, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); ref != "" {
		return strings.TrimPrefix(ref, "origin/")
	}
	if b := gitOutput(dir, "branch", "--show-current"); b != "" {
		return b
	}
	return "main"
}

var branchName = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,100}$`)

// fillTemplate puts the branch and the version to pin into a CI template.
func fillTemplate(t, dir string) string {
	branch := defaultBranch(dir)
	if !branchName.MatchString(branch) {
		branch = "main" // a name that would need quoting in YAML is not guessed at
	}
	return strings.NewReplacer("__BRANCH__", branch, "__VERSION__", actionPin(currentVersion()), "__IMAGE_TAG__", imageTag(currentVersion())).Replace(t)
}

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// ignoreVault makes sure .gitignore keeps the Evidence Vault out of git. It
// reports whether it added (or would add) the lines.
func ignoreVault(root *os.Root, dryRun bool) (bool, error) {
	const path = ".gitignore"
	data, err := root.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch strings.TrimSpace(line) {
		case ".achilles/vault.jsonl*", "/.achilles/vault.jsonl*", ".achilles/*", "/.achilles/*", ".achilles/", "/.achilles/":
			return false, nil
		}
	}
	if dryRun {
		return true, nil
	}
	block := "\n# Achilles: the Evidence Vault is local state. A committed one could carry\n" +
		"# feedback written by anyone who can change the repository.\n/.achilles/vault.jsonl*\n"
	if len(data) == 0 {
		block = strings.TrimPrefix(block, "\n")
	} else if !bytes.HasSuffix(data, []byte("\n")) {
		block = "\n" + block
	}
	f, err := root.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302 -- a committed repository file
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(block)
	return err == nil, err
}

// seedBaseline runs a scan now and writes its findings as the baseline, so the
// first CI run fails only on findings that are new. It reports whether it did.
// It insists on a complete scan: a baseline seeded from a scan that missed a
// scanner would let that scanner's existing findings fail the first real run,
// which is the opposite of what the baseline is for.
func seedBaseline(dir, config string, stdout, stderr io.Writer) bool {
	path := filepath.Join(dir, ".achilles", "baseline.json")
	if exists(path) {
		fmt.Fprintln(stdout, "  kept     .achilles/baseline.json (already there)")
		return false
	}
	// With the built-in registry, check the scanners first: a scan that is going to
	// fail on a missing tool is minutes of output for nothing.
	if config == "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		rep := toolchain.NewDoctor().Diagnose(ctx)
		cancel()
		var missing []string
		for _, t := range rep.Tools {
			if t.Required && (t.State == toolchain.StateMissing || t.State == toolchain.StateUnsupported) {
				missing = append(missing, t.Name)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(stdout, "\nThe baseline is not seeded yet: these scanners are not installed: %s.\n", strings.Join(missing, ", "))
			return false
		}
	}
	fmt.Fprintln(stdout, "\nSeeding the baseline: scanning the code as it is now, so that only new findings fail CI.")
	args := []string{"--strict-tools", "--fail-on", "", "--write-baseline", path, "--vault", filepath.Join(dir, ".achilles", "vault.jsonl")}
	if config != "" {
		args = append(args, "--config", config)
	}
	err := run(append(args, dir))
	if err != nil {
		// The scan writes the baseline before it decides the run failed. One from an
		// incomplete scan is not the baseline this repository needs; remove it.
		_ = os.Remove(path)
		fmt.Fprintf(stderr, "achilles init: the baseline was not seeded: %v\n", err)
		return false
	}
	return exists(path)
}

func gitOutput(dir string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- fixed git subcommands chosen above; dir is passed to -C
	out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func absOr(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// actionPin is the ref the generated workflow uses the Achilles action at. A
// release build knows the commit its tag points at, so the action is pinned to
// that commit with the version as a comment: a tag can be moved, a commit cannot,
// and zizmor (and GitHub's own guidance) ask for exactly this. A development build
// has no release to pin, and the file says so.
func actionPin(v versionInfo) string {
	switch {
	case releaseTag.MatchString(v.Version) && fullCommit.MatchString(v.Commit):
		return v.Commit + " # " + v.Version
	case releaseTag.MatchString(v.Version):
		return v.Version + " # pin the commit of this release for an immutable reference"
	}
	return "main # pin a release: Warzuponus/achilles@<commit> # vX.Y.Z"
}

// imageTag is the container image tag the GitLab job uses: this release, or the
// newest one for a development build.
func imageTag(v versionInfo) string {
	if releaseTag.MatchString(v.Version) {
		return strings.TrimPrefix(v.Version, "v")
	}
	return "latest"
}
