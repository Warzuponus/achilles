package eval

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Placeholder markers: a ground-truth file that still carries one of these has not
// been pinned to a verified commit, and the runner must refuse it rather than scan
// whatever the default branch happens to be today.
var placeholderMarkers = []string{"replace", "placeholder", "<", ">", "your_", "your-", "changeme"}

func looksLikePlaceholder(s string) bool {
	l := strings.ToLower(s)
	for _, m := range placeholderMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// CheckPinned returns an actionable error unless a git source is pinned to a real
// full commit SHA. Local sources are always pinned (they are in the repo).
func (g GroundTruth) CheckPinned() error {
	s := g.Source
	if !s.IsGit() {
		return nil
	}
	if looksLikePlaceholder(s.URL) {
		return fmt.Errorf("target %q (%s): source.url is still a placeholder (%q); set the real repository URL",
			g.ID, g.Path, s.URL)
	}
	if !commitRE.MatchString(s.Commit) { // a placeholder is never 40 hex digits
		return fmt.Errorf("target %q (%s): source.commit %q is not a pinned commit SHA.\n"+
			"  Pin it: clone the repository, choose the commit you will benchmark, run `git rev-parse <ref>`,\n"+
			"  and paste the full 40-character SHA. Then check every entry's file and line range against that\n"+
			"  exact commit — line numbers drift between commits, and a stale label measures the wrong code.\n"+
			"  (The runner will not scan a branch, a tag, or a placeholder.)",
			g.ID, g.Path, s.Commit)
	}
	return nil
}

// GitRunner runs git. It is a seam so tests can exercise resolution without a
// network; the real one shells out to the git binary.
type GitRunner interface {
	Git(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecGit runs the git binary with prompts disabled (a benchmark must never block
// on a credential prompt) and external transports refused.
type ExecGit struct{}

// Git implements GitRunner.
func (ExecGit) Git(ctx context.Context, dir string, args ...string) (string, error) {
	full := append([]string{"-c", "protocol.ext.allow=never", "-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...) // #nosec G204 -- fixed binary; URL validated by checkGitURL
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// checkGitURL accepts the usual remote forms and rejects anything git would parse
// as an option or an exotic transport.
func checkGitURL(u string) error {
	switch {
	case strings.HasPrefix(u, "-"):
		return fmt.Errorf("git url %q looks like an option", u)
	case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "http://"),
		strings.HasPrefix(u, "ssh://"), strings.HasPrefix(u, "file://"),
		strings.HasPrefix(u, "git@"):
		return nil
	}
	return fmt.Errorf("git url %q must start with https://, http://, ssh://, file:// or git@", u)
}

// ResolveSource returns the directory to scan for a target: the local path, or a
// checkout of the pinned commit in cacheDir. A cached checkout whose HEAD is
// already the pinned commit is reused, so repeated runs fetch once.
func ResolveSource(ctx context.Context, g GroundTruth, cacheDir string, git GitRunner) (string, error) {
	if err := g.CheckPinned(); err != nil {
		return "", err
	}
	s := g.Source
	if !s.IsGit() {
		p := s.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(g.Dir, filepath.FromSlash(p))
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return "", fmt.Errorf("target %q: local source %s is not a directory", g.ID, s.Path)
		}
		return abs, nil
	}
	if err := checkGitURL(s.URL); err != nil {
		return "", fmt.Errorf("target %q: %w", g.ID, err)
	}
	if cacheDir == "" {
		return "", fmt.Errorf("target %q: a git source needs a cache directory", g.ID)
	}
	dir := filepath.Join(cacheDir, g.ID+"-"+s.Commit[:12])
	if head, err := git.Git(ctx, dir, "rev-parse", "HEAD"); err == nil && head == s.Commit {
		return withSubdir(g, dir)
	}
	// A stale or half-written cache dir is rebuilt from scratch: reusing it could
	// scan the wrong tree while reporting the right commit.
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("target %q: %w", g.ID, err)
	}
	if _, err := git.Git(ctx, dir, "init", "--quiet"); err != nil {
		return fail(err)
	}
	if _, err := git.Git(ctx, dir, "remote", "add", "origin", s.URL); err != nil {
		return fail(err)
	}
	// Shallow fetch of exactly that commit; servers that refuse to serve an
	// arbitrary SHA get a full fetch instead.
	if _, err := git.Git(ctx, dir, "fetch", "--quiet", "--depth", "1", "origin", s.Commit); err != nil {
		if _, err2 := git.Git(ctx, dir, "fetch", "--quiet", "origin"); err2 != nil {
			return fail(fmt.Errorf("could not fetch %s at %s (shallow: %v; full: %v)", s.URL, s.Commit, err, err2))
		}
	}
	if _, err := git.Git(ctx, dir, "checkout", "--quiet", "--detach", s.Commit); err != nil {
		return fail(fmt.Errorf("commit %s is not in %s: %w", s.Commit, s.URL, err))
	}
	if head, err := git.Git(ctx, dir, "rev-parse", "HEAD"); err != nil || head != s.Commit {
		return fail(fmt.Errorf("checkout resolved to %q, not the pinned %s", head, s.Commit))
	}
	return withSubdir(g, dir)
}

func withSubdir(g GroundTruth, dir string) (string, error) {
	if g.Source.Subdir == "" {
		return dir, nil
	}
	if filepath.IsAbs(g.Source.Subdir) || hasDotDot(filepath.ToSlash(g.Source.Subdir)) {
		return "", fmt.Errorf("target %q: source.subdir %q must stay inside the checkout", g.ID, g.Source.Subdir)
	}
	sub := filepath.Join(dir, filepath.FromSlash(g.Source.Subdir))
	if st, err := os.Stat(sub); err != nil || !st.IsDir() {
		return "", fmt.Errorf("target %q: subdir %q not found in the checkout", g.ID, g.Source.Subdir)
	}
	return sub, nil
}
