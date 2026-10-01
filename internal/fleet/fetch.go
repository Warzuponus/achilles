package fleet

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultFetchTimeout bounds one git source's whole fetch (init+fetch+checkout).
const DefaultFetchTimeout = 5 * time.Minute

// FetchingRunner is a Runner decorator that materializes git-source jobs. For a
// job with a Source it fetches the repo into a per-job ephemeral directory under
// Workspace, hands the inner runner a copy of the job whose Target is that
// checkout, and ALWAYS removes the directory afterwards (success, scan failure,
// fetch failure, cancellation). Path jobs pass straight through untouched.
//
// Why a wrapper rather than code inside CLIRunner: CLIRunner's one job is turning a
// Job into a `achilles` invocation; fetching is a separate concern (own timeout,
// own credentials, own cleanup) that applies to ANY Runner (an in-process runner,
// a test double). Keeping it a decorator means the dispatcher, the scan runner and
// the fetcher each stay independently testable, and path-only fleets pay nothing.
//
// Credentials never touch argv, URLs, logs or the vault: see gitEnv and scrubber.
type FetchingRunner struct {
	Inner     Runner
	Workspace string        // parent dir for per-job checkouts; default os.TempDir()
	Timeout   time.Duration // per-source fetch bound; default DefaultFetchTimeout
	Git       string        // git binary; default "git"
	Getenv    func(string) string
	Logf      func(format string, args ...any)
}

var _ Runner = FetchingRunner{}

// Scan implements Runner.
func (f FetchingRunner) Scan(ctx context.Context, j Job) Result {
	if j.Source == nil {
		return f.Inner.Scan(ctx, j)
	}
	if err := j.Source.Validate(); err != nil {
		return failure(j, err.Error())
	}

	root, err := f.makeWorkspace()
	if err != nil {
		return failure(j, "workspace: "+err.Error())
	}
	defer f.cleanup(root)

	f.logf("fetching %s (depth %d)", j.Target, j.Source.EffectiveDepth())
	dir, sha, err := f.fetch(ctx, root, j.Source)
	if err != nil {
		return failure(j, fmt.Sprintf("fetch %s: %s", j.Target, err))
	}
	f.logf("fetched %s @ %s", j.Target, sha[:12])

	scanJob := j
	scanJob.Target, scanJob.Commit = dir, sha
	res := f.Inner.Scan(ctx, scanJob)
	res.Job = j // report against the stable label, not the ephemeral path
	res.Job.Commit = sha
	return res
}

func failure(j Job, msg string) Result {
	return Result{Job: j, Err: errors.New(msg), Detail: msg}
}

func (f FetchingRunner) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

func (f FetchingRunner) getenv(k string) string {
	if f.Getenv != nil {
		return f.Getenv(k)
	}
	return os.Getenv(k)
}

func (f FetchingRunner) makeWorkspace() (string, error) {
	ws := f.Workspace
	if ws == "" {
		ws = os.TempDir()
	}
	ws, err := filepath.Abs(ws)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(ws, "achilles-fleet-*") // mode 0700
}

func (f FetchingRunner) cleanup(root string) {
	if err := os.RemoveAll(root); err != nil {
		f.logf("WARNING: could not remove ephemeral workspace %s: %v", root, err)
	}
}

// fetch clones src into root and returns (checkout dir, resolved commit sha).
// Every returned error is already scrubbed of credentials.
func (f FetchingRunner) fetch(ctx context.Context, root string, src *GitSource) (string, string, error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var sc scrubber
	env, cleanupKey, err := f.gitEnv(root, src, &sc)
	if err != nil {
		return "", "", errors.New(sc.scrub(err.Error()))
	}
	defer cleanupKey() // the SSH key file never outlives the fetch

	dir := filepath.Join(root, repoDirName(src.URL))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", "", err
	}
	// init + fetch-by-refspec (rather than `clone --branch`) so branch, tag AND
	// commit sha all work through one path, shallow.
	refspec := src.Ref
	if refspec == "" {
		refspec = "HEAD"
	}
	steps := [][]string{
		{"init", "--quiet", "--template="},
		{"fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--depth", fmt.Sprint(src.EffectiveDepth()), "--", src.URL, refspec},
		{"-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if _, err := f.runGit(ctx, dir, env, &sc, args...); err != nil {
			return "", "", err
		}
	}
	out, err := f.runGit(ctx, dir, env, &sc, "rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	sha := strings.TrimSpace(out)
	if !shaRE.MatchString(sha) {
		return "", "", fmt.Errorf("git rev-parse returned an unexpected value")
	}
	return dir, sha, nil
}

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// runGit runs one git subcommand (argument list, never a shell string) and
// returns stdout. Failures carry the scrubbed tail of stderr.
func (f FetchingRunner) runGit(ctx context.Context, dir string, env []string, sc *scrubber, args ...string) (string, error) {
	bin := f.Git
	if bin == "" {
		bin = "git"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second // don't hang on helper processes after a kill
	if err := cmd.Run(); err != nil {
		name := subcommand(args)
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return "", fmt.Errorf("git %s timed out", name)
		case ctx.Err() != nil:
			return "", fmt.Errorf("git %s cancelled", name)
		}
		return "", fmt.Errorf("git %s: %s: %s", name, sc.scrub(err.Error()), tail(sc.scrub(stderr.String())))
	}
	return stdout.String(), nil
}

func subcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			continue
		}
		return args[i]
	}
	return "?"
}

// envPassthrough are the only variables inherited from the parent. Everything
// else (notably ACHILLES_LLM_API_KEY and other tenants' tokens) is withheld.
var envPassthrough = []string{
	"PATH", "HOME", "TMPDIR", "USER", "LOGNAME",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
}

// gitEnv builds the child environment and registers every secret with sc. The
// returned func removes any temp key file.
//
// Credentials travel ONLY in the environment of the git process:
//   - https token: GIT_CONFIG_COUNT/KEY_n/VALUE_n injects http.extraHeader, so the
//     token is in no argv (ps), no URL, no on-disk config. Redirects are disabled
//     with a token so the header can't be replayed to another host.
//   - ssh key: written 0600 into the 0700 per-job dir, referenced via
//     GIT_SSH_COMMAND, deleted as soon as the fetch finishes.
//
// User/system git config is disabled so a stray insteadOf/credential.helper on the
// host can't rewrite the URL or leak credentials; prompts are off.
func (f FetchingRunner) gitEnv(root string, src *GitSource, sc *scrubber) ([]string, func(), error) {
	noop := func() {}
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ALLOW_PROTOCOL=https:ssh:file",
		"LC_ALL=C",
	}
	kind, err := validateGitURL(src.URL)
	if err != nil {
		return nil, noop, err
	}
	for _, k := range envPassthrough {
		if v := f.getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}

	switch {
	case src.Auth.TokenEnv != "":
		tok := strings.TrimSpace(f.getenv(src.Auth.TokenEnv))
		if tok == "" {
			return nil, noop, fmt.Errorf("auth.tokenEnv: environment variable %s is not set or empty", src.Auth.TokenEnv)
		}
		if strings.ContainsAny(tok, "\r\n\x00") {
			return nil, noop, fmt.Errorf("auth.tokenEnv: %s contains control characters", src.Auth.TokenEnv)
		}
		b64 := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tok))
		header := "Authorization: Basic " + b64
		sc.add(tok, b64, header)
		env = append(env,
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0="+header,
			"GIT_CONFIG_KEY_1=http.followRedirects", "GIT_CONFIG_VALUE_1=false",
		)
	case src.Auth.SSHKeyEnv != "":
		key := strings.TrimSpace(f.getenv(src.Auth.SSHKeyEnv))
		if key == "" {
			return nil, noop, fmt.Errorf("auth.sshKeyEnv: environment variable %s is not set or empty", src.Auth.SSHKeyEnv)
		}
		sc.add(key)
		for _, line := range strings.Split(key, "\n") {
			if line = strings.TrimSpace(line); len(line) >= 8 {
				sc.add(line)
			}
		}
		path := filepath.Join(root, "id_key")
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, noop, fmt.Errorf("write ssh key: %w", err)
		}
		_, werr := fh.WriteString(key + "\n") // OpenSSH requires a trailing newline
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(path)
			return nil, noop, fmt.Errorf("write ssh key: %w", werr)
		}
		env = append(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "+shellQuote(path))
		return env, func() { _ = os.Remove(path) }, nil
	case kind == "ssh":
		// No explicit key: use the ambient agent, but never prompt.
		if v := f.getenv("SSH_AUTH_SOCK"); v != "" {
			env = append(env, "SSH_AUTH_SOCK="+v)
		}
		env = append(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new")
	}
	return env, noop, nil
}

// shellQuote single-quotes s for GIT_SSH_COMMAND (which git runs through a shell).
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var repoNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// repoDirName derives a readable, filesystem-safe checkout dir name from the URL.
func repoDirName(rawURL string) string {
	s := strings.TrimRight(rawURL, "/")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(repoNameRE.ReplaceAllString(s, "_"), ".")
	if s == "" {
		return "repo"
	}
	return s
}

// scrubber redacts known secret values (and any URL userinfo) from text before it
// can reach an error, log or result.
type scrubber struct{ secrets []string }

func (s *scrubber) add(vals ...string) {
	for _, v := range vals {
		if v != "" {
			s.secrets = append(s.secrets, v)
		}
	}
}

func (s *scrubber) scrub(text string) string {
	// Longest first so a header is replaced whole before its token fragment.
	sec := append([]string(nil), s.secrets...)
	sort.Slice(sec, func(i, j int) bool { return len(sec[i]) > len(sec[j]) })
	for _, v := range sec {
		text = strings.ReplaceAll(text, v, "[REDACTED]")
	}
	return redactURLs(text)
}
