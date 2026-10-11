package fleet

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- helpers ---------------------------------------------------------------

type runnerFunc func(context.Context, Job) Result

func (f runnerFunc) Scan(ctx context.Context, j Job) Result { return f(ctx, j) }

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func requireSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
}

// hermeticGit runs git with no host config and a fixed identity.
func hermeticGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type fixtureRepo struct {
	URL     string // file:// URL of a bare clone (like a mirror)
	C1, C2  string // first and second commit on main
	Feature string // sha of branch "feature"
}

// newFixtureRepo builds: main = c1 (a.txt) -> c2 (+b.txt); tag v1 -> c1;
// branch feature = c1 + feature.txt. Served via a bare clone over file://.
func newFixtureRepo(t *testing.T) fixtureRepo {
	t.Helper()
	requireGit(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hermeticGit(t, work, "init", "--quiet", "-b", "main")
	write("a.txt", "one\n")
	hermeticGit(t, work, "add", ".")
	hermeticGit(t, work, "commit", "--quiet", "-m", "c1")
	c1 := hermeticGit(t, work, "rev-parse", "HEAD")
	hermeticGit(t, work, "tag", "v1")
	hermeticGit(t, work, "checkout", "--quiet", "-b", "feature")
	write("feature.txt", "feature\n")
	hermeticGit(t, work, "add", ".")
	hermeticGit(t, work, "commit", "--quiet", "-m", "feat")
	feature := hermeticGit(t, work, "rev-parse", "HEAD")
	hermeticGit(t, work, "checkout", "--quiet", "main")
	write("b.txt", "two\n")
	hermeticGit(t, work, "add", ".")
	hermeticGit(t, work, "commit", "--quiet", "-m", "c2")
	c2 := hermeticGit(t, work, "rev-parse", "HEAD")

	bare := filepath.Join(t.TempDir(), "mirror.git")
	hermeticGit(t, work, "clone", "--quiet", "--bare", work, bare)
	return fixtureRepo{URL: fileURL(bare), C1: c1, C2: c2, Feature: feature}
}

// fileURL turns an absolute path into a file:// URL. On Windows the path is
// C:\dir\repo.git, and its URL is file:///C:/dir/repo.git, not file://C:\dir\...
// (which would make "C:" the host).
func fileURL(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p
}

func gitJob(url, ref string, depth int) Job {
	g := &GitSource{URL: url, Ref: ref, Depth: depth}
	return Job{Tenant: "acme", Target: Target{Git: g}.Label(), Mode: "oss", Profile: "default", Source: g}
}

// emptyDir fails the test unless dir exists and has no entries.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("workspace not cleaned up, left behind: %v", names)
	}
}

// ---- real-git tests (file://) ---------------------------------------------

func TestFetch_CheckoutRefsAndCommit(t *testing.T) {
	repo := newFixtureRepo(t)
	cases := []struct {
		name, ref string
		wantSHA   string
		has, not  []string
	}{
		{"default HEAD", "", repo.C2, []string{"a.txt", "b.txt"}, []string{"feature.txt"}},
		{"branch", "feature", repo.Feature, []string{"a.txt", "feature.txt"}, []string{"b.txt"}},
		{"tag", "v1", repo.C1, []string{"a.txt"}, []string{"b.txt", "feature.txt"}},
		{"full sha", repo.C1, repo.C1, []string{"a.txt"}, []string{"b.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			var seen Job
			var checked bool
			fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(_ context.Context, j Job) Result {
				seen = j
				for _, f := range tc.has {
					if _, err := os.Stat(filepath.Join(j.Target, f)); err != nil {
						t.Errorf("checkout missing %s: %v", f, err)
					}
				}
				for _, f := range tc.not {
					if _, err := os.Stat(filepath.Join(j.Target, f)); err == nil {
						t.Errorf("checkout should not contain %s", f)
					}
				}
				// default depth is a shallow clone of a single commit
				if n := hermeticGit(t, j.Target, "rev-list", "--count", "HEAD"); n != "1" {
					t.Errorf("want depth 1, got %s commits", n)
				}
				checked = true
				return Result{Job: j}
			})}
			j := gitJob(repo.URL, tc.ref, 0)
			res := fr.Scan(context.Background(), j)
			if res.Err != nil || !checked {
				t.Fatalf("scan: err=%v checked=%v detail=%q", res.Err, checked, res.Detail)
			}
			if seen.Commit != tc.wantSHA {
				t.Errorf("commit %s, want %s", seen.Commit, tc.wantSHA)
			}
			if seen.Source == nil || seen.Source.URL != repo.URL {
				t.Errorf("inner runner lost Source: %+v", seen)
			}
			if res.Job.Commit != tc.wantSHA || res.Job.Target != j.Target {
				t.Errorf("result should report the stable label + commit, got %+v", res.Job)
			}
			if seen.Target == j.Target || !strings.HasPrefix(seen.Target, ws) {
				t.Errorf("inner target %q should be an ephemeral dir under %s", seen.Target, ws)
			}
			if _, err := os.Stat(seen.Target); !os.IsNotExist(err) {
				t.Errorf("checkout dir still present after scan: %v", err)
			}
			assertEmptyDir(t, ws)
		})
	}
}

func TestFetch_DepthHonored(t *testing.T) {
	requireGit(t)
	repo := newFixtureRepo(t)
	fr := FetchingRunner{Workspace: t.TempDir(), Inner: runnerFunc(func(_ context.Context, j Job) Result {
		// main has 2 commits; depth 2 must bring both.
		if n := hermeticGit(t, j.Target, "rev-list", "--count", "HEAD"); n != "2" {
			t.Errorf("depth 2: want 2 commits, got %s", n)
		}
		return Result{Job: j}
	})}
	if res := fr.Scan(context.Background(), gitJob(repo.URL, "main", 2)); res.Err != nil {
		t.Fatal(res.Err)
	}
}

func TestFetch_CleanupOnScanFailure(t *testing.T) {
	repo := newFixtureRepo(t)
	ws := t.TempDir()
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(_ context.Context, j Job) Result {
		return Result{Job: j, Err: errors.New("scanner exploded")}
	})}
	res := fr.Scan(context.Background(), gitJob(repo.URL, "", 0))
	if res.Err == nil {
		t.Fatal("scan error should propagate")
	}
	assertEmptyDir(t, ws)
}

func TestFetch_CleanupOnScanPanic(t *testing.T) {
	repo := newFixtureRepo(t)
	ws := t.TempDir()
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(context.Context, Job) Result { panic("boom") })}
	func() {
		defer func() { _ = recover() }()
		fr.Scan(context.Background(), gitJob(repo.URL, "", 0))
	}()
	assertEmptyDir(t, ws)
}

func TestFetch_CleanupOnFetchFailure(t *testing.T) {
	requireGit(t)
	ws := t.TempDir()
	called := false
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(_ context.Context, j Job) Result {
		called = true
		return Result{Job: j}
	})}
	res := fr.Scan(context.Background(), gitJob("file:///nonexistent/achilles-test/missing.git", "", 0))
	if res.Err == nil || called {
		t.Fatalf("fetch failure must fail the job without scanning: err=%v called=%v", res.Err, called)
	}
	if !strings.Contains(res.Err.Error(), "missing.git") || res.Detail == "" {
		t.Errorf("error should name the source and carry detail: %v / %q", res.Err, res.Detail)
	}
	assertEmptyDir(t, ws)
}

func TestFetch_BadRefFails(t *testing.T) {
	repo := newFixtureRepo(t)
	ws := t.TempDir()
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(_ context.Context, j Job) Result { return Result{Job: j} })}
	if res := fr.Scan(context.Background(), gitJob(repo.URL, "no-such-branch", 0)); res.Err == nil {
		t.Fatal("unknown ref must fail")
	}
	assertEmptyDir(t, ws)
}

func TestFetch_CleanupOnCancel(t *testing.T) {
	repo := newFixtureRepo(t)
	ws := t.TempDir()
	started := make(chan struct{})
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(ctx context.Context, j Job) Result {
		close(started)
		<-ctx.Done() // a long scan, interrupted by shutdown
		return Result{Job: j, Err: ctx.Err()}
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result)
	go func() { done <- fr.Scan(ctx, gitJob(repo.URL, "", 0)) }()
	// Wait for the inner scan to start, but not forever: if the fetch fails first
	// the inner runner never runs, and a bare `<-started` hung this test (and the
	// whole package) until the 10-minute test timeout.
	select {
	case <-started:
	case res := <-done:
		t.Fatalf("Scan returned before the inner scan started: %v", res.Err)
	case <-time.After(60 * time.Second):
		t.Fatal("the inner scan never started")
	}
	cancel()
	select {
	case res := <-done:
		if res.Err == nil {
			t.Error("cancelled scan should report an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Scan did not return after cancel")
	}
	assertEmptyDir(t, ws)
}

func TestFetch_PathTargetsPassThroughUntouched(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "never-created")
	var got Job
	fr := FetchingRunner{Workspace: ws, Inner: runnerFunc(func(_ context.Context, j Job) Result {
		got = j
		return Result{Job: j, Detail: "inner"}
	})}
	in := Job{Tenant: "acme", Target: "/work/acme/api", Mode: "oss", Profile: "default"}
	res := fr.Scan(context.Background(), in)
	if got != in || res.Detail != "inner" || res.Job != in {
		t.Errorf("path job altered: in=%+v got=%+v res=%+v", in, got, res)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Error("path targets must not create a workspace")
	}
}

// ---- fake-git tests: argv/env/log/error hygiene ---------------------------

const (
	fakeToken  = "ghp_FAKEtokenDoNotLeak0123456789"
	fakeSHA    = "0123456789abcdef0123456789abcdef01234567"
	fakeKeyBod = "FAKEKEYBODYLINE1234567890abcdefXYZ"
)

type fakeGit struct{ bin, argvLog, envLog string }

// newFakeGit writes a `git` stand-in that records argv and env, then behaves per
// failFetch: either dies on `fetch` printing secrets the way a hostile server or
// verbose git might, or succeeds (rev-parse prints a fixed sha).
func newFakeGit(t *testing.T, failFetch bool) fakeGit {
	t.Helper()
	requireSh(t)
	dir := t.TempDir()
	fg := fakeGit{bin: filepath.Join(dir, "git"), argvLog: filepath.Join(dir, "argv.log"), envLog: filepath.Join(dir, "env.log")}
	fail := ""
	if failFetch {
		fail = fmt.Sprintf(`
  fetch)
    echo "fatal: unable to access 'https://x-access-token:%[1]s@example.com/acme/app.git/': 403" >&2
    echo "debug: sent $GIT_CONFIG_VALUE_0" >&2
    echo "debug: token is %[1]s" >&2
    echo "debug: otherpw https://bob:hunter2pw@example.com/x" >&2
    if [ -n "$KEY" ]; then cat "$KEY" >&2; fi
    exit 128;;`, fakeToken)
	}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" >> %[1]q
echo "--- git $1" >> %[2]q
env >> %[2]q
KEY=$(printf '%%s' "$GIT_SSH_COMMAND" | sed -n "s/.* -i '\(.*\)'$/\1/p")
if [ -n "$KEY" ]; then ls -l "$KEY" >> %[2]q; fi
case "$1" in%[3]s
  rev-parse) echo %[4]s;;
esac
exit 0
`, fg.argvLog, fg.envLog, fail, fakeSHA)
	if err := os.WriteFile(fg.bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return fg
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		return os.Getenv(k)
	}
}

type logSink struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logSink) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, format+"\n", args...)
}
func (l *logSink) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func tokenJob() Job {
	g := &GitSource{URL: "https://example.com/acme/example-app.git", Auth: GitAuth{TokenEnv: "ACME_GIT_TOKEN"}}
	return Job{Tenant: "acme", Target: Target{Git: g}.Label(), Source: g}
}

func TestFetch_TokenNeverInArgvLogsOrErrors(t *testing.T) {
	fg := newFakeGit(t, true)
	t.Setenv("ACHILLES_LLM_API_KEY", "llm-secret-must-not-reach-git")
	ws := t.TempDir()
	var logs logSink
	fr := FetchingRunner{Git: fg.bin, Workspace: ws, Logf: logs.Logf,
		Getenv: envMap(map[string]string{"ACME_GIT_TOKEN": fakeToken + "\n"}), // trailing newline like a mounted secret
		Inner:  runnerFunc(func(_ context.Context, j Job) Result { t.Error("must not scan after a failed fetch"); return Result{} })}
	res := fr.Scan(context.Background(), tokenJob())
	if res.Err == nil {
		t.Fatal("fetch should fail")
	}

	b64 := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + fakeToken))
	for name, text := range map[string]string{"err": res.Err.Error(), "detail": res.Detail, "log": logs.String()} {
		for _, secret := range []string{fakeToken, "hunter2pw", "Authorization: Basic", b64} {
			if strings.Contains(text, secret) {
				t.Errorf("%s leaked %q:\n%s", name, secret, text)
			}
		}
	}
	if !strings.Contains(res.Err.Error(), "[REDACTED]") || !strings.Contains(res.Err.Error(), "***@") {
		t.Errorf("expected redaction markers in %q", res.Err)
	}

	argv := readFile(t, fg.argvLog)
	if strings.Contains(argv, fakeToken) || strings.Contains(argv, "Authorization") || strings.Contains(argv, "x-access-token") {
		t.Errorf("credential in argv (visible via ps):\n%s", argv)
	}
	if !strings.Contains(argv, "https://example.com/acme/example-app.git") {
		t.Errorf("clean URL expected in argv:\n%s", argv)
	}
	env := readFile(t, fg.envLog)
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic ", "GIT_CONFIG_GLOBAL=/dev/null"} {
		if !strings.Contains(env, want) {
			t.Errorf("git env missing %q", want)
		}
	}
	if strings.Contains(env, "llm-secret-must-not-reach-git") || strings.Contains(env, "ACHILLES_LLM_API_KEY") {
		t.Error("unrelated secrets from the parent env leaked into git's environment")
	}
	assertEmptyDir(t, ws)
}

func TestFetch_MissingCredentialEnvIsActionable(t *testing.T) {
	fg := newFakeGit(t, false)
	fr := FetchingRunner{Git: fg.bin, Workspace: t.TempDir(), Getenv: envMap(map[string]string{"ACME_GIT_TOKEN": "  "}),
		Inner: runnerFunc(func(_ context.Context, j Job) Result { t.Error("must not scan"); return Result{} })}
	res := fr.Scan(context.Background(), tokenJob())
	if res.Err == nil || !strings.Contains(res.Err.Error(), "ACME_GIT_TOKEN") {
		t.Fatalf("error should name the unset variable: %v", res.Err)
	}
	if _, err := os.Stat(fg.argvLog); err == nil {
		t.Error("git must not run without its credential")
	}
}

func sshJob() Job {
	g := &GitSource{URL: "git@example.com:acme/example-app.git", Auth: GitAuth{SSHKeyEnv: "ACME_DEPLOY_KEY"}}
	return Job{Tenant: "acme", Target: Target{Git: g}.Label(), Source: g}
}

var fakeKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + fakeKeyBod + "\n-----END OPENSSH PRIVATE KEY-----"

func TestFetch_SSHKeyFile0600AndRemoved(t *testing.T) {
	fg := newFakeGit(t, false)
	ws := t.TempDir()
	fr := FetchingRunner{Git: fg.bin, Workspace: ws, Getenv: envMap(map[string]string{"ACME_DEPLOY_KEY": fakeKey}),
		Inner: runnerFunc(func(_ context.Context, j Job) Result {
			// By the time the scanner runs, the key must already be gone.
			ents, _ := os.ReadDir(filepath.Dir(j.Target))
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), "id_") {
					t.Errorf("ssh key file %s still present during the scan", e.Name())
				}
			}
			return Result{Job: j}
		})}
	if res := fr.Scan(context.Background(), sshJob()); res.Err != nil {
		t.Fatalf("scan: %v / %s", res.Err, res.Detail)
	}
	env := readFile(t, fg.envLog)
	if !strings.Contains(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes") || !strings.Contains(env, "IdentitiesOnly=yes -i '") {
		t.Errorf("GIT_SSH_COMMAND not set as expected:\n%s", env)
	}
	if !strings.Contains(env, "-rw-------") {
		t.Errorf("key file was not mode 0600:\n%s", env)
	}
	if strings.Contains(readFile(t, fg.argvLog), fakeKeyBod) {
		t.Error("key material in argv")
	}
	assertEmptyDir(t, ws)
}

func TestFetch_SSHKeyScrubbedFromErrors(t *testing.T) {
	fg := newFakeGit(t, true) // fake cats the key file to stderr on fetch failure
	ws := t.TempDir()
	var logs logSink
	fr := FetchingRunner{Git: fg.bin, Workspace: ws, Logf: logs.Logf,
		Getenv: envMap(map[string]string{"ACME_DEPLOY_KEY": fakeKey}),
		Inner:  runnerFunc(func(_ context.Context, j Job) Result { t.Error("must not scan"); return Result{} })}
	res := fr.Scan(context.Background(), sshJob())
	if res.Err == nil {
		t.Fatal("fetch should fail")
	}
	for name, text := range map[string]string{"err": res.Err.Error(), "detail": res.Detail, "log": logs.String()} {
		if strings.Contains(text, fakeKeyBod) {
			t.Errorf("%s leaked key material:\n%s", name, text)
		}
	}
	// key file gone, workspace clean
	assertEmptyDir(t, ws)
}

func TestFetch_TimeoutIsBoundedAndCleansUp(t *testing.T) {
	requireSh(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "git")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	fr := FetchingRunner{Git: bin, Workspace: ws, Timeout: 300 * time.Millisecond,
		Inner: runnerFunc(func(_ context.Context, j Job) Result { t.Error("must not scan"); return Result{} })}
	start := time.Now()
	res := fr.Scan(context.Background(), gitJob("file:///srv/x/app.git", "", 0))
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", res.Err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("timeout not enforced promptly: %v", d)
	}
	assertEmptyDir(t, ws)
}

func TestScrubber(t *testing.T) {
	var s scrubber
	s.add("tok123456", "Authorization: Basic abc")
	got := s.scrub("see Authorization: Basic abc and tok123456 at https://u:pw@h/x")
	if strings.Contains(got, "tok123456") || strings.Contains(got, "abc") || strings.Contains(got, "pw@") {
		t.Errorf("scrub incomplete: %q", got)
	}
}

func TestRepoDirName(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/acme/example-app.git": "example-app",
		"git@example.com:acme/example-app.git":     "example-app",
		"file:///srv/mirrors/app.git/":             "app",
		"https://example.com/":                     "example.com",
	} {
		if got := repoDirName(in); got != want {
			t.Errorf("repoDirName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("/a b/it's"); got != `'/a b/it'\''s'` {
		t.Errorf("shellQuote = %s", got)
	}
}
