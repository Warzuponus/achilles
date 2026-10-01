package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestTarget_MixedPathAndGitSource(t *testing.T) {
	c, err := loadYAML(t, `tenants:
  - id: acme
    targets:
      - /work/acme/api
      - url: https://example.com/acme/example-app.git
        ref: release/1.2
        depth: 5
        auth: {tokenEnv: ACME_GIT_TOKEN}
      - url: git@example.com:acme/example-app.git
        auth: {sshKeyEnv: ACME_DEPLOY_KEY}
`)
	if err != nil {
		t.Fatal(err)
	}
	jobs := c.Plan()
	if len(jobs) != 3 {
		t.Fatalf("want 3 jobs, got %d", len(jobs))
	}
	// Plain string stays a path target, exactly as before.
	if jobs[0].Target != "/work/acme/api" || jobs[0].Source != nil {
		t.Errorf("path target changed: %+v", jobs[0])
	}
	g := jobs[1].Source
	if g == nil || g.URL != "https://example.com/acme/example-app.git" || g.Ref != "release/1.2" ||
		g.Depth != 5 || g.Auth.TokenEnv != "ACME_GIT_TOKEN" {
		t.Fatalf("git source mis-parsed: %+v", g)
	}
	if jobs[1].Target != "https://example.com/acme/example-app.git#release/1.2" {
		t.Errorf("label: %q", jobs[1].Target)
	}
	if jobs[2].Source.EffectiveDepth() != DefaultDepth || jobs[2].Source.Auth.SSHKeyEnv != "ACME_DEPLOY_KEY" {
		t.Errorf("defaults/ssh: %+v", jobs[2].Source)
	}
}

func TestTarget_Rejections(t *testing.T) {
	cases := []struct{ name, target, want string }{
		{"https creds user:pass", `{url: "https://bob:s3cr3tpw@example.com/acme/app.git"}`, "embed credentials"},
		{"https token as user", `{url: "https://ghp_s3cr3ttoken@example.com/acme/app.git"}`, "embed credentials"},
		{"ssh with password", `{url: "ssh://git:s3cr3tpw@example.com/acme/app.git"}`, "embed credentials"},
		{"http scheme", `{url: "http://example.com/acme/app.git"}`, "not allowed"},
		{"git scheme", `{url: "git://example.com/acme/app.git"}`, "not allowed"},
		{"ext transport", `{url: "ext::sh%20-c%20true"}`, "supported git URL"},
		{"ext transport with spaces", `{url: "ext::sh -c touch% /tmp/pwn"}`, "whitespace"},
		{"bare path url", `{url: "/srv/repos/app.git"}`, "supported git URL"},
		{"option injection", `{url: "--upload-pack=evil"}`, "must not start with '-'"},
		{"query string", `{url: "https://example.com/acme/app.git?token=abc"}`, "query string"},
		{"file relative host", `{url: "file://otherhost/srv/app.git"}`, "must be absolute"},
		{"no url", `{ref: main}`, "needs a url"},
		{"bad ref", `{url: "https://example.com/a/b.git", ref: "--evil"}`, "invalid ref"},
		{"ref traversal", `{url: "https://example.com/a/b.git", ref: "a..b"}`, "invalid ref"},
		{"negative depth", `{url: "https://example.com/a/b.git", depth: -1}`, "depth must be"},
		{"both auths", `{url: "https://example.com/a/b.git", auth: {tokenEnv: A, sshKeyEnv: B}}`, "only one of"},
		{"token on ssh", `{url: "git@example.com:a/b.git", auth: {tokenEnv: A}}`, "only applies to https"},
		{"key on https", `{url: "https://example.com/a/b.git", auth: {sshKeyEnv: A}}`, "only applies to ssh"},
		{"credential in env field", `{url: "https://example.com/a/b.git", auth: {tokenEnv: "ghp token value"}}`, "valid environment variable name"},
		{"unknown field", `{url: "https://example.com/a/b.git", tokenenv: A}`, `unknown git source field "tokenenv"`},
		{"unknown auth field", `{url: "https://example.com/a/b.git", auth: {token: A}}`, `unknown auth field "token"`},
		{"auth not mapping", `{url: "https://example.com/a/b.git", auth: A}`, "auth must be a mapping"},
		{"empty path", `""`, "empty target path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, "tenants:\n  - id: acme\n    targets:\n      - "+tc.target+"\n")
			if err == nil {
				t.Fatalf("expected rejection containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing %q", err, tc.want)
			}
			// An embedded credential must never be echoed back in the error.
			for _, secret := range []string{"s3cr3tpw", "s3cr3ttoken"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaked credential %q: %v", secret, err)
				}
			}
		})
	}
}

func TestTarget_AcceptedURLForms(t *testing.T) {
	for _, u := range []string{
		"https://example.com/acme/app.git",
		"https://example.com:8443/acme/app",
		"ssh://git@example.com/acme/app.git",
		"ssh://example.com:2222/acme/app.git",
		"git@example.com:acme/app.git",
		"file:///srv/mirrors/app.git",
		"file://localhost/srv/mirrors/app.git",
	} {
		if err := (Target{Git: &GitSource{URL: u}}).Validate(); err != nil {
			t.Errorf("%s should be accepted: %v", u, err)
		}
	}
}
