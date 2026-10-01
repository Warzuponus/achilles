package fleet

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Target is one thing to scan for a tenant: either a local filesystem path (the
// original, still-default form) or a git source that the fleet fetches into an
// ephemeral workspace first. In YAML a plain string is a path; a mapping is a git
// source:
//
//	targets:
//	  - /work/acme/api                          # path
//	  - url: https://example.com/acme/app.git   # git source
//	    ref: main                               # optional branch | tag | sha
//	    depth: 1                                # optional, default 1
//	    auth: {tokenEnv: ACME_GIT_TOKEN}        # optional: tokenEnv | sshKeyEnv
type Target struct {
	Path string
	Git  *GitSource
}

// GitSource describes a repository to clone. It carries no secret: Auth only
// NAMES the environment variable that holds the credential.
type GitSource struct {
	URL   string  `yaml:"url"`
	Ref   string  `yaml:"ref"`
	Depth int     `yaml:"depth"`
	Auth  GitAuth `yaml:"auth"`
}

// GitAuth names the env var holding the credential (never the credential itself).
// At most one may be set.
type GitAuth struct {
	TokenEnv  string `yaml:"tokenEnv"`  // https: env var holding an access token
	SSHKeyEnv string `yaml:"sshKeyEnv"` // ssh: env var holding the PEM private key
}

// DefaultDepth is the clone depth when a git source doesn't set one.
const DefaultDepth = 1

// UnmarshalYAML accepts a scalar (path) or a mapping (git source). Mappings are
// strict: unknown keys are errors, so a typo like `tokenenv` can't silently
// downgrade to an unauthenticated clone.
func (t *Target) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var p string
		if err := n.Decode(&p); err != nil {
			return fmt.Errorf("line %d: target must be a path string or a git source mapping", n.Line)
		}
		*t = Target{Path: p}
		return nil
	case yaml.MappingNode:
		if err := checkKeys(n, "git source", "url", "ref", "depth", "auth"); err != nil {
			return err
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "auth" {
				if n.Content[i+1].Kind != yaml.MappingNode {
					return fmt.Errorf("line %d: auth must be a mapping with tokenEnv or sshKeyEnv", n.Content[i+1].Line)
				}
				if err := checkKeys(n.Content[i+1], "auth", "tokenEnv", "sshKeyEnv"); err != nil {
					return err
				}
			}
		}
		var g GitSource
		if err := n.Decode(&g); err != nil {
			return fmt.Errorf("line %d: invalid git source: %s", n.Line, redactURLs(err.Error()))
		}
		*t = Target{Git: &g}
		return nil
	default:
		return fmt.Errorf("line %d: target must be a path string or a git source mapping", n.Line)
	}
}

func checkKeys(n *yaml.Node, what string, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if !ok[k.Value] {
			return fmt.Errorf("line %d: unknown %s field %q (allowed: %s)", k.Line, what, k.Value, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// Label is the human/identity string for the target: the path, or the repo URL
// (credential-free by validation) plus "#ref" when a ref is pinned.
func (t Target) Label() string {
	if t.Git == nil {
		return t.Path
	}
	if t.Git.Ref != "" {
		return t.Git.URL + "#" + t.Git.Ref
	}
	return t.Git.URL
}

// Validate checks the target. Path targets only need to be non-empty.
func (t Target) Validate() error {
	if t.Git == nil {
		if strings.TrimSpace(t.Path) == "" {
			return fmt.Errorf("empty target path")
		}
		return nil
	}
	return t.Git.Validate()
}

var (
	refRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/+@-]*$`)
	envRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	scpRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$`)
	userinfo = regexp.MustCompile(`://[^/@\s]*@`)
)

// redactURLs masks any userinfo (user:pass@) so error text is safe to print even
// when the offending value was a URL with embedded credentials.
func redactURLs(s string) string { return userinfo.ReplaceAllString(s, "://***@") }

// Validate enforces the source rules with actionable messages. Errors never echo
// embedded credentials.
func (g *GitSource) Validate() error {
	kind, err := validateGitURL(g.URL)
	if err != nil {
		return err
	}
	if g.Ref != "" {
		if len(g.Ref) > 255 || !refRE.MatchString(g.Ref) || strings.Contains(g.Ref, "..") ||
			strings.Contains(g.Ref, "@{") || strings.HasSuffix(g.Ref, "/") {
			return fmt.Errorf("invalid ref %q (use a branch, tag or commit sha)", g.Ref)
		}
	}
	if g.Depth < 0 {
		return fmt.Errorf("depth must be >= 1 (got %d); omit it for the default of %d", g.Depth, DefaultDepth)
	}
	a := g.Auth
	if a.TokenEnv != "" && a.SSHKeyEnv != "" {
		return fmt.Errorf("auth: set only one of tokenEnv or sshKeyEnv")
	}
	for _, name := range []string{a.TokenEnv, a.SSHKeyEnv} {
		if name != "" && !envRE.MatchString(name) {
			return fmt.Errorf("auth: value is not a valid environment variable name (auth names the variable that holds the credential; never put the credential in the config)")
		}
	}
	if a.TokenEnv != "" && kind != "https" {
		return fmt.Errorf("auth.tokenEnv only applies to https:// URLs (this URL is %s)", kind)
	}
	if a.SSHKeyEnv != "" && kind != "ssh" {
		return fmt.Errorf("auth.sshKeyEnv only applies to ssh:// or git@host:path URLs (this URL is %s)", kind)
	}
	return nil
}

// EffectiveDepth is the clone depth after applying the default.
func (g *GitSource) EffectiveDepth() int {
	if g.Depth <= 0 {
		return DefaultDepth
	}
	return g.Depth
}

// validateGitURL accepts only https://, ssh://, git@host:path (scp-like) and
// file://, and rejects anything that embeds credentials. It returns the transport
// kind: "https" | "ssh" | "file".
func validateGitURL(raw string) (string, error) {
	safe := redactURLs(raw)
	if raw == "" {
		return "", fmt.Errorf("git source needs a url")
	}
	for _, r := range raw {
		if r <= ' ' || r == 0x7f {
			return "", fmt.Errorf("url %q contains whitespace or control characters", safe)
		}
	}
	if strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("url %q must not start with '-'", safe)
	}
	const hint = "use https://, ssh://, git@host:path or file://"
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("url %q is not valid (%s)", safe, hint)
		}
		if u.User != nil {
			_, hasPw := u.User.Password()
			if hasPw || u.Scheme != "ssh" {
				return "", fmt.Errorf("url must not embed credentials (user:pass@); remove them and use auth.tokenEnv (https) or auth.sshKeyEnv (ssh)")
			}
		}
		if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
			return "", fmt.Errorf("url %q must not carry a query string or fragment (put the branch/tag in ref)", safe)
		}
		switch u.Scheme {
		case "https", "ssh":
			if u.Host == "" || u.Path == "" || u.Path == "/" {
				return "", fmt.Errorf("url %q needs a host and repository path", safe)
			}
			return u.Scheme, nil
		case "file":
			if (u.Host != "" && u.Host != "localhost") || !strings.HasPrefix(u.Path, "/") {
				return "", fmt.Errorf("file:// url %q must be absolute, like file:///srv/mirrors/app.git", safe)
			}
			return "file", nil
		default:
			return "", fmt.Errorf("url %q: scheme %q is not allowed (%s)", safe, u.Scheme, hint)
		}
	}
	if scpRE.MatchString(raw) {
		return "ssh", nil
	}
	return "", fmt.Errorf("url %q is not a supported git URL (%s)", safe, hint)
}
