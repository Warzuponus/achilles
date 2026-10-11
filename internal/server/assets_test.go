package server

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// The War Room shows findings from repositories you may not trust. Nothing in a page
// may come from another origin, and nothing may run that is not the embedded script.
func TestTemplates_LoadNothingFromAnotherOrigin(t *testing.T) {
	remote := regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']?\s*(https?:)?//`)
	inline := regexp.MustCompile(`(?i)\son[a-z]+\s*=|<script(\s[^>]*)?>\s*[^<\s]|javascript:|\shx-|\sx-data`)
	err := fs.WalkDir(templatesFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(templatesFS, p)
		if err != nil {
			return err
		}
		if m := remote.Find(b); m != nil {
			t.Errorf("%s loads from another origin: %q", p, m)
		}
		if m := inline.Find(b); m != nil {
			t.Errorf("%s has inline script or a script-library attribute the policy would block: %q", p, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStaticScriptIsServedFromTheBinary(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	w := do(h, "GET", "/static/warroom.js", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /static/warroom.js = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want a JavaScript type (nosniff is set, so a wrong type will not run)", ct)
	}
	if !strings.Contains(w.Body.String(), "data-feedback") {
		t.Error("the served script is not the War Room script")
	}
	for _, p := range []string{"/static/", "/static", "/static/nope.js", "/static/../server.go"} {
		if code := do(h, "GET", p, "", nil).Code; code == http.StatusOK {
			t.Errorf("GET %s = 200, want it refused", p)
		}
	}
}

func TestEveryResponseCarriesTheContentSecurityPolicy(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", model.Finding{Fingerprint: "fp1", RuleID: "r", Tool: "t"})
	h := s.Handler()

	for _, p := range []string{"/", "/runs/run1", "/runs/run1/audit", "/static/warroom.js", "/admin/fleet", "/no-such-page"} {
		w := do(h, "GET", p, "acme", nil)
		csp := w.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("GET %s: policy %q lacks %q", p, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || regexp.MustCompile(`script-src[^;]*unsafe-inline`).MatchString(csp) {
			t.Errorf("GET %s: policy allows inline or eval script: %q", p, csp)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: no X-Content-Type-Options: nosniff", p)
		}
	}
}

// The run page's feedback form must work as an ordinary form post (no script), and
// the pages must reference the embedded script and nothing else.
func TestRunPage_FeedbackFormPostsWithoutAScriptLibrary(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", model.Finding{Fingerprint: "fp1", RuleID: "r", Tool: "t"})
	body := do(s.Handler(), "GET", "/runs/run1", "acme", nil).Body.String()

	if !strings.Contains(body, `method="post" action="/runs/run1/feedback"`) {
		t.Error("the feedback form is not a plain form post to this run")
	}
	if !strings.Contains(body, `<script defer src="/static/warroom.js"></script>`) {
		t.Error("the run page does not load the embedded script")
	}
	if n := strings.Count(body, "<script"); n != 1 {
		t.Errorf("the run page has %d script tags, want exactly the embedded one", n)
	}
}

// "GET /" used to match every path, so a mistyped URL rendered the dashboard with
// a 200 instead of saying the page does not exist.
func TestUnknownPathIsNotFound(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	if code := do(h, "GET", "/", "", nil).Code; code != http.StatusOK {
		t.Errorf("GET / = %d, want 200", code)
	}
	if code := do(h, "GET", "/?tenant=acme", "", nil).Code; code != http.StatusOK {
		t.Errorf("GET /?tenant=acme = %d, want 200 (the project switcher)", code)
	}
	for _, p := range []string{"/no-such-page", "/runs", "/admin"} {
		if code := do(h, "GET", p, "", nil).Code; code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}
