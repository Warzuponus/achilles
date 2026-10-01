package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestResolveTenant_Precedence(t *testing.T) {
	cases := []struct {
		name, header, query, cookie, want string
	}{
		{"default when nothing given", "", "", "", "default"},
		{"header wins", "hdr", "qry", "ck", "hdr"},
		{"query beats cookie", "", "qry", "ck", "qry"},
		{"cookie when only cookie", "", "", "ck", "ck"},
		// A bad value must never reach a store or a cookie.
		{"invalid header falls through", "bad/../id", "", "ck", "ck"},
		{"invalid query falls through", "", "bad id!", "ck", "ck"},
		{"invalid cookie falls back", "", "", "../etc", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?tenant="+url.QueryEscape(c.query), nil)
			if c.header != "" {
				r.Header.Set("X-Tenant", c.header)
			}
			if c.cookie != "" {
				r.AddCookie(&http.Cookie{Name: tenantCookie, Value: c.cookie})
			}
			if got := resolveTenant(httptest.NewRecorder(), r); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// Selecting a tenant must stick, so clicking into a run stays in that tenant.
func TestResolveTenant_QuerySetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/?tenant=acme", nil)
	if got := resolveTenant(w, r); got != "acme" {
		t.Fatalf("tenant=%q", got)
	}
	sc := w.Result().Cookies()
	if len(sc) != 1 || sc[0].Name != tenantCookie || sc[0].Value != "acme" {
		t.Fatalf("expected the choice persisted to a cookie, got %+v", sc)
	}
	if !sc[0].HttpOnly || sc[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("tenant cookie must be HttpOnly+SameSite=Lax, got %+v", sc[0])
	}
	if sc[0].Secure {
		t.Error("a plain-HTTP request must not set a Secure cookie (browsers would drop it)")
	}
}

func TestResolveTenant_InvalidQueryDoesNotSetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/?tenant="+url.QueryEscape("../../evil"), nil)
	resolveTenant(w, r)
	if len(w.Result().Cookies()) != 0 {
		t.Error("an invalid tenant must not be persisted")
	}
}

// The dropdown must list tenants that only exist as DATA (never registered),
// which is the whole point — scans don't register tenants.
func TestTenantOptions_IncludesDiscoveredAndCurrent(t *testing.T) {
	s := &Server{tenants: NewTenantsWithFactory(nil)}
	s.tenants.discover = func() ([]string, error) {
		return []string{"acme", "example-app", "bad/id"}, nil
	}
	got := s.tenantOptions("current-one")
	joined := strings.Join(got, ",")
	for _, want := range []string{"acme", "example-app", "current-one", "default"} {
		if !strings.Contains(joined, want) {
			t.Errorf("options %v missing %q", got, want)
		}
	}
	if strings.Contains(joined, "bad/id") {
		t.Error("invalid discovered id must be filtered out")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("options not sorted: %v", got)
		}
	}
}

// Discovery is best-effort: a backend that can't enumerate must not break the UI.
func TestTenantOptions_DiscoveryFailureDegrades(t *testing.T) {
	s := &Server{tenants: NewTenantsWithFactory(nil)}
	s.tenants.discover = func() ([]string, error) { return nil, http.ErrAbortHandler }
	got := s.tenantOptions("acme")
	if len(got) == 0 || !strings.Contains(strings.Join(got, ","), "acme") {
		t.Errorf("expected a usable list even when discovery fails, got %v", got)
	}
}

// Behind a TLS-terminating proxy the cookie should be Secure.
func TestResolveTenant_CookieIsSecureOverHTTPS(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/?tenant=acme", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	resolveTenant(w, r)
	if sc := w.Result().Cookies(); len(sc) != 1 || !sc[0].Secure {
		t.Errorf("want a Secure cookie when the request arrived over HTTPS, got %+v", sc)
	}
}
