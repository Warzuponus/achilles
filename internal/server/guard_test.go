package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// There is no authentication, so these two protections are the whole defence of a
// local War Room against the web page you happen to have open in another tab.

func guardServer(t *testing.T, opts ...Option) http.Handler {
	t.Helper()
	s, tenants := newServer(t)
	for _, o := range opts {
		o(s)
	}
	seed(t, tenants, "acme", "run1", evalFinding())
	return s.Handler()
}

func req(method, target, host string, hdr map[string]string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = host
	r.Header.Set("X-Tenant", "acme")
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func serve(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestHostHeader_OnlyThisMachineIsAccepted(t *testing.T) {
	h := guardServer(t)
	for _, tc := range []struct {
		host string
		want int
	}{
		{"localhost:8080", 200}, {"localhost", 200}, {"LOCALHOST:9", 200},
		{"127.0.0.1:8080", 200}, {"[::1]:8080", 200}, {"[::1]", 200},
		// DNS rebinding: a hostile name that resolves to 127.0.0.1 arrives with ITS name.
		{"evil.example.com", 403}, {"evil.example.com:8080", 403},
		{"127.0.0.1.evil.example.com", 403}, {"192.168.1.5:8080", 403}, {"", 403},
	} {
		if got := serve(h, req("GET", "/", tc.host, nil, "")); got != tc.want {
			t.Errorf("Host %q: got %d, want %d", tc.host, got, tc.want)
		}
	}
}

func TestHostHeader_ExplicitlyAllowedHostsWork(t *testing.T) {
	h := guardServer(t, WithAllowedHosts("War.Example.com", " 10.0.0.7 "))
	for _, host := range []string{"war.example.com", "war.example.com:443", "10.0.0.7:8080"} {
		if got := serve(h, req("GET", "/", host, nil, "")); got != 200 {
			t.Errorf("allowed host %q: got %d", host, got)
		}
	}
	if got := serve(h, req("GET", "/", "other.example.com", nil, "")); got != 403 {
		t.Errorf("a host that is not listed must still be refused, got %d", got)
	}
}

func TestHealthz_IgnoresTheHostGuard(t *testing.T) {
	h := guardServer(t)
	if got := serve(h, req("GET", "/healthz", "anything.internal:80", nil, "")); got != 200 {
		t.Errorf("/healthz must answer for orchestrator probes, got %d", got)
	}
}

func TestCrossOriginWrites_AreRejected(t *testing.T) {
	h := guardServer(t)
	form := url.Values{"fingerprint": {"fp1"}, "label": {"fp"}}.Encode()
	post := func(hdr map[string]string) int {
		return serve(h, req("POST", "/runs/run1/feedback", "localhost:8080", hdr, form))
	}
	purge := func(hdr map[string]string) int {
		return serve(h, req("POST", "/admin/tenants/acme/purge", "localhost:8080", hdr, ""))
	}

	// A web page on another site submitting a form / fetch to localhost.
	for name, hdr := range map[string]map[string]string{
		"sec-fetch-site cross-site": {"Sec-Fetch-Site": "cross-site"},
		"sec-fetch-site same-site":  {"Sec-Fetch-Site": "same-site"},
		"foreign Origin":            {"Origin": "https://evil.example.com"},
	} {
		if got := post(hdr); got != http.StatusForbidden {
			t.Errorf("feedback POST with %s: got %d, want 403", name, got)
		}
		if got := purge(hdr); got != http.StatusForbidden {
			t.Errorf("purge POST with %s: got %d, want 403 (never reaching the handler)", name, got)
		}
	}

	// The War Room's own page, and plain API clients, still work.
	for name, hdr := range map[string]map[string]string{
		"same-origin browser": {"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost:8080"},
		"curl (no headers)":   nil,
	} {
		if got := post(hdr); got != 200 {
			t.Errorf("feedback POST from %s: got %d, want 200", name, got)
		}
	}
}

func TestCrossOriginReads_StillServeButCarryNoCORSGrant(t *testing.T) {
	// Reads are not blocked server-side (a browser's same-origin policy stops a hostile page
	// from reading the response); what matters is that we never grant cross-origin access.
	h := guardServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/runs/run1/audit", "localhost:8080", map[string]string{"Origin": "https://evil.example.com"}, ""))
	if v := w.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("must not send CORS grants, got %q", v)
	}
}
