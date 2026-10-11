// Package server is the War Room HTTP layer: a server-rendered UI and JSON API over
// the Evidence Vault, with per-project (tenant) isolation and secret redaction. It is
// a single-user tool with no authentication by design; see Server for the protections
// it does provide.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/metrics"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/tenant"
	"github.com/Warzuponus/achilles/internal/vault"
)

//go:embed templates/*.html
var templatesFS embed.FS

// staticFS holds the War Room's own script. Nothing is loaded from a CDN: the page
// has to work with no network, and a script fetched from somewhere else would run
// with access to every finding shown here.
//
//go:embed static
var staticFS embed.FS

// contentSecurityPolicy is sent with every response. Scripts may come from this
// origin only (no inline script, no eval, no third party), so text that reaches a
// page from a scanned repository or a model cannot run as code even if an escaping
// bug let it through. Styles stay inline because the templates carry their own.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Server is the War Room HTTP application.
//
// It is a single-user tool and has NO authentication: anyone who can reach the port
// can read every finding and use every endpoint. Instead of pretending otherwise it
// is safe by default for local use (the caller binds loopback; see Guard):
//
//   - the Host header must name this machine, which defeats DNS-rebinding attacks that
//     would let a web page you visit read the API;
//   - state-changing requests are rejected when they come from another site (CSRF),
//     using the standard library's cross-origin protection.
//
// To share it, put your own authenticating reverse proxy in front and add its host
// name with WithAllowedHosts.
type Server struct {
	tenants  *Tenants
	registry *tenant.Registry
	tpl      *template.Template

	// allowedHosts are Host header values (lower-case, no port) accepted in addition
	// to the loopback names.
	allowedHosts map[string]bool
}

// Option customizes a Server at construction.
type Option func(*Server)

// WithAllowedHosts accepts additional Host header values (host names or IPs, no port),
// for example the name of a reverse proxy you put in front of the War Room.
func WithAllowedHosts(hosts ...string) Option {
	return func(s *Server) {
		for _, h := range hosts {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				s.allowedHosts[h] = true
			}
		}
	}
}

// New builds a server over per-tenant vaults + the tenant registry.
func New(tenants *Tenants, registry *tenant.Registry, opts ...Option) (*Server, error) {
	tpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{tenants: tenants, registry: registry, tpl: tpl, allowedHosts: map[string]bool{}}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// --- request context (tenant) ---

type ctxKey int

const ctxTenant ctxKey = iota

// Handler returns the routed handler: /healthz, then everything else behind the
// host and cross-origin guards.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// {$} matches the root only: an unknown path is a 404, not the dashboard.
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /runs/{id}", s.handleRun)
	mux.HandleFunc("POST /runs/{id}/feedback", s.handleFeedback)
	mux.HandleFunc("GET /runs/{id}/audit", s.handleAudit)
	mux.HandleFunc("GET /events", s.handleEvents)
	// Project (tenant) provisioning + retention.
	mux.HandleFunc("GET /admin/tenants", s.handleListTenants)
	mux.HandleFunc("POST /admin/tenants", s.handleCreateTenant)
	mux.HandleFunc("POST /admin/tenants/{id}/purge", s.handlePurge)
	// Rollup across every project.
	mux.HandleFunc("GET /admin/fleet", s.handleFleet)

	root := http.NewServeMux()
	// Liveness exposes nothing (no project data), so container health checks and
	// orchestrators can use it without a matching Host header.
	root.HandleFunc("GET /healthz", handleHealthz)
	// The script is the same for every project, so it sits outside withTenant (which
	// can set a cookie) but still behind the host guard.
	root.Handle("GET /static/warroom.js", s.guard(http.HandlerFunc(handleScript)))
	root.Handle("/", s.guard(s.withTenant(mux)))
	return root
}

// handleScript serves the one embedded script. The file name is fixed here, never
// taken from the request.
func handleScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, staticFS, "static/warroom.js")
}

// handleHealthz answers liveness probes. It touches no vault.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
}

// guard rejects requests that could only come from another website using this
// server on a victim's behalf: a Host header that does not name this machine
// (DNS rebinding), and cross-site state-changing requests (CSRF).
func (s *Server) guard(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	protected := cop.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !s.hostAllowed(r.Host) {
			http.Error(w, "forbidden: host not allowed (the War Room only answers to localhost; "+
				"to reach it by another name, start achillesd with --allowed-hosts)", http.StatusForbidden)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

// hostAllowed reports whether the Host header names this machine or an explicitly
// allowed host. The port is ignored.
func (s *Server) hostAllowed(hostport string) bool {
	host := strings.ToLower(hostport)
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = strings.ToLower(h)
	}
	host = strings.Trim(host, "[]") // bare IPv6 literal such as "[::1]"
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return s.allowedHosts[host]
}

// withTenant resolves which project (tenant) this request is about.
func (s *Server) withTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxTenant, resolveTenant(w, r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tenantCookie remembers the browser's selected project so navigating to a run
// detail page stays in the same project.
const tenantCookie = "achilles_tenant"

// resolveTenant picks the project for this request, most explicit first:
//
//	X-Tenant header  — programmatic callers
//	?tenant=<id>     — the War Room's switcher; also persisted to a cookie
//	cookie           — the last switcher choice, so links keep their project
//	"default"
//
// Values are validated against tenantRE so a bad id can't reach a store or a cookie.
func resolveTenant(w http.ResponseWriter, r *http.Request) string {
	if v := r.Header.Get("X-Tenant"); tenantRE.MatchString(v) {
		return v
	}
	if v := r.URL.Query().Get("tenant"); tenantRE.MatchString(v) {
		http.SetCookie(w, &http.Cookie{
			Name: tenantCookie, Value: v, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
			// The cookie only remembers a selection. Mark it Secure whenever the
			// request itself arrived over HTTPS (directly or via a TLS-terminating proxy).
			Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		return v
	}
	if c, err := r.Cookie(tenantCookie); err == nil && tenantRE.MatchString(c.Value) {
		return c.Value
	}
	return "default"
}

// tenantOptions is the switcher's list: every tenant that holds data (discovered
// from the backend) unioned with the registry's provisioned tenants, plus the
// current one so the dropdown always shows what you're looking at.
func (s *Server) tenantOptions(current string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] && tenantRE.MatchString(id) {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(current)
	for _, id := range s.tenants.Discover() {
		add(id)
	}
	if s.registry != nil {
		for _, t := range s.registry.List() {
			add(t.ID)
		}
	}
	add("default")
	sort.Strings(out)
	return out
}

func tenantOf(r *http.Request) string { v, _ := r.Context().Value(ctxTenant).(string); return v }

func (s *Server) vaultFor(w http.ResponseWriter, r *http.Request) (vault.Store, bool) {
	v, err := s.tenants.Vault(tenantOf(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return v, true
}

// --- handlers ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	v, ok := s.vaultFor(w, r)
	if !ok {
		return
	}
	s.render(w, "dashboard.html", map[string]any{
		"Tenant": tenantOf(r), "Runs": ListRuns(v),
		"Tenants": s.tenantOptions(tenantOf(r)),
	})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	v, ok := s.vaultFor(w, r)
	if !ok {
		return
	}
	runID := r.PathValue("id")
	s.render(w, "run.html", map[string]any{
		"Tenant": tenantOf(r), "RunID": runID,
		"Findings": RunFindings(v, runID),
	})
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	v, ok := s.vaultFor(w, r)
	if !ok {
		return
	}
	runID := r.PathValue("id")
	fingerprint := r.FormValue("fingerprint")
	label := knowledge.Label(map[string]knowledge.Label{"tp": knowledge.LabelTP, "fp": knowledge.LabelFP}[r.FormValue("label")])
	if fingerprint == "" || label == "" {
		http.Error(w, "fingerprint and label (tp|fp) required", http.StatusBadRequest)
		return
	}

	tool, rule := lookupToolRule(v, fingerprint)
	fb := knowledge.NewFeedbackStore(v)
	if err := fb.Record(runID, knowledge.Feedback{Fingerprint: fingerprint, Tool: tool, RuleID: rule, Label: label}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Plain text: the page's script shows it as text, and a browser without
	// JavaScript shows it as the result of the form post.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("recorded " + string(label) + " feedback\n"))
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	v, ok := s.vaultFor(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(AuditRecords(v, r.PathValue("id")))
}

// handleEvents streams run summaries as Server-Sent Events. A full live-scan
// stream is a follow-up; this proves the SSE transport for the War Room.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	v, ok := s.vaultFor(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for _, run := range ListRuns(v) {
		b, _ := json.Marshal(run)
		_, _ = w.Write([]byte("event: run\ndata: " + string(b) + "\n\n"))
		flusher.Flush()
	}
	_, _ = w.Write([]byte("event: done\ndata: {}\n\n"))
	flusher.Flush()
}

// --- project (tenant) handlers ---

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.registry.List())
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var t tenant.Tenant
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "invalid tenant JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	created, err := s.registry.Create(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, created)
}

// handlePurge applies a tenant's retention policy: delete vault records older
// than RetentionDays. RetentionDays == 0 means keep forever (no-op).
func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tnt, ok := s.registry.Get(id)
	if !ok {
		http.Error(w, "unknown tenant "+id, http.StatusNotFound)
		return
	}
	if tnt.RetentionDays <= 0 {
		writeJSON(w, map[string]any{"tenant": id, "purged": 0, "note": "retention disabled (keep forever)"})
		return
	}
	v, err := s.tenants.Vault(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	purger, ok := v.(vault.Purger)
	if !ok {
		http.Error(w, "vault backend does not support retention", http.StatusNotImplemented)
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -tnt.RetentionDays)
	n, err := purger.Purge(cutoff)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"tenant": id, "purged": n, "before": cutoff})
}

// handleFleet renders the cross-tenant rollup: fleet-wide totals + a per-tenant
// breakdown, aggregated over every project's isolated vault.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	perTenant := map[string][]vault.Record{}
	for _, t := range s.registry.List() {
		v, err := s.tenants.Vault(t.ID)
		if err != nil {
			continue
		}
		perTenant[t.ID] = v.All()
	}
	s.render(w, "fleet.html", map[string]any{
		"Fleet": metrics.ComputeFleet(perTenant, 10),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func lookupToolRule(v vault.Store, fingerprint string) (tool, rule string) {
	for _, rec := range v.ByFingerprint(fingerprint) {
		if rec.Kind == vault.KindFinding {
			var f model.Finding
			if json.Unmarshal(rec.Payload, &f) == nil {
				return f.Tool, f.RuleID
			}
		}
	}
	return "", ""
}
