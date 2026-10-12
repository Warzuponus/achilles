package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	tenantpkg "github.com/Warzuponus/achilles/internal/tenant"
	"github.com/Warzuponus/achilles/internal/vault"
)

func seed(t *testing.T, tenants *Tenants, tenant, runID string, f model.Finding) {
	t.Helper()
	v, err := tenants.Vault(tenant)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]any{"target": "/repo/" + tenant, "mode": "commercial"})
	if _, err := v.Append(vault.Record{RunID: runID, Kind: vault.KindScanMeta, Payload: meta}); err != nil {
		t.Fatal(err)
	}
	fb, _ := json.Marshal(f)
	v.Append(vault.Record{RunID: runID, Kind: vault.KindFinding, Fingerprint: f.Fingerprint, Payload: fb})
}

func newServer(t *testing.T) (*Server, *Tenants) {
	t.Helper()
	tenants := NewTenants(t.TempDir())
	rv, err := vault.NewFileStore(filepath.Join(t.TempDir(), "admin.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(tenants, tenantpkg.NewRegistry(rv))
	if err != nil {
		t.Fatal(err)
	}
	return s, tenants
}

func do(h http.Handler, method, path, tenant string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "localhost:8080" // what a browser sends; httptest's default "example.com" is rightly refused
	if tenant != "" {
		r.Header.Set("X-Tenant", tenant)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func evalFinding() model.Finding {
	return model.Finding{
		Tool: "opengrep", RuleID: "eval", Message: "eval on input", Severity: model.SeverityHigh,
		Fingerprint: "fp1", Location: model.Location{File: "app.py", Region: model.Region{StartLine: 2}},
	}
}

func TestDashboardListsRuns(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", evalFinding())
	h := s.Handler()

	w := do(h, "GET", "/", "acme", nil)
	if w.Code != 200 {
		t.Fatalf("dashboard: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "run1") {
		t.Error("dashboard should list run1")
	}
}

func TestTenantIsolation(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "acme-run", evalFinding())
	seed(t, tenants, "globex", "globex-run", evalFinding())
	h := s.Handler()

	acme := do(h, "GET", "/", "acme", nil).Body.String()
	if !strings.Contains(acme, "acme-run") || strings.Contains(acme, "globex-run") {
		t.Error("acme must see only its own run, never globex's")
	}
	globex := do(h, "GET", "/", "globex", nil).Body.String()
	if !strings.Contains(globex, "globex-run") || strings.Contains(globex, "acme-run") {
		t.Error("globex must see only its own run, never acme's")
	}
}

func TestFeedbackIsRecordedToTheProjectVault(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", evalFinding())
	h := s.Handler()

	w := do(h, "POST", "/runs/run1/feedback", "acme", url.Values{"fingerprint": {"fp1"}, "label": {"fp"}})
	if w.Code != 200 {
		t.Fatalf("feedback should be 200, got %d (%s)", w.Code, w.Body)
	}
	v, _ := tenants.Vault("acme")
	if n := len(knowledge.NewFeedbackStore(v).History("fp1")); n != 1 {
		t.Errorf("feedback not recorded: history len %d", n)
	}
	if code := do(h, "POST", "/runs/run1/feedback", "acme", url.Values{"fingerprint": {"fp1"}, "label": {"maybe"}}).Code; code != http.StatusBadRequest {
		t.Errorf("a bad label should be 400, got %d", code)
	}
}

func TestAuditExportReturnsTheRunsRecords(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", evalFinding())
	h := s.Handler()

	w := do(h, "GET", "/runs/run1/audit", "acme", nil)
	if w.Code != 200 {
		t.Fatalf("audit should be 200, got %d", w.Code)
	}
	var recs []vault.Record
	if err := json.Unmarshal(w.Body.Bytes(), &recs); err != nil {
		t.Fatalf("audit output not JSON: %v", err)
	}
	if len(recs) == 0 {
		t.Error("audit should return the run's records")
	}
}

func TestRedactionInUI(t *testing.T) {
	s, tenants := newServer(t)
	f := evalFinding()
	f.Message = "leaked key AKIAIOSFODNN7EXAMPLE in source"
	seed(t, tenants, "acme", "run1", f)
	h := s.Handler()

	body := do(h, "GET", "/runs/run1", "acme", nil).Body.String()
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret leaked into the War Room UI")
	}
	if !strings.Contains(body, mask) {
		t.Error("expected redaction mask in the UI")
	}
}

func jsonReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "localhost:8080"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Tenant", "acme")
	return r
}

func TestAdmin_CreateAndList(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, jsonReq("POST", "/admin/tenants", `{"id":"acme","name":"Acme","mode":"commercial","retentionDays":30}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create should be 201, got %d (%s)", w.Code, w.Body)
	}

	lw := do(h, "GET", "/admin/tenants", "acme", nil)
	if lw.Code != 200 {
		t.Fatalf("list should be 200, got %d", lw.Code)
	}
	var tenants []tenantpkg.Tenant
	if err := json.Unmarshal(lw.Body.Bytes(), &tenants); err != nil {
		t.Fatalf("list not JSON: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != "acme" || tenants[0].Mode != "commercial" {
		t.Errorf("listed tenants wrong: %+v", tenants)
	}
}

func TestAdmin_Purge(t *testing.T) {
	s, tenants := newServer(t)
	h := s.Handler()
	// Provision a tenant with a 1-day retention.
	cw := httptest.NewRecorder()
	h.ServeHTTP(cw, jsonReq("POST", "/admin/tenants", `{"id":"acme","name":"Acme","retentionDays":1}`))
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d", cw.Code)
	}
	// Seed the tenant's data vault with an old + a recent record.
	v, _ := tenants.Vault("acme")
	v.Append(vault.Record{RunID: "r", Kind: vault.KindFinding, Timestamp: time.Now().Add(-48 * time.Hour)})
	v.Append(vault.Record{RunID: "r", Kind: vault.KindFinding, Timestamp: time.Now()})

	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, jsonReq("POST", "/admin/tenants/acme/purge", ""))
	if pw.Code != 200 {
		t.Fatalf("purge should be 200, got %d (%s)", pw.Code, pw.Body)
	}
	var res struct {
		Purged int `json:"purged"`
	}
	json.Unmarshal(pw.Body.Bytes(), &res)
	if res.Purged != 1 {
		t.Errorf("expected 1 purged (the 48h-old record), got %d", res.Purged)
	}
	if n := len(v.ByRun("r")); n != 1 {
		t.Errorf("one record should remain after retention purge, got %d", n)
	}
}

func TestFleetView(t *testing.T) {
	s, tenants := newServer(t)
	h := s.Handler()

	// Register two tenants and seed one with a finding.
	for _, id := range []string{"acme", "globex"} {
		cw := httptest.NewRecorder()
		h.ServeHTTP(cw, jsonReq("POST", "/admin/tenants", `{"id":"`+id+`"}`))
		if cw.Code != http.StatusCreated {
			t.Fatalf("create %s: %d", id, cw.Code)
		}
	}
	seed(t, tenants, "acme", "run1", evalFinding()) // high-severity finding

	// The rollup spans every project: both tenants + acme's finding.
	w := do(h, "GET", "/admin/fleet", "acme", nil)
	if w.Code != 200 {
		t.Fatalf("fleet should be 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Fleet totals", "acme", "globex"} {
		if !strings.Contains(body, want) {
			t.Errorf("fleet view missing %q", want)
		}
	}
}

func TestSSE(t *testing.T) {
	s, tenants := newServer(t)
	seed(t, tenants, "acme", "run1", evalFinding())
	h := s.Handler()

	w := do(h, "GET", "/events", "acme", nil)
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("SSE content-type: got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "event: run") || !strings.Contains(w.Body.String(), "event: done") {
		t.Errorf("SSE stream missing events:\n%s", w.Body.String())
	}
}

// Anything that can reach the port could otherwise make the server read an
// arbitrarily large body into memory.
func TestCreateTenant_BodyIsBounded(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	post := func(body string) int {
		r := httptest.NewRequest("POST", "/admin/tenants", strings.NewReader(body))
		r.Host = "localhost:8080"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := post(`{"id":"acme","name":"Acme"}`); code != http.StatusCreated {
		t.Fatalf("a normal project definition: %d, want 201", code)
	}
	huge := `{"id":"big","name":"` + strings.Repeat("a", maxTenantBody*2) + `"}`
	if code := post(huge); code != http.StatusBadRequest {
		t.Errorf("an oversized body: %d, want 400", code)
	}
}
