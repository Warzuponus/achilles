package server

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	tenantpkg "github.com/Warzuponus/achilles/internal/tenant"
	"github.com/Warzuponus/achilles/internal/vault"
)

// downStore is a vault whose database is unreachable: every read returns nothing,
// exactly as an empty project would, and reports the failure on the side.
type downStore struct{}

func (downStore) Append(r vault.Record) (vault.Record, error) { return r, errors.New("down") }
func (downStore) Get(string) (vault.Record, bool)             { return vault.Record{}, false }
func (downStore) ByRun(string) []vault.Record                 { return nil }
func (downStore) ByFingerprint(string) []vault.Record         { return nil }
func (downStore) All() []vault.Record                         { return nil }
func (downStore) LastReadErr() error                          { return errors.New("connection refused") }
func (downStore) ReadFailures() int                           { return 1 }

// A database outage used to render as "No runs yet": a true-looking, false
// statement about the project. It must be an error the user can see.
func TestPages_AnUnreadableVaultIsAnErrorNotAnEmptyProject(t *testing.T) {
	tenants := NewTenantsWithFactory(func(string) (vault.Store, error) { return downStore{}, nil })
	rv, err := vault.NewFileStore(filepath.Join(t.TempDir(), "admin.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	registry := tenantpkg.NewRegistry(rv)
	if _, err := registry.Create(tenantpkg.Tenant{ID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	s, err := New(tenants, registry)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	for _, p := range []string{"/", "/runs/run1", "/runs/run1/audit", "/admin/fleet"} {
		w := do(h, "GET", p, "acme", nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503", p, w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, "No runs yet") || strings.Contains(body, "No findings for this run") {
			t.Errorf("GET %s presented an outage as an empty project:\n%s", p, body)
		}
		if strings.Contains(body, "connection refused") {
			t.Errorf("GET %s leaked the backend error into the page:\n%s", p, body)
		}
	}
}

// The ordinary case: a readable, genuinely empty project is still just empty.
func TestPages_AnEmptyReadableProjectIsNotAnError(t *testing.T) {
	s, _ := newServer(t)
	w := do(s.Handler(), "GET", "/", "nobody", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "No runs yet") {
		t.Errorf("GET / on an empty project = %d, want 200 with the empty-state text", w.Code)
	}
}
