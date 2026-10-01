package tenant

import (
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/vault"
)

func newRegistry(t *testing.T) *Registry {
	t.Helper()
	v, err := vault.NewFileStore(filepath.Join(t.TempDir(), "admin.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return NewRegistry(v)
}

func TestCreateGetList(t *testing.T) {
	r := newRegistry(t)
	if _, err := r.Create(Tenant{ID: "acme", Name: "Acme", Mode: "commercial", Profile: "full", RetentionDays: 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(Tenant{ID: "globex", Name: "Globex"}); err != nil {
		t.Fatal(err)
	}

	acme, ok := r.Get("acme")
	if !ok || acme.Mode != "commercial" || acme.RetentionDays != 30 {
		t.Errorf("get acme: %+v ok=%v", acme, ok)
	}
	// Defaults applied.
	globex, _ := r.Get("globex")
	if globex.Mode != "oss" || globex.Profile != "default" {
		t.Errorf("defaults not applied: %+v", globex)
	}
	if globex.Created == "" {
		t.Error("Created should be stamped")
	}
	if n := len(r.List()); n != 2 {
		t.Errorf("list: want 2, got %d", n)
	}
}

func TestUpdateLatestWins(t *testing.T) {
	r := newRegistry(t)
	r.Create(Tenant{ID: "acme", Name: "Acme", RetentionDays: 30})
	r.Create(Tenant{ID: "acme", Name: "Acme Corp", RetentionDays: 7}) // update

	got, _ := r.Get("acme")
	if got.Name != "Acme Corp" || got.RetentionDays != 7 {
		t.Errorf("latest config should win: %+v", got)
	}
	if n := len(r.List()); n != 1 {
		t.Errorf("update should not duplicate the tenant: got %d", n)
	}
}

func TestCreateValidates(t *testing.T) {
	r := newRegistry(t)
	if _, err := r.Create(Tenant{ID: "bad id!"}); err == nil {
		t.Error("invalid tenant id should error")
	}
	if _, err := r.Create(Tenant{ID: "x", RetentionDays: -1}); err == nil {
		t.Error("negative retention should error")
	}
}

func TestGetMissing(t *testing.T) {
	if _, ok := newRegistry(t).Get("nope"); ok {
		t.Error("missing tenant should return ok=false")
	}
}
