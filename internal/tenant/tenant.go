// Package tenant is the project (tenant) registry: provisioning + per-project policy
// (scan mode/profile, retention). It's backed by a vault.Store — tenant configs
// are append-only records (KindTenant), so the same file/PostgreSQL backends work
// with no new storage code, and config changes keep an audit history.
package tenant

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/Warzuponus/achilles/internal/vault"
)

// Tenant is a customer's provisioning record + policy.
type Tenant struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Mode          string `json:"mode"`          // "oss" | "commercial" (default license mode)
	Profile       string `json:"profile"`       // default scan profile ("default" | "full")
	RetentionDays int    `json:"retentionDays"` // vault retention; 0 = keep forever
	Created       string `json:"created,omitempty"`
}

var idRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Registry provisions and looks up tenants. Records are keyed by RunID = tenant
// ID, so updates are new records and the latest wins.
type Registry struct {
	store vault.Store
	now   func() time.Time
}

func NewRegistry(store vault.Store) *Registry {
	return &Registry{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// Create provisions (or updates) a tenant. Defaults: mode oss, profile default.
func (r *Registry) Create(t Tenant) (Tenant, error) {
	if !idRE.MatchString(t.ID) {
		return Tenant{}, fmt.Errorf("invalid tenant id %q", t.ID)
	}
	if t.Mode == "" {
		t.Mode = "oss"
	}
	if t.Profile == "" {
		t.Profile = "default"
	}
	if t.RetentionDays < 0 {
		return Tenant{}, fmt.Errorf("retentionDays must be >= 0")
	}
	if t.Created == "" {
		t.Created = r.now().Format(time.RFC3339)
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return Tenant{}, err
	}
	if _, err := r.store.Append(vault.Record{RunID: t.ID, Kind: vault.KindTenant, Source: "admin", Payload: payload}); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Get returns the latest config for a tenant.
func (r *Registry) Get(id string) (Tenant, bool) {
	var latest *Tenant
	for _, rec := range r.store.ByRun(id) { // insertion order → last KindTenant wins
		if rec.Kind != vault.KindTenant {
			continue
		}
		var t Tenant
		if json.Unmarshal(rec.Payload, &t) == nil {
			cp := t
			latest = &cp
		}
	}
	if latest == nil {
		return Tenant{}, false
	}
	return *latest, true
}

// List returns the latest config for every provisioned tenant.
func (r *Registry) List() []Tenant {
	byID := map[string]Tenant{}
	var order []string
	for _, rec := range r.store.All() {
		if rec.Kind != vault.KindTenant {
			continue
		}
		var t Tenant
		if json.Unmarshal(rec.Payload, &t) != nil {
			continue
		}
		if _, seen := byID[t.ID]; !seen {
			order = append(order, t.ID)
		}
		byID[t.ID] = t // latest wins
	}
	out := make([]Tenant, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}
