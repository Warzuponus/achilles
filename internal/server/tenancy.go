package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/Warzuponus/achilles/internal/vault"
)

// Tenants manages per-tenant Evidence Vaults. Each tenant gets its own isolated
// Store (its own directory for the file backend, its own key for the
// database backend), so one tenant's handle can never read another's records —
// isolation is structural, not a filter (DESIGN.md §10).
type Tenants struct {
	factory func(tenant string) (vault.Store, error)
	// discover lists tenants that actually hold data. Optional: nil means "we
	// can't enumerate", and callers fall back to the registry alone.
	discover func() ([]string, error)
	mu       sync.Mutex
	stores   map[string]vault.Store
}

// NewTenants builds tenants over a file-backed vault root (one dir per tenant).
func NewTenants(root string) *Tenants {
	t := NewTenantsWithFactory(func(tenant string) (vault.Store, error) {
		return vault.NewFileStore(filepath.Join(root, tenant, "vault.jsonl"))
	})
	t.discover = func() ([]string, error) { return fileTenants(root) }
	return t
}

// NewTenantsPostgres builds tenants over one PostgreSQL database; each tenant is
// the key "tenant-<id>" in the shared records table (the key the
// CLI's --vault-tenant and the fleet write to).
func NewTenantsPostgres(ctx context.Context, dsn string) *Tenants {
	t := NewTenantsWithFactory(func(tenant string) (vault.Store, error) {
		return vault.NewPostgresStore(ctx, dsn, vault.TenantKey(tenant))
	})
	t.discover = func() ([]string, error) {
		return vault.PostgresTenants(ctx, dsn, vault.TenantKey(""))
	}
	return t
}

// Discover lists tenant ids that hold data, or nil if this backend can't
// enumerate. Needed because scans write straight to their tenant vault without
// registering — so the registry alone under-reports which tenants exist.
func (t *Tenants) Discover() []string {
	if t.discover == nil {
		return nil
	}
	ids, err := t.discover()
	if err != nil {
		return nil // best-effort: the UI still shows registry tenants
	}
	valid := ids[:0]
	for _, id := range ids {
		if tenantRE.MatchString(id) {
			valid = append(valid, id)
		}
	}
	return valid
}

// fileTenants lists <root>/<tenant>/vault.jsonl directories.
func fileTenants(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "vault.jsonl")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// NewTenantsWithFactory builds tenants over an arbitrary per-tenant store factory.
func NewTenantsWithFactory(factory func(tenant string) (vault.Store, error)) *Tenants {
	return &Tenants{factory: factory, stores: map[string]vault.Store{}}
}

var tenantRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Vault returns the (cached) vault for a tenant, creating it on first use. The
// tenant id is validated (prevents path traversal / collection-name injection).
func (t *Tenants) Vault(tenant string) (vault.Store, error) {
	if !tenantRE.MatchString(tenant) {
		return nil, fmt.Errorf("invalid tenant id %q", tenant)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.stores[tenant]; ok {
		return s, nil
	}
	s, err := t.factory(tenant)
	if err != nil {
		return nil, err
	}
	t.stores[tenant] = s
	return s, nil
}
