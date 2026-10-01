package vault

import (
	"context"
	"fmt"
	"regexp"
)

// Options selects and configures a vault backend.
type Options struct {
	Backend string // "file" (default) | "postgres"
	Path    string // file backend: JSONL path
	DSN     string // postgres backend: connection string (from $ACHILLES_VAULT_DSN, never a flag)
	// Tenant is the project the results belong to (default "default"). The
	// postgres backend stores them under the key "tenant-<Tenant>", the same key the
	// War Room reads; the file backend is addressed by Path instead.
	Tenant string
}

// tenantRE bounds a project id: it becomes part of a database key.
var tenantRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// TenantKey is the storage key a project's records live under in a shared (database)
// backend.
func TenantKey(tenant string) string { return "tenant-" + tenant }

// Open builds a Store for the configured backend. The file backend keeps the
// single-binary/local story; the postgres backend is the shared database that lets
// scans (CLI, CI, the fleet) and the War Room see the same data.
func Open(ctx context.Context, o Options) (Store, error) {
	switch o.Backend {
	case "", "file":
		return NewFileStore(o.Path)
	case "postgres":
		tenant := o.Tenant
		if tenant == "" {
			tenant = "default"
		}
		if !tenantRE.MatchString(tenant) {
			return nil, fmt.Errorf("invalid project/tenant id %q (letters, digits, '_' and '-', up to 64)", tenant)
		}
		return NewPostgresStore(ctx, o.DSN, TenantKey(tenant))
	default:
		return nil, fmt.Errorf("unknown vault backend %q (want file|postgres)", o.Backend)
	}
}
