package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Warzuponus/achilles/internal/vault"
)

// A scan writes straight to its tenant's vault (never through the server); the
// War Room must then find and read that tenant. Needs a real PostgreSQL — see
// internal/vault/postgres_test.go for how to run one.
func TestTenantsPostgres_DiscoversAndReadsWhatAScanWrote(t *testing.T) {
	dsn := os.Getenv("ACHILLES_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ACHILLES_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	id := "pgtest" + time.Now().Format("150405")

	scan, err := vault.Open(ctx, vault.Options{Backend: "postgres", DSN: dsn, Tenant: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Append(vault.Record{RunID: "run1", Kind: vault.KindScanMeta}); err != nil {
		t.Fatal(err)
	}

	tn := NewTenantsPostgres(ctx, dsn)
	found := false
	for _, d := range tn.Discover() {
		found = found || d == id
	}
	if !found {
		t.Errorf("Discover() = %v, want it to include %q", tn.Discover(), id)
	}
	st, err := tn.Vault(id)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.ByRun("run1"); len(got) != 1 {
		t.Errorf("server sees %d records of the scan's run, want 1", len(got))
	}
	other, err := tn.Vault("someone-else")
	if err != nil {
		t.Fatal(err)
	}
	if got := other.ByRun("run1"); len(got) != 0 {
		t.Errorf("another tenant sees the scan's records: %d", len(got))
	}
}
