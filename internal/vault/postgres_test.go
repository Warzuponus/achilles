package vault

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// These tests need a real PostgreSQL. Point ACHILLES_TEST_POSTGRES_DSN at a
// disposable database, e.g.
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=vaulttest -p 127.0.0.1:55432:5432 postgres:16
//	ACHILLES_TEST_POSTGRES_DSN='postgres://postgres:test@127.0.0.1:55432/vaulttest?sslmode=disable' go test ./internal/vault
//
// They are skipped when it is unset (CI sets it from a service container).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("ACHILLES_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ACHILLES_TEST_POSTGRES_DSN not set")
	}
	return dsn
}

// uniqueKey keeps tests independent on a shared database and cleans up after.
func uniqueKey(t *testing.T, dsn, base string) string {
	t.Helper()
	key := fmt.Sprintf("test-%s-%d-%s", t.Name(), time.Now().UnixNano(), base)
	t.Cleanup(func() {
		db, err := poolFor(context.Background(), dsn)
		if err == nil {
			_, _ = db.Exec(`DELETE FROM `+pgTable+` WHERE tenant = $1`, key)
		}
	})
	return key
}

func TestPostgresStore_Contract(t *testing.T) {
	dsn := testDSN(t)
	keys := map[string]string{}
	var mu sync.Mutex
	storeContract(t, func(t *testing.T, key string) Store {
		mu.Lock()
		defer mu.Unlock()
		// A fresh isolation key per (subtest, key) so subtests never see each other.
		k := uniqueKey(t, dsn, key)
		keys[key] = k
		s, err := NewPostgresStore(context.Background(), dsn, k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestPostgresStore_ConcurrentWritersAndSchemaSetup(t *testing.T) {
	dsn := testDSN(t)
	key := uniqueKey(t, dsn, "c")
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := NewPostgresStore(context.Background(), dsn, key)
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < 25; i++ {
				if _, err := s.Append(Record{RunID: "r", Kind: KindFinding}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	s, _ := NewPostgresStore(context.Background(), dsn, key)
	all := s.All()
	if len(all) != 100 {
		t.Fatalf("got %d records, want 100", len(all))
	}
	seen := map[string]bool{}
	for _, r := range all {
		if seen[r.ID] {
			t.Fatalf("duplicate id %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestPostgresTenants(t *testing.T) {
	dsn := testDSN(t)
	prefix := fmt.Sprintf("disc-%d-", time.Now().UnixNano())
	for _, id := range []string{"acme", "globex"} {
		key := prefix + id
		s, err := NewPostgresStore(context.Background(), dsn, key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			db, _ := poolFor(context.Background(), dsn)
			_, _ = db.Exec(`DELETE FROM `+pgTable+` WHERE tenant = $1`, key)
		})
		if _, err := s.Append(Record{RunID: "r", Kind: KindFinding}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := PostgresTenants(context.Background(), dsn, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "acme" || got[1] != "globex" {
		t.Errorf("tenants = %v, want [acme globex]", got)
	}
}

func TestPostgresStore_Errors(t *testing.T) {
	if _, err := NewPostgresStore(context.Background(), "", "t"); err == nil {
		t.Error("empty DSN must error")
	}
	if _, err := NewPostgresStore(context.Background(), "postgres://x", ""); err == nil {
		t.Error("empty tenant key must error")
	}
	// An unreachable server must be an error at open, not a silent empty vault.
	if _, err := NewPostgresStore(context.Background(), "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1", "t"); err == nil {
		t.Error("unreachable server must error at open")
	}
}
