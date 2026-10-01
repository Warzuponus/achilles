package fleet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadAndPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.yaml")
	yaml := `tenants:
  - id: acme
    mode: commercial
    targets: [/repos/acme/api, /repos/acme/web]
  - id: globex
    targets: [/repos/globex/svc]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	jobs := c.Plan()
	if len(jobs) != 3 {
		t.Fatalf("want 3 jobs, got %d", len(jobs))
	}
	// acme inherits its mode; globex defaults to oss/default.
	if jobs[0].Tenant != "acme" || jobs[0].Mode != "commercial" || jobs[0].Profile != "default" {
		t.Errorf("acme job wrong: %+v", jobs[0])
	}
	if jobs[2].Tenant != "globex" || jobs[2].Mode != "oss" {
		t.Errorf("globex defaults wrong: %+v", jobs[2])
	}
}

func TestLoadConfig_RejectsBadTenant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.yaml")
	os.WriteFile(path, []byte("tenants:\n  - id: \"../evil\"\n    targets: [/x]\n"), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected invalid tenant id to be rejected (path-traversal guard)")
	}
}

// recordingRunner records every job it saw (concurrency-safe) and can fail some.
type recordingRunner struct {
	mu     sync.Mutex
	seen   []Job
	failOn string // tenant to fail
}

func (r *recordingRunner) Scan(_ context.Context, j Job) Result {
	r.mu.Lock()
	r.seen = append(r.seen, j)
	r.mu.Unlock()
	if j.Tenant == r.failOn {
		return Result{Job: j, Err: errors.New("boom")}
	}
	return Result{Job: j}
}

func TestDispatch(t *testing.T) {
	jobs := []Job{
		{Tenant: "acme", Target: "/a"},
		{Tenant: "acme", Target: "/b"},
		{Tenant: "globex", Target: "/c"},
	}
	r := &recordingRunner{failOn: "globex"}
	sum := Dispatch(context.Background(), jobs, r, 4)

	if sum.Total != 3 || sum.Succeeded != 2 || sum.Failed != 1 {
		t.Fatalf("tally wrong: %+v", sum)
	}
	if len(r.seen) != 3 {
		t.Errorf("every job should run even when one fails: saw %d", len(r.seen))
	}
	// Results are sorted (tenant, target) regardless of completion order.
	if sum.Results[0].Job.Target != "/a" || sum.Results[2].Job.Tenant != "globex" {
		t.Errorf("results not sorted: %+v", sum.Results)
	}
}

func TestDispatch_Empty(t *testing.T) {
	sum := Dispatch(context.Background(), nil, &recordingRunner{}, 4)
	if sum.Total != 0 || len(sum.Results) != 0 {
		t.Errorf("empty dispatch should be a no-op, got %+v", sum)
	}
}

func TestCLIRunner_VaultArgs(t *testing.T) {
	pg := CLIRunner{Backend: "postgres"}.vaultArgs("acme")
	if got := len(pg); got != 4 || pg[0] != "--vault-backend" || pg[1] != "postgres" || pg[2] != "--vault-tenant" || pg[3] != "acme" {
		t.Errorf("postgres vault args wrong: %v", pg)
	}
	file := CLIRunner{Backend: "file", VaultRoot: "/vaults"}.vaultArgs("acme")
	if file[0] != "--vault" || file[1] != filepath.Join("/vaults", "acme", "vault.jsonl") {
		t.Errorf("file vault args wrong: %v", file)
	}
}
