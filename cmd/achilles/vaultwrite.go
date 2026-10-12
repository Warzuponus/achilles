package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/Warzuponus/achilles/internal/vault"
)

// vaultWrites tracks Evidence Vault write failures for the whole run. The vault
// IS the audit trail, the reproducibility record, and the learning corpus, so
// losing writes silently is worse than failing loudly: a scan would report
// success while recording nothing. We don't abort mid-scan on a transient error
// (the report and gate are still worth producing) but the run reports the
// failure count and the first cause, and exits non-zero.
var vaultWrites struct {
	mu        sync.Mutex // findings are triaged concurrently, and each one writes
	failed    int
	firstErr  error
	attempted int
}

// trackedStore is the vault every part of a run writes through. The engines
// (triage, review, advisor, threat model, research) record what they did with
// `_, _ = vault.Append(...)`: they have no way to stop a scan over a lost record
// and should not. But that meant only the pipeline's own writes were counted. A
// disk that filled during the AI review lost every prompt, response and verdict,
// and the run still exited 0 saying "Evidence Vault: file". Counting at the store
// makes every write count, whoever makes it.
type trackedStore struct{ vault.Store }

// trackVault wraps a store so that every Append is counted (once).
func trackVault(s vault.Store) vault.Store {
	if _, ok := s.(*trackedStore); ok || s == nil {
		return s
	}
	return &trackedStore{Store: s}
}

func (t *trackedStore) Append(r vault.Record) (vault.Record, error) {
	rec, err := t.Store.Append(r)
	countVaultWrite(r.Kind, err)
	return rec, err
}

func countVaultWrite(kind vault.Kind, err error) {
	vaultWrites.mu.Lock()
	vaultWrites.attempted++
	vaultWrites.mu.Unlock()
	if err != nil {
		noteVaultFailure(fmt.Errorf("append %s record: %w", kind, err))
	}
}

func recordJSON(ev vault.Store, r vault.Record, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		noteVaultFailure(fmt.Errorf("marshal %s record: %w", r.Kind, err))
		return
	}
	r.Payload = b
	if _, tracked := ev.(*trackedStore); tracked {
		_, _ = ev.Append(r) // the store counts it
		return
	}
	_, err = ev.Append(r)
	countVaultWrite(r.Kind, err)
}

func noteVaultFailure(err error) {
	vaultWrites.mu.Lock()
	vaultWrites.failed++
	first := vaultWrites.firstErr == nil
	if first {
		vaultWrites.firstErr = err
	}
	vaultWrites.mu.Unlock()
	if first {
		// Surface the first one immediately — later ones are usually the same
		// cause, and a wall of identical errors helps nobody.
		fmt.Fprintf(os.Stderr, "achilles: VAULT WRITE FAILED: %v\n", err)
	}
}

// reportVaultFailures prints a summary if any vault write failed. Returns an
// error so the run exits non-zero: a scan whose evidence did not persist must
// not look like a clean success.
func reportVaultFailures() error {
	vaultWrites.mu.Lock()
	defer vaultWrites.mu.Unlock()
	if vaultWrites.failed == 0 {
		return nil
	}
	return fmt.Errorf("evidence vault: %d of %d record(s) FAILED to write — "+
		"the scan ran but its audit trail is incomplete; first error: %w",
		vaultWrites.failed, vaultWrites.attempted, vaultWrites.firstErr)
}
