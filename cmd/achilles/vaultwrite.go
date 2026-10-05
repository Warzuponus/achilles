package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Warzuponus/achilles/internal/vault"
)

// vaultWrites tracks Evidence Vault write failures for the whole run. The vault
// IS the audit trail, the reproducibility record, and the learning corpus, so
// losing writes silently is worse than failing loudly: a scan would report
// success while recording nothing. We don't abort mid-scan on a transient error
// (the report and gate are still worth producing) but the run reports the
// failure count and the first cause, and exits non-zero.
var vaultWrites struct {
	failed    int
	firstErr  error
	attempted int
}

func recordJSON(ev vault.Store, r vault.Record, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		noteVaultFailure(fmt.Errorf("marshal %s record: %w", r.Kind, err))
		return
	}
	r.Payload = b
	vaultWrites.attempted++
	if _, err := ev.Append(r); err != nil {
		noteVaultFailure(fmt.Errorf("append %s record: %w", r.Kind, err))
	}
}

func noteVaultFailure(err error) {
	vaultWrites.failed++
	if vaultWrites.firstErr == nil {
		vaultWrites.firstErr = err
		// Surface the first one immediately — later ones are usually the same
		// cause, and a wall of identical errors helps nobody.
		fmt.Fprintf(os.Stderr, "achilles: VAULT WRITE FAILED: %v\n", err)
	}
}

// reportVaultFailures prints a summary if any vault write failed. Returns an
// error so the run exits non-zero: a scan whose evidence did not persist must
// not look like a clean success.
func reportVaultFailures() error {
	if vaultWrites.failed == 0 {
		return nil
	}
	return fmt.Errorf("evidence vault: %d of %d record(s) FAILED to write — "+
		"the scan ran but its audit trail is incomplete; first error: %w",
		vaultWrites.failed, vaultWrites.attempted, vaultWrites.firstErr)
}
