package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/vault"
)

// failingStore rejects every write, standing in for a database backend the run
// cannot reach (bad credentials, network).
type failingStore struct{ err error }

func (f failingStore) Append(r vault.Record) (vault.Record, error) { return r, f.err }
func (f failingStore) Get(string) (vault.Record, bool)             { return vault.Record{}, false }
func (f failingStore) ByRun(string) []vault.Record                 { return nil }
func (f failingStore) ByFingerprint(string) []vault.Record         { return nil }
func (f failingStore) All() []vault.Record                         { return nil }

func reset() { vaultWrites.failed, vaultWrites.attempted, vaultWrites.firstErr = 0, 0, nil }

// The bug this guards: writes were `_, _ = ev.Append(r)`, so a scan could lose
// its entire audit trail and still exit 0.
func TestVaultWriteFailure_IsNotSilent(t *testing.T) {
	reset()
	defer reset()

	st := failingStore{err: errors.New("PermissionDenied: missing datastore.entities.create")}
	recordJSON(st, vault.Record{RunID: "r1", Kind: vault.KindScanMeta}, map[string]any{"a": 1})
	recordJSON(st, vault.Record{RunID: "r1", Kind: vault.KindFinding}, map[string]any{"b": 2})

	if vaultWrites.failed != 2 || vaultWrites.attempted != 2 {
		t.Fatalf("failed=%d attempted=%d, want 2/2", vaultWrites.failed, vaultWrites.attempted)
	}
	err := reportVaultFailures()
	if err == nil {
		t.Fatal("a run that persisted NO evidence must not report success")
	}
	// The message must carry the count and the underlying cause, or it's not
	// actionable at 3am.
	for _, want := range []string{"2 of 2", "PermissionDenied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestVaultWriteSuccess_IsSilent(t *testing.T) {
	reset()
	defer reset()

	st := failingStore{err: nil} // Append succeeds
	recordJSON(st, vault.Record{RunID: "r1", Kind: vault.KindScanMeta}, map[string]any{"a": 1})

	if vaultWrites.failed != 0 {
		t.Errorf("clean writes must not be counted as failures (got %d)", vaultWrites.failed)
	}
	if err := reportVaultFailures(); err != nil {
		t.Errorf("a healthy run must not error: %v", err)
	}
}

// An unmarshalable payload is also a lost record — it must count, not vanish.
func TestVaultWriteFailure_CountsMarshalErrors(t *testing.T) {
	reset()
	defer reset()

	recordJSON(failingStore{}, vault.Record{RunID: "r1", Kind: vault.KindFinding},
		map[string]any{"bad": make(chan int)}) // channels don't marshal
	if vaultWrites.failed != 1 {
		t.Errorf("marshal failure should count as a lost record, got %d", vaultWrites.failed)
	}
	if reportVaultFailures() == nil {
		t.Error("expected an error after a lost record")
	}
}
