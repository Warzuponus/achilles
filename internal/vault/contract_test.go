package vault

import (
	"encoding/json"
	"testing"
	"time"
)

// storeContract is the behavior every backend must share. open(key) returns a
// store bound to an isolation key (a tenant); two keys must never see each
// other's records.
func storeContract(t *testing.T, open func(t *testing.T, key string) Store) {
	t.Run("append assigns id and timestamp, preserves every field", func(t *testing.T) {
		s := open(t, "a")
		// Key order and number precision are evidence; insignificant whitespace is
		// not (the file backend compacts it), so the comparison below ignores it.
		payload := json.RawMessage(`{"z":1,"a":[1,2,3],"big":12345678901234567890}`)
		in := Record{RunID: "r", Phase: "triage", Kind: KindVerdict, Source: "m", PromptVersion: "v2",
			Fingerprint: "fp", PrevID: "prev", Payload: payload}
		got, err := s.Append(in)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID == "" || got.Timestamp.IsZero() {
			t.Fatalf("id/timestamp not assigned: %+v", got)
		}
		back, ok := s.Get(got.ID)
		if !ok {
			t.Fatal("Get missed an appended record")
		}
		if back.RunID != "r" || back.Phase != "triage" || back.Kind != KindVerdict || back.Source != "m" ||
			back.PromptVersion != "v2" || back.Fingerprint != "fp" || back.PrevID != "prev" {
			t.Errorf("fields lost: %+v", back)
		}
		if string(back.Payload) != string(payload) {
			t.Errorf("payload bytes changed:\n got %s\nwant %s", back.Payload, payload)
		}
		if !back.Timestamp.Equal(got.Timestamp) {
			t.Errorf("timestamp %v != %v", back.Timestamp, got.Timestamp)
		}
	})

	t.Run("ids are unique even for identical content", func(t *testing.T) {
		s := open(t, "a")
		seen := map[string]bool{}
		for i := 0; i < 20; i++ {
			r, err := s.Append(Record{RunID: "r", Kind: KindFinding, Timestamp: time.Unix(5, 0).UTC()})
			if err != nil {
				t.Fatal(err)
			}
			if seen[r.ID] {
				t.Fatalf("duplicate id %s", r.ID)
			}
			seen[r.ID] = true
		}
	})

	t.Run("queries return insertion order", func(t *testing.T) {
		s := open(t, "a")
		for _, src := range []string{"1", "2", "3"} {
			if _, err := s.Append(Record{RunID: "r", Kind: KindFinding, Fingerprint: "fp", Source: src}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Append(Record{RunID: "other", Kind: KindFinding, Fingerprint: "other", Source: "x"}); err != nil {
			t.Fatal(err)
		}
		for name, got := range map[string][]Record{"ByRun": s.ByRun("r"), "ByFingerprint": s.ByFingerprint("fp")} {
			if len(got) != 3 || got[0].Source != "1" || got[1].Source != "2" || got[2].Source != "3" {
				t.Errorf("%s = %+v, want sources 1,2,3 in order", name, got)
			}
		}
		if all := s.All(); len(all) != 4 || all[3].Source != "x" {
			t.Errorf("All = %d records, last %+v", len(all), all[len(all)-1])
		}
		if _, ok := s.Get("nope"); ok {
			t.Error("Get found a nonexistent id")
		}
	})

	t.Run("keys are isolated", func(t *testing.T) {
		a, b := open(t, "a"), open(t, "b")
		ra, err := a.Append(Record{RunID: "shared-run", Kind: KindFinding, Fingerprint: "shared-fp"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Append(Record{RunID: "shared-run", Kind: KindFinding, Fingerprint: "shared-fp"}); err != nil {
			t.Fatal(err)
		}
		if n := len(a.ByRun("shared-run")); n != 1 {
			t.Errorf("a sees %d records for the run, want only its own 1", n)
		}
		if n := len(b.All()); n != 1 {
			t.Errorf("b sees %d records, want only its own 1", n)
		}
		if _, ok := b.Get(ra.ID); ok {
			t.Error("b can Get a's record by id")
		}
	})

	t.Run("purge is scoped and time-based", func(t *testing.T) {
		a, b := open(t, "a"), open(t, "b")
		p, ok := a.(Purger)
		if !ok {
			t.Skip("backend has no Purger")
		}
		old := time.Now().Add(-72 * time.Hour).UTC()
		for _, s := range []Store{a, b} {
			if _, err := s.Append(Record{RunID: "old", Kind: KindFinding, Timestamp: old}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Append(Record{RunID: "new", Kind: KindFinding}); err != nil {
				t.Fatal(err)
			}
		}
		n, err := p.Purge(time.Now().Add(-24 * time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("Purge = %d, %v; want 1", n, err)
		}
		if got := a.All(); len(got) != 1 || got[0].RunID != "new" {
			t.Errorf("a after purge = %+v", got)
		}
		if got := b.All(); len(got) != 2 {
			t.Errorf("b was affected by a's purge: %d records", len(got))
		}
	})
}

func TestFileStore_Contract(t *testing.T) {
	storeContract(t, func(t *testing.T, key string) Store {
		// A fresh directory per (subtest, key): subtests must not see each other.
		s, err := NewFileStore(t.TempDir() + "/" + key + "/vault.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
