// Package baseline supports baseline-aware scanning: suppress findings that were
// already known so CI only fails on newly-introduced issues (DESIGN.md §11).
package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Warzuponus/achilles/internal/model"
)

// Baseline is a set of known finding fingerprints.
type Baseline struct {
	Fingerprints []string `json:"fingerprints"`
}

// Load reads a baseline file. A missing file is an empty baseline (not an error)
// so the first CI run works before a baseline exists.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{}, nil
		}
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Baseline) set() map[string]bool {
	m := make(map[string]bool, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		m[fp] = true
	}
	return m
}

// Filter partitions findings into those NOT in the baseline (surfaced) and a
// count of suppressed (already-known) findings.
func (b *Baseline) Filter(findings []model.Finding) (surfaced []model.Finding, suppressed int) {
	known := b.set()
	for _, f := range findings {
		if known[f.Fingerprint] {
			suppressed++
			continue
		}
		surfaced = append(surfaced, f)
	}
	return surfaced, suppressed
}

// Classification compares a scan against the baseline (DESIGN.md §11): findings
// present now split into Introduced (not in baseline — these gate CI) and
// PreExisting (already known); Fixed lists baseline fingerprints no longer
// present (resolved since the baseline was taken).
type Classification struct {
	Introduced  []model.Finding `json:"introduced"`
	PreExisting []model.Finding `json:"preExisting"`
	Fixed       []string        `json:"fixed"`
}

// Classify partitions findings relative to the baseline and derives the set of
// fixed fingerprints. Order within each group follows the input order.
func (b *Baseline) Classify(findings []model.Finding) Classification {
	known := b.set()
	present := make(map[string]bool, len(findings))
	var c Classification
	for _, f := range findings {
		present[f.Fingerprint] = true
		if known[f.Fingerprint] {
			c.PreExisting = append(c.PreExisting, f)
		} else {
			c.Introduced = append(c.Introduced, f)
		}
	}
	for _, fp := range b.Fingerprints {
		if !present[fp] {
			c.Fixed = append(c.Fixed, fp)
		}
	}
	return c
}

// Write persists the fingerprints of the given findings as a new baseline.
func Write(path string, findings []model.Finding) error {
	seen := map[string]bool{}
	b := Baseline{}
	for _, f := range findings {
		if f.Fingerprint == "" || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		b.Fingerprints = append(b.Fingerprints, f.Fingerprint)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}
