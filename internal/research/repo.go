package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Warzuponus/achilles/internal/vault"
)

// RuleRepo is the versioned generated-rule store (DESIGN.md §9.4). Admitted
// rules live under <dir>/admitted; failures under <dir>/quarantine — never
// auto-run. Each rule carries a provenance sidecar; both outcomes are logged to
// the Evidence Vault.
type RuleRepo struct {
	dir   string
	vault vault.Store // may be nil
	// excluded are provenance origins whose rules Provision must not load.
	excluded map[string]bool
}

// ExcludeOrigins makes Provision leave out admitted rules with these provenance
// origins (see OriginExternalRule). The rules stay in the repository.
func (r *RuleRepo) ExcludeOrigins(origins ...string) {
	if r.excluded == nil {
		r.excluded = map[string]bool{}
	}
	for _, o := range origins {
		r.excluded[o] = true
	}
}

func NewRuleRepo(dir string, v vault.Store) *RuleRepo { return &RuleRepo{dir: dir, vault: v} }

type ruleMeta struct {
	ID         string           `json:"id"`
	Provenance Provenance       `json:"provenance"`
	Validation ValidationResult `json:"validation"`
	Reason     string           `json:"reason,omitempty"`
	Admitted   bool             `json:"admitted"`
}

// Admit stores a rule that passed the validation gate.
func (r *RuleRepo) Admit(runID string, rule GeneratedRule, res ValidationResult) error {
	return r.write(runID, "admitted", rule, res, "passed validation gate", true)
}

// Quarantine stores a rule that failed the gate, for human review. It is never
// used in a scan.
func (r *RuleRepo) Quarantine(runID string, rule GeneratedRule, res ValidationResult, reason string) error {
	return r.write(runID, "quarantine", rule, res, reason, false)
}

func (r *RuleRepo) write(runID, sub string, rule GeneratedRule, res ValidationResult, reason string, admitted bool) error {
	dir := filepath.Join(r.dir, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, rule.ID+".yaml"), []byte(rule.RuleYAML), 0o644); err != nil {
		return err
	}
	meta := ruleMeta{ID: rule.ID, Provenance: rule.Provenance, Validation: res, Reason: reason, Admitted: admitted}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, rule.ID+".meta.json"), mb, 0o644); err != nil {
		return err
	}

	if r.vault != nil {
		payload, _ := json.Marshal(meta)
		_, _ = r.vault.Append(vault.Record{
			RunID: runID, Phase: "research", Kind: vault.KindGenRule,
			Source: rule.Provenance.Model, Payload: payload,
		})
	}
	return nil
}

// AdmittedDir is the directory of live generated rules (usable as an Opengrep
// rules path in future scans).
func (r *RuleRepo) AdmittedDir() string { return filepath.Join(r.dir, "admitted") }

// Count returns how many rules are in a subdirectory ("admitted"|"quarantine").
func (r *RuleRepo) Count(sub string) int {
	entries, err := os.ReadDir(filepath.Join(r.dir, sub))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".yaml" {
			n++
		}
	}
	return n
}

func ruleID(title, ruleYAML string) string {
	sum := sha256.Sum256([]byte(title + "\x00" + ruleYAML))
	return "gen-" + hex.EncodeToString(sum[:])[:12]
}
