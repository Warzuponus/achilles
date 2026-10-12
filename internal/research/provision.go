package research

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RuleSet is a materialized set of Opengrep rule directories for one scan.
//
// ActiveDir holds the always-active in-house baseline rules plus any admitted
// generated rules that have aged past the shadow window. ShadowDir holds newly
// admitted generated rules still inside the window — they run in a separate pass
// so their findings can be marked report-only (they must not gate CI or file
// issues until they've been observed). See DESIGN §9.4 (rule flywheel).
type RuleSet struct {
	ActiveDir       string
	ShadowDir       string // "" when no rules are currently shadowed
	ActiveGenerated int    // admitted generated rules promoted to active
	Shadow          int    // admitted generated rules still shadowed
	Excluded        int    // admitted rules left out because of where they came from
}

// admittedCreatedFmt is the date layout the synthesizer writes into a rule's
// provenance (see cmd/achilles: time.Now().UTC().Format("2006-01-02")).
const admittedCreatedFmt = "2006-01-02"

// Provision materializes the rule sets for a scan. baselineDir (may be "") is the
// in-house rules directory; admitted generated rules are split by admission age:
// older than shadowWindow → active, otherwise → shadowed. The returned cleanup
// removes the temp directories and must be called when the scan is done.
//
// A generated rule with a missing/unparseable created date defaults to active:
// it already passed the §9.3 validation gate, so the shadow window is a second
// observation layer, not the primary trust gate — better to let it gate than to
// strand it in shadow forever.
func (r *RuleRepo) Provision(baselineDir string, shadowWindow time.Duration, now time.Time) (*RuleSet, func(), error) {
	activeDir, err := os.MkdirTemp("", "achilles-rules-active-*")
	if err != nil {
		return nil, nil, err
	}
	shadowDir, err := os.MkdirTemp("", "achilles-rules-shadow-*")
	if err != nil {
		_ = os.RemoveAll(activeDir)
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(activeDir); _ = os.RemoveAll(shadowDir) }

	// Baseline rules are always active.
	if baselineDir != "" {
		if err := copyRules(baselineDir, activeDir, "base"); err != nil {
			cleanup()
			return nil, nil, err
		}
	}

	set := &RuleSet{ActiveDir: activeDir}
	entries, _ := os.ReadDir(r.AdmittedDir())
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".yaml")
		if r.excluded[r.admittedMeta(id).Provenance.Origin] {
			set.Excluded++
			continue
		}
		created := r.admittedCreated(id)
		shadowed := !created.IsZero() && now.Sub(created) < shadowWindow

		dst := activeDir
		if shadowed {
			dst = shadowDir
			set.Shadow++
		} else {
			set.ActiveGenerated++
		}
		if err := copyFile(filepath.Join(r.AdmittedDir(), e.Name()), filepath.Join(dst, e.Name())); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	if set.Shadow > 0 {
		set.ShadowDir = shadowDir
	}
	return set, cleanup, nil
}

// admittedMeta reads a rule's meta.json sidecar; the zero value if it is missing.
func (r *RuleRepo) admittedMeta(id string) ruleMeta {
	var m ruleMeta
	if b, err := os.ReadFile(filepath.Join(r.AdmittedDir(), id+".meta.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// admittedCreated reads a rule's admission date from its meta.json sidecar. A
// zero time means "unknown" (treated as active by the caller).
func (r *RuleRepo) admittedCreated(id string) time.Time {
	b, err := os.ReadFile(filepath.Join(r.AdmittedDir(), id+".meta.json"))
	if err != nil {
		return time.Time{}
	}
	var m ruleMeta
	if json.Unmarshal(b, &m) != nil || m.Provenance.Created == "" {
		return time.Time{}
	}
	t, err := time.Parse(admittedCreatedFmt, m.Provenance.Created)
	if err != nil {
		return time.Time{}
	}
	return t
}

// copyRules recursively copies every *.yaml/*.yml under src into dst, flattening
// nested paths into a unique prefixed name so opengrep loads them all.
func copyRules(src, dst, prefix string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		name := prefix + "-" + strings.ReplaceAll(rel, string(os.PathSeparator), "-")
		return copyFile(path, filepath.Join(dst, name))
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
