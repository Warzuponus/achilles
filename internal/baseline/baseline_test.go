package baseline

import (
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func f(fp string) model.Finding { return model.Finding{Fingerprint: fp} }

func TestFilter(t *testing.T) {
	b := &Baseline{Fingerprints: []string{"a", "b"}}
	surfaced, suppressed := b.Filter([]model.Finding{f("a"), f("c"), f("b"), f("d")})
	if suppressed != 2 {
		t.Errorf("suppressed: want 2, got %d", suppressed)
	}
	if len(surfaced) != 2 || surfaced[0].Fingerprint != "c" || surfaced[1].Fingerprint != "d" {
		t.Errorf("surfaced wrong: %+v", surfaced)
	}
}

func TestClassify(t *testing.T) {
	// Baseline knew a,b,c. Scan now sees a (pre-existing), b (pre-existing),
	// and d (introduced). c is gone → fixed.
	b := &Baseline{Fingerprints: []string{"a", "b", "c"}}
	c := b.Classify([]model.Finding{f("a"), f("d"), f("b")})

	if len(c.Introduced) != 1 || c.Introduced[0].Fingerprint != "d" {
		t.Errorf("introduced: want [d], got %+v", c.Introduced)
	}
	if len(c.PreExisting) != 2 {
		t.Errorf("pre-existing: want 2 (a,b), got %d", len(c.PreExisting))
	}
	if len(c.Fixed) != 1 || c.Fixed[0] != "c" {
		t.Errorf("fixed: want [c], got %+v", c.Fixed)
	}
}

func TestClassify_EmptyBaselineAllIntroduced(t *testing.T) {
	b := &Baseline{}
	c := b.Classify([]model.Finding{f("a"), f("b")})
	if len(c.Introduced) != 2 || len(c.PreExisting) != 0 || len(c.Fixed) != 0 {
		t.Errorf("empty baseline: want all introduced, got introduced=%d preexisting=%d fixed=%d",
			len(c.Introduced), len(c.PreExisting), len(c.Fixed))
	}
}

func TestWriteCreatesParentDir(t *testing.T) {
	// Writing into a not-yet-existing dir (e.g. .achilles/) must succeed.
	path := filepath.Join(t.TempDir(), ".achilles", "baseline.json")
	if err := Write(path, []model.Finding{f("a")}); err != nil {
		t.Fatalf("Write should create the parent dir: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	b, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(b.Fingerprints) != 0 {
		t.Error("missing baseline should be empty")
	}
}

func TestWriteThenLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Write(path, []model.Finding{f("x"), f("y"), f("x"), f("")}); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// dedup + drop empty fingerprint → {x, y}
	if len(b.Fingerprints) != 2 {
		t.Fatalf("want 2 fingerprints, got %d (%v)", len(b.Fingerprints), b.Fingerprints)
	}
	_, suppressed := b.Filter([]model.Finding{f("x"), f("y"), f("z")})
	if suppressed != 2 {
		t.Errorf("round-tripped baseline should suppress x and y, got %d", suppressed)
	}
}
