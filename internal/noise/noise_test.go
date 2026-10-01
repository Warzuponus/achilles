package noise

import (
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func f(path string) model.Finding {
	return model.Finding{Location: model.Location{File: path}}
}

func TestDefaultMatcher(t *testing.T) {
	m := DefaultMatcher()
	noise := []string{
		"node_modules/lodash/index.js",
		"/abs/app/vendor/pkg/x.go",
		"third_party/foo/bar.py",
		"web/assets/app.min.js",
		"api/service.pb.go",
	}
	for _, p := range noise {
		if !m.Matches(p) {
			t.Errorf("expected %q to be noise", p)
		}
	}
	// Real source must NOT be filtered — including test code (on purpose).
	for _, p := range []string{"src/app/main.go", "internal/auth/login.py", "app_test.go", "tests/test_login.py"} {
		if m.Matches(p) {
			t.Errorf("did not expect %q to be noise", p)
		}
	}
}

func TestAdd_SegmentAndGlob(t *testing.T) {
	m := NewMatcher()
	m.Add("tests/") // trailing slash → segment
	m.Add("*.gen.go")

	if !m.Matches("app/tests/foo.py") {
		t.Error("added segment 'tests' should match")
	}
	if !m.Matches("pkg/models.gen.go") {
		t.Error("added glob *.gen.go should match")
	}
	if m.Matches("pkg/models.go") {
		t.Error("models.go should not match *.gen.go")
	}
}

func TestFilter(t *testing.T) {
	m := DefaultMatcher()
	kept, excluded := m.Filter([]model.Finding{
		f("src/main.go"),
		f("node_modules/x/y.js"),
		f("internal/auth.go"),
		f("dist/app.min.js"),
	})
	if len(kept) != 2 || len(excluded) != 2 {
		t.Fatalf("kept=%d excluded=%d, want 2/2", len(kept), len(excluded))
	}
	if kept[0].Location.File != "src/main.go" || kept[1].Location.File != "internal/auth.go" {
		t.Errorf("wrong kept set: %+v", kept)
	}
}
