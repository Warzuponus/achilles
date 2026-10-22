package main

import (
	"path/filepath"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestRelativizeFindings(t *testing.T) {
	root := t.TempDir()
	fs := []model.Finding{
		{Location: model.Location{File: filepath.Join(root, "pkg", "a.py")}}, // absolute, inside
		{Location: model.Location{File: "main.go"}},                          // already relative
		{Location: model.Location{File: "/elsewhere/x.py"}},                  // outside: left alone
		{Location: model.Location{File: filepath.Join(filepath.Dir(root), "sibling", "y.py")}},
	}
	relativizeFindings(root, fs)
	want := []string{"pkg/a.py", "main.go", "/elsewhere/x.py", filepath.Join(filepath.Dir(root), "sibling", "y.py")}
	for i, w := range want {
		if fs[i].Location.File != w {
			t.Errorf("finding %d: %q, want %q", i, fs[i].Location.File, w)
		}
	}
}

func TestRelativizeFindings_FlowSteps(t *testing.T) {
	root := t.TempDir()
	fs := []model.Finding{{
		Location: model.Location{File: filepath.Join(root, "db.py")},
		Flow:     []model.FlowStep{{File: filepath.Join(root, "app.py"), Line: 3}, {File: "db.py", Line: 12}},
	}}
	relativizeFindings(root, fs)
	if fs[0].Flow[0].File != "app.py" || fs[0].Flow[1].File != "db.py" {
		t.Errorf("flow files = %+v", fs[0].Flow)
	}
}
