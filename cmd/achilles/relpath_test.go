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
