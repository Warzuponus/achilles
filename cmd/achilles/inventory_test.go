package main

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/inventory"
)

func TestLongPathDiag(t *testing.T) {
	inv := inventory.Inventory{LongPaths: 3, LongPathExample: `C:\deep\x.java`}
	if d, ok := longPathDiag("windows", inv, []string{"gitleaks", "opengrep"}); !ok || d.Tool != "opengrep" || d.Stage != "partial" ||
		!strings.Contains(d.Error, "3 file(s)") || !strings.Contains(d.Error, `C:\deep\x.java`) {
		t.Errorf("windows with long paths: %+v, %v", d, ok)
	}
	if _, ok := longPathDiag("linux", inv, []string{"opengrep"}); ok {
		t.Error("reported on Linux, where long paths are fine")
	}
	if _, ok := longPathDiag("windows", inventory.Inventory{}, []string{"opengrep"}); ok {
		t.Error("reported with no long paths")
	}
	if _, ok := longPathDiag("windows", inv, []string{"gitleaks"}); ok {
		t.Error("reported although Opengrep did not run")
	}
}
