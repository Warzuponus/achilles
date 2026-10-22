package main

import (
	"reflect"
	"testing"
)

func TestUncoveredLanguages(t *testing.T) {
	langs := map[string][]string{
		"opengrep":   {"python", "javascript", "go"},
		"gitleaks":   {"generic"},
		"shellcheck": {"shell"},
		"gosec":      {"go"},
	}
	// shellcheck failed, so it is not in ran; rust has no tool; gitleaks covers
	// no language's code.
	got := uncoveredLanguages([]string{"python", "rust", "shell", "go", "Rust"}, []string{"opengrep", "gitleaks", "gosec"}, langs)
	if want := []string{"rust", "shell"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := uncoveredLanguages(nil, []string{"opengrep"}, langs); got != nil {
		t.Errorf("no languages detected means nothing to report, got %q", got)
	}
}
