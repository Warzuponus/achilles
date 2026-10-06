package main

import "testing"

func TestIssuesReconcile(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    options
		want bool
	}{
		{"full scan", options{}, true},
		{"diff", options{diffRef: "origin/main"}, false},
		{"baseline", options{baselinePath: "b.json"}, false},
		{"pr-mini", options{prMini: "mini.json"}, false},
	} {
		got, why := issuesReconcile(&tc.o)
		if got != tc.want || (!got && why == "") {
			t.Errorf("%s: reconcile=%v why=%q", tc.name, got, why)
		}
	}
}
