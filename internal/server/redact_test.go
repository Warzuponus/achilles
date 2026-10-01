package server

import "testing"

func TestRedact(t *testing.T) {
	cases := []struct {
		in       string
		mustMask string
	}{
		{"key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"},
		{`password = "hunter2supersecret"`, "hunter2supersecret"},
		{"token: abcdef0123456789abcdef0123456789abcd", "abcdef0123456789abcdef0123456789abcd"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if contains(out, c.mustMask) {
			t.Errorf("Redact(%q) leaked secret %q -> %q", c.in, c.mustMask, out)
		}
		if !contains(out, mask) {
			t.Errorf("Redact(%q) did not insert mask -> %q", c.in, out)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
