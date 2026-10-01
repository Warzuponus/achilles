package research

import "testing"

func TestAdmit_Gate(t *testing.T) {
	cases := []struct {
		name   string
		res    ValidationResult
		wantOK bool
	}{
		{"passes: parses, matches vuln, not patched", ValidationResult{Parses: true, MatchesVulnerable: true, MatchesPatched: false}, true},
		{"rejects: does not parse", ValidationResult{Parses: false, MatchesVulnerable: true, MatchesPatched: false}, false},
		{"rejects: no true-positive proof", ValidationResult{Parses: true, MatchesVulnerable: false, MatchesPatched: false}, false},
		{"rejects: also matches patched (FP)", ValidationResult{Parses: true, MatchesVulnerable: true, MatchesPatched: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := Admit(tc.res)
			if ok != tc.wantOK {
				t.Errorf("Admit=%v (%s), want %v", ok, reason, tc.wantOK)
			}
			if !ok && reason == "" {
				t.Error("rejection should carry a reason")
			}
		})
	}
}
