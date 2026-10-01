package policy

import "testing"

func TestParseMode(t *testing.T) {
	for _, s := range []string{"oss", "commercial"} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q): unexpected error %v", s, err)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Error("ParseMode(bogus): want error")
	}
}

func TestGate(t *testing.T) {
	opengrep := ToolLicense{ID: "opengrep", License: "LGPL-2.1", CommercialSafe: true}
	brakeman := ToolLicense{ID: "brakeman", License: "CC-BY-NC-SA", CommercialSafe: false}
	codeql := ToolLicense{ID: "codeql", License: "GitHub", CommercialSafe: false, RequiresAttestation: true}

	tests := []struct {
		name      string
		gate      Gate
		tool      ToolLicense
		wantAllow bool
	}{
		{"oss allows safe", Gate{Mode: ModeOSS}, opengrep, true},
		{"oss allows non-safe", Gate{Mode: ModeOSS}, brakeman, true},
		{"oss allows attest tool", Gate{Mode: ModeOSS}, codeql, true},
		{"commercial allows safe", Gate{Mode: ModeCommercial}, opengrep, true},
		{"commercial blocks non-safe", Gate{Mode: ModeCommercial}, brakeman, false},
		{"commercial blocks unattested", Gate{Mode: ModeCommercial}, codeql, false},
		{"commercial allows attested", Gate{Mode: ModeCommercial, Attested: map[string]bool{"codeql": true}}, codeql, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.gate.Allow(tc.tool)
			if gotAllow := err == nil; gotAllow != tc.wantAllow {
				t.Errorf("Allow=%v (err=%v), want allow=%v", gotAllow, err, tc.wantAllow)
			}
		})
	}
}

func TestGate_UnknownMode(t *testing.T) {
	if err := (Gate{Mode: "weird"}).Allow(ToolLicense{CommercialSafe: true}); err == nil {
		t.Error("want error for unknown mode")
	}
}
