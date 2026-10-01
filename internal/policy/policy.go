// Package policy enforces which tools may run in which mode. This is the
// commercial-safety guarantee from DESIGN.md §3/§10: a scan in commercial-mode
// must never silently enable a tool that isn't license-clean for scanning
// third-party code.
package policy

import "fmt"

// Mode selects the license posture of a scan.
type Mode string

const (
	// ModeOSS runs every tool — for scanning our own or open-source code.
	ModeOSS Mode = "oss"
	// ModeCommercial runs only commercial-safe tools (plus attested ones).
	ModeCommercial Mode = "commercial"
)

// ParseMode validates a mode string.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeOSS:
		return ModeOSS, nil
	case ModeCommercial:
		return ModeCommercial, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want oss|commercial)", s)
	}
}

// ToolLicense is the license fact set the gate reasons about.
type ToolLicense struct {
	ID                  string
	License             string
	CommercialSafe      bool
	RequiresAttestation bool // e.g. CodeQL: usable on customer code only with a supplied license
}

// Gate decides tool admission for a mode.
type Gate struct {
	Mode Mode
	// Attested holds tool IDs for which the operator supplied a license
	// attestation (unlocks RequiresAttestation tools in commercial-mode).
	Attested map[string]bool
}

// Allow reports why a tool may not run, or nil if it may.
func (g Gate) Allow(t ToolLicense) error {
	switch g.Mode {
	case ModeOSS:
		return nil
	case ModeCommercial:
		if t.CommercialSafe {
			return nil
		}
		if t.RequiresAttestation {
			if g.Attested[t.ID] {
				return nil
			}
			return fmt.Errorf("tool %q (license %s) needs a license attestation for commercial-mode; pass --attest %s", t.ID, t.License, t.ID)
		}
		return fmt.Errorf("tool %q (license %s) is not commercial-safe and is refused in commercial-mode", t.ID, t.License)
	default:
		return fmt.Errorf("unknown mode %q", g.Mode)
	}
}
