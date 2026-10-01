package report

import (
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func TestGatingSeverity_IgnoresShadow(t *testing.T) {
	scan := model.Scan{Findings: []model.Finding{
		{Severity: model.SeverityLow},                    // active
		{Severity: model.SeverityCritical, Shadow: true}, // shadow — must not count toward the gate
	}}

	if got := GatingSeverity(scan); got != model.SeverityLow {
		t.Errorf("GatingSeverity should ignore the shadow critical: got %q, want low", got)
	}
	// MaxSeverity (used for display) still reflects everything.
	if got := MaxSeverity(scan); got != model.SeverityCritical {
		t.Errorf("MaxSeverity should include shadow findings: got %q, want critical", got)
	}
}

func TestGatingSeverity_AllShadowIsUnknown(t *testing.T) {
	scan := model.Scan{Findings: []model.Finding{
		{Severity: model.SeverityHigh, Shadow: true},
	}}
	if got := GatingSeverity(scan); got != model.SeverityUnknown {
		t.Errorf("all-shadow scan should not gate: got %q, want unknown", got)
	}
}
