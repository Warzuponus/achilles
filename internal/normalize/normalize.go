package normalize

import (
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// Normalizer converts a tool's native output bytes into findings. fallbackTool
// names the tool when the format doesn't carry it (SARIF does; most plain-JSON
// formats don't).
type Normalizer func(fallbackTool string, data []byte) ([]model.Finding, error)

// normalizers maps a tool's declared output format (config `format:`, carried on
// RawResult.Format) to its normalizer. SARIF is the common path — any tool that
// emits SARIF 2.1.0 needs no code. Tools that don't emit clean SARIF register a
// per-tool JSON normalizer here (DESIGN §4.4), so we don't have to wrap every
// such tool in a SARIF-converter container.
var normalizers = map[string]Normalizer{
	"sarif":      FromSARIF,
	"bandit":     FromBandit,
	"railroader": FromRailroader,
	"shellcheck": FromShellCheck,
}

// Register adds or overrides a normalizer for a format (case-insensitive). For
// out-of-package or test registration; built-ins are in the map above.
func Register(format string, n Normalizer) {
	normalizers[strings.ToLower(format)] = n
}

// Normalize dispatches to the normalizer for the given format. An empty format
// defaults to SARIF (the historical behavior). An unknown, non-empty format is
// an explicit error rather than a silent SARIF parse failure — so a
// misconfigured `format:` fails loudly instead of dropping every finding.
func Normalize(format, fallbackTool string, data []byte) ([]model.Finding, error) {
	if format == "" {
		format = "sarif"
	}
	n, ok := normalizers[strings.ToLower(format)]
	if !ok {
		return nil, fmt.Errorf("no normalizer registered for format %q", format)
	}
	fs, err := n(fallbackTool, data)
	if err != nil {
		return nil, err
	}
	// A credential finding's snippet IS the credential. Its fingerprint has
	// already been derived from it (so two secrets stay two findings), and nothing
	// downstream may show it: reports and issues withhold it, the model never sees
	// it. Keeping it would only copy the secret into the vault and everything that
	// reads the vault, so it stops here.
	for i := range fs {
		if fs[i].IsSecret() {
			fs[i].CodeContext = ""
		}
	}
	return fs, nil
}
