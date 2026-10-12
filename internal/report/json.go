package report

import (
	"encoding/json"
	"io"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
)

// JSONSchemaVersion is the version of the --json-report document. It changes when
// a field is removed or changes meaning; adding a field does not change it.
const JSONSchemaVersion = 1

// jsonReport is the machine-readable form of a scan: everything the other reports
// are rendered from, in Achilles' own shape rather than SARIF's.
type jsonReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	GeneratedBy   string `json:"generatedBy"`
	// Complete is false when a scanner failed or could not analyze everything, or
	// the AI review stopped early: an empty findings list then proves nothing.
	Complete bool `json:"complete"`
	model.Scan
}

// WriteJSON emits the scan as one JSON document, for scripts and dashboards that
// would otherwise scrape the human report or dig Achilles' fields out of SARIF
// property bags. Credential findings keep their place in the list but their
// message is masked, as in every other report; raw scanner output is never
// included.
func WriteJSON(w io.Writer, s model.Scan) error {
	out := s
	out.Findings = maskSecrets(s.Findings)
	out.Dismissed = maskSecrets(s.Dismissed)
	// Empty arrays, not null: consumers iterate without a nil check.
	if out.Findings == nil {
		out.Findings = []model.Finding{}
	}
	if out.Tools == nil {
		out.Tools = []string{}
	}
	doc := jsonReport{
		SchemaVersion: JSONSchemaVersion,
		GeneratedBy:   "achilles",
		Complete:      len(s.FailedTools) == 0 && (s.Triage == nil || s.Triage.Aborted == ""),
		Scan:          out,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// maskSecrets returns a copy of the findings in which a credential finding's
// message is masked. The originals are not modified.
func maskSecrets(fs []model.Finding) []model.Finding {
	if fs == nil {
		return nil
	}
	out := make([]model.Finding, len(fs))
	copy(out, fs)
	for i := range out {
		if out[i].IsSecret() {
			out[i].Message = redact.Secrets(out[i].Message)
			out[i].CodeContext = ""
		}
	}
	return out
}
