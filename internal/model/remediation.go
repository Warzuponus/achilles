package model

// Remediation is the fix proposal for a confirmed finding. We propose; we never
// auto-apply (DESIGN.md §1 Non-Goals). Diff is set when a concrete, local patch
// is possible; Guidance carries prose when the fix needs human judgment.
type Remediation struct {
	Summary    string  `json:"summary"`
	Diff       string  `json:"diff,omitempty"`
	Guidance   string  `json:"guidance,omitempty"`
	Confidence float64 `json:"confidence"`
}
