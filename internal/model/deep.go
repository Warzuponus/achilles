package model

// DeepVerification is the outcome of letting the model read and search the
// repository (bounded, read-only) to settle a finding the single-file review could
// not. Owned by internal/deep.
//
// It records what the deep pass concluded, not what the finding's final verdict is:
// internal/deep.Apply decides how (and whether) it changes Finding.Verdict.
type DeepVerification struct {
	Steps      int            `json:"steps"`              // tool calls used
	Conclusion Classification `json:"conclusion"`         // the deep pass's call
	Confidence float64        `json:"confidence"`         // 0..1
	Reasoning  string         `json:"reasoning"`          // why, in the model's words
	Evidence   []string       `json:"evidence,omitempty"` // file:line references it relied on (only ones a tool actually showed it)
	Aborted    string         `json:"aborted,omitempty"`  // non-empty: why the loop stopped without a conclusion

	// Audit fields. All optional so records written before they existed still decode.
	PromptVersion   string   `json:"promptVersion,omitempty"`   // prompt revision that produced this
	ToolBytes       int      `json:"toolBytes,omitempty"`       // bytes of tool output shown to the model
	Trace           []string `json:"trace,omitempty"`           // each tool call, in order, e.g. "read_file a/b.go 10-40"
	EvidenceDropped int      `json:"evidenceDropped,omitempty"` // cited references discarded because no tool showed that file

	// Path is the source-to-sink path the deep pass traced, entry first. Every
	// step is a line a tool showed the model; steps it was not shown are dropped
	// and counted in PathDropped.
	Path        []FlowStep `json:"path,omitempty"`
	PathDropped int        `json:"pathDropped,omitempty"`
}
