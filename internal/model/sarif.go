package model

import (
	"strconv"
	"strings"
)

// Minimal SARIF 2.1.0 types — only the fields Achilles consumes. This is
// intentionally partial: we ingest what we need and keep the raw result bytes
// on each Finding for anything we didn't model.

// SarifLog is the root of a SARIF document.
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun is one tool invocation.
type SarifRun struct {
	Tool        SarifTool         `json:"tool"`
	Results     []SarifResult     `json:"results"`
	Invocations []SarifInvocation `json:"invocations,omitempty"`
	// OriginalURIBaseIDs maps a symbolic base ("SRCROOT") to the location that a
	// result's artifact URI is relative to.
	OriginalURIBaseIDs map[string]SarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
}

// SarifInvocation records whether the run completed. A scan where a scanner
// failed reports executionSuccessful=false so consumers cannot mistake it for clean.
type SarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []SarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type SarifNotification struct {
	Level   string       `json:"level"`
	Message SarifMessage `json:"message"`
}

// SarifSuppression marks a result as ruled out. GitHub code scanning shows a
// suppressed result as dismissed instead of as an open alert.
type SarifSuppression struct {
	Kind          string `json:"kind"`   // "external": decided outside the source code
	Status        string `json:"status"` // "accepted"
	Justification string `json:"justification,omitempty"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     *SarifMessage       `json:"shortDescription,omitempty"`
	DefaultConfiguration SarifRuleConfig     `json:"defaultConfiguration,omitzero"`
	Properties           SarifRuleProps      `json:"properties,omitzero"`
	Relationships        []SarifRelationship `json:"relationships,omitempty"`
}

// SarifRelationship links a rule to an external taxonomy entry. gosec (and other
// tools that follow the spec closely) publish a rule's CWE this way rather than
// in a tag, with the taxonomy named in target.toolComponent.name and the bare
// numeric id in target.id.
type SarifRelationship struct {
	Kinds  []string `json:"kinds,omitempty"`
	Target struct {
		ID            string `json:"id,omitempty"`
		GUID          string `json:"guid,omitempty"`
		ToolComponent struct {
			Name string `json:"name,omitempty"`
		} `json:"toolComponent,omitempty"`
	} `json:"target,omitempty"`
}

// SarifRuleConfig carries the rule's default level. Per the SARIF spec a result
// with no explicit level inherits it from here.
type SarifRuleConfig struct {
	Level string `json:"level,omitempty"`
}

type SarifRuleProps struct {
	Tags             []string   `json:"tags,omitempty"`
	SecuritySeverity SarifScore `json:"security-severity,omitempty"`
}

// SarifScore is a "security-severity": a CVSS-style score from 0.0 to 10.0. The
// convention (set by GitHub code scanning) carries it as a string, but some tools
// emit a bare number, so decoding accepts either and never fails: a document
// must not become unreadable over one odd score.
type SarifScore string

func (s *SarifScore) UnmarshalJSON(b []byte) error {
	v := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if v == "null" {
		v = ""
	}
	*s = SarifScore(v)
	return nil
}

// Value returns the score and whether it is a usable number in (0, 10].
func (s SarifScore) Value() (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(string(s)), 64)
	if err != nil || f != f || f <= 0 || f > 10 {
		return 0, false
	}
	return f, true
}

type SarifResult struct {
	RuleID string `json:"ruleId"`
	// A result may name its rule by position in the driver's rule list, or through
	// a rule reference, instead of (or as well as) by ruleId.
	RuleIndex           *int               `json:"ruleIndex,omitempty"`
	Rule                *SarifRuleRef      `json:"rule,omitempty"`
	Level               string             `json:"level,omitempty"`
	Message             SarifMessage       `json:"message"`
	Locations           []SarifLocation    `json:"locations,omitempty"`
	Fingerprints        map[string]string  `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []SarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
	// BaselineState says how the result relates to a baseline: "new" when the
	// scan was compared with one and this finding was not in it.
	BaselineState string `json:"baselineState,omitempty"`
	// Fixes are proposed changes that resolve the result.
	Fixes []SarifFix `json:"fixes,omitempty"`
	// CodeFlows is the source-to-sink path a taint engine followed (Opengrep with
	// --dataflow-traces, CodeQL). Achilles reads the first thread flow of the first
	// code flow, and writes one back from Finding.Flow.
	CodeFlows []SarifCodeFlow `json:"codeFlows,omitempty"`
}

// SarifCodeFlow is one path through the code (SARIF 3.36).
type SarifCodeFlow struct {
	ThreadFlows []SarifThreadFlow `json:"threadFlows"`
}

// SarifThreadFlow is the ordered steps of a code flow in one thread (SARIF 3.37).
type SarifThreadFlow struct {
	Locations []SarifThreadFlowLocation `json:"locations"`
}

// SarifThreadFlowLocation is one step (SARIF 3.38).
type SarifThreadFlowLocation struct {
	Location SarifFlowLocation `json:"location"`
}

// SarifFlowLocation is a location that may carry a message saying what happens there.
type SarifFlowLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
	Message          *SarifMessage         `json:"message,omitempty"`
}

// SarifFix is a proposed change: a description and the edits, per file.
type SarifFix struct {
	Description     SarifMessage          `json:"description"`
	ArtifactChanges []SarifArtifactChange `json:"artifactChanges"`
}

type SarifArtifactChange struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Replacements     []SarifReplacement    `json:"replacements"`
}

// SarifReplacement replaces the text of DeletedRegion with InsertedContent.
type SarifReplacement struct {
	DeletedRegion   SarifRegion           `json:"deletedRegion"`
	InsertedContent *SarifArtifactContent `json:"insertedContent,omitempty"`
}

type SarifArtifactContent struct {
	Text string `json:"text"`
}

// SarifRuleRef is a reportingDescriptorReference: a rule named by id or index.
type SarifRuleRef struct {
	ID    string `json:"id,omitempty"`
	Index *int   `json:"index,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	// omitzero: a finding with no line (a dependency advisory, a whole-file
	// result) must be written with no region at all. An empty "region": {} is not
	// valid SARIF, which requires a region to say where it starts.
	Region SarifRegion `json:"region,omitzero"`
}

type SarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SarifRegion struct {
	StartLine   int          `json:"startLine,omitempty"`
	StartColumn int          `json:"startColumn,omitempty"`
	EndLine     int          `json:"endLine,omitempty"`
	EndColumn   int          `json:"endColumn,omitempty"`
	Snippet     SarifSnippet `json:"snippet,omitzero"`
}

type SarifSnippet struct {
	Text string `json:"text,omitempty"`
}
