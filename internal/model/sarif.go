package model

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
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
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
	DefaultConfiguration SarifRuleConfig     `json:"defaultConfiguration,omitempty"`
	Properties           SarifRuleProps      `json:"properties,omitempty"`
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
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type SarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level,omitempty"`
	Message             SarifMessage      `json:"message"`
	Locations           []SarifLocation   `json:"locations,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine   int          `json:"startLine,omitempty"`
	StartColumn int          `json:"startColumn,omitempty"`
	EndLine     int          `json:"endLine,omitempty"`
	EndColumn   int          `json:"endColumn,omitempty"`
	Snippet     SarifSnippet `json:"snippet,omitempty"`
}

type SarifSnippet struct {
	Text string `json:"text,omitempty"`
}
