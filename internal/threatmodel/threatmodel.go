// Package threatmodel is the threat-model agent (DESIGN §7). It infers a
// starting-point threat model from the codebase profile + scan findings and
// emits it as an OTM (Open Threat Model, https://github.com/iriusrisk/OpenThreatModel)
// document: trust zones, components, and STRIDE threats with mitigations.
//
// Honest scope: the model is INFERRED from the available signal (languages,
// dependencies, findings). It's a scaffold to review and refine, not a
// substitute for a human architecture/threat-modeling session.
package threatmodel

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

const otmVersion = "0.2.0"

// ThreatModel is a minimal OTM 0.2.0 document.
type ThreatModel struct {
	OTMVersion string      `json:"otmVersion"`
	Project    Project     `json:"project"`
	TrustZones []TrustZone `json:"trustZones"`
	Components []Component `json:"components"`
	Threats    []Threat    `json:"threats"`
}

type Project struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type TrustZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Risk string `json:"risk,omitempty"` // e.g. trusted / semi-trusted / untrusted
}

type Component struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`             // e.g. web-service, datastore, cli, library
	Parent      string `json:"parent,omitempty"` // trust-zone id
	Description string `json:"description,omitempty"`
}

type Threat struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"` // STRIDE
	Description string `json:"description"`
	Risk        string `json:"risk"` // low | medium | high | critical
	Mitigation  string `json:"mitigation"`
	Component   string `json:"component,omitempty"` // component id
}

// UnmarshalJSON accepts the key names models actually emit for the STRIDE
// category. The schema asks for "category"; kimi-k2.6 emits "stride" on some runs
// and "category" on others, for the same prompt. Silently dropping it produced
// documents whose every threat had an empty category — which renders blank in the
// HTML report and breaks any consumer grouping by STRIDE.
//
// Aliases are read only when the canonical key is absent, so a response that gets
// it right is never second-guessed.
func (t *Threat) UnmarshalJSON(data []byte) error {
	type alias Threat // avoid recursing into this method
	var raw struct {
		alias
		Stride         string `json:"stride"`
		StrideCategory string `json:"strideCategory"`
		ThreatCategory string `json:"threatCategory"`
		// Plural ARRAY forms. Observed on the wire as
		// `"categories":["Elevation of Privilege"]` — a different key AND a different
		// JSON type from the scalar the schema declares, so a string-typed alias
		// would fail to decode it rather than merely miss it. OTM carries one
		// category per threat, so the first entry wins.
		Categories      []string `json:"categories"`
		Strides         []string `json:"strides"`
		ComponentID     string   `json:"componentId"`
		ComponentIDSnak string   `json:"component_id"`
		Components      []string `json:"components"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*t = Threat(raw.alias)
	if t.Category == "" {
		alts := []string{raw.Stride, raw.StrideCategory, raw.ThreatCategory}
		alts = append(alts, first(raw.Categories), first(raw.Strides))
		for _, alt := range alts {
			if alt != "" {
				t.Category = alt
				break
			}
		}
	}
	if t.Component == "" {
		for _, alt := range []string{raw.ComponentID, raw.ComponentIDSnak, first(raw.Components)} {
			if alt != "" {
				t.Component = alt
				break
			}
		}
	}
	return nil
}

// body is what the LLM fills; otmVersion + project are set by us for grounding.
type body struct {
	TrustZones []TrustZone `json:"trustZones"`
	Components []Component `json:"components"`
	Threats    []Threat    `json:"threats"`
}

var modelSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "trustZones":{"type":"array","items":{
      "type":"object",
      "properties":{"id":{"type":"string"},"name":{"type":"string"},"risk":{"type":"string"}},
      "required":["id","name"],"additionalProperties":false}},
    "components":{"type":"array","items":{
      "type":"object",
      "properties":{"id":{"type":"string"},"name":{"type":"string"},"type":{"type":"string"},
        "parent":{"type":"string"},"description":{"type":"string"}},
      "required":["id","name","type"],"additionalProperties":false}},
    "threats":{"type":"array","items":{
      "type":"object",
      "properties":{"id":{"type":"string"},"name":{"type":"string"},
        "category":{"type":"string","enum":["Spoofing","Tampering","Repudiation","InformationDisclosure","DenialOfService","ElevationOfPrivilege"]},
        "description":{"type":"string"},"risk":{"type":"string","enum":["low","medium","high","critical"]},
        "mitigation":{"type":"string"},"component":{"type":"string"}},
      "required":["id","name","category","description","risk","mitigation"],"additionalProperties":false}}
  },
  "required":["trustZones","components","threats"],
  "additionalProperties":false
}`)

// first returns the leading element of a plural alias, or "".
func first(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

// canonicalCategories maps every spelling of a STRIDE category we have observed to
// the one the OTM schema declares. Models write these the way a human would —
// "Elevation of Privilege", "information disclosure" — which is semantically right
// and schema-wrong, and a downstream consumer filtering on the enum sees a value it
// does not recognize. Measured on the eval corpus: this was the ONLY structural
// defect in kimi-k2.6's output (5 of 7 threats per run), so normalizing here is
// worth more than choosing a different model.
var canonicalCategories = map[string]string{
	"spoofing": "Spoofing", "tampering": "Tampering", "repudiation": "Repudiation",
	"informationdisclosure": "InformationDisclosure",
	"denialofservice":       "DenialOfService",
	"elevationofprivilege":  "ElevationOfPrivilege",
}

// canonicalRisks does the same for the risk enum, which models title-case.
var canonicalRisks = map[string]string{
	"low": "low", "medium": "medium", "high": "high", "critical": "critical",
}

// normalizeThreats canonicalizes the enum fields, leaving anything unrecognized
// untouched so it stays visible as a defect rather than being silently coerced into
// a plausible-looking wrong value.
func normalizeThreats(in []Threat) []Threat {
	out := make([]Threat, len(in))
	copy(out, in)
	for i := range out {
		if c, ok := canonicalCategories[squash(out[i].Category)]; ok {
			out[i].Category = c
		}
		if r, ok := canonicalRisks[squash(out[i].Risk)]; ok {
			out[i].Risk = r
		}
	}
	return out
}

// squash lowercases and strips spaces, hyphens and underscores, so
// "Elevation of Privilege", "elevation-of-privilege" and "ElevationOfPrivilege"
// all collapse to the same key.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case ' ', '-', '_', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Engine runs the threat-model agent through the llm.Router (task "threat-model")
// and records the OTM to the vault.
type Engine struct {
	router *llm.Router
	vault  vault.Store
}

func NewEngine(router *llm.Router, v vault.Store) *Engine {
	return &Engine{router: router, vault: v}
}

// Generate infers an OTM threat model from the codebase profile + findings.
// target names the project (used for the OTM project name/id).
func (e *Engine) Generate(ctx context.Context, runID, target string, inv inventory.Inventory, scan model.Scan) (*ThreatModel, error) {
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt},
		{Role: llm.RoleUser, Content: profile(inv, scan)},
	}
	var bd body
	resp, err := llm.CompleteAndDecode(ctx, e.router.For("threat-model"), msgs,
		&llm.Schema{Name: "threat_model", Definition: modelSchema}, &bd,
		func() error {
			if len(bd.Components) == 0 && len(bd.Threats) == 0 {
				return fmt.Errorf("empty threat model (no components and no threats)")
			}
			return nil
		})
	// Record the RAW response before it is assembled into a document. Triage does
	// this for every call; the whole-repo agents did not, which made one class of
	// question unanswerable: when a field arrives empty, was it empty on the wire or
	// did we lose it in decoding? That cost real time on a blank-category bug.
	if e.vault != nil {
		raw, _ := json.Marshal(map[string]any{
			"task": "threat-model", "model": resp.Model, "response": resp.Content,
		})
		_, _ = e.vault.Append(vault.Record{RunID: runID, Phase: "threat-model",
			Kind: vault.KindLLMCall, Source: "threat-model", Payload: raw})
	}
	if err != nil {
		return nil, fmt.Errorf("threat model: %w", err)
	}
	name := filepath.Base(target)
	tm := &ThreatModel{
		OTMVersion: otmVersion,
		Project:    Project{Name: name, ID: slug(name)},
		TrustZones: bd.TrustZones,
		Components: bd.Components,
		Threats:    normalizeThreats(bd.Threats),
	}
	if e.vault != nil {
		payload, _ := json.Marshal(tm)
		_, _ = e.vault.Append(vault.Record{RunID: runID, Phase: "threat-model", Kind: vault.KindThreatModel,
			Source: resp.Model, Payload: payload})
	}
	return tm, nil
}

const systemPrompt = `You are a threat-modeling assistant. From the codebase profile and scanner
findings, infer a starting-point threat model as OTM (Open Threat Model) content:
- trustZones: trust boundaries (e.g. internet/untrusted, internal/trusted).
- components: the app's parts you can infer (services, datastores, CLIs, key
  libraries), each assigned to a trust zone via "parent".
- threats: concrete STRIDE threats, each tied to a component where possible, with
  a risk level and a mitigation. Ground threats in the findings and tech stack;
  don't invent components you have no evidence for. Return ONLY a single JSON
object matching the schema — no markdown fences, no prose. Every field must be the
exact type shown: where the schema says a string (e.g. a threat's risk), emit a
plain string, never a nested object.`

// profile is a compact codebase summary for the prompt.
func profile(inv inventory.Inventory, scan model.Scan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", scan.Target)
	fmt.Fprintf(&b, "Languages: %s\n", strings.Join(inv.Languages, ", "))
	fmt.Fprintf(&b, "Dependencies: %d\n", len(inv.Dependencies))
	if len(scan.Tools) > 0 {
		fmt.Fprintf(&b, "Scanners run: %s\n", strings.Join(scan.Tools, ", "))
	}
	counts := map[model.Severity]int{}
	rules := map[string]int{}
	for _, f := range scan.Findings {
		counts[f.Severity]++
		rules[f.RuleID]++
	}
	fmt.Fprintf(&b, "Findings: %d (critical=%d high=%d medium=%d low=%d)\n",
		len(scan.Findings), counts[model.SeverityCritical], counts[model.SeverityHigh],
		counts[model.SeverityMedium], counts[model.SeverityLow])
	fmt.Fprintf(&b, "Top rules: %s\n", topRules(rules, 10))
	return b.String()
}

func topRules(m map[string]int, n int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return strings.Join(keys, ", ")
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(s)
	s = nonSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "project"
	}
	return s
}
