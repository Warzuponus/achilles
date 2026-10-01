// Package advisor is the SCA dependency-upgrade advisor (DESIGN §7, Tier D). It
// turns the dependency inventory plus the SCA scanners' vulnerability findings
// into a prioritized, MERGE-SAFETY-scored upgrade plan: security-forced upgrades
// first, each scored by how risky it is to merge (a patch bump of a leaf library
// is low risk; a major bump of a core framework is high).
//
// Honest scope: the LLM reasons about *prioritization and merge risk* from the
// deps + the scanners' findings (which carry the vulnerable/fixed versions). It
// is advisory — not a substitute for the registry/changelog for exact versions.
package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// scaTools are the scanners whose findings carry dependency-vulnerability info
// (package + vulnerable/fixed versions) worth feeding the advisor.
var scaTools = map[string]bool{"osv-scanner": true, "trivy": true, "govulncheck": true}

// maxDeps caps how many dependencies go into the prompt (prompt-size bound).
const maxDeps = 200

// Upgrade is one recommended dependency upgrade with its merge-safety score.
type Upgrade struct {
	Package            string `json:"package"`
	Ecosystem          string `json:"ecosystem"`
	CurrentVersion     string `json:"currentVersion"`
	RecommendedVersion string `json:"recommendedVersion"` // best-effort; "" if unknown
	UpgradeType        string `json:"upgradeType"`        // patch | minor | major | unknown
	MergeRisk          string `json:"mergeRisk"`          // low | medium | high
	SecurityDriven     bool   `json:"securityDriven"`     // fixes a known vuln
	Rationale          string `json:"rationale"`
}

// Advice is the advisor's prioritized upgrade plan.
type Advice struct {
	Summary  string    `json:"summary"`
	Upgrades []Upgrade `json:"upgrades"`
}

var adviceSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "summary":{"type":"string"},
    "upgrades":{"type":"array","items":{
      "type":"object",
      "properties":{
        "package":{"type":"string"},
        "ecosystem":{"type":"string"},
        "currentVersion":{"type":"string"},
        "recommendedVersion":{"type":"string"},
        "upgradeType":{"type":"string","enum":["patch","minor","major","unknown"]},
        "mergeRisk":{"type":"string","enum":["low","medium","high"]},
        "securityDriven":{"type":"boolean"},
        "rationale":{"type":"string"}
      },
      "required":["package","upgradeType","mergeRisk","securityDriven","rationale"],
      "additionalProperties":false
    }}
  },
  "required":["summary","upgrades"],
  "additionalProperties":false
}`)

// Engine runs the advisor through the llm.Router (task "sca") and records the
// advice to the vault.
type Engine struct {
	router *llm.Router
	vault  vault.Store
}

func NewEngine(router *llm.Router, v vault.Store) *Engine {
	return &Engine{router: router, vault: v}
}

// Advise produces the upgrade plan from the dependency inventory + SCA findings.
func (e *Engine) Advise(ctx context.Context, runID string, inv inventory.Inventory, scan model.Scan) (*Advice, error) {
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt},
		{Role: llm.RoleUser, Content: promptBody(inv, scan)},
	}
	var a Advice
	resp, err := llm.CompleteAndDecode(ctx, e.router.For("sca"), msgs,
		&llm.Schema{Name: "advice", Definition: adviceSchema}, &a,
		func() error {
			for _, u := range a.Upgrades {
				if u.Package == "" || u.MergeRisk == "" || u.UpgradeType == "" {
					return fmt.Errorf("an upgrade is missing required fields (package/mergeRisk/upgradeType)")
				}
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("sca advice: %w", err)
	}
	if e.vault != nil {
		payload, _ := json.Marshal(a)
		_, _ = e.vault.Append(vault.Record{RunID: runID, Phase: "advisor", Kind: vault.KindAdvisory,
			Source: resp.Model, Payload: payload})
	}
	return &a, nil
}

const systemPrompt = `You are a dependency-upgrade advisor. Given a project's dependencies and the
vulnerability findings from SCA scanners, produce a prioritized upgrade plan.
Rank security-driven upgrades (those that fix a reported vulnerability) first.
For each, score how risky it is to MERGE: patch/minor bumps of leaf libraries are
low risk; major bumps or core frameworks are higher. Set securityDriven=true only
when a finding motivates the upgrade. Be honest when you cannot determine an exact
target version (leave recommendedVersion empty). Return ONLY a single JSON object
matching the schema — no markdown fences, no prose. Every field must be the exact
type shown (where the schema says a string, emit a plain string, never a nested
object), and you MUST fill EVERY field of every upgrade, including summary,
upgradeType, mergeRisk, and rationale. Use exactly these key names, shaped like:
{"summary":"6 security upgrades; prioritize Pillow and Jinja2.","upgrades":[
{"package":"jinja2","ecosystem":"PyPI","currentVersion":"3.1.0",
"recommendedVersion":"3.1.5","upgradeType":"patch","mergeRisk":"low",
"securityDriven":true,"rationale":"Fixes CVE-2024-22195 template injection."}]}`

// promptBody lists the dependencies and the SCA scanners' vulnerability findings
// (which carry package + vulnerable/fixed versions) — the advisor's grounding.
func promptBody(inv inventory.Inventory, scan model.Scan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Dependencies (%d):\n", len(inv.Dependencies))
	for i, d := range inv.Dependencies {
		if i >= maxDeps {
			fmt.Fprintf(&b, "  ... (%d more omitted)\n", len(inv.Dependencies)-maxDeps)
			break
		}
		fmt.Fprintf(&b, "  - %s@%s [%s]\n", d.Name, d.Version, d.Ecosystem)
	}

	b.WriteString("\nSCA vulnerability findings:\n")
	n := 0
	for _, f := range scan.Findings {
		if !scaTools[f.Tool] {
			continue
		}
		fmt.Fprintf(&b, "  - [%s] %s: %s (%s)\n", f.Severity, f.RuleID, strings.TrimSpace(f.Message), f.Tool)
		n++
	}
	if n == 0 {
		b.WriteString("  (none reported by SCA scanners this run)\n")
	}
	return b.String()
}
