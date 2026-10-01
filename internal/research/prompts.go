package research

import (
	"encoding/json"
	"fmt"

	"github.com/Warzuponus/achilles/internal/triage/llm"
)

const PromptVersion = "research/v1"

var issuesSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "issues":{"type":"array","items":{
      "type":"object",
      "properties":{
        "title":{"type":"string"},
        "description":{"type":"string"},
        "citation":{"type":"string"},
        "cwe":{"type":"string"},
        "language":{"type":"string"}
      },
      "required":["title","description","citation","language"],
      "additionalProperties":false
    }}
  },
  "required":["issues"],
  "additionalProperties":false
}`)

var ruleSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "ruleYAML":{"type":"string"},
    "language":{"type":"string"},
    "vulnerableSnippet":{"type":"string"},
    "patchedSnippet":{"type":"string"}
  },
  "required":["ruleYAML","language","vulnerableSnippet","patchedSnippet"],
  "additionalProperties":false
}`)

func researchMessages(t Target) []llm.Message {
	system := "You are a security researcher. For the given technology and version, " +
		"identify concrete, code-detectable security issues (dangerous-API misuse, " +
		"insecure defaults, or a specific known vulnerability). " +
		"EVERY issue MUST include a 'citation' that is a real, resolvable source " +
		"(a CVE id, GHSA id, OSV id, or advisory URL). If you cannot cite a real " +
		"source, DO NOT include the issue. " +
		"Respond with ONLY a JSON object: {\"issues\":[{title, description, citation, cwe, language}]}."

	user := fmt.Sprintf("Technology: %s\nVersion: %s\nEcosystem: %s", t.Tech, t.Version, t.Ecosystem)
	return []llm.Message{{Role: llm.RoleSystem, Content: system}, {Role: llm.RoleUser, Content: user}}
}

func synthesisMessages(i Issue) []llm.Message {
	system := "You are a detection engineer. Write an ORIGINAL Opengrep/Semgrep rule " +
		"(YAML, ASCII only) that detects the described issue, plus two test snippets. " +
		"The 'vulnerableSnippet' MUST trigger the rule; the 'patchedSnippet' MUST be a " +
		"fixed version that must NOT trigger it. Keep snippets minimal and self-contained. " +
		"Do not copy third-party rule content. " +
		"Respond with ONLY a JSON object: {ruleYAML, language, vulnerableSnippet, patchedSnippet}."

	user := fmt.Sprintf("Issue: %s\nDescription: %s\nLanguage: %s\nCWE: %s\nSource: %s",
		i.Title, i.Description, i.Language, i.CWE, i.Citation)
	return []llm.Message{{Role: llm.RoleSystem, Content: system}, {Role: llm.RoleUser, Content: user}}
}
