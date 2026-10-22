package deep

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// The tool-calling protocol works on any OpenAI-compatible endpoint, with no native
// function calling: each turn the model replies with ONE JSON object whose "action"
// names a tool or is "conclude".
const (
	ActionReadFile       = "read_file"
	ActionGrep           = "grep"
	ActionListDir        = "list_dir"
	ActionFindReferences = "find_references"
	ActionConclude       = "conclude"
	// ActionReport ends a hunt (hunt.go) with the candidates found, if any.
	ActionReport = "report"
)

// Action is one decoded model turn. Fields not used by an action are zero.
type Action struct {
	Action string `json:"action"`

	// Tool arguments.
	Path     string  `json:"path,omitempty"`      // read_file, list_dir; optional search root for grep
	Start    flexInt `json:"start,omitempty"`     // read_file
	End      flexInt `json:"end,omitempty"`       // read_file
	Pattern  string  `json:"pattern,omitempty"`   // grep
	PathGlob string  `json:"path_glob,omitempty"` // grep, find_references
	Symbol   string  `json:"symbol,omitempty"`    // find_references

	// Conclusion.
	Classification string      `json:"classification,omitempty"`
	Confidence     flexFloat   `json:"confidence,omitempty"`
	Reasoning      string      `json:"reasoning,omitempty"`
	Evidence       flexStrings `json:"evidence,omitempty"`
	// Route is the source-to-sink path, entry first: "file:line what happens here".
	// ("path" is taken: it is read_file's argument.)
	Route flexStrings `json:"route,omitempty"`

	// Candidates are a hunt's findings (report only).
	Candidates []RawCandidate `json:"candidates,omitempty"`
}

// RawCandidate is one issue a hunt reports, as the model wrote it.
type RawCandidate struct {
	Location  string      `json:"location"` // "file:line" of the sink
	Class     string      `json:"class"`
	Severity  string      `json:"severity"`
	Title     string      `json:"title"`
	Reasoning string      `json:"reasoning"`
	Route     flexStrings `json:"route,omitempty"`
}

// IsTool reports whether the action asks for a tool call.
func (a Action) IsTool() bool {
	switch a.Action {
	case ActionReadFile, ActionGrep, ActionListDir, ActionFindReferences:
		return true
	}
	return false
}

// Describe is a compact one-line form for the audit trace. It never includes more
// than the arguments the model supplied.
func (a Action) Describe() string {
	clip := func(s string) string { return capBytes(cleanText(s), 80, "…") }
	switch a.Action {
	case ActionReadFile:
		return fmt.Sprintf("read_file %s %d-%d", clip(a.Path), a.Start.Int(), a.End.Int())
	case ActionGrep:
		d := "grep " + strconv.Quote(clip(a.Pattern))
		if a.PathGlob != "" {
			d += " glob=" + clip(a.PathGlob)
		}
		if a.Path != "" {
			d += " in=" + clip(a.Path)
		}
		return d
	case ActionListDir:
		return "list_dir " + clip(a.Path)
	case ActionFindReferences:
		return "find_references " + clip(a.Symbol)
	}
	return a.Action
}

// compact is the normalized form echoed back into the transcript in place of the
// model's raw reply, so a long or hostile reply is not replayed on every later turn.
func (a Action) compact() string {
	m := map[string]any{"action": a.Action}
	switch a.Action {
	case ActionReadFile:
		m["path"], m["start"], m["end"] = a.Path, a.Start.Int(), a.End.Int()
	case ActionGrep:
		m["pattern"] = a.Pattern
		if a.PathGlob != "" {
			m["path_glob"] = a.PathGlob
		}
		if a.Path != "" {
			m["path"] = a.Path
		}
	case ActionListDir:
		m["path"] = a.Path
	case ActionFindReferences:
		m["symbol"] = a.Symbol
		if a.PathGlob != "" {
			m["path_glob"] = a.PathGlob
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ParseAction decodes and validates one model reply. The error text is fed back to
// the model for its single repair attempt, so it says what to fix.
func ParseAction(content string) (Action, error) { return parseAction(content, ActionConclude) }

// parseAction decodes one reply whose final action must be terminal (conclude for
// verification, report for a hunt). The other final action is refused, so a model
// cannot end a hunt with a verdict or a verification with candidates.
func parseAction(content, terminal string) (Action, error) {
	var a Action
	body := llm.ExtractJSON(content)
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		return Action{}, fmt.Errorf("the reply was not a single valid JSON object (%v)", err)
	}
	a.Action = strings.ToLower(strings.TrimSpace(a.Action))
	switch a.Action {
	case ActionReadFile, ActionListDir:
		if a.Action == ActionReadFile && strings.TrimSpace(a.Path) == "" {
			return Action{}, errors.New(`read_file needs "path"`)
		}
	case ActionGrep:
		if strings.TrimSpace(a.Pattern) == "" {
			return Action{}, errors.New(`grep needs "pattern"`)
		}
	case ActionFindReferences:
		if strings.TrimSpace(a.Symbol) == "" {
			return Action{}, errors.New(`find_references needs "symbol"`)
		}
	case ActionReport:
		if terminal != ActionReport {
			return Action{}, fmt.Errorf("unknown action %q; use read_file, grep, list_dir, find_references or conclude", a.Action)
		}
		if len(a.Candidates) > maxRawCandidates {
			a.Candidates = a.Candidates[:maxRawCandidates]
		}
	case ActionConclude:
		if terminal != ActionConclude {
			return Action{}, errors.New(`end the hunt with "report" (an empty candidates list when you found nothing), not "conclude"`)
		}
		switch model.Classification(strings.ToLower(strings.TrimSpace(a.Classification))) {
		case model.ClassTruePositive, model.ClassFalsePositive, model.ClassUncertain:
			a.Classification = strings.ToLower(strings.TrimSpace(a.Classification))
		default:
			return Action{}, errors.New(`conclude needs "classification" of true_positive, false_positive or uncertain`)
		}
		c := float64(a.Confidence)
		if c > 1 && c <= 100 { // a model that says 85 means 85%
			c /= 100
		}
		if math.IsNaN(c) || c < 0 || c > 1 {
			return Action{}, errors.New(`conclude needs "confidence" between 0 and 1`)
		}
		a.Confidence = flexFloat(c)
		if strings.TrimSpace(a.Reasoning) == "" {
			return Action{}, errors.New(`conclude needs a non-empty "reasoning"`)
		}
	case "":
		return Action{}, errors.New(`the JSON object needs an "action" field`)
	default:
		return Action{}, fmt.Errorf("unknown action %q; use read_file, grep, list_dir, find_references or %s", a.Action, terminal)
	}
	return a, nil
}

// maxRawCandidates bounds how many candidates one reply may carry before they are
// checked; hunt.go keeps fewer.
const maxRawCandidates = 10

// stepSchema is the JSON Schema sent as response_format. It is flat (not a oneOf)
// because many OpenAI-compatible servers reject unions; optional fields also keep
// it out of strict mode, which the client detects on its own.
var stepSchema = &llm.Schema{Name: "deep_step", Definition: json.RawMessage(`{
  "type":"object",
  "properties":{
    "action":{"type":"string","enum":["read_file","grep","list_dir","find_references","conclude"]},
    "path":{"type":"string"},
    "start":{"type":"integer"},
    "end":{"type":"integer"},
    "pattern":{"type":"string"},
    "path_glob":{"type":"string"},
    "symbol":{"type":"string"},
    "classification":{"type":"string","enum":["true_positive","false_positive","uncertain"]},
    "confidence":{"type":"number"},
    "reasoning":{"type":"string"},
    "evidence":{"type":"array","items":{"type":"string"}},
    "route":{"type":"array","items":{"type":"string"}}
  },
  "required":["action"]
}`)}

// ---- lenient scalar decoding ------------------------------------------------

// Open models send numbers as strings and a lone string where a list belongs; none
// of that is worth a repair round-trip.

type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e9 {
		return fmt.Errorf("not a number: %s", b)
	}
	*f = flexInt(int(v))
	return nil
}

// Int returns the value as an int.
func (f flexInt) Int() int { return int(f) }

type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	s = strings.TrimSuffix(s, "%")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("not a number: %s", b)
	}
	*f = flexFloat(v)
	return nil
}

type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	if s := strings.TrimSpace(string(b)); s == "null" || s == "" {
		*f = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*f = flexStrings{one}
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("evidence must be a list of strings")
	}
	out := make(flexStrings, 0, len(raw))
	for _, r := range raw {
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			s = strings.Trim(string(r), `"`)
		}
		out = append(out, s)
	}
	*f = out
	return nil
}
