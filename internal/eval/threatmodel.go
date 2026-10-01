package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/threatmodel"
)

// The threat-model seat cannot be scored the way triage is: there is no ground
// truth for "the right threats", and inventing one would just encode one person's
// opinion. What IS objectively checkable is whether the artifact is USABLE, and
// that is the seat's known failure mode — the config comments have long warned that
// open models "drift on nested schemas and silently omit required fields", and this
// document has the deepest schema Achilles asks for.
//
// So this mode checks structure, not wisdom:
//
//	produced a document -> it is NON-EMPTY -> ids are UNIQUE ->
//	references RESOLVE (threat->component, component->trustZone) ->
//	enums are VALID (STRIDE category, risk level)
//
// A model that emits five plausible threats attached to component ids that do not
// exist has produced something that renders as broken in the report and cannot be
// filtered or grouped. That is a real defect and it is measurable. Whether the
// threats are the *right* threats is not, and this mode does not pretend otherwise.

var strideCategories = map[string]bool{
	"Spoofing": true, "Tampering": true, "Repudiation": true,
	"InformationDisclosure": true, "DenialOfService": true, "ElevationOfPrivilege": true,
}

var riskLevels = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

// ThreatModelOutcome is one generation attempt.
type ThreatModelOutcome struct {
	Generated  bool  `json:"generated"`
	TrustZones int   `json:"trustZones"`
	Components int   `json:"components"`
	Threats    int   `json:"threats"`
	LatencyMS  int64 `json:"latencyMs"`

	// Structural defects, counted rather than just flagged, because "3 of 7 threats
	// point at a component that does not exist" is a different problem from "all
	// of them do".
	DanglingThreatRefs    int `json:"danglingThreatRefs"`
	DanglingComponentRefs int `json:"danglingComponentRefs"`
	UnattachedThreats     int `json:"unattachedThreats"`
	BadCategories         int `json:"badCategories"`
	BadRisks              int `json:"badRisks"`
	DuplicateIDs          int `json:"duplicateIds"`

	Err string `json:"error,omitempty"`
}

// Sound reports a document with no structural defects — every reference resolves,
// every enum is valid, no duplicate ids, and it is not empty.
func (o ThreatModelOutcome) Sound() bool {
	return o.Generated && o.Components > 0 && o.Threats > 0 &&
		o.DanglingThreatRefs == 0 && o.DanglingComponentRefs == 0 &&
		o.BadCategories == 0 && o.BadRisks == 0 && o.DuplicateIDs == 0
}

// ThreatModelReport is the scored result of a threat-model screen.
type ThreatModelReport struct {
	Mode   string `json:"mode"`
	Model  string `json:"model"`
	Repeat int    `json:"repeat"`
	Runs   int    `json:"runs"`

	SoundRate      float64 `json:"soundRate"`
	MeanComponents float64 `json:"meanComponents"`
	MeanThreats    float64 `json:"meanThreats"`

	TotalDangling   int `json:"totalDanglingRefs"`
	TotalBadEnums   int `json:"totalBadEnums"`
	TotalUnattached int `json:"totalUnattachedThreats"`
	Errors          int `json:"errors"`

	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`

	Outcomes []ThreatModelOutcome `json:"outcomes"`
}

// ErrorRate mirrors the other reports.
func (r ThreatModelReport) ErrorRate() float64 {
	if r.Runs == 0 {
		return 0
	}
	return float64(r.Errors) / float64(r.Runs)
}

// Unreliable flags a screen dominated by failed calls.
func (r ThreatModelReport) Unreliable() bool { return r.ErrorRate() >= 0.2 }

// ThreatModelRunner screens the threat-model seat.
type ThreatModelRunner struct {
	Engine   *threatmodel.Engine
	Repeat   int
	Progress func(done, total int)
}

// Run generates the document Repeat times over a profile derived from the corpus,
// and scores each for structural soundness. The corpus doubles as the target: its
// fixtures are real multi-language source with real findings, which is a fairer
// input than a synthetic profile.
func (rn ThreatModelRunner) Run(ctx context.Context, c Corpus, runID string) ThreatModelReport {
	repeat := rn.Repeat
	if repeat < 1 {
		repeat = 1
	}
	rep := ThreatModelReport{Mode: "threat-model", Repeat: repeat}

	inv, scan := corpusProfile(c)
	var comps, threats int
	for i := 0; i < repeat; i++ {
		started := time.Now()
		tm, err := rn.Engine.Generate(ctx, runID, "eval-corpus", inv, scan)
		out := ThreatModelOutcome{LatencyMS: time.Since(started).Milliseconds()}

		switch {
		case err != nil:
			out.Err = err.Error()
			rep.Errors++
		case tm == nil:
			out.Err = "no threat model returned"
			rep.Errors++
		default:
			out = scoreThreatModel(tm, out)
			comps += out.Components
			threats += out.Threats
		}
		rep.Runs++
		rep.TotalDangling += out.DanglingThreatRefs + out.DanglingComponentRefs
		rep.TotalBadEnums += out.BadCategories + out.BadRisks
		rep.TotalUnattached += out.UnattachedThreats
		rep.Outcomes = append(rep.Outcomes, out)
		if rn.Progress != nil {
			rn.Progress(i+1, repeat)
		}
	}

	sound := 0
	for _, o := range rep.Outcomes {
		if o.Sound() {
			sound++
		}
	}
	if rep.Runs > 0 {
		rep.SoundRate = float64(sound) / float64(rep.Runs)
		rep.MeanComponents = float64(comps) / float64(rep.Runs)
		rep.MeanThreats = float64(threats) / float64(rep.Runs)
	}
	return rep
}

// scoreThreatModel checks the document's internal consistency.
func scoreThreatModel(tm *threatmodel.ThreatModel, out ThreatModelOutcome) ThreatModelOutcome {
	out.Generated = true
	out.TrustZones = len(tm.TrustZones)
	out.Components = len(tm.Components)
	out.Threats = len(tm.Threats)

	zoneIDs := map[string]bool{}
	compIDs := map[string]bool{}
	seen := map[string]bool{}
	for _, z := range tm.TrustZones {
		if seen["z:"+z.ID] {
			out.DuplicateIDs++
		}
		seen["z:"+z.ID] = true
		zoneIDs[z.ID] = true
	}
	for _, cp := range tm.Components {
		if seen["c:"+cp.ID] {
			out.DuplicateIDs++
		}
		seen["c:"+cp.ID] = true
		compIDs[cp.ID] = true
	}
	for _, cp := range tm.Components {
		// A component parented to a zone that was never declared cannot be placed
		// in the report's trust-zone grouping.
		if cp.Parent != "" && !zoneIDs[cp.Parent] {
			out.DanglingComponentRefs++
		}
	}
	for _, t := range tm.Threats {
		if seen["t:"+t.ID] {
			out.DuplicateIDs++
		}
		seen["t:"+t.ID] = true
		switch {
		case t.Component == "":
			// Allowed by the schema, and the prompt says not to invent components —
			// so count it separately from an outright broken reference.
			out.UnattachedThreats++
		case !compIDs[t.Component]:
			out.DanglingThreatRefs++
		}
		if !strideCategories[t.Category] {
			out.BadCategories++
		}
		if !riskLevels[strings.ToLower(t.Risk)] {
			out.BadRisks++
		}
	}
	return out
}

// corpusProfile turns the corpus into the inventory + scan the agent consumes, so
// the screen runs against real source and real findings rather than a stub.
func corpusProfile(c Corpus) (inventory.Inventory, model.Scan) {
	langs := map[string]bool{}
	scan := model.Scan{Target: "eval-corpus"}
	tools := map[string]bool{}
	for _, cs := range c.SortedCases() {
		f := cs.ToFinding()
		scan.Findings = append(scan.Findings, f)
		tools[f.Tool] = true
		switch {
		case strings.HasSuffix(cs.Fixture, ".go"):
			langs["go"] = true
		case strings.HasSuffix(cs.Fixture, ".py"):
			langs["python"] = true
		}
	}
	for t := range tools {
		scan.Tools = append(scan.Tools, t)
	}
	sort.Strings(scan.Tools)
	inv := inventory.Inventory{}
	for l := range langs {
		inv.Languages = append(inv.Languages, l)
	}
	sort.Strings(inv.Languages)
	return inv, scan
}

// Write renders the threat-model screen.
func (r ThreatModelReport) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "Threat-model seat — model %s, %d run(s)\n", r.Model, r.Runs)
	if r.Unreliable() {
		fmt.Fprintf(w, "\n  *** RATES BELOW ARE NOT A MODEL RESULT ***\n")
		fmt.Fprintf(w, "  %.0f%% of runs FAILED (%d of %d).\n", 100*r.ErrorRate(), r.Errors, r.Runs)
	}
	fmt.Fprintf(w, "\n  structurally SOUND: %.0f%% of runs   <- every reference resolves, enums valid, no dup ids\n", 100*r.SoundRate)
	fmt.Fprintf(w, "  mean size: %.1f components, %.1f threats\n", r.MeanComponents, r.MeanThreats)
	fmt.Fprintf(w, "  defects across all runs: %d dangling reference(s), %d invalid enum(s), %d unattached threat(s)\n",
		r.TotalDangling, r.TotalBadEnums, r.TotalUnattached)
	if r.Errors > 0 {
		fmt.Fprintf(w, "  errors: %d\n", r.Errors)
	}
	fmt.Fprintf(w, "  tokens: %d prompt + %d completion\n", r.PromptTokens, r.CompletionTokens)

	if verbose {
		fmt.Fprintf(w, "\n  %-5s %5s %6s %7s %9s %6s %6s\n", "RUN", "ZONES", "COMPS", "THREATS", "DANGLING", "ENUMS", "SOUND")
		for i, o := range r.Outcomes {
			fmt.Fprintf(w, "  %-5d %5d %6d %7d %9d %6d %6s\n", i+1, o.TrustZones, o.Components, o.Threats,
				o.DanglingThreatRefs+o.DanglingComponentRefs, o.BadCategories+o.BadRisks, yn(o.Sound()))
		}
	}
	fmt.Fprintf(w, "\n  NOT measured: whether these are the RIGHT threats. There is no ground truth\n")
	fmt.Fprintf(w, "  for that and inventing one would encode one person's opinion. This mode\n")
	fmt.Fprintf(w, "  checks that the artifact is usable, which is the seat's known failure mode.\n")
}

// WriteJSON persists the screen.
func (r ThreatModelReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
