package normalize

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Warzuponus/achilles/internal/model"
)

func step(file string, line int, msg string) model.SarifThreadFlowLocation {
	fl := model.SarifFlowLocation{PhysicalLocation: model.SarifPhysicalLocation{
		ArtifactLocation: model.SarifArtifactLocation{URI: file},
		Region:           model.SarifRegion{StartLine: line},
	}}
	if msg != "" {
		fl.Message = &model.SarifMessage{Text: msg}
	}
	return model.SarifThreadFlowLocation{Location: fl}
}

func withFlow(locs ...model.SarifThreadFlowLocation) model.SarifResult {
	return model.SarifResult{CodeFlows: []model.SarifCodeFlow{{ThreadFlows: []model.SarifThreadFlow{{Locations: locs}}}}}
}

// A scanner's data-flow trace becomes the finding's path: steps without a
// place are skipped, a repeated step collapses, and notes are tidied.
func TestFlowFor(t *testing.T) {
	got := flowFor(withFlow(
		step("app.py", 3, "  source:\n request.args "),
		step("app.py", 3, "same place again"),
		step("", 9, "no file"),
		step("app.py", 0, "no line"),
		step("db.py", 12, "sink: cursor.execute"),
	), nil)
	if len(got) != 2 {
		t.Fatalf("steps = %+v", got)
	}
	if got[0] != (model.FlowStep{File: "app.py", Line: 3, Note: "source: request.args"}) || got[1].File != "db.py" || got[1].Line != 12 {
		t.Errorf("steps = %+v", got)
	}
}

func TestFlowFor_DropsTrivialAndBoundsLength(t *testing.T) {
	if got := flowFor(withFlow(step("a.py", 1, "")), nil); got != nil {
		t.Errorf("a one-step path says nothing the location does not: %+v", got)
	}
	if got := flowFor(model.SarifResult{}, nil); got != nil {
		t.Errorf("no code flow: %+v", got)
	}
	var many []model.SarifThreadFlowLocation
	for i := 1; i <= model.MaxFlowSteps+10; i++ {
		many = append(many, step("a.py", i, strings.Repeat("é", 150)))
	}
	got := flowFor(withFlow(many...), nil)
	if len(got) != model.MaxFlowSteps {
		t.Errorf("len = %d, want %d", len(got), model.MaxFlowSteps)
	}
	if !utf8.ValidString(got[0].Note) || len(got[0].Note) > 210 {
		t.Errorf("note not bounded on a character boundary: %d bytes", len(got[0].Note))
	}
}
