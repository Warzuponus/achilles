package issues

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// An issue carries the actionable detail of a verdict: who can exploit it and
// what they gain, or, for an undecided one, the open question and how to settle
// it. A line reference the model was not shown is flagged, not repeated as fact.
func TestBody_CarriesVerdictDetail(t *testing.T) {
	f := fnd("py.open-redirect", "/work/proj/web.py", 8, model.SeverityHigh)
	f.Verdict = &model.Verdict{
		Classification: model.ClassUncertain, Confidence: 0.4, Exploitability: model.ExploitUnknown,
		Blockers:            []string{"whether next= is checked upstream @maintainer"},
		ValidationPlan:      &model.ValidationPlan{Owner: "check the proxy redirect policy"},
		UnverifiedCitations: []string{"line 99"},
	}
	_, body := renderOne(t, f, baseOpts())
	for _, want := range []string{"**Open question:** whether next= is checked upstream", "**Ask whoever runs it:** check the proxy redirect policy", "**Unchecked references:**", "line 99"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "@maintainer") {
		t.Error("model-written detail must go through the same mention defusing as the rest of the body")
	}
}
