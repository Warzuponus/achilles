package model

import (
	"strings"
	"testing"
)

func TestNormalizeDetail_BoundsAndKeepsByClassification(t *testing.T) {
	long := strings.Repeat("x", 1000)
	v := Verdict{Classification: ClassUncertain, Blockers: []string{"a", "b", "c", "d", "e", "f", long},
		ValidationPlan: &ValidationPlan{}, Attacker: "anyone", Impact: "all", AssessedSeverity: SeverityHigh}
	v.NormalizeDetail()
	if len(v.Blockers) != maxBlockers {
		t.Errorf("blockers = %d, want capped at %d", len(v.Blockers), maxBlockers)
	}
	if v.ValidationPlan != nil {
		t.Error("an empty validation plan should be dropped")
	}
	if v.Attacker != "" || v.Impact != "" || v.AssessedSeverity != "" {
		t.Error("impact detail belongs to a true positive")
	}
	tp := Verdict{Classification: ClassTruePositive, Impact: long, Blockers: []string{"x"}}
	tp.NormalizeDetail()
	if len([]rune(tp.Impact)) > maxDetail+3 || tp.Blockers != nil {
		t.Errorf("true positive detail not normalized: impact %d runes, blockers %v", len([]rune(tp.Impact)), tp.Blockers)
	}
}

func TestHardening_IsDismissedOnlyWhenConfident(t *testing.T) {
	if !(Verdict{Classification: ClassHardening, Confidence: 0.8}).Hardening() {
		t.Error("a confident hardening verdict is a hardening note")
	}
	if (Verdict{Classification: ClassHardening, Confidence: 0.5}).Dismissed() {
		t.Error("an unsure hardening verdict stays in the gate")
	}
	if (Verdict{Classification: ClassHardening, Confidence: 0.9, Overturned: true}).Dismissed() {
		t.Error("an overturned hardening verdict stays in the gate")
	}
	if (Verdict{Classification: ClassFalsePositive, Confidence: 0.9}).Hardening() {
		t.Error("a false positive is not a hardening note")
	}
}

func TestDetails_OnlyWhatIsSet(t *testing.T) {
	if d := (Verdict{Classification: ClassTruePositive}).Details(); len(d) != 0 {
		t.Errorf("no detail expected, got %v", d)
	}
	d := Verdict{AssessedSeverity: SeverityMedium, UnverifiedCitations: []string{"line 4"}}.Details()
	if len(d) != 2 || !strings.Contains(d[0].Text, "the gate uses the scanner's severity") || !strings.Contains(d[1].Text, "line 4") {
		t.Errorf("details = %v", d)
	}
}
