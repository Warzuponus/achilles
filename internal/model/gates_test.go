package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func openGates() *Gates {
	return &Gates{
		DesignedBehavior:   Gate{Answer: GateNo},
		Reachable:          Gate{Answer: GateYes},
		AttackerControlled: Gate{Answer: GateYes},
		Sanitized:          Gate{Answer: SanitizedNone},
		NewCapability:      Gate{Answer: GateYes},
	}
}

func TestDismissed_GateContradictionIsNeverDismissed(t *testing.T) {
	// A false positive whose own gates describe an open, new-capability path
	// contradicts itself: a human should look.
	fp := Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Gates: openGates()}
	if fp.Dismissed() {
		t.Error("a false_positive with open gates must not be dismissed")
	}
	refuted := Verdict{Classification: ClassTruePositive, Confidence: 0.9, Refuted: true, Gates: openGates()}
	if refuted.Dismissed() {
		t.Error("a refuted verdict whose gates are open must not be dismissed")
	}

	// A gate that closes the path leaves dismissal exactly as it was.
	closed := openGates()
	closed.Sanitized.Answer = SanitizedEffective
	if v := (Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Gates: closed}); !v.Dismissed() {
		t.Error("closed gates must not block a confident dismissal")
	}
	// "unknown" is never an open gate, so it cannot change today's behavior.
	unk := openGates()
	unk.NewCapability.Answer = GateUnknown
	if v := (Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Gates: unk}); !v.Dismissed() {
		t.Error("an unknown gate must not by itself block dismissal")
	}
}

func TestDismissed_NeverEasierWithGatesOrStability(t *testing.T) {
	// Property: attaching gates or stability can only ever turn a dismissal off.
	bases := []Verdict{
		{Classification: ClassFalsePositive, Confidence: 0.9},
		{Classification: ClassFalsePositive, Confidence: 0.5},
		{Classification: ClassTruePositive, Confidence: 0.9},
		{Classification: ClassTruePositive, Confidence: 0.9, Refuted: true},
		{Classification: ClassUncertain, Confidence: 0.9},
		{Classification: ClassFalsePositive, Confidence: 0.9, Overturned: true},
	}
	extras := []Verdict{
		{Gates: openGates()},
		{Stability: &Stability{Samples: 3, Agreeing: 2, Classifications: map[Classification]int{ClassFalsePositive: 2, ClassTruePositive: 1}}},
		{Stability: &Stability{Samples: 3, Agreeing: 3, Classifications: map[Classification]int{ClassFalsePositive: 3}}},
	}
	for _, b := range bases {
		for _, x := range extras {
			v := b
			v.Gates, v.Stability = x.Gates, x.Stability
			if v.Dismissed() && !b.Dismissed() {
				t.Errorf("%+v became dismissable with extras %+v", b, x)
			}
		}
	}
}

func TestDismissed_NonUnanimousSamplesAreKept(t *testing.T) {
	split := &Stability{Samples: 3, Agreeing: 2, Classifications: map[Classification]int{ClassFalsePositive: 2, ClassTruePositive: 1}}
	if v := (Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Stability: split}); v.Dismissed() {
		t.Error("a 2-1 false_positive must not be dismissed")
	}
	if v := (Verdict{Classification: ClassTruePositive, Confidence: 0.9, Refuted: true, Stability: split}); v.Dismissed() {
		t.Error("a refuted verdict with split samples must not be dismissed")
	}
	same := &Stability{Samples: 3, Agreeing: 3, Classifications: map[Classification]int{ClassFalsePositive: 3}}
	if v := (Verdict{Classification: ClassFalsePositive, Confidence: 0.95, Stability: same}); !v.Dismissed() {
		t.Error("unanimous samples keep today's dismissal")
	}
}

func TestGate_UnmarshalToleratesEveryShape(t *testing.T) {
	var g Gates
	if err := json.Unmarshal([]byte(`{"reachable":null,"attackerControlled":[1],"sanitized":{"answer":{"x":1}},"newCapability":"No"}`), &g); err != nil {
		t.Fatalf("gates must never fail a verdict decode: %v", err)
	}
	g.Normalize()
	if g.Reachable.Answer != GateUnknown || g.AttackerControlled.Answer != GateUnknown || g.NewCapability.Answer != GateNo {
		t.Errorf("gates = %+v", g)
	}
}

func TestGate_EvidenceIsBounded(t *testing.T) {
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'a'
	}
	g := Gates{Reachable: Gate{Answer: GateYes, Evidence: string(long)}}
	g.Normalize()
	if n := len(g.Reachable.Evidence); n > maxGateEvidence+3 {
		t.Errorf("evidence length %d not bounded", n)
	}
}

func TestVerdict_JSONOmitsGatesAndStabilityWhenAbsent(t *testing.T) {
	b, _ := json.Marshal(Verdict{Classification: ClassUncertain})
	for _, k := range []string{"gates", "stability"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be omitted when nil: %s", k, b)
		}
	}
}
