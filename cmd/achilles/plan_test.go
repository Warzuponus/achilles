package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/surface"
)

func TestPrioritizeFlag(t *testing.T) {
	o, err := parseFlags([]string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if o.prioritize != prioritizeSeverity || o.planWanted() {
		t.Errorf("default: prioritize=%q planWanted=%v; the map must cost nothing unless asked for", o.prioritize, o.planWanted())
	}
	if _, err := parseFlags([]string{"--prioritize", "exposure", "."}); err == nil || !strings.Contains(err.Error(), "--prioritize") {
		t.Errorf("an unknown order must be refused, got %v", err)
	}
	o, err = parseFlags([]string{"--prioritize", "surface", "."})
	if err != nil || !o.planWanted() {
		t.Fatalf("--prioritize surface builds the map: %v", err)
	}
	if o.reviewPriority() != nil {
		t.Error("no map yet: the order must stay by severity")
	}
}

// The order the review takes findings in decides what is reviewed when the
// budget runs out. Without a priority it is most severe first, exactly as before.
func TestOrderPass1(t *testing.T) {
	fs := []model.Finding{
		{Severity: model.SeverityHigh, Location: model.Location{File: "lib/cold.go"}},     // 0
		{Severity: model.SeverityMedium, Location: model.Location{File: "api/hot.go"}},    // 1
		{Severity: model.SeverityCritical, Location: model.Location{File: "lib/cold.go"}}, // 2
		{Severity: model.SeverityLow, Location: model.Location{File: "api/hot.go"}},       // 3
		{Severity: model.SeverityHigh, Location: model.Location{File: "api/hot.go"}},      // 4
	}
	idx := []int{0, 1, 2, 3, 4}
	orderPass1(fs, idx, nil)
	if want := []int{2, 0, 4, 1, 3}; !equalIdx(idx, want) {
		t.Fatalf("by severity: %v, want %v", idx, want)
	}
	score := func(f *model.Finding) float64 {
		if f.Location.File == "api/hot.go" {
			return surface.Risk(f.Severity, 1)
		}
		return surface.Risk(f.Severity, 0)
	}
	idx = []int{0, 1, 2, 3, 4}
	orderPass1(fs, idx, score)
	// high@hot 6 > critical@cold 5 > medium@hot 4.5 > high@cold 4 > low@hot 3
	if want := []int{4, 2, 1, 0, 3}; !equalIdx(idx, want) {
		t.Fatalf("by risk: %v, want %v", idx, want)
	}
}

func equalIdx(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// End to end: --plan-out writes the map before the scan, the vault records it, and
// it carries the target's surface but none of its source.
func TestRun_PlanOutWritesTheSurfaceMap(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	handler := "from flask import request\n@app.route('/run')\ndef run():\n    os.system(request.args['c'])  # not-a-real-token-123\n"
	if err := os.WriteFile(filepath.Join(target, "web.py"), []byte(handler), 0o644); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := run([]string{"--config", cfg, "--vault", vaultPath, "--plan-out", planPath, "--prioritize", "surface", target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var m surface.Map
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("plan is not JSON: %v", err)
	}
	if m.Version != surface.Version || len(m.Hotspots) == 0 || m.Hotspots[0].File != "web.py" {
		t.Errorf("plan: version %d, hotspots %+v", m.Version, m.Hotspots)
	}
	if bytes.Contains(raw, []byte("not-a-real-token")) || bytes.Contains(raw, []byte("request.args")) {
		t.Error("the plan must not carry source text")
	}
	if bytes.Contains(raw, []byte(target)) {
		t.Error("the plan must not carry the absolute target path")
	}
	v, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(v, []byte(`"kind":"scan_plan"`)) {
		t.Error("the plan must be recorded in the Evidence Vault")
	}
}

func TestRun_NoPlanUnlessAsked(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	if err := run([]string{"--config", cfg, "--vault", vaultPath, target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	v, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(v, []byte(`"kind":"scan_plan"`)) {
		t.Error("a run that asked for no plan must not build one")
	}
}

func TestBuildPlan_UnwritablePlanOutIsAnError(t *testing.T) {
	o := &options{prioritize: prioritizeSeverity, planOut: filepath.Join(t.TempDir(), "no-such-dir", "plan.json")}
	_, ev := triageFixture(t)
	var w bytes.Buffer
	if err := buildPlan(o, ev, "run", t.TempDir(), &w); err == nil {
		t.Error("a requested plan file that cannot be written must fail the run")
	}
}
