package surface

import (
	"strings"
	"testing"
)

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

func TestLoadContext_AbsentIsNil(t *testing.T) {
	c, err := LoadContext(t.TempDir())
	if c != nil || err != nil {
		t.Fatalf("no file: got %+v, %v; want nil, nil", c, err)
	}
}

func TestLoadContext_ReadsTheFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".achilles/threat-context.yml", "businessCritical: true\ncrownJewels: [internal/auth/]\noutOfScope: [examples/]\n")
	c, err := LoadContext(root)
	if err != nil {
		t.Fatal(err)
	}
	if c.File != ".achilles/threat-context.yml" || c.BusinessCritical == nil || !*c.BusinessCritical || c.ConfidentialData != nil {
		t.Errorf("context: %+v", c)
	}
}

// A misspelled question must not quietly count as "unknown": that would change
// the scan without anyone noticing.
func TestParseContext_RefusesUnknownKeysAndBadPatterns(t *testing.T) {
	for name, doc := range map[string]string{
		"misspelled key": "busnessCritical: true\n",
		"not a bool":     "autonomous: sometimes\n",
		"absolute path":  "outOfScope: [/etc/]\n",
		"parent path":    "crownJewels: [../other/]\n",
		"empty pattern":  "outOfScope: ['']\n",
		"bad glob":       "outOfScope: ['[a-']\n",
	} {
		if _, err := ParseContext([]byte(doc)); err == nil {
			t.Errorf("%s: %q was accepted", name, doc)
		}
	}
	if c, err := ParseContext([]byte("# only comments\n")); err != nil || c == nil {
		t.Errorf("a file of comments is an empty context, got %v, %v", c, err)
	}
	if _, err := ParseContext([]byte(ContextTemplate)); err != nil {
		t.Errorf("the init template must parse: %v", err)
	}
}

func TestMatchOne(t *testing.T) {
	for _, c := range []struct {
		pat, rel string
		want     bool
	}{
		{"examples/", "examples/a/b.go", true},
		{"examples/**", "examples/a.go", true},
		{"examples/", "src/examples/a.go", false},
		{"examples", "src/examples/a.go", true}, // no slash: any segment
		{"*.pb.go", "api/v1/x.pb.go", true},
		{"cmd/*/main.go", "cmd/tool/main.go", true},
		{"cmd/*/main.go", "cmd/tool/sub/main.go", false},
		{"services/*/internal/", "services/billing/internal/db.go", true},
		{"services/*/internal/", "services/billing/api.go", false},
	} {
		if got := matchOne(c.pat, c.rel); got != c.want {
			t.Errorf("matchOne(%q, %q) = %v, want %v", c.pat, c.rel, got, c.want)
		}
	}
}

func TestDecideDepth(t *testing.T) {
	exposed := &Map{NetworkEntries: 3}
	for _, c := range []struct {
		name string
		ctx  *Context
		m    *Map
		want string
	}{
		{"no context, no entry points", nil, &Map{}, DepthStandard},
		{"no context, network entry points", nil, exposed, DepthStandard},
		{"business critical", &Context{BusinessCritical: yes()}, nil, DepthFull},
		{"confidential data", &Context{ConfidentialData: yes()}, nil, DepthFull},
		{"autonomous only", &Context{BusinessCritical: no(), ConfidentialData: no(), ExternallyFacing: no(), Autonomous: yes(), MultiAgent: no()}, nil, DepthStandard},
		{"all five no", &Context{BusinessCritical: no(), ConfidentialData: no(), ExternallyFacing: no(), Autonomous: no(), MultiAgent: no()}, &Map{}, DepthLightweight},
		// "No" from the owners stands against the inference: they know whether it is deployed.
		{"all five no, entry points", &Context{BusinessCritical: no(), ConfidentialData: no(), ExternallyFacing: no(), Autonomous: no(), MultiAgent: no()}, exposed, DepthLightweight},
		{"four no, one unknown", &Context{BusinessCritical: no(), ConfidentialData: no(), ExternallyFacing: no(), Autonomous: no()}, &Map{}, DepthStandard},
	} {
		d := DecideDepth(c.ctx, c.m)
		if d.Level != c.want || len(d.Reasons) == 0 || len(d.Answers) != 5 {
			t.Errorf("%s: %+v, want %s", c.name, d, c.want)
		}
	}
	d := DecideDepth(nil, exposed)
	if d.Answers[2].Value != "yes" || d.Answers[2].Source != "inferred" || !strings.Contains(d.Reasons[0], "inferred") {
		t.Errorf("network entry points answer externallyFacing: %+v", d)
	}
	if d := DecideDepth(&Context{BusinessCritical: no(), ConfidentialData: no(), ExternallyFacing: no(), Autonomous: no()}, &Map{}); !strings.Contains(d.Reasons[0], "1 of 5") {
		t.Errorf("an unanswered question is named: %v", d.Reasons)
	}
}

// Crown jewels rank first, even with no hint in them; out-of-scope code ranks
// last; neither is ever dropped from the map.
func TestBuild_ContextShapesTheOrder(t *testing.T) {
	root := fixture(t)
	write(t, root, "internal/auth/token.go", "package auth\nfunc Sign() {}\n")
	write(t, root, "examples/demo.py", "@app.route('/x')\ndef x():\n    os.system(request.args['c'])\n")
	ctx := &Context{CrownJewels: []string{"internal/auth/"}, OutOfScope: []string{"examples/"}}
	m, err := Build(root, Options{Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	jewel := m.score["internal/auth/token.go"]
	if jewel < 0.3 {
		t.Errorf("a crown jewel with no hints still scores: %v", jewel)
	}
	demo, admin := m.score["examples/demo.py"], m.score["app/admin.py"]
	if demo == 0 || demo >= admin {
		t.Errorf("out of scope is scored down, not dropped: demo %v, admin %v", demo, admin)
	}
	if m.Context != ctx || m.Depth.Level == "" {
		t.Errorf("the map carries the context and the depth: %+v", m.Depth)
	}
	py := m.Languages["python"]
	if py.Files < 5 || py.InScope != py.Files-2 { // the test file and the example are not in scope
		t.Errorf("python: %+v", py)
	}
}

func TestBuild_MarkersAndLanguages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module x\n")
	write(t, root, "main.go", "package main\n")
	write(t, root, "psalm.xml", "<psalm/>\n")
	write(t, root, "web/index.php", "<?php echo 1;\n")
	write(t, root, "svc/App.csproj", "<Project/>\n")
	write(t, root, "app/Main.kt", "fun main() {}\n")
	write(t, root, "build/classes/Main.class", "\xca\xfe\xba\xbe")
	write(t, root, "build/gen/Gen.java", "class Gen {}\n") // build output: not counted
	write(t, root, "config/routes.rb", "Rails.application.routes.draw do\nend\n")
	write(t, root, ".github/workflows/ci.yml", "on: push\n")
	write(t, root, "deploy/stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
	write(t, root, "deploy/azure.json", `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"}`)
	write(t, root, "k8s/kustomization.yaml", "resources: []\n")
	write(t, root, "config/app.yaml", "name: plain config\n")
	m, err := Build(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mk := range []string{MarkerGoMod, MarkerPsalm, MarkerDotNet, MarkerBytecode, MarkerRails, MarkerIaC, MarkerWorkflows} {
		if !m.HasMarker(mk) {
			t.Errorf("marker %s not found (markers %v)", mk, m.Markers)
		}
	}
	if m.Languages["kotlin"].Files != 1 || m.Languages["java"].Files != 0 {
		t.Errorf("languages: %+v", m.Languages)
	}
	kinds := map[string]string{}
	for _, i := range m.Infra {
		kinds[i.File] = i.Kind
	}
	for file, want := range map[string]string{
		"deploy/stack.yaml": "cloudformation", "deploy/azure.json": "arm",
		"k8s/kustomization.yaml": "kubernetes", ".github/workflows/ci.yml": "ci-workflow",
	} {
		if kinds[file] != want {
			t.Errorf("%s: kind %q, want %q", file, kinds[file], want)
		}
	}
	if k, ok := kinds["config/app.yaml"]; ok {
		t.Errorf("a plain config file is not infrastructure: %q", k)
	}
}

// Markers in out-of-scope or test code do not count: a fixture Rails app does not
// make the repository a Rails app.
func TestBuild_MarkersOutOfScopeDoNotCount(t *testing.T) {
	root := t.TempDir()
	write(t, root, "testdata/rails/config/routes.rb", "x\n")
	write(t, root, "examples/go.mod", "module x\n")
	m, err := Build(root, Options{Context: &Context{OutOfScope: []string{"examples/"}}})
	if err != nil {
		t.Fatal(err)
	}
	if m.HasMarker(MarkerRails) || m.HasMarker(MarkerGoMod) {
		t.Errorf("markers: %v", m.Markers)
	}
}
