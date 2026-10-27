package surface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixture is a small app: an exposed handler that runs SQL with no guard, a
// guarded handler, a helper with a sink and no input, a CLI, a test, a credential
// file and an LLM client.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "app/admin.py", `from flask import Flask, request
app = Flask(__name__)

@app.route("/admin/users", methods=["POST"])
def users():
    q = request.form["q"]
    cur.execute("SELECT * FROM users WHERE name = '" + q + "'")
`)
	write(t, root, "app/account.py", `@app.route("/account")
@login_required
def account():
    cur.execute("SELECT 1")
`)
	write(t, root, "app/util.py", `import subprocess
def run(x):
    subprocess.run(x)
`)
	write(t, root, "cmd/tool/main.go", `package main
import ("flag"; "os/exec")
func main() { flag.Parse(); exec.Command("ls").Run() }
`)
	write(t, root, "tests/test_admin.py", `@app.route("/t")
def t():
    cur.execute("x")
`)
	write(t, root, ".env", "PASSWORD=hunter2-not-real\n")
	write(t, root, "agent/bot.py", `from openai import OpenAI
client = OpenAI()
resp = client.chat.completions.create(model="m", tools=[lookup], messages=m)
`)
	write(t, root, "node_modules/lib/index.js", `app.get("/x", (req, res) => eval(req.query.q))`)
	write(t, root, "Dockerfile", "FROM scratch\n")
	write(t, root, ".github/workflows/ci.yml", "on: push\n")
	write(t, root, "deploy/app.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	return root
}

func TestBuild_ScoresExposedSinkWithoutGuardHighest(t *testing.T) {
	m, err := Build(fixture(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Hotspots) == 0 || m.Hotspots[0].File != "app/admin.py" {
		t.Fatalf("the exposed, unguarded SQL handler must rank first, got %+v", m.Hotspots)
	}
	admin, account, util, test := m.Score("app/admin.py"), m.Score("app/account.py"), m.Score("app/util.py"), m.Score("tests/test_admin.py")
	if !(admin > account) {
		t.Errorf("a guard in the file must rank it below the unguarded one: admin %.2f, account %.2f", admin, account)
	}
	if !(account > util) {
		t.Errorf("network input + sink must outrank a sink alone: account %.2f, util %.2f", account, util)
	}
	if !(test < util) {
		t.Errorf("a test file must be scored down: test %.2f, util %.2f", test, util)
	}
	if !strings.Contains(strings.Join(m.Hotspots[0].Reasons, ";"), "no guard seen") {
		t.Errorf("reasons must say why: %v", m.Hotspots[0].Reasons)
	}
}

func TestBuild_SkipsDependencyTreesAndNeverReadsCredentialFiles(t *testing.T) {
	root := fixture(t)
	m, err := Build(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Score("node_modules/lib/index.js") != 0 {
		t.Error("node_modules is not the project's code")
	}
	var env *Fact
	for i := range m.Facts {
		if strings.HasPrefix(m.Facts[i].File, "node_modules/") {
			t.Errorf("fact from a dependency tree: %+v", m.Facts[i])
		}
		if m.Facts[i].File == ".env" {
			env = &m.Facts[i]
		}
	}
	if env == nil || env.Class != "credential-file" || env.Line != 0 {
		t.Errorf("a credential file is an asset by name, with no line read: %+v", env)
	}
	doc, _ := json.Marshal(m)
	if strings.Contains(string(doc), "hunter2") {
		t.Fatal("the plan must never carry file contents")
	}
	if strings.Contains(string(doc), root) {
		t.Error("the plan must not carry the absolute target path")
	}
}

func TestBuild_FindsAISurfaceAndInfra(t *testing.T) {
	m, err := Build(fixture(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.AIFiles) != 1 || m.AIFiles[0] != "agent/bot.py" {
		t.Errorf("AI files: %v", m.AIFiles)
	}
	classes := map[string]bool{}
	for _, f := range m.Facts {
		if f.Kind == KindAI {
			classes[f.Class] = true
		}
	}
	if !classes["llm-sdk"] || !classes["tool-calling"] {
		t.Errorf("AI classes: %v", classes)
	}
	kinds := map[string]string{}
	for _, i := range m.Infra {
		kinds[i.File] = i.Kind
	}
	want := map[string]string{"Dockerfile": "dockerfile", ".github/workflows/ci.yml": "ci-workflow", "deploy/app.yaml": "kubernetes"}
	for f, k := range want {
		if kinds[f] != k {
			t.Errorf("infra %s: got %q want %q (all: %v)", f, kinds[f], k, kinds)
		}
	}
}

func TestBuild_TruncationIsReported(t *testing.T) {
	m, err := Build(fixture(t), Options{MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated || m.FilesRead != 1 {
		t.Errorf("a walk stopped by its bound must say so: truncated=%v read=%d", m.Truncated, m.FilesRead)
	}
}

func TestBuild_CommentedCodeIsNotASink(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n// exec.Command(\"rm\")\n/*\nexec.Command(\"rm\")\n*/\n")
	m, err := Build(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Score("a.go") != 0 || len(m.Facts) != 0 {
		t.Errorf("comments are not code: %+v", m.Facts)
	}
}

func TestScore_PathForms(t *testing.T) {
	m, err := Build(fixture(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := m.Score("app/admin.py")
	for _, p := range []string{"./app/admin.py", filepath.FromSlash("app/admin.py"), "app//admin.py"} {
		if got := m.Score(p); got != want {
			t.Errorf("Score(%q) = %.2f, want %.2f", p, got, want)
		}
	}
	var nilMap *Map
	if nilMap.Score("app/admin.py") != 0 {
		t.Error("a nil map scores nothing")
	}
}

func TestRisk(t *testing.T) {
	// No exposure: the severity rank, so ordering by risk is ordering by severity.
	for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if Risk(s, 0) != float64(s.Rank()) {
			t.Errorf("Risk(%s, 0) = %v", s, Risk(s, 0))
		}
	}
	if !(Risk(model.SeverityMedium, 1) > Risk(model.SeverityHigh, 0)) {
		t.Error("a medium in the most exposed file must come before a high with no surface")
	}
	if !(Risk(model.SeverityCritical, 0) > Risk(model.SeverityMedium, 1)) {
		t.Error("nothing below high may overtake a critical")
	}
	if Risk(model.SeverityHigh, 7) != Risk(model.SeverityHigh, 1) || Risk(model.SeverityHigh, -1) != Risk(model.SeverityHigh, 0) {
		t.Error("scores are clamped to 0..1")
	}
}

func TestBuild_TestdataIsScoredDown(t *testing.T) {
	root := t.TempDir()
	body := "@app.route(\"/x\")\ndef x():\n    cur.execute(q)\n"
	write(t, root, "app.py", body)
	write(t, root, "pkg/testdata/app.py", body)
	m, err := Build(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !(m.Score("pkg/testdata/app.py") < m.Score("app.py")) {
		t.Errorf("testdata is never deployed: %.2f vs %.2f", m.Score("pkg/testdata/app.py"), m.Score("app.py"))
	}
}
