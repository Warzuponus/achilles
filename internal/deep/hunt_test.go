package deep

import (
	"context"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm/llmtest"
)

const flaskApp = `from flask import Flask, request
import db

app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args["id"]
    return db.find(uid)
`

const flaskDB = `import sqlite3

def find(uid):
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT * FROM u WHERE id = " + uid).fetchall()
`

func huntRepo(t *testing.T) string {
	t.Helper()
	root, _ := fixture(t, map[string]string{
		"app.py":                  flaskApp,
		"db.py":                   flaskDB,
		"tests/test_app.py":       "from app import app\n\n@app.route(\"/fixture\")\ndef f():\n    pass\n",
		"node_modules/x/index.js": "app.get('/vendored', (req, res) => {})\n",
	})
	return root
}

func TestSeeds_FindsRoutesAndSkipsTestsAndVendored(t *testing.T) {
	v := newV(t, &llmtest.Fake{}, huntRepo(t), Config{})
	seeds := v.Seeds(10, nil)
	if len(seeds) == 0 {
		t.Fatal("no seeds")
	}
	for _, s := range seeds {
		if s.File != "app.py" {
			t.Errorf("seed from %s; tests and vendored code are not entry points", s.File)
		}
	}
	if seeds[0].Kind != "http-route" || seeds[0].Line != 6 {
		t.Errorf("first seed = %+v, want the route on line 6", seeds[0])
	}
	if got := v.Seeds(10, map[string]bool{"db.py": true}); len(got) != 0 {
		t.Errorf("only= limits the walk: %+v", got)
	}
	if got := v.Seeds(0, nil); got != nil {
		t.Error("n=0 is no seeds")
	}
}

func TestSeeds_SpreadAcrossFiles(t *testing.T) {
	root, _ := fixture(t, map[string]string{
		"a.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/1')\ndef a(): pass\n@app.route('/2')\ndef b(): pass\n",
		"b.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/3')\ndef c(): pass\n",
	})
	seeds := newV(t, &llmtest.Fake{}, root, Config{}).Seeds(2, nil)
	if len(seeds) != 2 || seeds[0].File == seeds[1].File {
		t.Errorf("two seeds should come from two files: %+v", seeds)
	}
}

func TestHunt_ReportsOnlyWhatItWasShown(t *testing.T) {
	fake := &llmtest.Fake{Responses: []string{
		`{"action":"read_file","path":"db.py","start":1,"end":10}`,
		`{"action":"report","candidates":[` +
			`{"location":"db.py:5","class":"SQL Injection","severity":"critical","title":"id from the query string reaches SQL","reasoning":"concatenated","route":["app.py:8 request.args","db.py:5 execute"]},` +
			`{"location":"db.py:99","class":"xss","severity":"high","title":"never shown"},` +
			`{"location":"db.py:5","class":"sql-injection","severity":"high","title":"duplicate"}]}`,
	}}
	v := newV(t, fake, huntRepo(t), Config{})
	res, err := v.Hunt(context.Background(), HuntSeed{File: "app.py", Line: 6, Kind: "http-route", Summary: "HTTP route /user"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Aborted != "" || len(res.Candidates) != 1 || res.Dropped != 1 {
		t.Fatalf("res = %+v", res)
	}
	c := res.Candidates[0]
	if c.File != "db.py" || c.Line != 5 || c.Class != "sql-injection" || c.Severity != model.SeverityHigh || len(c.Route) != 2 {
		t.Errorf("candidate = %+v (critical is capped at high: the review assesses severity)", c)
	}
	f := HuntFinding(c, res.Seed)
	if f.Tool != HuntTool || f.RuleID != "hunt/sql-injection" || !f.Hunted || f.CWE[0] != "CWE-89" || len(f.Flow) != 2 {
		t.Errorf("finding = %+v", f)
	}
	sys := fake.Calls[0].Messages[0].Content
	if !strings.Contains(sys, "Precision over recall") || !strings.Contains(sys, `"action":"report"`) {
		t.Error("hunt prompt missing its standard of proof or report format")
	}
	if !strings.Contains(fake.Calls[0].Messages[1].Content, `request.args["id"]`) {
		t.Error("the first message should show the code around the entry point")
	}
}

func TestHunt_EmptyReportAndRefusedConclude(t *testing.T) {
	v := newV(t, &llmtest.Fake{Responses: []string{`{"action":"report","candidates":[]}`}}, huntRepo(t), Config{})
	res, err := v.Hunt(context.Background(), HuntSeed{File: "app.py", Line: 6})
	if err != nil || res.Aborted != "" || len(res.Candidates) != 0 {
		t.Fatalf("an empty report is a good answer: %+v %v", res, err)
	}

	// A verdict is not a report: refused, repaired once, then aborted.
	bad := conclude("true_positive", 0.9)
	v = newV(t, &llmtest.Fake{Responses: []string{bad, bad}}, huntRepo(t), Config{})
	res, _ = v.Hunt(context.Background(), HuntSeed{File: "app.py", Line: 6})
	if res.Aborted == "" || !strings.Contains(res.Aborted, "report") {
		t.Errorf("conclude should not end a hunt: %+v", res)
	}
}

func TestHunt_ProtectedSeedIsNeverShown(t *testing.T) {
	root, _ := fixture(t, map[string]string{".env": "KEY=1\n"})
	fake := &llmtest.Fake{}
	res, _ := newV(t, fake, root, Config{}).Hunt(context.Background(), HuntSeed{File: ".env", Line: 1})
	if res.Aborted == "" || len(fake.Calls) != 0 {
		t.Errorf("res = %+v, calls = %d", res, len(fake.Calls))
	}
}

func TestParseAction_ReportOnlyInAHunt(t *testing.T) {
	if _, err := ParseAction(`{"action":"report","candidates":[]}`); err == nil {
		t.Error("deep verification must not accept a report")
	}
	if a, err := parseAction(`{"action":"report"}`, ActionReport); err != nil || a.Action != ActionReport {
		t.Errorf("hunt report: %v", err)
	}
}
