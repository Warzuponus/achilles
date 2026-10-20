package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVulnLines(t *testing.T) {
	src := strings.Join([]string{
		"const a = 1",
		"models.sequelize.query(`SELECT ${q}`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge",
		"// vuln-code-snippet neutral-line unionSqlInjectionChallenge",
		// lib/codingChallenges.ts reads the marker; it names no challenge.
		"if (new RegExp(`vuln-code-snippet vuln-line.*${challengeKey}`).exec(lines[i]) != null) {",
		"snippet = snippet.replace(/\\s?[/#]{0,2} vuln-code-snippet vuln-line.*/g, '')",
	}, "\n")
	got, err := parseVulnLines("routes/search.ts", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 2 || strings.Join(got[0].Challenges, ",") != "unionSqlInjectionChallenge,dbSchemaChallenge" {
		t.Fatalf("got %+v, want line 2 with both challenges", got)
	}
}

func TestParseJuiceShopSkipsTestsAndReadsFixes(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mark := "x() // vuln-code-snippet vuln-line loginAdminChallenge\n"
	write("routes/login.ts", mark)
	write("test/api/loginSpec.ts", mark)
	write("frontend/src/app/x.component.spec.ts", mark)
	write("node_modules/y/index.js", mark)
	write("data/static/codefixes/loginAdminChallenge_1.ts", mark)
	write("data/static/codefixes/loginAdminChallenge_4_correct.ts", "")
	write("data/static/codefixes/loginAdminChallenge.info.yml", "")

	labels, variants, err := ParseJuiceShop(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 1 || labels[0].File != "routes/login.ts" {
		t.Errorf("labels: got %+v, want only routes/login.ts", labels)
	}
	if len(variants) != 2 || variants[0].Correct || !variants[1].Correct {
		t.Errorf("variants: got %+v, want _1 (wrong) and _4_correct", variants)
	}
}

func TestScoreJuiceShop(t *testing.T) {
	truth := JuiceShopTruth{
		Commit:     strings.Repeat("a", 40),
		OutOfReach: map[string]string{"adminSectionChallenge": "access control"},
		Judgements: []JuiceShopJudgement{
			{Rule: "r.eval", File: "routes/captcha.ts", Line: 22, Verdict: "wrong"},
			{Rule: "r.ssrf", File: "routes/upload.ts", Line: 24, Verdict: "real"},
		},
	}
	labels := []JuiceShopLabel{
		{File: "routes/login.ts", Line: 34, Challenges: []string{"loginAdminChallenge", "loginJimChallenge"}},
		{File: "routes/search.ts", Line: 23, Challenges: []string{"unionSqlInjectionChallenge"}},
		{File: "app.routing.ts", Line: 79, Challenges: []string{"adminSectionChallenge"}},
	}
	variants := []JuiceShopVariant{
		{File: "data/static/codefixes/loginAdminChallenge_1.ts", Challenge: "loginAdminChallenge"},
		{File: "data/static/codefixes/loginAdminChallenge_4_correct.ts", Challenge: "loginAdminChallenge", Correct: true},
		{File: "data/static/codefixes/adminSectionChallenge_1.ts", Challenge: "adminSectionChallenge"},
	}
	findings := []JuiceShopFinding{
		{Rule: "r.sql", File: "routes/login.ts", Line: 32, EndLine: 32}, // within 2 lines
		{Rule: "r.sql", File: "routes/search.ts", Line: 19},             // 4 lines off: not the label
		{Rule: "r.eval", File: "routes/captcha.ts", Line: 22},           // judged wrong
		{Rule: "r.ssrf", File: "routes/upload.ts", Line: 24},            // judged real
		{Rule: "r.new", File: "routes/other.ts", Line: 5},               // nobody judged it
		{Rule: "r.secret", File: "test/api/x.ts", Line: 1},              // tests are not counted
		{Rule: "r.sql", File: "data/static/codefixes/loginAdminChallenge_1.ts", Line: 18},
	}
	r := ScoreJuiceShop(truth, labels, variants, findings)

	if r.Total != 4 || r.Found != 2 || r.TotalInReach != 3 || r.FoundInReach != 2 {
		t.Errorf("challenges: found %d/%d, in reach %d/%d; want 2/4 and 2/3", r.Found, r.Total, r.FoundInReach, r.TotalInReach)
	}
	if r.Labeled != 1 || r.Real != 1 || r.Wrong != 1 || r.Unjudged != 2 || r.InTests != 1 {
		t.Errorf("findings: labeled %d real %d wrong %d unjudged %d tests %d; want 1 1 1 2 1",
			r.Labeled, r.Real, r.Wrong, r.Unjudged, r.InTests)
	}
	if p := r.Precision(); p < 66.6 || p > 66.7 {
		t.Errorf("precision %.2f, want 66.67 (2 real of 3 judged; the unjudged are left out)", p)
	}
	if r.WrongFixes != 2 || r.WrongFixesFlagged != 1 || r.CorrectFixes != 1 || r.CorrectFixesFlagged != 0 {
		t.Errorf("fixes: wrong %d/%d correct %d/%d", r.WrongFixesFlagged, r.WrongFixes, r.CorrectFixesFlagged, r.CorrectFixes)
	}
	if r.ReachWrong != 1 || r.ReachWrongFlagged != 1 {
		t.Errorf("fixes in reach: %d/%d, want 1/1 (adminSection is out of reach)", r.ReachWrongFlagged, r.ReachWrong)
	}
}

func TestLoadJuiceShopTruthRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"branch.json":  `{"url":"https://x","commit":"master","outOfReach":{},"judgements":[]}`,
		"verdict.json": `{"url":"https://x","commit":"` + strings.Repeat("a", 40) + `","outOfReach":{},"judgements":[{"rule":"r","file":"f","line":1,"verdict":"maybe"}]}`,
		"twice.json": `{"url":"https://x","commit":"` + strings.Repeat("a", 40) + `","outOfReach":{},"judgements":[` +
			`{"rule":"r","file":"f","line":1,"verdict":"real"},{"rule":"r","file":"f","line":1,"verdict":"wrong"}]}`,
		"unknown.json": `{"url":"https://x","commit":"` + strings.Repeat("a", 40) + `","extra":1}`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadJuiceShopTruth(p); err == nil {
			t.Errorf("%s: loaded without error", name)
		}
	}
}

// The committed truth file must load: a typo in it would only show on a full run.
func TestCommittedJuiceShopTruthLoads(t *testing.T) {
	tr, err := LoadJuiceShopTruth(filepath.Join("..", "..", "evals", "juice-shop", "truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Judgements) == 0 || len(tr.OutOfReach) == 0 {
		t.Errorf("truth file has %d judgements and %d out-of-reach challenges", len(tr.Judgements), len(tr.OutOfReach))
	}
}
