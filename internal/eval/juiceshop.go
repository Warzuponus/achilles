package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// --mode juice-shop scores Achilles' own rules against OWASP Juice Shop, an
// application none of them was written against. Juice Shop marks the vulnerable
// line of each of its coding challenges in the source itself
// (`// vuln-code-snippet vuln-line loginAdminChallenge`), and ships every
// challenge's candidate fixes, one of them correct, in data/static/codefixes/.
// Both are the project's own labels, so neither the ground truth nor the decoys
// were written by us.
//
// Three numbers come out of a run:
//
//   - recall: the challenges whose marked line in the application has a finding
//     within JuiceShopTolerance lines;
//   - precision: of the findings in the application outside tests, how many are
//     real. A finding on a marked line is real by the label; any other one is
//     looked up in a committed file of hand judgements (Juice Shop has many more
//     flaws than coding challenges), and one that nobody has judged yet is
//     counted apart, never guessed;
//   - fix variants: how many of the wrong fixes (still vulnerable) and of the
//     correct fixes (not vulnerable) have a finding.

// JuiceShopTolerance is how many lines a finding may sit from a marked line and
// still count: a multi-line call is reported where it starts.
const JuiceShopTolerance = 2

// JuiceShopLabel is one marked line.
type JuiceShopLabel struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Challenges []string `json:"challenges"`
}

// JuiceShopVariant is one candidate fix of a coding challenge.
type JuiceShopVariant struct {
	File      string `json:"file"`
	Challenge string `json:"challenge"`
	Correct   bool   `json:"correct"`
}

// JuiceShopJudgement is a hand judgement of a finding that is not on a marked line.
type JuiceShopJudgement struct {
	Rule    string `json:"rule"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Verdict string `json:"verdict"` // real | wrong
	Note    string `json:"note"`
}

// JuiceShopTruth is the committed side of the evaluation: the pinned commit, the
// challenges no static rule can be expected to find, and the hand judgements.
type JuiceShopTruth struct {
	URL        string               `json:"url"`
	Commit     string               `json:"commit"`
	OutOfReach map[string]string    `json:"outOfReach"`
	Judgements []JuiceShopJudgement `json:"judgements"`
}

// LoadJuiceShopTruth reads and checks the committed truth file.
func LoadJuiceShopTruth(p string) (JuiceShopTruth, error) {
	var t JuiceShopTruth
	b, err := os.ReadFile(p) // #nosec G304 -- the operator's truth file
	if err != nil {
		return t, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return t, fmt.Errorf("%s: %w", p, err)
	}
	if !commitRE.MatchString(t.Commit) {
		return t, fmt.Errorf("%s: commit %q is not a full commit SHA", p, t.Commit)
	}
	seen := map[string]bool{}
	for _, j := range t.Judgements {
		if j.Verdict != "real" && j.Verdict != "wrong" {
			return t, fmt.Errorf("%s: %s %s:%d: verdict must be real or wrong, got %q", p, j.Rule, j.File, j.Line, j.Verdict)
		}
		k := judgementKey(j.Rule, j.File, j.Line)
		if seen[k] {
			return t, fmt.Errorf("%s: %s %s:%d is judged twice", p, j.Rule, j.File, j.Line)
		}
		seen[k] = true
	}
	return t, nil
}

func judgementKey(rule, file string, line int) string {
	return rule + "\x00" + file + "\x00" + strconv.Itoa(line)
}

var (
	// A trailing comment naming one or more challenges. lib/codingChallenges.ts,
	// which reads these comments, mentions the marker in regular expressions; it has
	// no "//" before it and no challenge name after it, so it does not match.
	vulnLineRE = regexp.MustCompile(`//\s*vuln-code-snippet vuln-line((?:\s+[A-Za-z0-9]+Challenge)+)\s*$`)
	variantRE  = regexp.MustCompile(`^([A-Za-z0-9]+Challenge)_(\d+)(_correct)?\.(ts|js)$`)
)

// juiceShopCodefixes is where Juice Shop keeps the candidate fixes.
const juiceShopCodefixes = "data/static/codefixes"

// isJuiceShopTest reports whether a path is test code: the server tests, the
// Cypress tests and the Angular specs.
func isJuiceShopTest(p string) bool {
	return strings.HasPrefix(p, "test/") || strings.HasSuffix(p, ".spec.ts")
}

func isScript(p string) bool {
	switch path.Ext(p) {
	case ".ts", ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

// ParseJuiceShop walks a Juice Shop checkout for its marked lines (JavaScript and
// TypeScript only: the Solidity, YAML and Terraform challenges are not what the
// JavaScript rules are for) and its candidate fixes.
func ParseJuiceShop(root string) ([]JuiceShopLabel, []JuiceShopVariant, error) {
	var labels []JuiceShopLabel
	var variants []JuiceShopVariant
	// Files are opened through the root, so a symlink swapped in during the walk
	// cannot lead outside the checkout.
	rt, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, err
	}
	defer rt.Close()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", ".angular":
				return filepath.SkipDir
			}
			return nil
		}
		if !isScript(rel) {
			return nil
		}
		if path.Dir(rel) == juiceShopCodefixes {
			if m := variantRE.FindStringSubmatch(d.Name()); m != nil {
				variants = append(variants, JuiceShopVariant{File: rel, Challenge: m[1], Correct: m[3] != ""})
			}
			return nil
		}
		if isJuiceShopTest(rel) {
			return nil
		}
		f, err := rt.Open(rel)
		if err != nil {
			return err
		}
		defer f.Close()
		got, err := parseVulnLines(rel, f)
		labels = append(labels, got...)
		return err
	})
	return labels, variants, err
}

func parseVulnLines(rel string, r io.Reader) ([]JuiceShopLabel, error) {
	var out []JuiceShopLabel
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		if m := vulnLineRE.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, JuiceShopLabel{File: rel, Line: n, Challenges: strings.Fields(m[1])})
		}
	}
	return out, sc.Err()
}

// JuiceShopFinding is a scan finding reduced to what the scoring needs.
type JuiceShopFinding struct {
	Rule    string `json:"rule"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"endLine,omitempty"`
}

// JuiceShopFindings reads achilles' SARIF report into findings from Achilles' own
// rules, with paths relative to the checkout. It returns how many findings came
// from other scanners, which are not scored. Findings the AI review dismissed are
// left out, as a user would not see them.
func JuiceShopFindings(sarif []byte, root string) ([]JuiceShopFinding, int, error) {
	surfaced, _, err := parseSARIFReport(sarif)
	if err != nil {
		return nil, 0, err
	}
	roots := rootsOf(root)
	var out []JuiceShopFinding
	other := 0
	for _, f := range surfaced {
		if !strings.HasPrefix(f.RuleID, "achilles.") {
			other++
			continue
		}
		start, end, ok := span(f)
		if !ok {
			continue
		}
		out = append(out, JuiceShopFinding{
			Rule: f.RuleID, File: normalizeFindingPath(f.Location.File, roots), Line: start, EndLine: end,
		})
	}
	return out, other, nil
}

// JuiceShopChallenge is one challenge's outcome.
type JuiceShopChallenge struct {
	Challenge  string `json:"challenge"`
	Found      bool   `json:"found"`
	OutOfReach string `json:"outOfReach,omitempty"`
	By         string `json:"by,omitempty"` // the rule that found it
}

// JuiceShopJudged is a finding in the application with its verdict.
type JuiceShopJudged struct {
	JuiceShopFinding
	Verdict string `json:"verdict"` // labeled | real | wrong | unjudged
	Note    string `json:"note,omitempty"`
}

// JuiceShopResult is a scored run.
type JuiceShopResult struct {
	Commit     string               `json:"commit"`
	Challenges []JuiceShopChallenge `json:"challenges"`
	Findings   []JuiceShopJudged    `json:"findings"`

	Found, Total               int `json:"-"`
	FoundInReach, TotalInReach int `json:"-"`
	Labeled, Real, Wrong       int `json:"-"`
	Unjudged, InTests          int `json:"-"`

	WrongFixesFlagged, WrongFixes     int `json:"-"`
	CorrectFixesFlagged, CorrectFixes int `json:"-"`
	// Fix-variant scoring is limited to the challenges in reach, where a rule has
	// something to find.
	ReachWrongFlagged, ReachWrong     int `json:"-"`
	ReachCorrectFlagged, ReachCorrect int `json:"-"`
}

// Recall is challenges found over challenges, and over those in reach.
func (r JuiceShopResult) Recall() (all, inReach float64) {
	return jsPct(r.Found, r.Total), jsPct(r.FoundInReach, r.TotalInReach)
}

// Precision is real findings over judged findings in the application.
func (r JuiceShopResult) Precision() float64 {
	return jsPct(r.Labeled+r.Real, r.Labeled+r.Real+r.Wrong)
}

func jsPct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func near(f JuiceShopFinding, line int) bool {
	end := f.EndLine
	if end < f.Line {
		end = f.Line
	}
	return line >= f.Line-JuiceShopTolerance && line <= end+JuiceShopTolerance
}

// ScoreJuiceShop scores findings against the labels, the fix variants and the
// judgements.
func ScoreJuiceShop(t JuiceShopTruth, labels []JuiceShopLabel, variants []JuiceShopVariant, findings []JuiceShopFinding) JuiceShopResult {
	res := JuiceShopResult{Commit: t.Commit}
	judged := map[string]JuiceShopJudgement{}
	for _, j := range t.Judgements {
		judged[judgementKey(j.Rule, j.File, j.Line)] = j
	}

	byChallenge := map[string]*JuiceShopChallenge{}
	var order []string
	for _, l := range labels {
		for _, c := range l.Challenges {
			if byChallenge[c] == nil {
				byChallenge[c] = &JuiceShopChallenge{Challenge: c, OutOfReach: t.OutOfReach[c]}
				order = append(order, c)
			}
		}
	}

	flaggedFile := map[string]bool{}
	for _, f := range findings {
		if path.Dir(f.File) == juiceShopCodefixes {
			flaggedFile[f.File] = true
			continue
		}
		if isJuiceShopTest(f.File) {
			res.InTests++
			continue
		}
		j := JuiceShopJudged{JuiceShopFinding: f, Verdict: "unjudged"}
		for _, l := range labels {
			if l.File != f.File || !near(f, l.Line) {
				continue
			}
			j.Verdict = "labeled"
			j.Note = strings.Join(l.Challenges, " ")
			for _, c := range l.Challenges {
				if ch := byChallenge[c]; !ch.Found {
					ch.Found, ch.By = true, f.Rule
				}
			}
		}
		if j.Verdict == "unjudged" {
			if h, ok := judged[judgementKey(f.Rule, f.File, f.Line)]; ok {
				j.Verdict, j.Note = h.Verdict, h.Note
			}
		}
		switch j.Verdict {
		case "labeled":
			res.Labeled++
		case "real":
			res.Real++
		case "wrong":
			res.Wrong++
		default:
			res.Unjudged++
		}
		res.Findings = append(res.Findings, j)
	}

	sort.Strings(order)
	for _, c := range order {
		ch := *byChallenge[c]
		res.Challenges = append(res.Challenges, ch)
		res.Total++
		if ch.Found {
			res.Found++
		}
		if ch.OutOfReach == "" {
			res.TotalInReach++
			if ch.Found {
				res.FoundInReach++
			}
		}
	}

	for _, v := range variants {
		inReach := byChallenge[v.Challenge] != nil && t.OutOfReach[v.Challenge] == ""
		hit := flaggedFile[v.File]
		if v.Correct {
			res.CorrectFixes++
			if hit {
				res.CorrectFixesFlagged++
			}
			if inReach {
				res.ReachCorrect++
				if hit {
					res.ReachCorrectFlagged++
				}
			}
			continue
		}
		res.WrongFixes++
		if hit {
			res.WrongFixesFlagged++
		}
		if inReach {
			res.ReachWrong++
			if hit {
				res.ReachWrongFlagged++
			}
		}
	}
	sort.Slice(res.Findings, func(i, k int) bool {
		a, b := res.Findings[i], res.Findings[k]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res
}

// WriteJuiceShopReport prints the scorecard.
func WriteJuiceShopReport(w io.Writer, r JuiceShopResult) {
	all, reach := r.Recall()
	fmt.Fprintf(w, "OWASP Juice Shop at %s\n\n", r.Commit)
	fmt.Fprintf(w, "Challenges found:   %d of %d (%.1f%%); of the %d a static rule can reach: %d (%.1f%%)\n",
		r.Found, r.Total, all, r.TotalInReach, r.FoundInReach, reach)
	fmt.Fprintf(w, "Precision:          %.1f%% (%d on a marked line, %d judged real, %d judged wrong; %d not judged yet, %d in tests, not counted)\n",
		r.Precision(), r.Labeled, r.Real, r.Wrong, r.Unjudged, r.InTests)
	fmt.Fprintf(w, "Wrong fixes found:  %d of %d (in reach: %d of %d)\n", r.WrongFixesFlagged, r.WrongFixes, r.ReachWrongFlagged, r.ReachWrong)
	fmt.Fprintf(w, "Correct fixes hit:  %d of %d (in reach: %d of %d)\n\n", r.CorrectFixesFlagged, r.CorrectFixes, r.ReachCorrectFlagged, r.ReachCorrect)

	fmt.Fprintln(w, "Challenges:")
	for _, c := range r.Challenges {
		mark := "missed"
		switch {
		case c.Found:
			mark = "found by " + c.By
		case c.OutOfReach != "":
			mark = "out of reach: " + c.OutOfReach
		}
		fmt.Fprintf(w, "  %-34s %s\n", c.Challenge, mark)
	}
	fmt.Fprintln(w, "\nFindings in the application:")
	for _, f := range r.Findings {
		note := ""
		if f.Note != "" {
			note = " (" + f.Note + ")"
		}
		fmt.Fprintf(w, "  %-9s %s:%d %s%s\n", f.Verdict, f.File, f.Line, f.Rule, note)
	}
}
