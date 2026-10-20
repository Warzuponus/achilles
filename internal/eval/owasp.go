package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The OWASP Benchmark (https://owasp.org/www-project-benchmark/) is a suite of
// small test cases (a Java edition and, since 2026, a Python one), each either a real vulnerability or a decoy that looks
// like one, with an answer key (expectedresults-*.csv). Its scorecard flags a test
// case when a tool reports, anywhere in that case's file, a finding whose CWE is
// the category's, and scores each category as true-positive rate minus
// false-positive rate. OWASPScore reproduces that from an Achilles SARIF report.

// OWASPCase is one row of the answer key.
type OWASPCase struct {
	Name     string // BenchmarkTest00001
	Category string // sqli, xss, pathtraver, ...
	Real     bool   // a real vulnerability (true) or a decoy (false)
	CWE      int
}

// owaspRelated lists CWEs that tools commonly report for the same flaw as the
// category's own. The Benchmark's scorer accepts only the category's CWE; the
// "related" figures also accept these, and are reported as a separate column.
var owaspRelated = map[string][]int{
	"cmdi":         {77, 88},
	"sqli":         {564},
	"pathtraver":   {23, 36, 73},
	"xss":          {80},
	"crypto":       {326, 696},
	"hash":         {327, 916},
	"weakrand":     {338},
	"securecookie": {1004, 315},
	"codeinj":      {94, 95},
}

// ParseOWASPExpected reads an expectedresults CSV ("# test name, category, real
// vulnerability, cwe, ..." then one row per test case).
func ParseOWASPExpected(r io.Reader) ([]OWASPCase, error) {
	var out []OWASPCase
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 4 {
			return nil, fmt.Errorf("expected results line %d: want at least 4 fields, got %q", n, line)
		}
		cwe, err := strconv.Atoi(strings.TrimSpace(f[3]))
		if err != nil {
			return nil, fmt.Errorf("expected results line %d: CWE %q: %w", n, f[3], err)
		}
		out = append(out, OWASPCase{
			Name: strings.TrimSpace(f[0]), Category: strings.TrimSpace(f[1]),
			Real: strings.EqualFold(strings.TrimSpace(f[2]), "true"), CWE: cwe,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("expected results: no test cases")
	}
	return out, nil
}

var (
	owaspTestFile = regexp.MustCompile(`(BenchmarkTest\d+)\.(?:java|py)\b`)
	sarifCWETag   = regexp.MustCompile(`(?i)(?:^|/)cwe-0*(\d+)`)
)

// OWASPFlags reads a SARIF report and returns, per test case, the CWEs reported
// in its file. A result's CWEs come from its rule's tags (external/cwe/cwe-89),
// the form Achilles' unified report writes, from its rule's relationships to the
// CWE taxonomy, or from the result's own properties.
func OWASPFlags(r io.Reader) (map[string]map[int]bool, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
						Relationships []struct {
							Target struct {
								ID            string `json:"id"`
								ToolComponent struct {
									Name string `json:"name"`
								} `json:"toolComponent"`
							} `json:"target"`
						} `json:"relationships"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties struct {
					Tags []string `json:"tags"`
					CWE  []string `json:"cwe"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("read SARIF: %w", err)
	}
	cwes := func(tags []string, into map[int]bool) {
		for _, t := range tags {
			if m := sarifCWETag.FindStringSubmatch(t); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					into[n] = true
				}
			}
		}
	}
	flags := map[string]map[int]bool{}
	for _, run := range doc.Runs {
		byRule := map[string]map[int]bool{}
		for _, rule := range run.Tool.Driver.Rules {
			set := map[int]bool{}
			cwes(rule.Properties.Tags, set)
			// SARIF's own form (SpotBugs, gosec): a relationship to the CWE taxonomy.
			for _, rel := range rule.Relationships {
				if strings.EqualFold(rel.Target.ToolComponent.Name, "CWE") {
					if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(rel.Target.ID), "CWE-")); err == nil {
						set[n] = true
					}
				}
			}
			byRule[rule.ID] = set
		}
		for _, res := range run.Results {
			if len(res.Locations) == 0 {
				continue
			}
			m := owaspTestFile.FindStringSubmatch(res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			if m == nil {
				continue
			}
			set := flags[m[1]]
			if set == nil {
				set = map[int]bool{}
				flags[m[1]] = set
			}
			for c := range byRule[res.RuleID] {
				set[c] = true
			}
			cwes(res.Properties.Tags, set)
			cwes(res.Properties.CWE, set)
		}
	}
	return flags, nil
}

// OWASPCategory is one category's confusion matrix.
type OWASPCategory struct {
	Category       string  `json:"category"`
	CWE            int     `json:"cwe"`
	TP, FN, FP, TN int     `json:"-"`
	TPR            float64 `json:"tpr"`
	FPR            float64 `json:"fpr"`
	Score          float64 `json:"score"` // TPR - FPR, in percentage points
}

// OWASPResult is a scored run, by the Benchmark's own rule (Strict: the category's
// CWE only) and with related CWEs accepted (Related).
type OWASPResult struct {
	Strict  []OWASPCategory `json:"strict"`
	Related []OWASPCategory `json:"related"`
	// Averages over categories, as the Benchmark's scorecard reports them.
	StrictTPR, StrictFPR, StrictScore    float64
	RelatedTPR, RelatedFPR, RelatedScore float64
	// StrictPrecision is the share of flagged test cases that are real, pooled
	// over every case rather than averaged over categories. The scorecard does not
	// report it; a comparison of tools needs it (docs/comparison.md).
	StrictPrecision float64
}

// OWASPScore scores flags against the answer key.
func OWASPScore(cases []OWASPCase, flags map[string]map[int]bool) OWASPResult {
	score := func(related bool) ([]OWASPCategory, float64, float64, float64) {
		byCat := map[string]*OWASPCategory{}
		for _, c := range cases {
			cat := byCat[c.Category]
			if cat == nil {
				cat = &OWASPCategory{Category: c.Category, CWE: c.CWE}
				byCat[c.Category] = cat
			}
			want := []int{c.CWE}
			if related {
				want = append(want, owaspRelated[c.Category]...)
			}
			hit := false
			for _, w := range want {
				if flags[c.Name][w] {
					hit = true
					break
				}
			}
			switch {
			case c.Real && hit:
				cat.TP++
			case c.Real:
				cat.FN++
			case hit:
				cat.FP++
			default:
				cat.TN++
			}
		}
		var out []OWASPCategory
		var sumTPR, sumFPR float64
		for _, cat := range byCat {
			if n := cat.TP + cat.FN; n > 0 {
				cat.TPR = 100 * float64(cat.TP) / float64(n)
			}
			if n := cat.FP + cat.TN; n > 0 {
				cat.FPR = 100 * float64(cat.FP) / float64(n)
			}
			cat.Score = cat.TPR - cat.FPR
			sumTPR += cat.TPR
			sumFPR += cat.FPR
			out = append(out, *cat)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
		n := float64(len(out))
		if n == 0 {
			return out, 0, 0, 0
		}
		return out, sumTPR / n, sumFPR / n, (sumTPR - sumFPR) / n
	}
	var r OWASPResult
	r.Strict, r.StrictTPR, r.StrictFPR, r.StrictScore = score(false)
	r.Related, r.RelatedTPR, r.RelatedFPR, r.RelatedScore = score(true)
	var tp, fp int
	for _, c := range r.Strict {
		tp += c.TP
		fp += c.FP
	}
	if tp+fp > 0 {
		r.StrictPrecision = 100 * float64(tp) / float64(tp+fp)
	}
	return r
}

// WriteOWASPScorecard prints both scorings side by side.
func WriteOWASPScorecard(w io.Writer, r OWASPResult) {
	fmt.Fprintf(w, "%-17s %5s %5s %5s %5s %7s %7s %7s   %s\n", "CATEGORY", "TP", "FN", "FP", "TN", "TPR", "FPR", "SCORE", "(with related CWEs)")
	for i, c := range r.Strict {
		rel := r.Related[i]
		fmt.Fprintf(w, "%-17s %5d %5d %5d %5d %6.1f%% %6.1f%% %7.1f   %.1f\n",
			fmt.Sprintf("%s/%d", c.Category, c.CWE), c.TP, c.FN, c.FP, c.TN, c.TPR, c.FPR, c.Score, rel.Score)
	}
	fmt.Fprintf(w, "%-17s %23s %6.1f%% %6.1f%% %7.1f   %.1f\n", "AVERAGE", "", r.StrictTPR, r.StrictFPR, r.StrictScore, r.RelatedScore)
	fmt.Fprintf(w, "PRECISION %.1f%% (flagged cases that are real, over all categories)\n", r.StrictPrecision)
}
