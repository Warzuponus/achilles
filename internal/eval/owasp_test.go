package eval

import (
	"strings"
	"testing"
)

const owaspCSV = `# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,false,22
BenchmarkTest00003,hash,true,328
BenchmarkTest00004,hash,false,328
BenchmarkTest00005,sqli,true,89
`

// A rule tagged cwe-22 fires in test 1 (real) and test 2 (decoy); a rule tagged
// cwe-327 fires in test 3 (real hash case: right only with related CWEs); nothing
// fires in the SQL case.
const owaspSARIF = `{"runs":[{"tool":{"driver":{"rules":[
  {"id":"pt","properties":{"tags":["security","external/cwe/cwe-22"]}},
  {"id":"wc","properties":{"tags":["external/cwe/cwe-327"]}}]}},
 "results":[
  {"ruleId":"pt","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x/BenchmarkTest00001.java"}}}]},
  {"ruleId":"pt","locations":[{"physicalLocation":{"artifactLocation":{"uri":"BenchmarkTest00002.java"}}}]},
  {"ruleId":"wc","locations":[{"physicalLocation":{"artifactLocation":{"uri":"BenchmarkTest00003.java"}}}]},
  {"ruleId":"pt","locations":[{"physicalLocation":{"artifactLocation":{"uri":"Helper.java"}}}]}]}]}`

func TestOWASPScoreMatchesTheBenchmarkRule(t *testing.T) {
	cases, err := ParseOWASPExpected(strings.NewReader(owaspCSV))
	if err != nil || len(cases) != 5 {
		t.Fatalf("parse: %d cases, %v", len(cases), err)
	}
	flags, err := OWASPFlags(strings.NewReader(owaspSARIF))
	if err != nil {
		t.Fatal(err)
	}
	r := OWASPScore(cases, flags)
	get := func(cs []OWASPCategory, name string) OWASPCategory {
		for _, c := range cs {
			if c.Category == name {
				return c
			}
		}
		t.Fatalf("no category %s", name)
		return OWASPCategory{}
	}
	pt := get(r.Strict, "pathtraver")
	if pt.TP != 1 || pt.FP != 1 || pt.TPR != 100 || pt.FPR != 100 || pt.Score != 0 {
		t.Errorf("pathtraver = %+v; want TP 1, FP 1, score 0", pt)
	}
	if h := get(r.Strict, "hash"); h.TP != 0 || h.FN != 1 {
		t.Errorf("strict hash = %+v; CWE-327 must not count for CWE-328 by the Benchmark's rule", h)
	}
	if h := get(r.Related, "hash"); h.TP != 1 || h.Score != 100 {
		t.Errorf("related hash = %+v; want the CWE-327 finding accepted", h)
	}
	if s := get(r.Strict, "sqli"); s.FN != 1 || s.Score != 0 {
		t.Errorf("sqli = %+v", s)
	}
	// Averages are over categories: (0 + 0 + 0)/3 strict, (0 + 100 + 0)/3 related.
	if r.StrictScore != 0 || r.RelatedScore < 33.3 || r.RelatedScore > 33.4 {
		t.Errorf("averages: strict %.2f related %.2f", r.StrictScore, r.RelatedScore)
	}
	var b strings.Builder
	WriteOWASPScorecard(&b, r)
	if !strings.Contains(b.String(), "pathtraver/22") || !strings.Contains(b.String(), "AVERAGE") {
		t.Errorf("scorecard:\n%s", b.String())
	}
}

func TestParseOWASPExpectedRejectsGarbage(t *testing.T) {
	if _, err := ParseOWASPExpected(strings.NewReader("# header only\n")); err == nil {
		t.Error("an answer key with no cases was accepted")
	}
	if _, err := ParseOWASPExpected(strings.NewReader("BenchmarkTest1,sqli,true,eighty-nine\n")); err == nil {
		t.Error("a non-numeric CWE was accepted")
	}
}
