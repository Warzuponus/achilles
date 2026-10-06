package eval

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// MatcherVersion identifies the matching rule below; bump it when the rule changes.
const MatcherVersion = 1

// DefaultLineTolerance is how many lines a finding may sit outside a ground-truth
// range and still count. Scanners disagree about which line of a multi-line
// statement they report, and labels are written by people.
const DefaultLineTolerance = 3

// Matching rule (deterministic; no model needed):
//
//	a finding matches a ground-truth entry when ALL hold:
//	  1. same file — both paths normalized to scan-root-relative, slash-separated;
//	  2. the finding's line span overlaps [startLine-tol, endLine+tol]
//	     (a finding with no line, e.g. a dependency finding that points at a
//	     manifest, matches by file alone — but only for vulnerable-dependency
//	     entries, and only if the entry's package is named in the finding);
//	  3. EITHER the CWE sets intersect, OR the entry's class is among the classes
//	     the finding is compatible with (inferred from its CWEs, its tool, and its
//	     rule id — see findingClasses).
//
// Rule 3 exists because scanners are inconsistent about CWE metadata (gitleaks and
// osv-scanner report none; some rules carry a parent CWE) while class is usually
// evident from the tool or rule. A same-place finding that fails rule 3 is an
// AMBIGUOUS match: reported as a class-mismatch loss point, and the only thing
// the optional --judge ever looks at.

// cweClasses maps CWE numbers to the classes they imply.
var cweClasses = map[string]string{}

func init() {
	add := func(class string, cwes ...string) {
		for _, c := range cwes {
			cweClasses[c] = class
		}
	}
	add(ClassInjection, "74", "77", "78", "88", "89", "90", "91", "94", "95", "96", "98", "564", "643", "652", "917", "943")
	add(ClassXSS, "79", "80", "83", "87")
	add(ClassPathTraversal, "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "73")
	add(ClassHardcodedSecret, "798", "259", "321", "547", "256", "312")
	add(ClassWeakCrypto, "326", "327", "328", "329", "330", "331", "338", "759", "760", "780", "916")
	add(ClassSSRF, "918")
	add(ClassAuthz, "284", "285", "287", "306", "425", "639", "862", "863", "732")
	add(ClassDeserialization, "502")
	add(ClassVulnDependency, "1104", "937", "1035")
}

// gosecClass maps gosec rule ids whose class is not obvious from the CWE alone.
var gosecClass = map[string]string{
	"G101": ClassHardcodedSecret, "G107": ClassSSRF,
	"G201": ClassInjection, "G202": ClassInjection, "G203": ClassXSS, "G204": ClassInjection,
	"G304": ClassPathTraversal, "G305": ClassPathTraversal,
	"G401": ClassWeakCrypto, "G402": ClassWeakCrypto, "G403": ClassWeakCrypto, "G404": ClassWeakCrypto,
	"G405": ClassWeakCrypto, "G406": ClassWeakCrypto,
	"G501": ClassWeakCrypto, "G502": ClassWeakCrypto, "G503": ClassWeakCrypto, "G504": ClassWeakCrypto, "G505": ClassWeakCrypto,
	"G701": ClassInjection, "G702": ClassInjection, "G703": ClassPathTraversal, "G704": ClassSSRF, "G705": ClassXSS,
}

// ruleKeywords are tokens in a rule id (split on non-alphanumerics) that imply a
// class. Single tokens only: matching by token avoids "des" firing inside "describe".
var ruleKeywords = map[string]string{
	"sqli": ClassInjection, "sql": ClassInjection, "nosql": ClassInjection, "injection": ClassInjection,
	"eval": ClassInjection, "exec": ClassInjection, "shell": ClassInjection, "ssti": ClassInjection,
	"ldap": ClassInjection, "xpath": ClassInjection,
	"xss": ClassXSS, "innerhtml": ClassXSS,
	"traversal": ClassPathTraversal, "zipslip": ClassPathTraversal,
	"secret": ClassHardcodedSecret, "password": ClassHardcodedSecret, "credential": ClassHardcodedSecret,
	"credentials": ClassHardcodedSecret, "apikey": ClassHardcodedSecret, "hardcoded": ClassHardcodedSecret,
	"md5": ClassWeakCrypto, "sha1": ClassWeakCrypto, "des": ClassWeakCrypto, "ecb": ClassWeakCrypto,
	"crypto": ClassWeakCrypto, "cipher": ClassWeakCrypto,
	"ssrf":     ClassSSRF,
	"deserial": ClassDeserialization, "deserialization": ClassDeserialization, "pickle": ClassDeserialization,
	"idor": ClassAuthz, "authz": ClassAuthz, "authorization": ClassAuthz,
}

var (
	nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)
	advisory = regexp.MustCompile(`(?i)^(CVE-|GHSA-|PYSEC-|GO-\d|RUSTSEC-|OSV-|GSD-|NPM-|MAL-)`)
)

// findingClasses returns every class a finding is compatible with.
func findingClasses(f model.Finding) map[string]bool {
	out := map[string]bool{}
	for _, c := range f.CWE {
		if cl, ok := cweClasses[cweNumber(c)]; ok {
			out[cl] = true
		}
	}
	tool := strings.ToLower(f.Tool)
	switch tool {
	case "gitleaks", "trufflehog", "detect-secrets":
		out[ClassHardcodedSecret] = true
	case "osv-scanner", "govulncheck", "npm-audit", "pip-audit", "dependency-check":
		out[ClassVulnDependency] = true
	case "trivy":
		if advisory.MatchString(f.RuleID) {
			out[ClassVulnDependency] = true
		}
	case "gosec":
		if cl, ok := gosecClass[strings.ToUpper(f.RuleID)]; ok {
			out[cl] = true
		}
	}
	if advisory.MatchString(f.RuleID) {
		out[ClassVulnDependency] = true
	}
	for _, tok := range strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(f.RuleID), " ")) {
		if cl, ok := ruleKeywords[tok]; ok {
			out[cl] = true
		}
	}
	return out
}

// normalizeFindingPath turns whatever a scanner reported (absolute path, file://
// URI, "./x") into a scan-root-relative slash path. roots are the absolute scan
// root and its symlink-resolved twin (macOS /tmp -> /private/tmp).
func normalizeFindingPath(p string, roots []string) string {
	p = strings.TrimPrefix(p, "file://")
	p = filepath.ToSlash(p)
	for _, r := range roots {
		r = strings.TrimRight(filepath.ToSlash(r), "/")
		if r != "" && strings.HasPrefix(p, r+"/") {
			p = strings.TrimPrefix(p, r+"/")
			break
		}
	}
	p = path.Clean(p)
	return strings.TrimPrefix(p, "./")
}

// span returns the finding's line range; ok is false when it has no line.
func span(f model.Finding) (start, end int, ok bool) {
	start = f.Location.Region.StartLine
	end = f.Location.Region.EndLine
	if start <= 0 {
		return 0, 0, false
	}
	if end < start {
		end = start
	}
	return start, end, true
}

// matchKind says how a finding relates to an entry.
type matchKind int

const (
	matchNone      matchKind = iota
	matchExact               // same place, compatible class (the deterministic rule)
	matchAmbiguous           // same place, but the class/CWE does not agree
)

// location reports whether the finding is in the entry's file and span (within
// tol). Dependency findings with no line match by file + package.
func locationMatches(v Vuln, f model.Finding, tol int) bool {
	if f.Location.File != v.File {
		return false
	}
	s, e, ok := span(f)
	if !ok {
		return v.Package != "" && mentionsPackage(f, v.Package)
	}
	return s <= v.EndLine+tol && e >= v.StartLine-tol
}

func mentionsPackage(f model.Finding, pkg string) bool {
	pkg = strings.ToLower(pkg)
	return strings.Contains(strings.ToLower(f.Message), pkg) || strings.Contains(strings.ToLower(f.RuleID), pkg)
}

// classCompatible implements rule 3.
func classCompatible(v Vuln, f model.Finding) bool {
	want := map[string]bool{}
	for _, c := range v.CWE {
		if n := cweNumber(c); n != "" {
			want[n] = true
		}
	}
	for _, c := range f.CWE {
		if want[cweNumber(c)] {
			return true
		}
	}
	return findingClasses(f)[strings.ToLower(v.Class)]
}

// classify relates one finding to one entry.
func classify(v Vuln, f model.Finding, tol int) matchKind {
	if !locationMatches(v, f, tol) {
		return matchNone
	}
	if classCompatible(v, f) {
		return matchExact
	}
	return matchAmbiguous
}

// nearestLineDistance is how many lines a same-file, class-compatible finding sits
// from the entry's range; -1 when there is no such finding. It explains a
// line-mismatch miss ("reported 12 lines away").
func nearestLineDistance(v Vuln, f model.Finding) int {
	if f.Location.File != v.File || !classCompatible(v, f) {
		return -1
	}
	s, e, ok := span(f)
	if !ok {
		return -1
	}
	switch {
	case e < v.StartLine:
		return v.StartLine - e
	case s > v.EndLine:
		return s - v.EndLine
	}
	return 0
}

// matcher applies the matching rule across a target's whole label set. The only
// thing it adds to classify is a guard against ONE finding vouching for several
// neighbouring labels: a finding that lands squarely on one entry cannot also
// count for another entry merely because it falls inside the line tolerance.
// Without it, a scanner that finds the secret on line 5 would be credited with the
// secrets labeled on lines 3 and 4.
type matcher struct {
	vulns []Vuln
	tol   int
}

// classify relates finding f to entry v.
func (m matcher) classify(v Vuln, f model.Finding) matchKind {
	k := classify(v, f, m.tol)
	if k == matchNone {
		return k
	}
	if m.tol > 0 && classify(v, f, 0) == matchNone && m.landsOnAnother(v, f) {
		return matchNone
	}
	return k
}

// landsOnAnother reports whether f sits directly (no tolerance) on an entry other
// than v.
func (m matcher) landsOnAnother(v Vuln, f model.Finding) bool {
	for _, o := range m.vulns {
		if o.ID != v.ID && classify(o, f, 0) != matchNone {
			return true
		}
	}
	return false
}
