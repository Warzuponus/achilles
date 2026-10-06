package eval

// Detection benchmark — ground truth.
//
// The triage eval (corpus.go) asks "given a finding, does the pipeline judge it
// correctly?". It cannot say whether the scanners FIND the bugs in the first
// place: a vulnerability no scanner reports never reaches triage, so triage
// quality is irrelevant to it. The detection benchmark measures that earlier,
// harder question — recall on real code — and, for every miss, traces WHERE in
// the pipeline the vulnerability was lost (see detect_trace.go).
//
// The ideas (a labeled corpus of known vulnerabilities, scored by matching, with
// loss-point analysis over the misses) are adapted from the open-source VulnHunter
// project's benchmark harness; the schema, matcher and prompts here are our own.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// GroundTruthVersion is the schema version this build reads and writes.
const GroundTruthVersion = 1

// Vulnerability classes. A ground-truth entry's class is free-form text, but these
// are the ones the matcher understands (see detect_match.go); anything else only
// matches on a CWE overlap.
const (
	ClassInjection       = "injection"
	ClassXSS             = "xss"
	ClassPathTraversal   = "path-traversal"
	ClassHardcodedSecret = "hardcoded-secret"
	ClassWeakCrypto      = "weak-crypto"
	ClassSSRF            = "ssrf"
	ClassAuthz           = "authz"
	ClassDeserialization = "deserialization"
	ClassVulnDependency  = "vulnerable-dependency"
)

// KnownClasses lists the classes with matcher support, in report order.
var KnownClasses = []string{
	ClassInjection, ClassXSS, ClassPathTraversal, ClassHardcodedSecret,
	ClassWeakCrypto, ClassSSRF, ClassAuthz, ClassDeserialization, ClassVulnDependency,
}

// Source says where a target's code comes from: a pinned commit of a git
// repository, or a local path (used by the hermetic fixtures).
type Source struct {
	// Git sources: URL + the exact commit to test. The commit must be a full
	// 40-hex SHA — a branch or tag name would let the target move under the
	// ground truth, silently invalidating every line number.
	URL    string `json:"url,omitempty"`
	Commit string `json:"commit,omitempty"`
	// Subdir narrows the scan root inside a checkout. Ground-truth file paths are
	// relative to this root.
	Subdir string `json:"subdir,omitempty"`

	// Local sources: a directory, resolved against the ground-truth file's own
	// directory unless absolute.
	Path string `json:"path,omitempty"`
}

// IsGit reports whether the source is a git checkout (as opposed to a local path).
func (s Source) IsGit() bool { return s.URL != "" }

// Vuln is one known vulnerability in a target.
type Vuln struct {
	ID    string   `json:"id"`
	Class string   `json:"class"`
	CWE   []string `json:"cwe,omitempty"`
	// File is relative to the scan root, slash-separated.
	File      string `json:"file"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
	// Package names the dependency for vulnerable-dependency entries. Dependency
	// scanners report a manifest, not a line, so the package name is what ties a
	// finding to the entry.
	Package     string `json:"package,omitempty"`
	Description string `json:"description"`
	// Note is free-form context for reviewers (why it is expected to be hard,
	// what the label is based on). Never sent to a model.
	Note string `json:"note,omitempty"`
}

// GroundTruth is one target's labeled vulnerabilities.
type GroundTruth struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	Description   string `json:"description,omitempty"`
	Source        Source `json:"source"`
	Vulns         []Vuln `json:"vulnerabilities"`

	// Dir is the directory of the file this was loaded from (local sources resolve
	// against it). Not serialized.
	Dir string `json:"-"`
	// Path is the file this was loaded from. Not serialized.
	Path string `json:"-"`
}

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// LoadGroundTruthFile reads one file. A file holds one target object, or (for the
// external example) an array of them.
func LoadGroundTruthFile(path string) ([]GroundTruth, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied corpus path
	if err != nil {
		return nil, fmt.Errorf("read ground truth: %w", err)
	}
	var raw []json.RawMessage
	if t := strings.TrimLeft(string(data), " \t\r\n"); strings.HasPrefix(t, "[") {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse ground truth %s: %w", path, err)
		}
	} else {
		raw = []json.RawMessage{data}
	}
	var out []GroundTruth
	for i, r := range raw {
		var gt GroundTruth
		dec := json.NewDecoder(strings.NewReader(string(r)))
		dec.DisallowUnknownFields() // a misspelled "startLine" must not silently become line 0
		if err := dec.Decode(&gt); err != nil {
			return nil, fmt.Errorf("parse ground truth %s (target #%d): %w", path, i+1, err)
		}
		gt.Dir = filepath.Dir(path)
		gt.Path = path
		if err := gt.Validate(); err != nil {
			return nil, fmt.Errorf("ground truth %s: %w", path, err)
		}
		out = append(out, gt)
	}
	return out, nil
}

// LoadGroundTruth loads a file, or every *.json in a directory except
// *.example.json (those document the format and are never scored). Targets come
// back sorted by id so every report is stable.
func LoadGroundTruth(path string) ([]GroundTruth, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ground truth: %w", err)
	}
	var files []string
	if st.IsDir() {
		ents, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".example.json") {
				continue
			}
			files = append(files, filepath.Join(path, n))
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("ground truth directory %s has no *.json targets", path)
		}
	} else {
		files = []string{path}
	}
	var all []GroundTruth
	seen := map[string]string{}
	for _, f := range files {
		gts, err := LoadGroundTruthFile(f)
		if err != nil {
			return nil, err
		}
		for _, gt := range gts {
			if prev, dup := seen[gt.ID]; dup {
				return nil, fmt.Errorf("duplicate target id %q in %s and %s", gt.ID, prev, f)
			}
			seen[gt.ID] = f
			all = append(all, gt)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

// Validate checks the structure. Line ranges are additionally checked against the
// files for local sources (ValidateAgainstTree) — a stale line number measures the
// wrong span, which is worse than not measuring.
func (g GroundTruth) Validate() error {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	if g.SchemaVersion != GroundTruthVersion {
		add("schemaVersion must be %d, got %d", GroundTruthVersion, g.SchemaVersion)
	}
	if !idRE.MatchString(g.ID) {
		add("target id %q must be letters, digits, '.', '_' or '-'", g.ID)
	}
	switch {
	case g.Source.IsGit() && g.Source.Path != "":
		add("source has both url and path; choose one")
	case g.Source.IsGit():
		// Commit syntax is checked when the source is RESOLVED, not here, so an
		// example file with a placeholder still loads (and is then refused with an
		// actionable message instead of a parse error).
		if g.Source.Commit == "" {
			add("git source needs a pinned commit")
		}
	case g.Source.Path == "":
		add("source needs a git url+commit or a local path")
	}
	if len(g.Vulns) == 0 {
		add("no vulnerabilities listed")
	}
	seen := map[string]bool{}
	for i, v := range g.Vulns {
		where := v.ID
		if where == "" {
			where = fmt.Sprintf("vulnerability #%d", i+1)
			add("%s: missing id", where)
		} else if seen[v.ID] {
			add("%s: duplicate id", where)
		}
		seen[v.ID] = true
		if strings.TrimSpace(v.Class) == "" {
			add("%s: missing class", where)
		}
		if strings.TrimSpace(v.Description) == "" {
			add("%s: missing description (a label nobody can review is not ground truth)", where)
		}
		if v.File == "" {
			add("%s: missing file", where)
		} else if filepath.IsAbs(v.File) || strings.Contains(v.File, `\`) || hasDotDot(v.File) {
			add("%s: file %q must be a relative, slash-separated path inside the target", where, v.File)
		}
		if v.StartLine < 1 || v.EndLine < v.StartLine {
			add("%s: need 1 <= startLine <= endLine, got %d..%d", where, v.StartLine, v.EndLine)
		}
		for _, c := range v.CWE {
			if cweNumber(c) == "" {
				add("%s: cwe %q is not of the form CWE-<n>", where, c)
			}
		}
		if strings.EqualFold(v.Class, ClassVulnDependency) && v.Package == "" {
			add("%s: vulnerable-dependency entries need a package (scanners report the manifest, not a line)", where)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("target %s: %d problem(s):\n  - %s", g.ID, len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// ValidateAgainstTree checks every entry's file exists under root and that its
// line range lies inside it. It returns one message per bad entry id.
func (g GroundTruth) ValidateAgainstTree(root string) map[string]string {
	bad := map[string]string{}
	for _, v := range g.Vulns {
		full := filepath.Join(root, filepath.FromSlash(v.File))
		data, err := os.ReadFile(full) // #nosec G304 -- Validate rejected absolute and ".." paths
		if err != nil {
			bad[v.ID] = fmt.Sprintf("file %s not found in the target (wrong commit or subdir?)", v.File)
			continue
		}
		if n := len(strings.Split(string(data), "\n")); v.StartLine > n {
			bad[v.ID] = fmt.Sprintf("startLine %d is past the end of %s (%d lines)", v.StartLine, v.File, n)
		}
	}
	return bad
}

// cweNumber returns the numeric part of "CWE-89", "cwe-089", "89" or
// "CWE-89: Improper ...", or "" if there is none. Leading zeros are dropped so
// "089" and "89" compare equal.
func cweNumber(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "cwe-")
	s = strings.TrimPrefix(s, "cwe")
	s = strings.TrimLeft(s, " -_:")
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return ""
	}
	return strings.TrimLeft(s[:end], "0")
}
