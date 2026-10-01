package eval

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Verifying a patch by string-matching the source does not work. The first attempt
// here asked whether a hand-authored "dangerous construct" string disappeared, and
// it was wrong three different ways: `ast.literal_eval(expr)` *contains*
// `eval(expr)`, so the canonical Python fix scored as a failure; the match was
// whitespace-sensitive, so `"convert "+x` vs `"convert " + x` flipped the result;
// and some findings have several legitimate fixes (allowlisting a table name is a
// real fix that keeps `FROM %s`).
//
// So the scanner is the ground truth instead — the same shape as the §9.3 generated
// rule gate, which admits a rule only if it "matches vulnerable AND does not match
// patched". Here: re-run the tool that reported the finding, on the patched file,
// and ask whether its rule still fires.
//
// The reason this needs care rather than a one-liner is that a scanner which FAILS
// looks identical to a scanner which finds nothing. gosec emits no JSON at all when
// a patch adds an unresolvable import (bcrypt, say), and bandit reports an `errors`
// entry for a file it cannot parse. Treating either as "the rule is gone" would
// score every such patch as a successful fix. Every failure mode here therefore
// resolves to UNKNOWN, never to success.

// fixVerdict is deliberately tri-state. "Could not verify" is not "fixed".
type fixVerdict int

const (
	fixUnknown fixVerdict = iota // no tool, scanner failed, or the rule was not reproducible
	fixNo                        // the rule still fires on the patched file
	fixYes                       // the rule no longer fires
)

func (v fixVerdict) String() string {
	switch v {
	case fixYes:
		return "yes"
	case fixNo:
		return "no"
	default:
		return "unknown"
	}
}

// ruleHit is what a scanner reported for one rule, beyond the fact that it fired.
// The corpus declares these same fields and they feed the triage prompt, so drift
// in any of them means the eval measures a prompt no real scan would produce.
type ruleHit struct {
	line     int
	message  string
	severity string
}

// scanOutcome is one scanner invocation.
type scanOutcome struct {
	rules   map[string]bool
	hits    map[string]ruleHit
	trusted bool // the scan ran cleanly enough for its ABSENCES to mean anything
	// absent distinguishes "the tool is not installed" from "the tool ran and could
	// not analyze this". Both are untrusted, but only the second is a fixture problem,
	// and reporting them as one message sent this author off diagnosing the wrong one.
	absent bool
}

// fixChecker verifies patches with the real scanner, caching the per-case baseline
// so the "does the rule even fire on the original?" question is asked once.
type fixChecker struct {
	root string

	mu       sync.Mutex
	baseline map[string]bool // caseID -> the rule is reproducible on the unpatched fixture
}

func newFixChecker(root string) *fixChecker {
	return &fixChecker{root: root, baseline: map[string]bool{}}
}

// reproducible reports whether the case's own tool actually flags its own rule on
// the pristine fixture. If it does not — tool missing, rule renamed, fixture
// drifted — then "the rule is absent after patching" proves nothing, and the whole
// check must degrade to unknown rather than quietly score a pass.
func (fc *fixChecker) reproducible(cs Case) bool {
	fc.mu.Lock()
	if v, ok := fc.baseline[cs.ID]; ok {
		fc.mu.Unlock()
		return v
	}
	fc.mu.Unlock()

	body, err := cs.fixtureBody(fc.root)
	ok := false
	if err == nil {
		out := scanSource(cs, []byte(body))
		ok = out.trusted && out.rules[strings.ToUpper(cs.Finding.RuleID)]
	}

	fc.mu.Lock()
	fc.baseline[cs.ID] = ok
	fc.mu.Unlock()
	return ok
}

// verify runs the case's scanner over the patched content.
func (fc *fixChecker) verify(cs Case, patched []byte) fixVerdict {
	if len(patched) == 0 || !fc.reproducible(cs) {
		return fixUnknown
	}
	out := scanSource(cs, patched)
	if !out.trusted {
		// The scanner could not analyze the patched file. An absent rule here is an
		// absent ANALYSIS, which is the trap this whole file exists to avoid.
		return fixUnknown
	}
	if out.rules[strings.ToUpper(cs.Finding.RuleID)] {
		return fixNo
	}
	return fixYes
}

// scanSource writes content to a throwaway tree and runs the appropriate scanner.
func scanSource(cs Case, content []byte) scanOutcome {
	dir, err := os.MkdirTemp("", "achilles-eval-fixcheck-*")
	if err != nil {
		return scanOutcome{}
	}
	defer os.RemoveAll(dir)

	path, ok := containedPath(dir, filepath.Base(cs.Fixture))
	if !ok {
		return scanOutcome{}
	}
	if err := os.WriteFile(path, content, 0o600); err != nil { // #nosec G703 -- containedPath
		return scanOutcome{}
	}

	switch strings.ToLower(filepath.Ext(cs.Fixture)) {
	case ".go":
		// gosec needs a module to load packages at all.
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module evalfixcheck\n\ngo 1.21\n"), 0o600); err != nil {
			return scanOutcome{}
		}
		return runGosec(dir)
	case ".py":
		return runBandit(path)
	default:
		return scanOutcome{}
	}
}

// runGosec reports which rules fired, and whether the run can be trusted. gosec
// prints nothing parseable when package loading fails, and reports "Golang errors"
// when a file will not typecheck — both make absences meaningless.
//
// Deliberately NOT -quiet. That flag means "only show output when errors are found",
// so a clean scan emits zero bytes and is byte-identical to a scan that crashed —
// collapsing the one distinction this whole file exists to preserve. It biased the
// fix check exactly backwards: a patch that removed every finding (the ideal result)
// produced no JSON and scored UNKNOWN, while a patch that removed the target rule but
// left some other finding behind stayed verifiable and scored as fixed. So FixRate
// was computed over a subset that systematically excluded the best outcomes.
func runGosec(dir string) scanOutcome {
	if _, err := exec.LookPath("gosec"); err != nil {
		return scanOutcome{absent: true}
	}
	cmd := exec.Command("gosec", "-fmt=json", "-no-fail", "./...") // #nosec G204 -- fixed argv
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil && len(raw) == 0 {
		return scanOutcome{}
	}
	var parsed struct {
		Issues []struct {
			RuleID string `json:"rule_id"`
			// gosec reports the line as a STRING, and as a "12-14" range for a
			// multi-line finding. Decoding it as an int silently zeroes both.
			Line     string `json:"line"`
			Details  string `json:"details"`
			Severity string `json:"severity"`
		} `json:"Issues"`
		GolangErrors map[string]any `json:"Golang errors"`
		Stats        struct {
			Files int `json:"files"`
		} `json:"Stats"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return scanOutcome{}
	}
	if len(parsed.GolangErrors) > 0 || parsed.Stats.Files < 1 {
		return scanOutcome{}
	}
	rules := map[string]bool{}
	hits := map[string]ruleHit{}
	for _, i := range parsed.Issues {
		id := strings.ToUpper(i.RuleID)
		rules[id] = true
		if _, seen := hits[id]; !seen {
			hits[id] = ruleHit{
				line:     firstLine(i.Line),
				message:  i.Details,
				severity: strings.ToLower(i.Severity),
			}
		}
	}
	return scanOutcome{rules: rules, hits: hits, trusted: true}
}

// firstLine parses gosec's line field, which is a string and may be a "12-14"
// range. Returns 0 when it cannot be read, which callers treat as "unknown" rather
// than as line zero.
func firstLine(s string) int {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// runBandit reports which tests fired. bandit exits non-zero when it finds
// something, so exit status is not an error signal; its `errors` array is.
func runBandit(path string) scanOutcome {
	if _, err := exec.LookPath("bandit"); err != nil {
		return scanOutcome{absent: true}
	}
	raw, err := exec.Command("bandit", "-f", "json", "-q", path).Output() // #nosec G204 -- our own temp path
	if err != nil && len(raw) == 0 {
		return scanOutcome{}
	}
	var parsed struct {
		Results []struct {
			TestID   string `json:"test_id"`
			Line     int    `json:"line_number"`
			Issue    string `json:"issue_text"`
			Severity string `json:"issue_severity"`
		} `json:"results"`
		Errors []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return scanOutcome{}
	}
	if len(parsed.Errors) > 0 {
		// A syntax error in the patched file lands here. Absent tests would just
		// mean bandit never got to run them.
		return scanOutcome{}
	}
	rules := map[string]bool{}
	hits := map[string]ruleHit{}
	for _, r := range parsed.Results {
		id := strings.ToUpper(r.TestID)
		rules[id] = true
		if _, seen := hits[id]; !seen {
			hits[id] = ruleHit{line: r.Line, message: r.Issue, severity: strings.ToLower(r.Severity)}
		}
	}
	return scanOutcome{rules: rules, hits: hits, trusted: true}
}

// containedPath resolves rel inside base and refuses anything that escapes it.
//
// Every path this package writes to is influenced by data we do not control — the
// corpus manifest's `fixture`, or the target path a model chose to put in its diff
// header. filepath.Join already neutralizes an absolute rel and a "../" is screened
// before we get here, but "already safe if you trace three call sites" is not a
// property a reader or a scanner can check. gosec's taint analysis (G703) flagged
// exactly these writes, and it was right to: the containment was real but invisible.
// One helper makes it checkable in one place.
func containedPath(base, rel string) (string, bool) {
	if rel == "" {
		return "", false
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", false
	}
	// Clean("/"+rel) collapses any traversal before it can escape, and Join keeps
	// an absolute rel inside base rather than honouring it.
	full := filepath.Join(absBase, filepath.Clean("/"+rel))
	if full != absBase && !strings.HasPrefix(full, absBase+string(os.PathSeparator)) {
		return "", false
	}
	return full, true
}
