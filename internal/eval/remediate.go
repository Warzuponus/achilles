package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage"
)

// Remediation is a different seat from triage and judge, and it fails in a
// different way — so it needs its own ground truth. A judge fails by reaching the
// wrong conclusion; a remediation model fails by emitting a patch that does not
// apply, breaks the file, or "fixes" nothing.
//
// The chain scored here is deliberately mechanical, because each step is
// objectively checkable without a human and without a scanner:
//
//	produced a diff -> the diff APPLIES -> the patched file still PARSES ->
//	the SCANNER no longer reports the rule (see fixcheck.go)
//
// The last step is what stops a patch that deletes the function from scoring as a
// fix, and it is verified by re-running the tool that reported the finding rather
// than by matching strings — string matching was tried first and was wrong three
// ways (see the fixcheck.go header). "Could not verify" is reported as its own
// state and never counted as a fix.
//
// NOT measured: whether the patch preserves behaviour. That needs the fixture to
// have tests, which these do not. A patch can pass every check here and still be
// wrong in a way only a reviewer would catch — which is exactly why Achilles
// proposes patches and never merges them (DESIGN §1 Non-Goals).

// RemediationOutcome is one remediation attempt on one case.
type RemediationOutcome struct {
	HasDiff bool `json:"hasDiff"`
	Applies bool `json:"applies"`
	Parses  bool `json:"parses"`
	// FixVerified is set only when the scanner confirms the rule stopped firing.
	// FixUnverifiable records that the check could not run (tool absent, patched
	// file unanalyzable, rule not reproducible on the original) — distinct from a
	// patch that demonstrably failed to fix anything.
	FixVerified     bool    `json:"fixVerified"`
	FixUnverifiable bool    `json:"fixUnverifiable,omitempty"`
	Confidence      float64 `json:"confidence"`
	// ParseSkipped records that no toolchain was available to check the patched
	// file, so Parses is not evidence either way.
	ParseSkipped bool   `json:"parseSkipped,omitempty"`
	Guidance     bool   `json:"guidanceOnly,omitempty"` // prose instead of a patch
	LatencyMS    int64  `json:"latencyMs"`
	Err          string `json:"error,omitempty"`
}

// Good reports a patch that made it all the way through.
func (o RemediationOutcome) Good() bool {
	return o.HasDiff && o.Applies && o.Parses && o.FixVerified
}

// RemediationResult aggregates the repeats for one case.
type RemediationResult struct {
	CaseID   string               `json:"caseId"`
	Outcomes []RemediationOutcome `json:"outcomes"`
	Good     int                  `json:"good"`
}

// RemediationReport is the scored result of a remediation screen.
type RemediationReport struct {
	Mode   string `json:"mode"`
	Model  string `json:"model"`
	Repeat int    `json:"repeat"`
	Cases  int    `json:"cases"`
	Runs   int    `json:"runs"`

	// Each rate is over all runs, so the funnel is readable end to end: a model
	// can score well on DiffRate and badly on FixRate, which is the interesting
	// failure (confident patches that change nothing).
	DiffRate  float64 `json:"diffRate"`
	ApplyRate float64 `json:"applyRate"`
	ParseRate float64 `json:"parseRate"`
	FixRate   float64 `json:"fixRate"`

	// Unverifiable runs are excluded from FixRate's denominator rather than counted
	// as failures — a missing scanner is our problem, not the model's.
	Unverifiable int `json:"unverifiable"`
	GuidanceOnly int `json:"guidanceOnly"`
	Errors       int `json:"errors"`

	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`

	Results []RemediationResult `json:"results"`
}

// ErrorRate mirrors VerdictReport.ErrorRate.
func (r RemediationReport) ErrorRate() float64 {
	if r.Runs == 0 {
		return 0
	}
	return float64(r.Errors) / float64(r.Runs)
}

// Unreliable flags a screen dominated by failed calls, for the same reason as
// VerdictReport.Unreliable: a 0% built from HTTP errors is a plumbing fact.
func (r RemediationReport) Unreliable() bool { return r.ErrorRate() >= 0.2 }

// RemediationRunner screens the remediation seat.
type RemediationRunner struct {
	Engine   *triage.Engine
	Repeat   int
	Progress func(caseID string, done, total int)
}

// Run scores every TP case's remediation. FP cases are skipped: the product never
// remediates something it believes is not a problem.
//
// A synthetic high-confidence verdict is injected rather than running real triage
// first. That isolates the seat under test — one call per case instead of three —
// on the same principle as holding triage fixed while screening judges. It also
// means the score cannot be contaminated by a weak triage model.
func (rn RemediationRunner) Run(ctx context.Context, c Corpus, runID string) RemediationReport {
	repeat := rn.Repeat
	if repeat < 1 {
		repeat = 1
	}
	var cases []Case
	for _, cs := range c.SortedCases() {
		if cs.Label == LabelTP {
			cases = append(cases, cs)
		}
	}
	rep := RemediationReport{Mode: "remediate", Repeat: repeat, Cases: len(cases)}
	fc := newFixChecker(c.Root)

	var diff, applies, parses, fixes, fixScored int
	for i, cs := range cases {
		res := RemediationResult{CaseID: cs.ID}
		for r := 0; r < repeat; r++ {
			f := cs.ToFinding()
			// The seat only runs on confirmed findings, so hand it one.
			f.Verdict = &model.Verdict{
				Classification: model.ClassTruePositive, Confidence: 0.95,
				Exploitability: model.ExploitReachable,
				Reasoning:      "confirmed for the purposes of screening the remediation seat",
			}
			started := time.Now()
			err := rn.Engine.Remediate(ctx, runID, &f)
			out := RemediationOutcome{LatencyMS: time.Since(started).Milliseconds()}

			switch {
			case err != nil:
				out.Err = err.Error()
				rep.Errors++
			case f.Remediation == nil:
				out.Err = "no remediation attached"
				rep.Errors++
			default:
				out.Confidence = f.Remediation.Confidence
				out.HasDiff = strings.TrimSpace(f.Remediation.Diff) != ""
				out.Guidance = !out.HasDiff && strings.TrimSpace(f.Remediation.Guidance) != ""
				if out.HasDiff {
					diff++
					ap, pr, skipped, verdict := checkPatch(fc, c.Root, cs, f.Remediation.Diff)
					out.Applies, out.Parses, out.ParseSkipped = ap, pr, skipped
					switch verdict {
					case fixYes:
						out.FixVerified = true
						fixes++
						fixScored++
					case fixNo:
						fixScored++
					default:
						out.FixUnverifiable = true
						rep.Unverifiable++
					}
					if ap {
						applies++
					}
					if pr {
						parses++
					}
				}
				if out.Guidance {
					rep.GuidanceOnly++
				}
			}
			if out.Good() {
				res.Good++
			}
			rep.Runs++
			res.Outcomes = append(res.Outcomes, out)
		}
		rep.Results = append(rep.Results, res)
		if rn.Progress != nil {
			rn.Progress(cs.ID, i+1, len(cases))
		}
	}

	if rep.Runs > 0 {
		n := float64(rep.Runs)
		rep.DiffRate = float64(diff) / n
		rep.ApplyRate = float64(applies) / n
		rep.ParseRate = float64(parses) / n
	}
	// FixRate is over VERIFIABLE runs only. Folding unverifiable ones in either
	// direction would misreport: as failures it blames the model for our missing
	// tooling, as successes it invents fixes.
	if fixScored > 0 {
		rep.FixRate = float64(fixes) / float64(fixScored)
	}
	u := rn.Engine.Usage()
	rep.PromptTokens, rep.CompletionTokens = u.PromptTokens, u.CompletionTokens
	return rep
}

// checkPatch copies the fixture into a temp tree, applies the diff there, and
// inspects the result. The corpus is never touched.
func checkPatch(fc *fixChecker, root string, cs Case, diff string) (applies, parses, parseSkipped bool, fix fixVerdict) {
	src, err := cs.fixturePath(root)
	if err != nil {
		return false, false, true, fixUnknown
	}
	data, err := os.ReadFile(src) // #nosec G304 -- contained by fixturePath
	if err != nil {
		return false, false, true, fixUnknown
	}
	dir, err := os.MkdirTemp("", "achilles-eval-patch-*")
	if err != nil {
		return false, false, true, fixUnknown
	}
	defer os.RemoveAll(dir)

	// Materialize the fixture at whatever path the DIFF references, plus the
	// corpus-relative path and the bare basename. Models pick their own prefix —
	// one emitted "a/evals/triage/testdata/x.go" while the prompt said
	// "testdata/x.go" — and a screen that fails on prefix choice would be measuring
	// our path guessing, not their patch.
	targets := map[string]bool{cs.Fixture: true, filepath.Base(cs.Fixture): true}
	if p := diffTargetPath(diff); p != "" {
		targets[p] = true
	}
	for t := range targets {
		dst, ok := containedPath(dir, t)
		if !ok {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			continue
		}
		_ = os.WriteFile(dst, data, 0o600) // #nosec G703 -- containedPath
	}

	if !applyDiff(dir, diff) {
		return false, false, true, fixUnknown
	}
	applies = true

	// Read back whichever copy actually changed.
	var patched []byte
	for t := range targets {
		full, ok := containedPath(dir, t)
		if !ok {
			continue
		}
		b, err := os.ReadFile(full) // #nosec G304,G703 -- containedPath
		if err != nil || len(b) == 0 {
			continue
		}
		if string(b) != string(data) {
			patched = b
			break
		}
		patched = b
	}
	rel := cs.Fixture
	parses, parseSkipped = checkParses(rel, patched)
	// Only ask the scanner about a file that still parses; otherwise the tool would
	// fail and the verdict would be unknown anyway, at the cost of a subprocess.
	if parses {
		fix = fc.verify(cs, patched)
	}
	return applies, parses, parseSkipped, fix
}

// diffTargetPath pulls the destination path out of a unified diff's "+++ b/path"
// header, stripping the a/ or b/ prefix git conventionally adds.
func diffTargetPath(diff string) string {
	for _, line := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(line, "+++ ") {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
		p = strings.Fields(p)[0] // drop any trailing timestamp
		for _, pre := range []string{"a/", "b/", "./"} {
			p = strings.TrimPrefix(p, pre)
		}
		if p == "/dev/null" {
			return ""
		}
		return p
	}
	return ""
}

// applyDiff tries the strip levels models actually produce, then retries tolerating
// whitespace. git apply is used because it is stricter than patch(1) about corrupt
// hunks, which is what a screen wants — but LLMs routinely mangle leading tabs, and
// failing a semantically correct patch over indentation would measure the wrong
// thing. Strict is tried first so the distinction stays visible in the code.
func applyDiff(dir, diff string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	body := ensureTrailingNewline(diff)
	attempts := [][]string{
		{"apply", "-p1", "--whitespace=nowarn", "-"},
		{"apply", "-p0", "--whitespace=nowarn", "-"},
		{"apply", "-p1", "--ignore-whitespace", "--whitespace=nowarn", "-"},
		{"apply", "-p0", "--ignore-whitespace", "--whitespace=nowarn", "-"},
		// Last resort: let git search for the right offset/context.
		{"apply", "-p1", "--ignore-whitespace", "--recount", "-C1", "--whitespace=nowarn", "-"},
	}
	for _, args := range attempts {
		cmd := exec.Command("git", args...) // #nosec G204 -- fixed argv, no user input
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(body)
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// checkParses reports whether the patched file is still syntactically valid.
// skipped is true when no toolchain for that language is available, in which case
// the result is not evidence either way.
func checkParses(path string, content []byte) (ok, skipped bool) {
	dir, err := os.MkdirTemp("", "achilles-eval-parse-*")
	if err != nil {
		return false, true
	}
	defer os.RemoveAll(dir)
	f, ok := containedPath(dir, filepath.Base(path))
	if !ok {
		return false, true
	}
	if err := os.WriteFile(f, content, 0o600); err != nil { // #nosec G703 -- containedPath
		return false, true
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		if _, err := exec.LookPath("gofmt"); err != nil {
			return false, true
		}
		// gofmt -e reports syntax errors; exit status is enough. The path is our own
		// temp file via containedPath, and the argv is fixed.
		return exec.Command("gofmt", "-e", f).Run() == nil, false // #nosec G204 -- fixed argv, containedPath
	case ".py":
		if _, err := exec.LookPath("python3"); err != nil {
			return false, true
		}
		return exec.Command("python3", "-m", "py_compile", f).Run() == nil, false // #nosec G204 -- fixed argv, containedPath
	default:
		return false, true
	}
}

// Write renders the remediation screen for a terminal.
func (r RemediationReport) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "Remediation seat — model %s, %d tp case(s) x %d repeat(s)\n", r.Model, r.Cases, r.Repeat)
	if r.Unreliable() {
		fmt.Fprintf(w, "\n  *** RATES BELOW ARE NOT A MODEL RESULT ***\n")
		fmt.Fprintf(w, "  %.0f%% of runs FAILED (%d of %d).\n", 100*r.ErrorRate(), r.Errors, r.Runs)
	}
	fmt.Fprintf(w, "\n  the funnel (share of all %d runs):\n", r.Runs)
	fmt.Fprintf(w, "    produced a diff   %5.1f%%\n", 100*r.DiffRate)
	fmt.Fprintf(w, "    diff APPLIES      %5.1f%%\n", 100*r.ApplyRate)
	fmt.Fprintf(w, "    still PARSES      %5.1f%%\n", 100*r.ParseRate)
	fmt.Fprintf(w, "    scanner CLEAN     %5.1f%%   <- the headline, over VERIFIABLE runs only: the tool no longer reports the rule\n", 100*r.FixRate)
	if r.Unverifiable > 0 {
		fmt.Fprintf(w, "  unverifiable: %d run(s) — scanner unavailable or could not analyze the patched file.\n", r.Unverifiable)
		fmt.Fprintf(w, "                Excluded from the rate above; NOT counted as failures.\n")
	}
	if r.GuidanceOnly > 0 {
		fmt.Fprintf(w, "  prose-only (no patch): %d run(s) — legitimate when a fix needs judgement, but not a fix\n", r.GuidanceOnly)
	}
	if r.Errors > 0 {
		fmt.Fprintf(w, "  errors: %d\n", r.Errors)
	}
	fmt.Fprintf(w, "  tokens: %d prompt + %d completion\n", r.PromptTokens, r.CompletionTokens)

	if verbose {
		fmt.Fprintf(w, "\n  %-28s %6s %8s %7s %9s\n", "CASE", "DIFF", "APPLIES", "PARSES", "SCANNER")
		for _, res := range r.Results {
			for _, o := range res.Outcomes {
				scanner := "clean"
				switch {
				case o.FixUnverifiable:
					scanner = "unknown"
				case !o.FixVerified:
					scanner = "still"
				}
				fmt.Fprintf(w, "  %-28s %6s %8s %7s %9s\n", res.CaseID,
					yn(o.HasDiff), yn(o.Applies), ynSkip(o.Parses, o.ParseSkipped), scanner)
			}
		}
	}
	fmt.Fprintf(w, "\n  NOT measured: whether a patch preserves behaviour. These fixtures have no\n")
	fmt.Fprintf(w, "  tests, so a patch can pass every check here and still be wrong — which is\n")
	fmt.Fprintf(w, "  why Achilles proposes patches and never merges them.\n")
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func ynSkip(b, skipped bool) string {
	if skipped {
		return "skip"
	}
	return yn(b)
}

// WriteJSON persists the screen.
func (r RemediationReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
