package eval

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/noise"
)

// DetectTarget is a ground-truth file bound to the directory it will be scanned in.
type DetectTarget struct {
	Truth GroundTruth
	Dir   string // absolute scan root
}

// ResolveTargets pins every target to a directory (cloning git sources into
// cacheDir) before any scan starts, so a placeholder commit or an unreachable
// repository fails the whole run up front rather than half way through.
func ResolveTargets(ctx context.Context, truths []GroundTruth, cacheDir string, git GitRunner) ([]DetectTarget, error) {
	// Refuse unpinned sources first: that check needs no network and its message
	// is the one the operator most needs.
	for _, g := range truths {
		if err := g.CheckPinned(); err != nil {
			return nil, err
		}
	}
	var out []DetectTarget
	for _, g := range truths {
		dir, err := ResolveSource(ctx, g, cacheDir, git)
		if err != nil {
			return nil, err
		}
		out = append(out, DetectTarget{Truth: g, Dir: dir})
	}
	return out, nil
}

// DetectOptions configures a detection run.
type DetectOptions struct {
	// LineTolerance widens each entry's line range on both sides when matching.
	LineTolerance int
	// AI says the scanner runs with LLM review: pass 1 keeps dismissed findings (the
	// unfiltered result), pass 2 lets the review filter (the scored result).
	AI bool
	// Excludes / NoDefaultExcludes mirror what the scan was given, so a noise-filter
	// drop can be recognized. Unknown extra flags are not understood by the trace.
	Excludes          string
	NoDefaultExcludes bool
	// ScanBaselineUsed / DiffUsed say the scan ran with --baseline / --diff.
	ScanBaselineUsed bool
	DiffUsed         bool
	// ToolLanguages is each registered tool's declared languages (from the tool
	// registry); a nil map means unknown, in which case every tool is assumed to
	// cover every language.
	ToolLanguages map[string][]string
	// Judge optionally adjudicates same-place findings whose class/CWE disagrees.
	Judge Judge
	// Repeat runs the whole benchmark this many times (default 1) so run-to-run
	// stability is visible.
	Repeat int
	// Progress is called after each target.
	Progress func(id string, done, total int)
	// Now stamps the report; defaults to time.Now.
	Now func() time.Time
	// GroundTruthLabel is recorded in the report (a path as the operator gave it).
	GroundTruthLabel string
}

// DetectRunner runs the benchmark through a ScanRunner.
type DetectRunner struct {
	Scan ScanRunner
	Opts DetectOptions
}

// Run executes the benchmark Repeat times and returns the last run's report with
// the stability of all runs recorded in it.
func (r DetectRunner) Run(ctx context.Context, targets []DetectTarget) DetectReport {
	n := r.Opts.Repeat
	if n < 1 {
		n = 1
	}
	var last DetectReport
	var summaries []RunSummary
	for i := 0; i < n; i++ {
		last = r.runOnce(ctx, targets)
		summaries = append(summaries, last.summary())
	}
	last.History = summaries
	last.Runs = n
	last.Unstable = unstableEntries(summaries)
	return last
}

func (r DetectRunner) now() time.Time {
	if r.Opts.Now != nil {
		return r.Opts.Now()
	}
	return time.Now()
}

func (r DetectRunner) runOnce(ctx context.Context, targets []DetectTarget) DetectReport {
	rep := DetectReport{
		SchemaVersion: DetectReportVersion,
		GeneratedAt:   r.now().UTC().Format(time.RFC3339),
		Config: DetectConfig{
			LineTolerance: r.Opts.LineTolerance, AI: r.Opts.AI, Judge: r.Opts.Judge != nil,
			Exclude: r.Opts.Excludes, NoDefaultExcludes: r.Opts.NoDefaultExcludes,
			GroundTruth: ScrubPaths(r.Opts.GroundTruthLabel, nil), MatcherVersion: MatcherVersion,
		},
	}
	for i, t := range targets {
		rep.Targets = append(rep.Targets, r.runTarget(ctx, t))
		if r.Opts.Progress != nil {
			r.Opts.Progress(t.Truth.ID, i+1, len(targets))
		}
	}
	rep.aggregate()
	return rep
}

func rootsOf(dir string) []string {
	roots := []string{dir}
	if real, err := filepath.EvalSymlinks(dir); err == nil && real != dir {
		roots = append(roots, real)
	}
	return roots
}

// passView is one scan pass with paths normalized and the vault digested.
type passView struct {
	surfaced  []model.Finding
	dismissed []model.Finding
	facts     scanFacts
	note      string
}

func (r DetectRunner) runPass(ctx context.Context, dir string, req ScanRequest) (passView, error) {
	req.Dir = dir
	out, err := r.Scan.RunScan(ctx, req)
	if err != nil {
		return passView{}, err
	}
	roots := rootsOf(dir)
	pv := passView{surfaced: out.Findings, dismissed: out.Dismissed, facts: digest(out.Records), note: out.ExitNote}
	enrichFromVault(pv.surfaced, pv.facts.Candidates, pv.facts.Verdicts, roots)
	enrichFromVault(pv.dismissed, pv.facts.Candidates, pv.facts.Verdicts, roots)
	for _, set := range [][]model.Finding{pv.surfaced, pv.dismissed, pv.facts.Candidates} {
		for i := range set {
			set[i].Location.File = normalizeFindingPath(set[i].Location.File, roots)
		}
	}
	return pv, nil
}

func (r DetectRunner) runTarget(ctx context.Context, t DetectTarget) TargetResult {
	tr := r.scoreTarget(ctx, t)
	scrubTarget(&tr, rootsOf(t.Dir))
	return tr
}

func (r DetectRunner) scoreTarget(ctx context.Context, t DetectTarget) TargetResult {
	g := t.Truth
	tr := TargetResult{ID: g.ID, Description: g.Description, Source: sourceLabel(g)}

	invalid := g.ValidateAgainstTree(t.Dir)

	// Pass 1: nothing the AI review decides is removed. With AI off this is the
	// whole scan.
	unfiltered, err := r.runPass(ctx, t.Dir, ScanRequest{KeepDismissed: true, AI: r.Opts.AI})
	if err != nil {
		tr.Error = err.Error()
		tr.Incomplete = true
		for _, v := range g.Vulns {
			e := newEntry(v)
			if msg, bad := invalid[v.ID]; bad {
				e.Status, e.Invalid = StatusInvalid, msg
			} else {
				e.Loss = &LossTrace{Point: LossScanFailed, Detail: "the scan did not complete: " + detectFirstLine(err.Error())}
			}
			tr.Entries = append(tr.Entries, e)
		}
		return tr
	}
	final := unfiltered
	if r.Opts.AI {
		filtered, err := r.runPass(ctx, t.Dir, ScanRequest{KeepDismissed: false, AI: true})
		if err != nil {
			tr.Notes = append(tr.Notes, "AI-filtered pass failed ("+detectFirstLine(err.Error())+"); scored the unfiltered pass instead")
		} else {
			final = filtered
		}
	}
	if unfiltered.note != "" {
		tr.Notes = append(tr.Notes, "achilles exited non-zero but wrote its report: "+unfiltered.note)
	}

	facts := unfiltered.facts
	tr.Tools = ToolStatus{Registered: facts.Registered, Ran: facts.Ran, Failed: facts.Failed, Skipped: facts.Skipped, KnownToVault: facts.HasVault}
	tr.Incomplete = len(facts.Failed) > 0

	m := matcher{vulns: g.Vulns, tol: r.Opts.LineTolerance}
	tc := traceContext{
		m: m, opts: r.Opts, facts: facts, unfiltered: unfiltered.surfaced,
		finalSurfaced: final.surfaced, finalDismissed: final.dismissed,
		noise: r.noiseMatcher(),
	}

	labeledFiles := map[string]bool{}
	for _, v := range g.Vulns {
		labeledFiles[v.File] = true
	}
	matchedFinding := map[int]bool{} // index into final.surfaced

	for _, v := range g.Vulns {
		e := newEntry(v)
		if msg, bad := invalid[v.ID]; bad {
			e.Status, e.Invalid = StatusInvalid, msg
			tr.Entries = append(tr.Entries, e)
			continue
		}
		// Scored set first.
		var exact, ambiguous []int
		for i, f := range final.surfaced {
			switch m.classify(v, f) {
			case matchExact:
				exact = append(exact, i)
			case matchAmbiguous:
				ambiguous = append(ambiguous, i)
			}
		}
		e.MatchedBy = "rule"
		if len(exact) == 0 && r.Opts.Judge != nil {
			for _, i := range firstN(ambiguous, 3) {
				ok, reason, jerr := r.Opts.Judge.SameVulnerability(ctx, JudgeInput{
					Entry: v, Finding: final.surfaced[i], Root: t.Dir,
				})
				if jerr != nil {
					tr.Notes = append(tr.Notes, fmt.Sprintf("judge failed for %s: %s", v.ID, detectFirstLine(jerr.Error())))
					break
				}
				if ok {
					exact = append(exact, i)
					e.MatchedBy, e.JudgeReason = "judge", reason
					break
				}
			}
		}
		for _, i := range exact {
			matchedFinding[i] = true
		}
		if len(exact) > 0 {
			e.Status, e.Detected = StatusDetected, true
			for _, i := range firstN(exact, 5) {
				e.Matches = append(e.Matches, refOf(final.surfaced[i]))
			}
		} else {
			e.MatchedBy = ""
			e.Status = StatusMissed
		}
		// Unfiltered detection: did the scanners surface it before AI review?
		e.DetectedUnfiltered = e.Detected
		if r.Opts.AI {
			e.DetectedUnfiltered = false
			for _, f := range unfiltered.surfaced {
				if m.classify(v, f) == matchExact {
					e.DetectedUnfiltered = true
					break
				}
			}
			if e.Detected {
				e.DetectedUnfiltered = true
			}
		}
		if !e.Detected {
			lt := tc.trace(v)
			e.Loss = &lt
		}
		tr.Entries = append(tr.Entries, e)
	}

	// Precision proxy over the scored set. Not false positives: a finding in a file
	// with no label is just unlabeled.
	for i, f := range final.surfaced {
		tr.Findings.Surfaced++
		switch {
		case matchedFinding[i] || matchesAnyEntry(m, f, invalid):
			tr.Findings.Matched++
		case labeledFiles[f.Location.File]:
			tr.Findings.UnmatchedInLabeledFiles++
			if len(tr.Findings.Samples) < 25 {
				tr.Findings.Samples = append(tr.Findings.Samples, refOf(f))
			}
		default:
			tr.Findings.UnlabeledFiles++
		}
	}
	tr.Findings.Dismissed = len(final.dismissed)
	return tr
}

func matchesAnyEntry(m matcher, f model.Finding, invalid map[string]string) bool {
	for _, v := range m.vulns {
		if _, bad := invalid[v.ID]; bad {
			continue
		}
		if m.classify(v, f) == matchExact {
			return true
		}
	}
	return false
}

func (r DetectRunner) noiseMatcher() *noise.Matcher {
	nm := noise.DefaultMatcher()
	if r.Opts.NoDefaultExcludes {
		nm = noise.NewMatcher()
	}
	for _, p := range strings.Split(r.Opts.Excludes, ",") {
		nm.Add(p)
	}
	return nm
}

func newEntry(v Vuln) EntryResult {
	return EntryResult{
		ID: v.ID, Class: v.Class, CWE: v.CWE, File: v.File, StartLine: v.StartLine, EndLine: v.EndLine,
		Description: v.Description, Status: StatusMissed,
	}
}

func refOf(f model.Finding) FindingRef {
	return FindingRef{Tool: f.Tool, RuleID: f.RuleID, File: f.Location.File, Line: f.Location.Region.StartLine, CWE: f.CWE}
}

func sourceLabel(g GroundTruth) string {
	if g.Source.IsGit() {
		c := g.Source.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		return g.Source.URL + "@" + c
	}
	return "local:" + filepath.ToSlash(g.Source.Path)
}

func firstN(xs []int, n int) []int {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func detectFirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// unstableEntries lists entries that were detected in some runs and missed in
// others — the number that says whether a recall change is signal or noise.
func unstableEntries(runs []RunSummary) []Unstable {
	if len(runs) < 2 {
		return nil
	}
	count := map[string]int{}
	seen := map[string]int{}
	for _, run := range runs {
		for _, id := range run.ScoredIDs {
			seen[id]++
		}
		for _, id := range run.DetectedIDs {
			count[id]++
		}
	}
	var out []Unstable
	for id, n := range seen {
		if d := count[id]; d > 0 && d < n {
			out = append(out, Unstable{ID: id, Runs: n, Detected: d})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

var homePathRE = regexp.MustCompile(`/Users/[^/\s"']+|/home/[^/\s"']+|[A-Za-z]:\\Users\\[^\\\s"']+`)

// ScrubPaths removes machine-specific paths from text that ends up in a report: the
// scan root becomes "<target>" and any home directory becomes "<home>". Reports are
// committed as baselines and pasted into issues, and a tool's error message
// routinely embeds the absolute path it was run on.
func ScrubPaths(s string, roots []string) string {
	for _, r := range roots {
		if r != "" && r != "/" {
			s = strings.ReplaceAll(s, r, "<target>")
		}
	}
	return homePathRE.ReplaceAllString(s, "<home>")
}

func scrubTarget(tr *TargetResult, roots []string) {
	sc := func(s string) string { return ScrubPaths(s, roots) }
	tr.Error = sc(tr.Error)
	for i := range tr.Notes {
		tr.Notes[i] = sc(tr.Notes[i])
	}
	for i := range tr.Tools.Failed {
		tr.Tools.Failed[i].Error = sc(tr.Tools.Failed[i].Error)
	}
	for i := range tr.Entries {
		e := &tr.Entries[i]
		e.Invalid = sc(e.Invalid)
		e.JudgeReason = sc(e.JudgeReason)
		if e.Loss != nil {
			e.Loss.Detail = sc(e.Loss.Detail)
			if v := e.Loss.Verdict; v != nil {
				v.Reasoning, v.RefuteReason = sc(v.Reasoning), sc(v.RefuteReason)
			}
		}
	}
}
