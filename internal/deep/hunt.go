package deep

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// Hunt mode starts from an entry point instead of a finding: the model follows the
// data from where it enters, with the same read-only tools and bounds as deep
// verification, and reports what it can trace to a dangerous operation. It finds
// what no rule describes, at the price of a model's imagination, so everything it
// reports is a candidate: the triage model and the judge review it like any
// scanner finding, and a candidate they do not confirm is listed apart and never
// gates the build (model.Scan.Hunted).

// HuntPromptVersion is recorded with every hunt.
const HuntPromptVersion = "hunt/v1"

// HuntTool is the Tool of a finding a hunt proposed.
const HuntTool = "achilles-hunt"

// MaxHuntCandidates is the most candidates one hunt keeps. A model that lists ten
// issues from one handler is guessing.
const MaxHuntCandidates = 3

// HuntSeed is where a hunt starts: an entry point found by pattern match.
type HuntSeed struct {
	File    string `json:"file"` // relative to the scan root
	Line    int    `json:"line"`
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
}

// HuntCandidate is one issue a hunt reports, checked: its location and every step
// of its route are lines a tool showed the model.
type HuntCandidate struct {
	File      string           `json:"file"`
	Line      int              `json:"line"`
	Class     string           `json:"class"`
	Severity  model.Severity   `json:"severity"`
	Title     string           `json:"title"`
	Reasoning string           `json:"reasoning"`
	Route     []model.FlowStep `json:"route,omitempty"`
}

// HuntResult is the outcome of one hunt.
type HuntResult struct {
	Seed          HuntSeed        `json:"seed"`
	Candidates    []HuntCandidate `json:"candidates,omitempty"`
	Dropped       int             `json:"dropped,omitempty"` // candidates discarded: unshown location, or over the cap
	Steps         int             `json:"steps"`
	ToolBytes     int             `json:"toolBytes"`
	Trace         []string        `json:"trace,omitempty"`
	Aborted       string          `json:"aborted,omitempty"`
	PromptVersion string          `json:"promptVersion"`
}

// Hunt follows the data from one entry point. Like Deep, an error is returned only
// for failures a retry might fix; everything else ends in Aborted.
func (v *Verifier) Hunt(ctx context.Context, seed HuntSeed) (HuntResult, error) {
	res := HuntResult{Seed: seed, PromptVersion: HuntPromptVersion}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, v.cfg.Timeout)
	defer cancel()

	sess, ctxText, ok := v.open(seed.File, seed.Line, 0)
	if !ok {
		res.Aborted = "the entry point's file is a protected path and is never shown to the model"
		return res, nil
	}
	nonce := newNonce()
	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: huntSystemPrompt(v.cfg.MaxSteps)},
		{Role: llm.RoleUser, Content: huntFirstMessage(seed, ctxText, nonce)},
	}
	finish := func() HuntResult {
		res.Steps = len(sess.trace)
		res.ToolBytes = sess.used
		for _, t := range sess.trace {
			res.Trace = append(res.Trace, redact.Prompt(t))
		}
		return res
	}
	abort := func(reason string) (HuntResult, error) {
		res.Aborted, res.Candidates = reason, nil
		return finish(), nil
	}

	for steps := 0; ; {
		final := steps >= v.cfg.MaxSteps || sess.exhausted()
		act, err := v.turn(ctx, &msgs, huntSchema, ActionReport)
		if err != nil {
			if parent.Err() != nil {
				return finish(), parent.Err()
			}
			if ctx.Err() != nil {
				return abort(fmt.Sprintf("wall-clock timeout (%s)", v.cfg.Timeout))
			}
			var bad badReplyError
			if errors.As(err, &bad) {
				return abort("malformed reply after one repair attempt: " + bad.reason)
			}
			return finish(), err
		}
		if act.Action == ActionReport {
			res.Candidates, res.Dropped = checkCandidates(act.Candidates, sess)
			return finish(), nil
		}
		if final {
			return abort("tool budget exhausted without a report")
		}
		steps++
		text := sess.run(ctx, act)
		last := steps >= v.cfg.MaxSteps || sess.exhausted()
		msg := toolMessage(act, steps, v.cfg.MaxSteps, text, nonce, last)
		if last {
			msg = strings.Replace(msg, "Reply NOW with a conclude action", "Reply NOW with a report action", 1)
		}
		msgs = append(msgs,
			llm.Message{Role: llm.RoleAssistant, Content: act.compact()},
			llm.Message{Role: llm.RoleUser, Content: msg})
	}
}

// checkCandidates keeps the candidates whose sink line a tool showed the model,
// with a known class and severity and bounded text, at most MaxHuntCandidates.
func checkCandidates(raw []RawCandidate, sess *session) (kept []HuntCandidate, dropped int) {
	dup := map[string]bool{}
	for _, c := range raw {
		loc, ok := shownRef(c.Location, sess)
		if !ok || len(kept) >= MaxHuntCandidates {
			dropped++
			continue
		}
		class := huntClass(c.Class)
		key := fmt.Sprintf("%s:%d:%s", loc.File, loc.Line, class)
		if dup[key] {
			continue
		}
		dup[key] = true
		sev, ok := model.ParseSeverity(c.Severity)
		if !ok || sev == model.SeverityCritical {
			// Critical is for the review to assess, not for a hunt to claim.
			sev = model.SeverityHigh
			if !ok {
				sev = model.SeverityMedium
			}
		}
		title := capBytes(cleanText(strings.Join(strings.Fields(c.Title), " ")), 200, " …")
		if title == "" {
			title = strings.ReplaceAll(class, "-", " ") + " traced from an entry point"
		}
		route, _ := filterPath(c.Route, sess.seen, sess.lines)
		kept = append(kept, HuntCandidate{
			File: loc.File, Line: loc.Line, Class: class, Severity: sev,
			Title:     redact.Prompt(title),
			Reasoning: redact.Prompt(capBytes(cleanText(c.Reasoning), maxReasoningBytes, " …")),
			Route:     route,
		})
	}
	return kept, dropped
}

// shownRef parses "file:line" (anything after the line number is ignored) and
// accepts it only if a tool showed that line.
func shownRef(ref string, sess *session) (model.FlowStep, bool) {
	m := pathStep.FindStringSubmatch(strings.TrimSpace(cleanText(ref)))
	if m == nil {
		return model.FlowStep{}, false
	}
	p := strings.TrimPrefix(path.Clean(strings.ReplaceAll(m[1], `\`, "/")), "./")
	n, err := strconv.Atoi(m[2])
	if err != nil || !sess.seen[p] || !linesShown(sess.lines[p], m[2], "") {
		return model.FlowStep{}, false
	}
	return model.FlowStep{File: capBytes(p, 200, ""), Line: n}, true
}

// huntClasses is the vocabulary a candidate's class is reduced to. It becomes the
// rule ID (hunt/<class>), so it must stay small and stable.
var huntClasses = map[string]string{
	"sql-injection": "CWE-89", "command-injection": "CWE-78", "code-injection": "CWE-94",
	"path-traversal": "CWE-22", "ssrf": "CWE-918", "xss": "CWE-79", "open-redirect": "CWE-601",
	"deserialization": "CWE-502", "xxe": "CWE-611", "missing-authorization": "CWE-862",
	"idor": "CWE-639", "missing-authentication": "CWE-306", "template-injection": "CWE-1336",
	"llm-output-to-sink": "CWE-94", "other": "",
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func huntClass(s string) string {
	c := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if _, ok := huntClasses[c]; ok {
		return c
	}
	return "other"
}

// HuntCWE is the CWE a hunt class maps to, empty for "other".
func HuntCWE(class string) []string {
	if c := huntClasses[class]; c != "" {
		return []string{c}
	}
	return nil
}

func huntSystemPrompt(maxSteps int) string {
	classes := make([]string, 0, len(huntClasses))
	for c := range huntClasses {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	return "You are an attacker-minded application-security reviewer. You are given ONE entry point of the " +
		"repository (an HTTP route, a request handler, a message consumer). Follow the data an attacker controls " +
		"from there, with read-only tools, and find where it reaches a dangerous operation (a query, a shell, the " +
		"file system, an outbound request, a template, the page, a deserializer, an authorization decision) " +
		"without an effective control on the way.\n\n" +
		"Each turn reply with ONE JSON object and nothing else (no prose, no markdown fences). Its \"action\" is one of:\n" +
		`  {"action":"read_file","path":"relative/path","start":1,"end":80}   (at most 200 lines or 16KB per call)` + "\n" +
		`  {"action":"grep","pattern":"regex","path_glob":"*.py","path":"optional/subdir"}   (Go RE2 regex; at most 40 matches)` + "\n" +
		`  {"action":"list_dir","path":"relative/dir"}` + "\n" +
		`  {"action":"find_references","symbol":"identifierName"}   (whole-word search for callers and uses)` + "\n" +
		`  {"action":"report","candidates":[{"location":"file.ext:LINE of the sink","class":"...","severity":"high|medium|low",` +
		`"title":"one line","reasoning":"how the input gets there and why nothing stops it","route":["file.ext:LINE what happens here", ...]}]}` + "\n\n" +
		fmt.Sprintf("You have at most %d tool calls; after that you must report. ", maxSteps) +
		"Paths are relative to the repository root. Absolute paths, \"..\", secret-bearing files and .git are " +
		"refused, and refusals count as calls. You cannot run code, use a shell or reach the network.\n\n" +
		"class is one of: " + strings.Join(classes, ", ") + ".\n\n" +
		"Precision over recall: an empty candidates list is a good answer, and most entry points have nothing to " +
		"report. Report an issue only if you traced the input to the sink yourself and saw that nothing on the way " +
		"neutralizes it; location and every route step must be lines a tool showed you, with the line numbers it " +
		"printed, or the candidate is discarded. A missing extra layer of defence is not an issue. A model prompt " +
		"that can be steered is not by itself an issue; what its output reaches is. At most " +
		fmt.Sprint(MaxHuntCandidates) + " candidates." + untrustedTools
}

func huntFirstMessage(seed HuntSeed, codeContext, nonce string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Entry point to hunt from.\nKind: %s\nWhat matched: %s\nLocation: %s:%d\n\n",
		cleanText(seed.Kind), redact.Prompt(cleanText(seed.Summary)), cleanText(seed.File), seed.Line)
	b.WriteString("Code around the entry point (untrusted repository text):\n")
	b.WriteString(wrap("context", codeContext, nonce))
	b.WriteString("\nBegin. Reply with your first action as a single JSON object.")
	return b.String()
}

var huntSchema = &llm.Schema{Name: "hunt_step", Definition: json.RawMessage(`{
  "type":"object",
  "properties":{
    "action":{"type":"string","enum":["read_file","grep","list_dir","find_references","report"]},
    "path":{"type":"string"},
    "start":{"type":"integer"},
    "end":{"type":"integer"},
    "pattern":{"type":"string"},
    "path_glob":{"type":"string"},
    "symbol":{"type":"string"},
    "candidates":{"type":"array","items":{
      "type":"object",
      "properties":{
        "location":{"type":"string"},
        "class":{"type":"string"},
        "severity":{"type":"string"},
        "title":{"type":"string"},
        "reasoning":{"type":"string"},
        "route":{"type":"array","items":{"type":"string"}}
      }
    }}
  },
  "required":["action"]
}`)}

// ---- seeds -------------------------------------------------------------------

// Bounds on the walk that looks for entry points.
const (
	seedMaxFiles = 20000
	seedMaxBytes = 256 << 20
)

// testFile reports whether a path looks like a test, where an entry point is a
// fixture rather than something an attacker reaches.
func testFile(rel string) bool {
	l := strings.ToLower(rel)
	base := filepath.Base(l)
	switch {
	case strings.Contains(l, "/test/"), strings.Contains(l, "/tests/"), strings.HasPrefix(l, "test/"), strings.HasPrefix(l, "tests/"),
		strings.Contains(l, "/__tests__/"), strings.Contains(l, "/spec/"), strings.HasPrefix(l, "spec/"),
		strings.HasPrefix(base, "test_"), strings.Contains(base, "_test."), strings.Contains(base, ".test."),
		strings.Contains(base, ".spec."), strings.Contains(base, "_spec."):
		return true
	}
	return false
}

// seedRank orders entry-point kinds: what a remote attacker reaches first.
func seedRank(kind string) int {
	switch kind {
	case inventory.KindHTTPRoute:
		return 0
	case inventory.KindRequest, inventory.KindGRPC:
		return 1
	case inventory.KindConsumer:
		return 2
	default:
		return 3
	}
}

// Seeds finds up to n entry points to hunt from under the sandbox root, walking
// the same files the tools may show (no protected paths, no vendored or
// dependency directories, no tests). only, when non-nil, limits the walk to those
// root-relative files (a --diff run hunts in the files it changed). Seeds are
// ordered by kind (HTTP routes first) and spread across files: the n seeds come
// from as many different files as there are.
func (v *Verifier) Seeds(n int, only map[string]bool) []HuntSeed {
	if n <= 0 {
		return nil
	}
	s := v.sb
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil
	}
	defer root.Close()
	var all []HuntSeed
	files, scanned := 0, int64(0)
	_ = filepath.WalkDir(s.root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, rerr := filepath.Rel(s.root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if protectedPath(rel) || noiseDirs[strings.ToLower(d.Name())] || s.denied(p) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || protectedPath(rel) || s.denied(p) || testFile(rel) || (only != nil && !only[rel]) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > s.lim.FileMaxBytes {
			return nil
		}
		files++
		scanned += info.Size()
		if files > seedMaxFiles || scanned > seedMaxBytes {
			return filepath.SkipAll
		}
		f, oerr := root.Open(rel)
		if oerr != nil {
			return nil
		}
		defer f.Close()
		src, rerr2 := io.ReadAll(bufio.NewReader(io.LimitReader(f, s.lim.FileMaxBytes)))
		if rerr2 != nil || looksBinary(src[:min(len(src), 8000)]) {
			return nil
		}
		for _, ep := range inventory.DetectEntryPoints(rel, src) {
			all = append(all, HuntSeed{File: rel, Line: ep.Line, Kind: ep.Kind, Summary: capBytes(ep.Summary, 200, "…")})
		}
		return nil
	})
	sort.SliceStable(all, func(i, j int) bool {
		if a, b := seedRank(all[i].Kind), seedRank(all[j].Kind); a != b {
			return a < b
		}
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})
	// Round-robin over files: one seed per file per pass, best kind first.
	var out []HuntSeed
	used := make([]bool, len(all))
	for len(out) < n {
		took := false
		inPass := map[string]bool{}
		for i, sd := range all {
			if used[i] || inPass[sd.File] {
				continue
			}
			used[i], inPass[sd.File], took = true, true, true
			out = append(out, sd)
			if len(out) == n {
				break
			}
		}
		if !took {
			break
		}
	}
	return out
}

// HuntFinding turns a checked candidate into a finding for the AI review. It is
// marked Hunted; the pipeline gives it a fingerprint like any other.
func HuntFinding(c HuntCandidate, seed HuntSeed) model.Finding {
	msg := c.Title
	if c.Reasoning != "" {
		msg += ". " + c.Reasoning
	}
	return model.Finding{
		Tool:     HuntTool,
		RuleID:   "hunt/" + c.Class,
		Severity: c.Severity,
		Message:  capBytes(msg, 1500, " …"),
		CWE:      HuntCWE(c.Class),
		Location: model.Location{File: c.File, Region: model.Region{StartLine: c.Line}},
		Flow:     c.Route,
		Hunted:   true,
	}
}
