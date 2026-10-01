// Package eval measures whether Achilles's LLM triage layer actually works, and
// whether a change to it made things better or worse.
//
// Why this exists: DESIGN §8 promises metrics ("precision/recall of LLM triage vs
// human ground truth over time"), but until now every change to prompts, context,
// or model routing was argued rather than measured. A 12-finding bake-off was run
// once, ad hoc, and its corpus was never committed — so no result was reproducible
// and no regression could be caught.
//
// The harness has two modes, deliberately split by what they need:
//
//   - CONTEXT mode is hermetic. For each case it builds the prompt Achilles would
//     send and checks whether the deciding evidence (declared per case in the
//     corpus) is actually inside it. No API key, no network, no cost — so it runs
//     in CI and can gate. It answers "did we give the model what it needed?"
//   - VERDICT mode needs a real model. It runs the real triage→judge path and
//     scores the verdicts against the labels. It answers "did the model get the
//     right answer?"
//
// The distinction matters: context mode can prove the prompt improved while
// verdict mode still shows no gain. Both are worth knowing, and conflating them
// is how "it should be better" gets mistaken for "it is better".
package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"gopkg.in/yaml.v3"
)

// Label is the ground-truth answer for a case.
type Label string

const (
	// LabelTP marks a genuine issue the pipeline must not suppress.
	LabelTP Label = "tp"
	// LabelFP marks safe-but-flagged code the pipeline should suppress.
	LabelFP Label = "fp"
)

// FindingSpec is what the scanner reports for a case.
type FindingSpec struct {
	Tool     string   `yaml:"tool"`
	RuleID   string   `yaml:"ruleId"`
	CWE      []string `yaml:"cwe"`
	Severity string   `yaml:"severity"`
	Message  string   `yaml:"message"`
	Line     int      `yaml:"line"`
}

// Case is one labeled finding over one fixture file.
type Case struct {
	ID      string      `yaml:"id"`
	Fixture string      `yaml:"fixture"`
	Label   Label       `yaml:"label"`
	Why     string      `yaml:"why"`
	Finding FindingSpec `yaml:"finding"`
	// EvidenceLines are the lines a triager must see to decide correctly. Context
	// mode checks them against the prompt window; they are never sent to a model
	// as hints.
	EvidenceLines []int `yaml:"evidenceLines"`
}

// Corpus is a loaded, validated manifest.
type Corpus struct {
	Version int    `yaml:"version"`
	Cases   []Case `yaml:"cases"`

	// Root is the manifest's directory; fixtures resolve against it.
	Root string `yaml:"-"`
}

// LoadCorpus reads and validates a corpus manifest. Validation is strict on
// purpose: a corpus with a stale line number silently measures the wrong thing,
// which is worse than not measuring at all.
func LoadCorpus(path string) (Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, fmt.Errorf("read corpus: %w", err)
	}
	var c Corpus
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Corpus{}, fmt.Errorf("parse corpus %s: %w", path, err)
	}
	c.Root = filepath.Dir(path)
	if len(c.Cases) == 0 {
		return Corpus{}, fmt.Errorf("corpus %s has no cases", path)
	}
	if err := c.validate(); err != nil {
		return Corpus{}, fmt.Errorf("corpus %s: %w", path, err)
	}
	return c, nil
}

func (c Corpus) validate() error {
	seen := map[string]bool{}
	var problems []string
	for i, cs := range c.Cases {
		where := cs.ID
		if where == "" {
			where = fmt.Sprintf("case #%d", i+1)
		}
		if cs.ID == "" {
			problems = append(problems, where+": missing id")
		}
		if seen[cs.ID] {
			problems = append(problems, where+": duplicate id")
		}
		seen[cs.ID] = true

		switch cs.Label {
		case LabelTP, LabelFP:
		default:
			problems = append(problems, fmt.Sprintf("%s: label must be tp or fp, got %q", where, cs.Label))
		}
		if strings.TrimSpace(cs.Why) == "" {
			problems = append(problems, where+": missing why (a label nobody can review is not ground truth)")
		}
		if cs.Finding.Tool == "" || cs.Finding.RuleID == "" {
			problems = append(problems, where+": finding needs tool and ruleId")
		}

		// Line numbers are checked against the real file, so a fixture edit that
		// shifts lines fails loudly instead of scoring the wrong span.
		lines, err := cs.fixtureLineCount(c.Root)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", where, err))
			continue
		}
		if cs.Finding.Line < 1 || cs.Finding.Line > lines {
			problems = append(problems, fmt.Sprintf("%s: finding.line %d outside %s (%d lines)",
				where, cs.Finding.Line, cs.Fixture, lines))
		}
		if len(cs.EvidenceLines) == 0 {
			problems = append(problems, where+": needs at least one evidenceLine")
		}
		for _, l := range cs.EvidenceLines {
			if l < 1 || l > lines {
				problems = append(problems, fmt.Sprintf("%s: evidenceLine %d outside %s (%d lines)",
					where, l, cs.Fixture, lines))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d validation problem(s):\n  - %s", len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

// fixturePath resolves a case's fixture inside the corpus root and refuses
// anything that escapes it. A manifest is data, not code: without this a corpus
// could name "../../../../etc/passwd" and the harness would read it and paste it
// into a prompt. Contained here once, so every later reader is safe by
// construction.
func (cs Case) fixturePath(root string) (string, error) {
	if cs.Fixture == "" {
		return "", fmt.Errorf("missing fixture")
	}
	// Reject traversal explicitly rather than only neutralizing it. Clean("/"+p)
	// would silently rewrite "../../etc/passwd" to "/etc/passwd" and then fail
	// with a confusing "no such file"; saying what is actually wrong is better for
	// whoever is editing the corpus.
	if filepath.IsAbs(cs.Fixture) {
		return "", fmt.Errorf("fixture %q must be relative to the corpus directory", cs.Fixture)
	}
	for _, seg := range strings.Split(filepath.ToSlash(cs.Fixture), "/") {
		if seg == ".." {
			return "", fmt.Errorf("fixture %q escapes the corpus directory", cs.Fixture)
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve corpus root: %w", err)
	}
	full := filepath.Join(absRoot, filepath.Clean("/"+cs.Fixture))
	// Belt and braces: a symlink or an odd path could still land outside.
	if !strings.HasPrefix(full, absRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("fixture %q escapes the corpus directory", cs.Fixture)
	}
	return full, nil
}

// fixtureBody reads the fixture's contents, contained by fixturePath.
func (cs Case) fixtureBody(root string) (string, error) {
	path, err := cs.fixturePath(root)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- contained by fixturePath above
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (cs Case) fixtureLineCount(root string) (int, error) {
	path, err := cs.fixturePath(root)
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- contained by fixturePath above
	if err != nil {
		return 0, fmt.Errorf("read fixture: %w", err)
	}
	return len(strings.Split(string(data), "\n")), nil
}

// ToFinding converts a case into the Finding the triage layer consumes. The
// fixture path is made relative-to-root so the enricher resolves it the same way
// it resolves a real scan target's file.
func (cs Case) ToFinding() model.Finding {
	sev := model.Severity(strings.ToLower(cs.Finding.Severity))
	if sev.Rank() == 0 {
		sev = model.SeverityUnknown
	}
	loc := model.Location{
		File:   cs.Fixture,
		Region: model.Region{StartLine: cs.Finding.Line, EndLine: cs.Finding.Line},
	}
	return model.Finding{
		ID:          model.ComputeID(cs.Finding.Tool, cs.Finding.RuleID, loc),
		Tool:        cs.Finding.Tool,
		RuleID:      cs.Finding.RuleID,
		CWE:         cs.Finding.CWE,
		Message:     cs.Finding.Message,
		Location:    loc,
		Severity:    sev,
		Fingerprint: "eval:" + cs.ID,
	}
}

// Counts returns how many cases carry each label, which every report prints so a
// score can be read against the corpus balance.
func (c Corpus) Counts() (tp, fp int) {
	for _, cs := range c.Cases {
		switch cs.Label {
		case LabelTP:
			tp++
		case LabelFP:
			fp++
		}
	}
	return tp, fp
}

// SortedCases returns cases ordered by id, so every report and diff is stable.
func (c Corpus) SortedCases() []Case {
	out := make([]Case, len(c.Cases))
	copy(out, c.Cases)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
