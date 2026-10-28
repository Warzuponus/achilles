package surface

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContextFiles are the names the threat-context file may have, relative to the
// target root.
var ContextFiles = []string{".achilles/threat-context.yaml", ".achilles/threat-context.yml"}

// maxContextBytes bounds the file. A real one is a few hundred bytes.
const maxContextBytes = 64 << 10

// Context is what the people who own the code say about it: the answers to the
// five questions that pick how deeply it is scanned (taken from the OWASP MAESTRO
// playbook's depth decision tree), the paths that matter most, and the paths that
// are not shipped.
//
// It is committed with the code, so a change under review can edit it. It can
// therefore only shape the scan of that code: reorder the review, skip a scanner
// whose languages appear only in out-of-scope paths, and add an opt-in scanner the
// operator has installed. It never turns on a model, a network call or an output,
// and whatever it changed is named on stderr and in the reports.
type Context struct {
	BusinessCritical *bool `yaml:"businessCritical" json:"businessCritical,omitempty"`
	ConfidentialData *bool `yaml:"confidentialData" json:"confidentialData,omitempty"`
	ExternallyFacing *bool `yaml:"externallyFacing" json:"externallyFacing,omitempty"`
	Autonomous       *bool `yaml:"autonomous" json:"autonomous,omitempty"`
	MultiAgent       *bool `yaml:"multiAgent" json:"multiAgent,omitempty"`

	// CrownJewels are paths whose compromise matters most: they rank first in
	// the review order.
	CrownJewels []string `yaml:"crownJewels" json:"crownJewels,omitempty"`
	// OutOfScope are paths that are never deployed (tooling, examples, fixtures):
	// they rank last, and a scanner whose languages appear only there is skipped.
	// Findings in them are still reported; use the `exclude` setting to drop them.
	OutOfScope []string `yaml:"outOfScope" json:"outOfScope,omitempty"`

	// File is the path the context was read from, relative to the target.
	File string `yaml:"-" json:"file"`
}

// LoadContext reads the target's threat-context file. It returns nil and no
// error when there is none. An unknown key, a bad value or a bad pattern is an
// error: a misspelled question that silently counted as "unknown" would change
// the scan without anyone noticing.
func LoadContext(root string) (*Context, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, name := range ContextFiles {
		f, err := r.Open(filepath.FromSlash(name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		data, err := io.ReadAll(io.LimitReader(f, maxContextBytes+1))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(data) > maxContextBytes {
			return nil, fmt.Errorf("%s: larger than %d KiB; a threat context is a few lines", name, maxContextBytes>>10)
		}
		c, err := ParseContext(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		c.File = name
		return c, nil
	}
	return nil, nil
}

// ParseContext decodes a threat-context document.
func ParseContext(data []byte) (*Context, error) {
	c := &Context{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for _, list := range [][]string{c.CrownJewels, c.OutOfScope} {
		for _, p := range list {
			if err := checkPattern(p); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func checkPattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("empty path pattern")
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return fmt.Errorf("path pattern %q: use a path relative to the repository root, with no .. segment", p)
	}
	if _, err := path.Match(strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/"), ""); err != nil {
		return fmt.Errorf("path pattern %q: %v", p, err)
	}
	return nil
}

// matchAny reports whether a slash-separated relative path matches one of the
// patterns. "dir/" and "dir/**" match everything under dir; a pattern with no
// slash matches a file name or a directory name anywhere ("fixtures"); anything
// else is matched against the whole path with path.Match ("cmd/*/main.go").
func matchAny(patterns []string, rel string) bool {
	for _, p := range patterns {
		if matchOne(p, rel) {
			return true
		}
	}
	return false
}

func matchOne(p, rel string) bool {
	if dir, ok := strings.CutSuffix(p, "/**"); ok {
		p = dir + "/"
	}
	if dir, ok := strings.CutSuffix(p, "/"); ok {
		if ok, _ := path.Match(dir, rel); ok {
			return true
		}
		// The directory itself may be a glob ("services/*/internal/").
		segs := strings.Split(rel, "/")
		n := strings.Count(dir, "/") + 1
		for i := n; i < len(segs); i++ {
			if ok, _ := path.Match(dir, strings.Join(segs[:i], "/")); ok {
				return true
			}
		}
		return false
	}
	if !strings.Contains(p, "/") {
		for _, seg := range strings.Split(rel, "/") {
			if ok, _ := path.Match(p, seg); ok {
				return true
			}
		}
		return false
	}
	ok, _ := path.Match(p, rel)
	return ok
}

// Depth levels, after the MAESTRO playbook's decision tree.
const (
	DepthLightweight = "lightweight"
	DepthStandard    = "standard"
	DepthFull        = "full"
)

// Answer is one of the five depth questions, and where its answer came from.
type Answer struct {
	Question string `json:"question"`
	Value    string `json:"value"`  // yes | no | unknown
	Source   string `json:"source"` // context | inferred | none
}

// Depth is how deeply the target should be scanned, and why.
type Depth struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
	Answers []Answer `json:"answers"`
}

// DecideDepth applies the decision tree: business-critical or confidential data
// means full; externally facing, autonomous or multi-agent means standard;
// lightweight only when all five are a definite no. An unknown answer is never
// read as "no", so a target with no context file is at least standard.
//
// Only "externally facing" is ever inferred, and only towards yes: network entry
// points outside tests and out-of-scope paths are evidence that it is. Nothing in
// the code can prove a system is not business-critical.
func DecideDepth(c *Context, m *Map) Depth {
	if c == nil {
		c = &Context{}
	}
	ans := func(q string, v *bool) Answer {
		switch {
		case v == nil:
			return Answer{Question: q, Value: "unknown", Source: "none"}
		case *v:
			return Answer{Question: q, Value: "yes", Source: "context"}
		}
		return Answer{Question: q, Value: "no", Source: "context"}
	}
	as := []Answer{
		ans("businessCritical", c.BusinessCritical),
		ans("confidentialData", c.ConfidentialData),
		ans("externallyFacing", c.ExternallyFacing),
		ans("autonomous", c.Autonomous),
		ans("multiAgent", c.MultiAgent),
	}
	if as[2].Source == "none" && m != nil && m.NetworkEntries > 0 {
		as[2] = Answer{Question: "externallyFacing", Value: "yes", Source: "inferred"}
	}
	yes := func(i int) bool { return as[i].Value == "yes" }
	d := Depth{Answers: as}
	switch {
	case yes(0) || yes(1):
		d.Level = DepthFull
		for _, i := range []int{0, 1} {
			if yes(i) {
				d.Reasons = append(d.Reasons, describe(as[i]))
			}
		}
	case yes(2) || yes(3) || yes(4):
		d.Level = DepthStandard
		for _, i := range []int{2, 3, 4} {
			if yes(i) {
				d.Reasons = append(d.Reasons, describe(as[i]))
			}
		}
	default:
		unknown := 0
		for _, a := range as {
			if a.Value == "unknown" {
				unknown++
			}
		}
		if unknown == 0 {
			d.Level = DepthLightweight
			d.Reasons = []string{"the context file answers no to all five questions"}
		} else {
			d.Level = DepthStandard
			d.Reasons = []string{fmt.Sprintf("%d of 5 depth questions unanswered; answer them in %s", unknown, ContextFiles[0])}
		}
	}
	return d
}

func describe(a Answer) string {
	s := a.Question + " = " + a.Value
	if a.Source == "inferred" {
		s += " (inferred from network entry points)"
	} else {
		s += " (context file)"
	}
	return s
}

// ContextTemplate is the commented file `achilles init` writes.
const ContextTemplate = `# What the owners of this code say about it. Achilles reads it before scanning to
# decide how deeply to scan and which code to review first. Written by
# ` + "`achilles init`" + `; see docs/surface-map.md#the-threat-context-file
#
# The five questions follow the OWASP MAESTRO playbook's depth decision tree.
# Answer true or false; leave a question out if you do not know. An unanswered
# question is never read as "no".

# businessCritical: false   # would an outage or a compromise hurt the business or someone's safety?
# confidentialData: false   # does it store or process confidential or regulated data?
# externallyFacing: true    # can people outside the organisation reach it?
# autonomous: false         # does it act without a person approving each step (agents, jobs)?
# multiAgent: false         # do several AI agents work together in it?

# Paths whose compromise matters most. Findings there are reviewed first.
# crownJewels: [internal/auth/, api/admin/]

# Paths that are never deployed (tooling, examples, fixtures). Findings there are
# still reported, but reviewed last, and a scanner whose languages appear only
# here is skipped. To drop findings altogether, use exclude in .achilles.yaml.
# outOfScope: [examples/, scripts/]
`
