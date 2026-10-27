// Package surface builds the attack-surface map of a codebase before it is
// scanned: where attacker-influenced input enters (entry points), where it can do
// damage (sinks), what guards it (controls), what is worth stealing (assets), and
// where the code talks to an LLM or exposes tools to one (AI surface). From those
// facts it scores each file, so the AI review and deep verification can spend a
// limited budget on the most exposed code first.
//
// Everything here is a line-level pattern match: no parsing, no cross-file
// resolution, no model. A fact is a HINT, never a proof. A file with no entry point
// may still be reachable (its handler is registered elsewhere), and a file with a
// control may still be unprotected on the flagged path. The map therefore only
// ever changes the ORDER of work; it never removes a finding, lowers a severity or
// argues for a dismissal.
//
// What leaves this package is bounded and carries no source text: a fact holds a
// kind, a class, a file, a line and a fixed summary (or an entry point's scrubbed
// route literal from internal/inventory).
package surface

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/deep"
	"github.com/Warzuponus/achilles/internal/inventory"
	"github.com/Warzuponus/achilles/internal/model"
)

// Version is the version of the plan document this build writes.
const Version = 1

// Fact kinds.
const (
	KindEntry   = "entry"   // attacker-influenced input enters here
	KindSink    = "sink"    // an operation that is dangerous with such input
	KindControl = "control" // a guard: authentication, validation, CSRF, rate limiting
	KindAsset   = "asset"   // credentials, personal data, session tokens
	KindAI      = "ai"      // LLM calls, tool definitions, MCP servers, vector stores
)

// Fact is one hint about one line of one file.
type Fact struct {
	Kind    string `json:"kind"`
	Class   string `json:"class"` // e.g. "sql", "exec", "http-route", "llm-sdk"
	File    string `json:"file"`  // slash-separated, relative to the target
	Line    int    `json:"line,omitempty"`
	Summary string `json:"summary"`
}

// Hotspot is a file's score and the reasons for it.
type Hotspot struct {
	File    string   `json:"file"`
	Score   float64  `json:"score"` // 0..1
	Reasons []string `json:"reasons"`
}

// Infra is a deployment or CI file, found by its name or the head of its content.
type Infra struct {
	File string `json:"file"`
	Kind string `json:"kind"` // dockerfile | compose | terraform | kubernetes | helm | cloudformation | arm | bicep | serverless | ci-workflow
}

// Summary counts the facts by kind.
type Summary struct {
	Entries  int `json:"entries"`
	Sinks    int `json:"sinks"`
	Controls int `json:"controls"`
	Assets   int `json:"assets"`
	AI       int `json:"ai"`
}

// Map is the attack-surface map of one target. It is also the scan plan written
// by --plan-out: later milestones add components and hypotheses.
type Map struct {
	Version   int    `json:"version"`
	Target    string `json:"target"` // the target's base name, never an absolute path
	FilesRead int    `json:"filesRead"`
	BytesRead int64  `json:"bytesRead"`
	// Truncated is set when the walk stopped at a bound: files past it have no
	// facts and score 0. Callers must say so; a quiet map is not a complete one.
	Truncated bool      `json:"truncated,omitempty"`
	Summary   Summary   `json:"summary"`
	Hotspots  []Hotspot `json:"hotspots"`
	AIFiles   []string  `json:"aiFiles,omitempty"`
	Infra     []Infra   `json:"infra,omitempty"`
	Facts     []Fact    `json:"facts"`
	// FactsDropped counts facts left out of Facts by MaxFacts (scores still count them).
	FactsDropped int `json:"factsDropped,omitempty"`
	// NetworkEntries counts network entry points (routes, request input, gRPC,
	// consumers) outside tests and out-of-scope paths.
	NetworkEntries int `json:"networkEntries"`
	// Languages counts files per language by extension: all of them, and those
	// outside tests and out-of-scope paths. Build output is not counted.
	Languages map[string]LangCount `json:"languages"`
	// Markers are project files that some scanners need before they can run
	// (go.mod, psalm.xml, a .NET project, compiled JVM bytecode, a Rails app).
	Markers []string `json:"markers,omitempty"`
	// Context is the threat-context file that shaped this map, if any.
	Context *Context `json:"context,omitempty"`
	// Depth is how deeply the target should be scanned, and why.
	Depth Depth `json:"depth"`
	// ToolPlan is the choice of scanners made from this map (filled in by the
	// caller, which knows the tool registry).
	ToolPlan *model.ToolPlan `json:"toolPlan,omitempty"`

	score   map[string]float64
	markers map[string]bool
}

// LangCount is a language's file count.
type LangCount struct {
	Files   int `json:"files"`
	InScope int `json:"inScope"`
}

// Marker names.
const (
	MarkerGoMod     = "go.mod"
	MarkerPsalm     = "psalm.xml"
	MarkerDotNet    = "dotnet-project"
	MarkerBytecode  = "jvm-bytecode"
	MarkerRails     = "rails-app"
	MarkerIaC       = "iac"
	MarkerWorkflows = "github-workflows"
)

// HasMarker reports whether the walk found a marker.
func (m *Map) HasMarker(name string) bool {
	return m != nil && m.markers[name]
}

// Options bounds the walk. Zero values take the defaults.
type Options struct {
	MaxFiles     int   // files read; default 20000
	MaxBytes     int64 // bytes read in total; default 256 MiB
	MaxFileBytes int64 // bytes read per file; default 1 MiB
	MaxFacts     int   // facts kept in the document; default 5000
	MaxHotspots  int   // hotspots kept in the document; default 500
	MaxEntries   int   // directory entries visited; default 200000

	// Context is the repository's threat-context file (LoadContext), or nil.
	Context *Context
}

func (o Options) withDefaults() Options {
	if o.MaxFiles <= 0 {
		o.MaxFiles = 20000
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 256 << 20
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 1 << 20
	}
	if o.MaxFacts <= 0 {
		o.MaxFacts = 5000
	}
	if o.MaxHotspots <= 0 {
		o.MaxHotspots = 500
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 200000
	}
	return o
}

// skipDirs are trees that are not the project's own code: vendored dependencies
// and caches. Protected directories (.git, .achilles, .ssh ...) are skipped
// through deep.ProtectedPath.
var skipDirs = map[string]bool{
	"bower_components": true, "third_party": true, "third-party": true,
}

// buildDirs hold build output. Nothing in them is read or scored, but they are
// walked for compiled bytecode, which some scanners need.
var buildDirs = map[string]bool{
	"dist": true, "build": true, "target": true, "out": true, "bin": true, "obj": true,
}

// Build walks root and returns its attack-surface map. Unreadable files are
// skipped; only a root that cannot be walked at all is an error.
func Build(root string, opt Options) (*Map, error) {
	opt = opt.withDefaults()
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("surface: %s is not a directory", root)
	}
	rootFS, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	defer rootFS.Close()

	m := &Map{Version: Version, Target: filepath.Base(abs), Context: opt.Context,
		Languages: map[string]LangCount{}, score: map[string]float64{}, markers: map[string]bool{}}
	var facts []Fact
	var read []string
	var outOfScope []string
	if opt.Context != nil {
		outOfScope = opt.Context.OutOfScope
	}
	entries := 0
	inBuild := ""
	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if d != nil && d.IsDir() && p != abs {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow a link out of the target
		}
		rel, rerr := filepath.Rel(abs, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entries++; entries > opt.MaxEntries {
			m.Truncated = true
			return filepath.SkipAll
		}
		if inBuild != "" && !strings.HasPrefix(rel, inBuild+"/") {
			inBuild = ""
		}
		if d.IsDir() {
			if deep.ProtectedPath(rel) || deep.NoiseDir(d.Name()) || skipDirs[strings.ToLower(d.Name())] {
				return fs.SkipDir
			}
			if inBuild == "" && buildDirs[strings.ToLower(d.Name())] {
				inBuild = rel
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if inBuild != "" {
			if ext := strings.ToLower(path.Ext(rel)); ext == ".class" || ext == ".jar" || ext == ".war" {
				m.markers[MarkerBytecode] = true
			}
			return nil
		}
		scoped := !testOnly(rel) && !matchAny(outOfScope, rel)
		if l := countLang(rel); l != "" {
			c := m.Languages[l]
			c.Files++
			if scoped {
				c.InScope++
			}
			m.Languages[l] = c
		}
		if scoped {
			m.noteMarker(rel)
		}
		if deep.ProtectedPath(rel) {
			// A credential file is an asset by its name alone. It is never opened.
			facts = append(facts, Fact{Kind: KindAsset, Class: "credential-file", File: rel, Summary: "credential file (not read)"})
			return nil
		}
		if k := infraKind(rel); k != "" {
			m.Infra = append(m.Infra, Infra{File: rel, Kind: k})
		}
		lang := langOf(rel)
		sniff := lang == "" && sniffInfra(rel)
		if lang == "" && !sniff {
			return nil
		}
		if m.FilesRead >= opt.MaxFiles || m.BytesRead >= opt.MaxBytes {
			m.Truncated = true
			return filepath.SkipAll
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		limit := min(fi.Size(), opt.MaxFileBytes)
		if sniff {
			limit = min(limit, 64<<10) // the kind of a config file shows in its head
		}
		src, rerr2 := readBounded(rootFS, rel, limit)
		if rerr2 != nil || bytes.IndexByte(src[:min(len(src), 8000)], 0) >= 0 {
			return nil
		}
		m.FilesRead++
		m.BytesRead += int64(len(src))
		if lang == "" {
			if k := infraByContent(rel, src); k != "" && !hasInfra(m.Infra, rel) {
				m.Infra = append(m.Infra, Infra{File: rel, Kind: k})
			}
			return nil
		}
		fileFacts := scanFile(rel, lang, src)
		if scoped {
			for _, f := range fileFacts {
				if f.Kind == KindEntry && f.Class != inventory.KindCLI {
					m.NetworkEntries++
				}
			}
		}
		read = append(read, rel)
		facts = append(facts, fileFacts...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	for _, i := range m.Infra {
		m.markers[MarkerIaC] = m.markers[MarkerIaC] || i.Kind != "ci-workflow"
		if i.Kind == "ci-workflow" && strings.Contains("/"+i.File, "/.github/workflows/") {
			m.markers[MarkerWorkflows] = true
		}
	}
	m.finish(facts, read, opt)
	m.Depth = DecideDepth(opt.Context, m)
	return m, nil
}

// noteMarker records the project files some scanners need.
func (m *Map) noteMarker(rel string) {
	base := strings.ToLower(path.Base(rel))
	switch {
	case base == "go.mod":
		m.markers[MarkerGoMod] = true
	case rel == "psalm.xml":
		m.markers[MarkerPsalm] = true // Achilles runs Psalm with the root's psalm.xml
	case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".vbproj") || strings.HasSuffix(base, ".sln"):
		m.markers[MarkerDotNet] = true
	case strings.HasSuffix(rel, "config/routes.rb") || strings.HasSuffix(rel, "config/application.rb"):
		m.markers[MarkerRails] = true
	}
}

func readBounded(r *os.Root, rel string, n int64) ([]byte, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(bufio.NewReader(io.LimitReader(f, n)))
}

func hasInfra(in []Infra, file string) bool {
	for _, i := range in {
		if i.File == file {
			return true
		}
	}
	return false
}

// finish scores the files and fills the document fields.
func (m *Map) finish(facts []Fact, read []string, opt Options) {
	byFile := map[string][]Fact{}
	for _, f := range facts {
		byFile[f.File] = append(byFile[f.File], f)
		switch f.Kind {
		case KindEntry:
			m.Summary.Entries++
		case KindSink:
			m.Summary.Sinks++
		case KindControl:
			m.Summary.Controls++
		case KindAsset:
			m.Summary.Assets++
		case KindAI:
			m.Summary.AI++
		}
	}
	var crown, outOfScope []string
	if opt.Context != nil {
		crown, outOfScope = opt.Context.CrownJewels, opt.Context.OutOfScope
	}
	files := map[string]bool{}
	for f := range byFile {
		files[f] = true
	}
	for _, f := range read {
		if matchAny(crown, f) {
			files[f] = true // a crown jewel ranks first even with no hint in it
		}
	}
	for file := range files {
		fs := byFile[file]
		score, reasons := scoreFile(file, fs)
		if matchAny(crown, file) {
			score = min(score+0.3, 1)
			reasons = append(reasons, "crown jewel (threat context)")
		}
		if matchAny(outOfScope, file) {
			score *= 0.25
			reasons = append(reasons, "out of scope (threat context, scored down)")
		}
		score = float64(int(score*100+0.5)) / 100
		if score <= 0 {
			continue
		}
		m.score[file] = score
		m.Hotspots = append(m.Hotspots, Hotspot{File: file, Score: score, Reasons: reasons})
		for _, f := range fs {
			if f.Kind == KindAI {
				m.AIFiles = append(m.AIFiles, file)
				break
			}
		}
	}
	sort.Slice(m.Hotspots, func(i, j int) bool {
		if m.Hotspots[i].Score != m.Hotspots[j].Score {
			return m.Hotspots[i].Score > m.Hotspots[j].Score
		}
		return m.Hotspots[i].File < m.Hotspots[j].File
	})
	if len(m.Hotspots) > opt.MaxHotspots {
		m.Hotspots = m.Hotspots[:opt.MaxHotspots]
	}
	sort.Strings(m.AIFiles)
	sort.Slice(m.Infra, func(i, j int) bool { return m.Infra[i].File < m.Infra[j].File })
	sort.SliceStable(facts, func(i, j int) bool {
		if facts[i].File != facts[j].File {
			return facts[i].File < facts[j].File
		}
		return facts[i].Line < facts[j].Line
	})
	if len(facts) > opt.MaxFacts {
		m.FactsDropped = len(facts) - opt.MaxFacts
		facts = facts[:opt.MaxFacts]
	}
	m.Facts = facts
	if m.Facts == nil {
		m.Facts = []Fact{}
	}
	if m.Hotspots == nil {
		m.Hotspots = []Hotspot{}
	}
	for k := range m.markers {
		m.Markers = append(m.Markers, k)
	}
	sort.Strings(m.Markers)
}

// Score returns a file's hotspot score (0 when it has none or is unknown). The
// path may be relative to the target in either separator style, with or without
// a leading "./".
func (m *Map) Score(file string) float64 {
	if m == nil || file == "" {
		return 0
	}
	return m.score[normalize(file)]
}

// FindingScore is Score for the file a finding is in.
func (m *Map) FindingScore(f *model.Finding) float64 {
	return m.Score(f.Location.File)
}

func normalize(file string) string {
	p := path.Clean(filepath.ToSlash(file))
	return strings.TrimPrefix(p, "./")
}

// Weight is how much a file's exposure raises a finding's priority. With 0.5 a
// medium finding in the most exposed file (3 x 1.5 = 4.5) is reviewed before a
// high one in a file with no surface (4), and a critical one is never overtaken
// by anything below high.
const Weight = 0.5

// Risk is the review priority of a finding of this severity in a file with this
// hotspot score. With score 0 it is the severity rank, so ordering by Risk with
// no map is ordering by severity.
func Risk(sev model.Severity, score float64) float64 {
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return float64(sev.Rank()) * (1 + Weight*score)
}

// Priority returns the risk of a finding under this map; a nil map gives the
// severity rank.
func (m *Map) Priority(f *model.Finding) float64 {
	return Risk(f.Severity, m.FindingScore(f))
}

// scoreFile turns a file's facts into a score in 0..1 and the reasons for it.
//
// The weights are a starting point, chosen so that the order reads the way a
// reviewer would triage by hand: network input reaching a dangerous operation in
// the same file first, with no guard in sight ahead of one with a guard; then
// files that only take input or only hold a sink; tests last.
func scoreFile(file string, facts []Fact) (float64, []string) {
	var netEntry, cliEntry, controls, assets, ai int
	sinkClasses := map[string]bool{}
	for _, f := range facts {
		switch f.Kind {
		case KindEntry:
			if f.Class == inventory.KindCLI {
				cliEntry++
			} else {
				netEntry++
			}
		case KindSink:
			sinkClasses[f.Class] = true
		case KindControl:
			controls++
		case KindAsset:
			if f.Class != "credential-file" {
				assets++
			}
		case KindAI:
			ai++
		}
	}
	var score float64
	var reasons []string
	switch {
	case netEntry > 0:
		score += 0.45
		reasons = append(reasons, "takes network input")
	case cliEntry > 0:
		score += 0.15
		reasons = append(reasons, "takes command-line or local input")
	}
	if n := len(sinkClasses); n > 0 {
		score += 0.25 + 0.05*float64(min(n-1, 2))
		reasons = append(reasons, "dangerous operation: "+strings.Join(sortedKeys(sinkClasses), ", "))
	}
	if netEntry > 0 && len(sinkClasses) > 0 {
		score += 0.1
		reasons = append(reasons, "input and dangerous operation in the same file")
		if controls == 0 {
			score += 0.1
			reasons = append(reasons, "no guard seen in this file")
		}
	}
	if assets > 0 {
		score += 0.1
		reasons = append(reasons, "handles credentials, personal data or sessions")
	}
	if ai > 0 {
		score += 0.1
		reasons = append(reasons, "calls an LLM or exposes tools to one")
	}
	if score > 1 {
		score = 1
	}
	if score > 0 && testOnly(file) {
		score *= 0.25
		reasons = append(reasons, "test file (scored down)")
	}
	// Two decimals: the document is read by people, and ties should look like ties.
	score = float64(int(score*100+0.5)) / 100
	return score, reasons
}

// testOnly reports test files and Go-style testdata trees: code that is never
// deployed, where an entry point or a sink is a fixture.
func testOnly(file string) bool {
	l := strings.ToLower(file)
	return deep.TestFile(file) || strings.HasPrefix(l, "testdata/") || strings.Contains(l, "/testdata/")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
