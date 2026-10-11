// Package verifyfix checks a proposed fix by re-scanning it. The patch is applied
// to a throwaway copy of the scan target, the one scanner that reported the finding
// is run again over the copy, and the two results are compared: the finding must be
// gone and the scanner must not report anything new.
//
// That is all it proves. A clean re-scan does not show the patch is correct, or
// that the program still builds or behaves; see docs/verifying-fixes.md.
package verifyfix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/gitops"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
)

// Result is the outcome of one verification; it is stored on the Remediation.
type Result = model.FixVerification

// Status values, re-exported for callers that only import this package.
const (
	Verified      = model.FixVerified
	NotFixed      = model.FixNotFixed
	IntroducesNew = model.FixIntroducesNew
	PatchFailed   = model.FixPatchFailed
	Skipped       = model.FixSkipped
	Error         = model.FixError
)

// Default caps; see Options.
const (
	DefaultMaxCopyBytes = 200 << 20
	DefaultMaxCopyFiles = 50000
	DefaultMaxDiffBytes = 256 << 10
	DefaultMaxDiffFiles = 20
	DefaultLineWindow   = 10
	maxNewListed        = 20
)

// Lookup finds the scanner that reported a finding. *scanner.Registry satisfies it.
type Lookup interface {
	Get(id string) (scanner.Scanner, bool)
}

// Applier applies a unified diff inside dir. The default is `git apply`.
type Applier func(ctx context.Context, dir, diff string) error

// Options tunes a Verifier. Zero values select the defaults.
type Options struct {
	MaxCopyBytes int64 // largest target copied (default 200 MiB); over it the result is "skipped"
	MaxCopyFiles int   // most files copied (default 50000); over it the result is "skipped"
	MaxDiffBytes int   // largest diff accepted (default 256 KiB)
	MaxDiffFiles int   // most files one diff may touch (default 20)
	LineWindow   int   // +/- lines within which a same-rule finding counts as the original (default 10)

	// Languages is passed to the scanner as scanner.Target.Languages.
	Languages []string
	// Known are findings already reported by the main scan (any tool). They are
	// added to the "before" set so a finding the main scan filtered out is not
	// mistaken for one the patch introduced.
	Known []model.Finding
	// Apply overrides how a diff is applied (tests). Default: git apply.
	Apply Applier
	// TempDir is where the copy is made. Default: the system temp directory.
	TempDir string
}

func (o Options) withDefaults() Options {
	if o.MaxCopyBytes <= 0 {
		o.MaxCopyBytes = DefaultMaxCopyBytes
	}
	if o.MaxCopyFiles <= 0 {
		o.MaxCopyFiles = DefaultMaxCopyFiles
	}
	if o.MaxDiffBytes <= 0 {
		o.MaxDiffBytes = DefaultMaxDiffBytes
	}
	if o.MaxDiffFiles <= 0 {
		o.MaxDiffFiles = DefaultMaxDiffFiles
	}
	if o.LineWindow <= 0 {
		o.LineWindow = DefaultLineWindow
	}
	if o.Apply == nil {
		o.Apply = gitApply
	}
	return o
}

func gitApply(ctx context.Context, dir, diff string) error {
	return (&gitops.Repo{Dir: dir}).Apply(ctx, diff)
}

// Verifier verifies fixes against one scan target. It is safe for concurrent use;
// each tool's baseline (its findings on the unpatched target) is computed once.
type Verifier struct {
	scanners Lookup
	target   string
	opts     Options

	mu        sync.Mutex
	baselines map[string]*baseline
}

type baseline struct {
	once sync.Once
	fs   []model.Finding
	err  error
}

// New returns a Verifier for the scan target (an absolute path).
func New(scanners Lookup, target string, opts Options) *Verifier {
	return &Verifier{scanners: scanners, target: target, opts: opts.withDefaults(), baselines: map[string]*baseline{}}
}

// Verify applies diff to a temporary copy of the target and re-runs the scanner
// that reported f. It never returns an error: every outcome is a Result, and the
// temporary copy is always removed.
func (v *Verifier) Verify(ctx context.Context, f model.Finding, diff string) Result {
	if err := checkDiff(diff, v.opts.MaxDiffBytes, v.opts.MaxDiffFiles); err != nil {
		return Result{Status: PatchFailed, Detail: "diff rejected: " + err.Error()}
	}
	file := relTo(v.target, f.Location.File)
	// Scope comes before anything is copied or run: a diff that reaches outside the
	// finding's own file is never applied, not even to the throwaway copy.
	if err := checkScope(diff, file); err != nil {
		return Result{Status: PatchFailed, Detail: "diff rejected: " + err.Error()}
	}
	sc, ok := v.scanners.Get(f.Tool)
	if !ok {
		return Result{Status: Skipped, Detail: fmt.Sprintf("scanner %q is not available to re-run (shadow or unregistered tool)", f.Tool)}
	}
	if file != "" && inSkippedDir(file) {
		return Result{Status: Skipped, Detail: fmt.Sprintf("%s is in a directory excluded from the verification copy", file)}
	}

	tmp, err := os.MkdirTemp(v.opts.TempDir, "achilles-verifyfix-*")
	if err != nil {
		return Result{Status: Error, Detail: "create temp dir: " + err.Error()}
	}
	defer os.RemoveAll(tmp)

	if err := copyTree(v.target, tmp, v.opts.MaxCopyBytes, v.opts.MaxCopyFiles); err != nil {
		if isTooLarge(err) {
			return Result{Status: Skipped, Detail: "skipped: target too large to copy (" + err.Error() + ")"}
		}
		return Result{Status: Error, Detail: "copy target: " + err.Error()}
	}
	if err := v.opts.Apply(ctx, tmp, diff); err != nil {
		return Result{Status: PatchFailed, Detail: "patch does not apply cleanly: " + firstLine(err.Error())}
	}

	before, err := v.before(ctx, sc)
	if err != nil {
		return Result{Status: Error, Detail: "baseline scan: " + err.Error()}
	}
	after, err := run(ctx, sc, tmp, v.opts.Languages)
	if err != nil {
		return Result{Status: Error, Detail: "re-scan of patched copy: " + err.Error()}
	}
	return v.compare(f, file, before, after)
}

func (v *Verifier) compare(orig model.Finding, file string, before, after []model.Finding) Result {
	line := orig.Location.Region.StartLine
	for _, a := range after {
		if sameFile(a, file) && (a.Fingerprint == orig.Fingerprint && orig.Fingerprint != "" ||
			a.RuleID == orig.RuleID && within(a.Location.Region.StartLine, line, v.opts.LineWindow)) {
			return Result{Status: NotFixed, Detail: fmt.Sprintf("%s still reports %s at %s:%d after the patch", orig.Tool, a.RuleID, file, a.Location.Region.StartLine)}
		}
	}

	seenFP := map[string]bool{}
	seenKey := map[string]bool{}
	for _, b := range append(append([]model.Finding{}, before...), v.opts.Known...) {
		seenFP[b.Fingerprint] = true
		seenKey[ruleFileKey(b.RuleID, b.Location.File)] = true
	}
	var fresh []string
	for _, a := range after {
		if seenFP[a.Fingerprint] && a.Fingerprint != "" || seenKey[ruleFileKey(a.RuleID, a.Location.File)] {
			continue
		}
		fresh = append(fresh, fmt.Sprintf("%s %s:%d", a.RuleID, a.Location.File, a.Location.Region.StartLine))
	}
	if len(fresh) > 0 {
		sort.Strings(fresh)
		n := len(fresh)
		if n > maxNewListed {
			fresh = fresh[:maxNewListed]
		}
		return Result{Status: IntroducesNew, NewFindings: fresh,
			Detail: fmt.Sprintf("the finding is gone, but %s reports %d new finding(s) after the patch", orig.Tool, n)}
	}
	return Result{Status: Verified, Detail: fmt.Sprintf("%s no longer reports %s at %s and reports nothing new", orig.Tool, orig.RuleID, file)}
}

// before returns the tool's findings on the unpatched target, computed once per tool.
func (v *Verifier) before(ctx context.Context, sc scanner.Scanner) ([]model.Finding, error) {
	v.mu.Lock()
	b := v.baselines[sc.ID()]
	if b == nil {
		b = &baseline{}
		v.baselines[sc.ID()] = b
	}
	v.mu.Unlock()
	b.once.Do(func() { b.fs, b.err = run(ctx, sc, v.target, v.opts.Languages) })
	return b.fs, b.err
}

// run executes one scanner over root and returns its findings with file paths made
// relative to root, so findings from the original and the copy are comparable.
func run(ctx context.Context, sc scanner.Scanner, root string, langs []string) ([]model.Finding, error) {
	raw, err := sc.Run(ctx, scanner.Target{Path: root, Languages: langs})
	if err != nil {
		return nil, err
	}
	fs, err := normalize.Normalize(raw.Format, raw.Tool, raw.Data)
	if err != nil {
		return nil, fmt.Errorf("normalize %s output: %w", sc.ID(), err)
	}
	for i := range fs {
		fs[i].Location.File = relTo(root, fs[i].Location.File)
	}
	return fs, nil
}

// ----- matching helpers -----

func sameFile(f model.Finding, file string) bool { return f.Location.File == file }

func within(a, b, window int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= window
}

func ruleFileKey(rule, file string) string { return rule + "\x00" + file }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func isTooLarge(err error) bool { return errors.Is(err, errTooLarge) }

func inSkippedDir(rel string) bool {
	segs := strings.Split(rel, "/")
	for _, s := range segs[:len(segs)-1] {
		if skipDirs[s] {
			return true
		}
	}
	return false
}

// relTo returns file relative to root with forward slashes. A path already relative
// is cleaned; an absolute path outside root is returned cleaned but absolute (it
// will simply not match). Symlinked roots (macOS /tmp) are resolved too.
func relTo(root, file string) string {
	file = strings.TrimPrefix(file, "file://")
	if file == "" {
		return ""
	}
	if !filepath.IsAbs(file) {
		return path.Clean(filepath.ToSlash(file))
	}
	roots := []string{root}
	if real, err := filepath.EvalSymlinks(root); err == nil && real != root {
		roots = append(roots, real)
	}
	for _, r := range roots {
		if rel, err := filepath.Rel(r, file); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(file)
}
