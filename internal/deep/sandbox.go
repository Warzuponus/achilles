// Package deep is the bounded, read-only, opt-in "deep verification" pass: for the
// few findings that matter most, the model may look at other files in the scanned
// repository (callers, sanitizers, middleware, config) before it decides whether a
// finding is real. DESIGN.md §7 rejects open-ended agent loops; this is the
// opposite of one. Every limit is a hard cap, there is no shell, no network and no
// write, and everything a tool returns is treated as untrusted text.
//
// The tool sandbox in this file is the security-critical part. Its rules:
//
//   - Every path is relative to the scan root. Absolute paths, "..", NUL bytes and
//     drive letters are refused. Symlinks are resolved (EvalSymlinks) and the
//     result must still be inside the root; directory walks never follow a symlink.
//   - Secret-bearing and internal paths are refused by name, both before and after
//     symlink resolution: .git, .achilles, vault files, .env*, *.pem, *.key,
//     id_rsa*, *.p12, .netrc, credentials files, terraform state and tfvars, ...
//   - Refusals are returned to the model as "access denied" text, never as errors,
//     so a hostile repo cannot use them to crash or stall the run.
//   - Output is capped per call, and every line goes through redact.Prompt (with a
//     line-preserving private-key mask) before the model sees it. Searches match
//     against the REDACTED line, so a regex cannot be used as an oracle for the
//     masked characters.
//   - Regular expressions are Go RE2 (linear time), length-limited, and compiled
//     under a timeout; searches are capped in matches, files visited and bytes read.
package deep

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Warzuponus/achilles/internal/redact"
)

// Limits are the per-call caps on what a tool may return or read. A zero field
// takes its default (see DefaultLimits).
type Limits struct {
	ReadMaxLines     int   // read_file: most lines per call
	ReadMaxBytes     int   // read_file: most output bytes per call
	CallMaxBytes     int   // every tool: most output bytes per call
	LineMaxBytes     int   // longest line shown; longer ones are cut
	GrepMaxMatches   int   // grep / find_references: most matches returned
	GrepMaxFiles     int   // grep: most files opened per call
	GrepMaxScanBytes int64 // grep: most bytes read per call
	FileMaxBytes     int64 // largest file that is read or searched
	ListMaxEntries   int   // list_dir: most entries returned
	PatternMaxLen    int   // longest regular expression accepted
	CompileTimeout   time.Duration
}

// DefaultLimits returns the caps used when a Limits field is left zero.
func DefaultLimits() Limits {
	return Limits{
		ReadMaxLines: 200, ReadMaxBytes: 16 << 10, CallMaxBytes: 16 << 10, LineMaxBytes: 240,
		GrepMaxMatches: 40, GrepMaxFiles: 3000, GrepMaxScanBytes: 16 << 20, FileMaxBytes: 1 << 20,
		ListMaxEntries: 100, PatternMaxLen: 200, CompileTimeout: 2 * time.Second,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.ReadMaxLines <= 0 {
		l.ReadMaxLines = d.ReadMaxLines
	}
	if l.ReadMaxBytes <= 0 {
		l.ReadMaxBytes = d.ReadMaxBytes
	}
	if l.CallMaxBytes <= 0 {
		l.CallMaxBytes = d.CallMaxBytes
	}
	if l.LineMaxBytes <= 0 {
		l.LineMaxBytes = d.LineMaxBytes
	}
	if l.GrepMaxMatches <= 0 {
		l.GrepMaxMatches = d.GrepMaxMatches
	}
	if l.GrepMaxFiles <= 0 {
		l.GrepMaxFiles = d.GrepMaxFiles
	}
	if l.GrepMaxScanBytes <= 0 {
		l.GrepMaxScanBytes = d.GrepMaxScanBytes
	}
	if l.FileMaxBytes <= 0 {
		l.FileMaxBytes = d.FileMaxBytes
	}
	if l.ListMaxEntries <= 0 {
		l.ListMaxEntries = d.ListMaxEntries
	}
	if l.PatternMaxLen <= 0 {
		l.PatternMaxLen = d.PatternMaxLen
	}
	if l.CompileTimeout <= 0 {
		l.CompileTimeout = d.CompileTimeout
	}
	return l
}

// Result is what a tool returns: text for the model (already redacted and capped)
// and the root-relative paths whose content it showed (used to check evidence).
type Result struct {
	Text   string
	Paths  []string
	Denied bool // the request was refused by the sandbox

	// Lines are the source lines the text shows, in the order they appear, one per
	// line of Text after the first header lines. Evidence the model cites has to
	// point at one of these: citing a file is not enough, or a model could read
	// one line of auth.go and then cite auth.go:999 as the sanitizer.
	Lines  []Shown
	header int // lines of Text before the first entry of Lines
}

// Shown is one source line that was put in front of the model.
type Shown struct {
	Path string
	Line int
}

// shownIn returns the entries of Lines that are still in text once text has been
// cut down from r.Text (by a byte budget): only lines the model actually received
// count as shown. A line cut off partway is not counted.
func (r Result) shownIn(text string) []Shown {
	if len(r.Lines) == 0 {
		return nil
	}
	if text == r.Text {
		return r.Lines
	}
	if !strings.HasPrefix(r.Text, text) {
		// Not a prefix: the cut appended a notice. Compare up to the common part.
		n := 0
		for n < len(text) && n < len(r.Text) && text[n] == r.Text[n] {
			n++
		}
		text = text[:n]
	}
	complete := strings.Count(text, "\n") - r.header
	if complete <= 0 {
		return nil
	}
	if complete > len(r.Lines) {
		complete = len(r.Lines)
	}
	return r.Lines[:complete]
}

// Sandbox runs the read-only tools against one directory tree. It is immutable
// after construction and safe for concurrent use.
type Sandbox struct {
	root string   // absolute, symlink-resolved
	deny []string // extra absolute, symlink-resolved paths that are never shown
	lim  Limits
}

// NewSandbox confines the tools to root. denyPaths are additional files or
// directories (for example the Evidence Vault file) that must never be shown, even
// when they live inside root.
func NewSandbox(root string, lim Limits, denyPaths ...string) (*Sandbox, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("deep: scan root: %w", err)
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("deep: scan root %q is not a directory", root)
	}
	s := &Sandbox{root: real, lim: lim.withDefaults()}
	for _, p := range denyPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		a, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(a); err == nil {
			a = r
		}
		s.deny = append(s.deny, a)
	}
	return s, nil
}

// Root returns the resolved scan root.
func (s *Sandbox) Root() string { return s.root }

// Run executes one tool action. Anything that is not a tool action returns a
// refusal; Run never returns an error and never panics on hostile input.
func (s *Sandbox) Run(ctx context.Context, a Action) Result {
	var r Result
	switch a.Action {
	case ActionReadFile:
		r = s.ReadFile(a.Path, a.Start.Int(), a.End.Int())
	case ActionGrep:
		r = s.Grep(ctx, a.Pattern, a.PathGlob, a.Path)
	case ActionListDir:
		r = s.ListDir(a.Path)
	case ActionFindReferences:
		r = s.FindReferences(ctx, a.Symbol, a.PathGlob)
	default:
		r = Result{Text: fmt.Sprintf("unknown tool %q: use read_file, grep, list_dir, find_references or conclude", a.Action)}
	}
	r.Text = s.finish(r.Text)
	return r
}

// finish is the last gate on every byte shown to the model: control and format
// characters are stripped, credentials are masked a second time, and the size cap
// is enforced.
func (s *Sandbox) finish(text string) string {
	text = redact.Prompt(cleanText(text))
	return capBytes(text, s.lim.CallMaxBytes, "\n[output truncated at the per-call limit]")
}

// ---- path policy -----------------------------------------------------------

var driveLetter = regexp.MustCompile(`^[A-Za-z]:`)

const maxPathLen = 512

// refusal is returned for a path the sandbox will not touch.
type refusal struct{ msg string }

func (r refusal) Error() string { return r.msg }

var errNotFound = errors.New("not found")

// Directories that are never entered or shown.
var protectedDirs = map[string]bool{
	".git": true, ".achilles": true, ".ssh": true, ".aws": true, ".gnupg": true,
	".kube": true, ".docker": true, ".terraform": true,
}

// Directories a search skips for being dependency or cache trees, not because
// they are secret.
var noiseDirs = map[string]bool{
	"node_modules": true, "vendor": true, "__pycache__": true, ".venv": true, "venv": true,
	".mypy_cache": true, ".pytest_cache": true, ".tox": true,
}

var secretSuffixes = []string{
	".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".p8", ".ppk", ".gpg", ".kdbx",
	".tfstate", ".tfvars", ".tfvars.json", ".tfstate.backup", ".secret", ".secrets", ".kubeconfig",
}

var secretPrefixes = []string{
	".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}

var secretExact = map[string]bool{
	".netrc": true, "_netrc": true, ".npmrc": true, ".pypirc": true, ".htpasswd": true,
	".pgpass": true, ".git-credentials": true, ".dockercfg": true, ".s3cfg": true,
	".credentials": true, "kubeconfig": true, "vault.jsonl": true,
}

var dataExts = map[string]bool{
	"": true, ".json": true, ".yml": true, ".yaml": true, ".xml": true, ".ini": true,
	".toml": true, ".csv": true, ".txt": true, ".cfg": true, ".conf": true, ".properties": true,
}

// isSecretFileName reports whether a file NAME marks it as secret-bearing. The
// test is deliberately broad: refusing a harmless file costs the model a little
// context, showing a credential file leaks it.
func isSecretFileName(name string) bool {
	n := strings.ToLower(name)
	if secretExact[n] {
		return true
	}
	for _, p := range secretPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, sfx := range secretSuffixes {
		if strings.HasSuffix(n, sfx) {
			return true
		}
	}
	if strings.Contains(n, ".tfstate.") || (strings.HasSuffix(n, ".jsonl") && strings.Contains(n, "vault")) {
		return true
	}
	ext := path.Ext(n)
	stem := strings.TrimSuffix(n, ext)
	if dataExts[ext] {
		switch {
		case strings.HasPrefix(stem, "credential"), strings.HasPrefix(stem, "secret"),
			strings.HasPrefix(stem, "service-account"), strings.HasPrefix(stem, "service_account"),
			strings.HasPrefix(stem, "client_secret"), strings.HasPrefix(stem, "client-secret"),
			strings.HasSuffix(stem, "credentials"), strings.HasSuffix(stem, "_secrets"):
			return true
		}
	}
	return false
}

// protectedPath reports whether any segment of a slash-separated relative path is
// an internal directory or a secret-bearing file name.
func protectedPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if protectedDirs[strings.ToLower(seg)] || isSecretFileName(seg) {
			return true
		}
	}
	return false
}

func (s *Sandbox) denied(real string) bool {
	for _, d := range s.deny {
		if real == d || strings.HasPrefix(real, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolve turns a model-supplied relative path into a real absolute path inside the
// root, or says why not. The returned rel is slash-separated and root-relative
// ("." for the root itself).
func (s *Sandbox) resolve(p string) (real, rel string, err error) {
	p = strings.TrimSpace(p)
	if len(p) > maxPathLen {
		return "", "", refusal{"path is too long"}
	}
	if strings.ContainsRune(p, 0) {
		return "", "", refusal{"invalid path"}
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "/") || driveLetter.MatchString(p) || filepath.IsAbs(p) {
		return "", "", refusal{"absolute paths are not allowed; give a path relative to the scan root"}
	}
	if p == "" {
		p = "."
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", "", refusal{"'..' is not allowed; give a path relative to the scan root"}
		}
	}
	clean := path.Clean(p)
	if protectedPath(clean) {
		return "", "", refusal{"this path is protected (secret-bearing or internal) and is never shown"}
	}
	joined := filepath.Join(s.root, filepath.FromSlash(clean))
	real, err = filepath.EvalSymlinks(joined)
	if err != nil {
		return "", "", errNotFound
	}
	r, err := filepath.Rel(s.root, real)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", "", refusal{"path resolves outside the scan root"}
	}
	rel = filepath.ToSlash(r)
	if protectedPath(rel) || s.denied(real) {
		return "", "", refusal{"this path is protected (secret-bearing or internal) and is never shown"}
	}
	return real, rel, nil
}

func refuse(err error, p string) Result {
	var r refusal
	if errors.As(err, &r) {
		return Result{Text: "access denied: " + r.msg, Denied: true}
	}
	return Result{Text: fmt.Sprintf("not found: %s", cleanText(capBytes(p, 120, "…")))}
}

// ---- output hygiene --------------------------------------------------------

// cleanText drops control and format characters (ANSI escapes, zero-width and
// bidirectional controls) that could hide text from a human reviewer while still
// reaching the model, and repairs invalid UTF-8. Newlines and tabs are kept.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\r':
			return -1
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

// capBytes shortens s to at most n bytes at a rune boundary, appending note when it cut.
func capBytes(s string, n int, note string) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + note
}

var (
	keyBegin = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	keyEnd   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
)

// lineRedactor masks credentials one line at a time WITHOUT changing the line
// count (redact.Prompt's private-key rule swallows newlines, which would shift the
// line numbers the model cites). It must see a file from its first line.
type lineRedactor struct{ inKey bool }

func (r *lineRedactor) line(s string) string {
	if r.inKey {
		if keyEnd.MatchString(s) {
			r.inKey = false
		}
		return redact.Mask
	}
	if keyBegin.MatchString(s) {
		if !keyEnd.MatchString(s) {
			r.inKey = true
		}
		return redact.Mask
	}
	return redact.Prompt(s)
}

func (s *Sandbox) capLine(l string) string {
	if len(l) <= s.lim.LineMaxBytes {
		return l
	}
	return capBytes(l, s.lim.LineMaxBytes, " …[line truncated]")
}

// ---- read_file -------------------------------------------------------------

func looksBinary(head []byte) bool { return bytes.IndexByte(head, 0) >= 0 }

// ReadFile returns numbered lines start..end (1-indexed, inclusive) of a file,
// at most ReadMaxLines lines and ReadMaxBytes bytes.
func (s *Sandbox) ReadFile(p string, start, end int) Result {
	_, rel, err := s.resolve(p)
	if err != nil {
		return refuse(err, p)
	}
	// Open through os.Root so the kernel-level lookup itself refuses anything that
	// would leave the scan root, even if a path component is swapped for a symlink
	// between the checks in resolve and this open.
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return Result{Text: "cannot read " + rel}
	}
	defer root.Close()
	fi, err := root.Stat(rel)
	if err != nil {
		return refuse(errNotFound, p)
	}
	if fi.IsDir() {
		return Result{Text: rel + " is a directory; use list_dir"}
	}
	if !fi.Mode().IsRegular() {
		return Result{Text: rel + " is not a regular file", Denied: true}
	}
	f, err := root.Open(rel)
	if err != nil {
		return Result{Text: "cannot read " + rel}
	}
	defer f.Close()

	br := bufio.NewReaderSize(io.LimitReader(f, s.lim.FileMaxBytes), 64<<10)
	if head, _ := br.Peek(8000); looksBinary(head) {
		return Result{Text: rel + " looks like a binary file; not shown"}
	}
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start + s.lim.ReadMaxLines - 1
	}
	if end-start+1 > s.lim.ReadMaxLines {
		end = start + s.lim.ReadMaxLines - 1
	}

	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64<<10), int(s.lim.FileMaxBytes)+1)
	var (
		rd             lineRedactor
		b              strings.Builder
		lineNo, last   int
		cutBytes, more bool
		shown          []Shown
	)
	for sc.Scan() {
		lineNo++
		red := rd.line(cleanText(sc.Text())) // state advances for every line, shown or not
		if lineNo < start {
			continue
		}
		if lineNo > end {
			more = true
			break
		}
		entry := fmt.Sprintf("%5d  %s\n", lineNo, s.capLine(red))
		if b.Len()+len(entry) > s.lim.ReadMaxBytes {
			cutBytes = true
			break
		}
		b.WriteString(entry)
		shown = append(shown, Shown{Path: rel, Line: lineNo})
		last = lineNo
	}
	if last == 0 && !cutBytes && !more {
		return Result{Text: fmt.Sprintf("%s has %d line(s); start=%d is past the end", rel, lineNo, start), Paths: []string{rel}}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "FILE %s lines %d-%d\n", rel, start, last)
	out.WriteString(b.String())
	switch {
	case cutBytes:
		fmt.Fprintf(&out, "[output limit reached; continue with start=%d]\n", last+1)
	case more:
		fmt.Fprintf(&out, "[more lines follow; continue with start=%d]\n", last+1)
	default:
		out.WriteString("[end of file]\n")
	}
	if fi.Size() > s.lim.FileMaxBytes {
		fmt.Fprintf(&out, "[file is larger than %d bytes; only the beginning is readable]\n", s.lim.FileMaxBytes)
	}
	return Result{Text: out.String(), Paths: []string{rel}, Lines: shown, header: 1}
}

// ---- list_dir --------------------------------------------------------------

// ListDir lists one directory (not recursive), at most ListMaxEntries entries.
// Protected entries are omitted. Symlinks are listed but never followed.
func (s *Sandbox) ListDir(p string) Result {
	real, rel, err := s.resolve(p)
	if err != nil {
		return refuse(err, p)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return refuse(errNotFound, p)
	}
	if !fi.IsDir() {
		return Result{Text: rel + " is not a directory; use read_file"}
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return Result{Text: "cannot list " + rel}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out strings.Builder
	fmt.Fprintf(&out, "DIR %s\n", rel)
	n, hidden := 0, 0
	for _, e := range entries {
		name := e.Name()
		child := path.Join(rel, name)
		if protectedPath(child) || s.denied(filepath.Join(real, name)) {
			hidden++
			continue
		}
		if n >= s.lim.ListMaxEntries {
			out.WriteString(fmt.Sprintf("[%d more entries not shown]\n", len(entries)-hidden-n))
			break
		}
		n++
		line := cleanText(name)
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			line += "@"
		case e.IsDir():
			line += "/"
		default:
			if info, err := e.Info(); err == nil {
				line += fmt.Sprintf("  (%d bytes)", info.Size())
			}
		}
		out.WriteString(line + "\n")
	}
	if n == 0 {
		out.WriteString("(empty)\n")
	}
	return Result{Text: out.String()}
}

// ---- grep / find_references ------------------------------------------------

func (s *Sandbox) compile(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("pattern is empty")
	}
	if len(pattern) > s.lim.PatternMaxLen {
		return nil, fmt.Errorf("pattern is longer than %d characters", s.lim.PatternMaxLen)
	}
	if _, err := syntax.Parse(pattern, syntax.Perl); err != nil {
		return nil, fmt.Errorf("invalid pattern (Go RE2 syntax): %v", err)
	}
	type res struct {
		re  *regexp.Regexp
		err error
	}
	ch := make(chan res, 1)
	go func() {
		re, err := regexp.Compile(pattern)
		ch <- res{re, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("invalid pattern (Go RE2 syntax): %v", r.err)
		}
		return r.re, nil
	case <-time.After(s.lim.CompileTimeout):
		return nil, errors.New("pattern took too long to compile; simplify it")
	}
}

func globMatch(glob, rel string) bool {
	if glob == "" {
		return true
	}
	glob = strings.ReplaceAll(glob, `\`, "/")
	if !strings.Contains(glob, "/") {
		ok, _ := path.Match(glob, path.Base(rel))
		return ok
	}
	glob = strings.TrimPrefix(glob, "**/")
	parts := strings.Split(rel, "/")
	for i := range parts {
		if ok, _ := path.Match(glob, strings.Join(parts[i:], "/")); ok {
			return true
		}
	}
	return false
}

var errStopWalk = errors.New("stop")

// Grep searches file contents with a Go regular expression. subdir (optional)
// narrows the search to one directory or file; pathGlob filters by file name.
func (s *Sandbox) Grep(ctx context.Context, pattern, pathGlob, subdir string) Result {
	re, err := s.compile(pattern)
	if err != nil {
		return Result{Text: "grep: " + err.Error()}
	}
	if _, err := path.Match(strings.ReplaceAll(pathGlob, `\`, "/"), ""); err != nil {
		return Result{Text: "grep: path_glob is not a valid glob (use * ? [..]; a leading **/ is allowed)"}
	}
	return s.search(ctx, re, pathGlob, subdir)
}

var symbolRE = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.\-]{0,99}$`)

// FindReferences finds whole-word occurrences of an identifier. It is grep with the
// regular expression built for the model, so a symbol containing metacharacters
// cannot become a pattern.
func (s *Sandbox) FindReferences(ctx context.Context, symbol, pathGlob string) Result {
	symbol = strings.TrimSpace(symbol)
	if !symbolRE.MatchString(symbol) {
		return Result{Text: "find_references: symbol must be a plain identifier (letters, digits, _ $ . -), at most 100 characters"}
	}
	re, err := regexp.Compile(`(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(symbol) + `(?:[^A-Za-z0-9_]|$)`)
	if err != nil {
		return Result{Text: "find_references: " + err.Error()}
	}
	return s.search(ctx, re, pathGlob, "")
}

func (s *Sandbox) search(ctx context.Context, re *regexp.Regexp, glob, subdir string) Result {
	start, _, err := s.resolve(subdir)
	if err != nil {
		return refuse(err, subdir)
	}
	var (
		out        strings.Builder
		paths      []string
		matches    int
		files      int
		scanned    int64
		stopReason string
	)
	seenPath := map[string]bool{}
	var shown []Shown
	// Files are opened through os.Root, so a path swapped for a symlink during the
	// walk cannot lead a read outside the scan root.
	root, rerr := os.OpenRoot(s.root)
	if rerr != nil {
		return Result{Text: "search is unavailable"}
	}
	defer root.Close()
	walk := func(p string, d fs.DirEntry, werr error) error {
		if ctx.Err() != nil {
			stopReason = "cancelled"
			return errStopWalk
		}
		if werr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow, never read through a link
		}
		rel, rerr := filepath.Rel(s.root, p)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p == start {
				return nil
			}
			if protectedPath(rel) || noiseDirs[strings.ToLower(d.Name())] || s.denied(p) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || protectedPath(rel) || s.denied(p) || !globMatch(glob, rel) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > s.lim.FileMaxBytes {
			return nil
		}
		files++
		if files > s.lim.GrepMaxFiles {
			stopReason = fmt.Sprintf("stopped after %d files; narrow with path or path_glob", s.lim.GrepMaxFiles)
			return errStopWalk
		}
		scanned += info.Size()
		if scanned > s.lim.GrepMaxScanBytes {
			stopReason = "stopped after reading the per-call byte limit; narrow with path or path_glob"
			return errStopWalk
		}
		f, oerr := root.Open(rel)
		if oerr != nil {
			return nil
		}
		defer f.Close()
		br := bufio.NewReaderSize(f, 64<<10)
		if head, _ := br.Peek(8000); looksBinary(head) {
			return nil
		}
		sc := bufio.NewScanner(br)
		sc.Buffer(make([]byte, 64<<10), 256<<10)
		var rd lineRedactor
		lineNo := 0
		for sc.Scan() {
			lineNo++
			red := rd.line(cleanText(sc.Text()))
			hay := red
			if len(hay) > 2000 {
				hay = capBytes(hay, 2000, "")
			}
			if !re.MatchString(hay) {
				continue
			}
			matches++
			fmt.Fprintf(&out, "%s:%d: %s\n", rel, lineNo, s.capLine(strings.TrimSpace(red)))
			shown = append(shown, Shown{Path: rel, Line: lineNo})
			if !seenPath[rel] {
				seenPath[rel] = true
				paths = append(paths, rel)
			}
			if matches >= s.lim.GrepMaxMatches {
				stopReason = fmt.Sprintf("stopped after %d matches; narrow the pattern, path or path_glob", s.lim.GrepMaxMatches)
				return errStopWalk
			}
		}
		return nil
	}
	_ = filepath.WalkDir(start, walk)

	if matches == 0 {
		msg := fmt.Sprintf("No matches (searched %d file(s)).", files)
		if stopReason != "" {
			msg += " [" + stopReason + "]"
		}
		return Result{Text: msg}
	}
	text := out.String()
	if stopReason != "" {
		text += "[" + stopReason + "]\n"
	}
	return Result{Text: text, Paths: paths, Lines: shown}
}

// ProtectedPath reports whether a slash-separated path relative to a scan root
// names a credential file or a directory the deep agent never reads (.git, .ssh,
// the Evidence Vault, ...). Other whole-repository walks use it so they skip the
// same files.
func ProtectedPath(rel string) bool { return protectedPath(rel) }

// TestFile reports whether a slash-separated relative path looks like a test,
// where an entry point or a sink is a fixture rather than something an attacker
// reaches.
func TestFile(rel string) bool { return testFile(rel) }

// NoiseDir reports whether a directory name is a dependency or cache tree that
// whole-repository walks skip.
func NoiseDir(name string) bool { return noiseDirs[strings.ToLower(name)] }
