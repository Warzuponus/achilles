package deep

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// PromptVersion is recorded with every deep verification.
// v2: evidence must point at lines that were shown, not merely at a file that was
// read in part; the prompt says so.
const PromptVersion = "deep/v2"

// Hard ceilings: a flag cannot raise a bound past these.
const (
	DefaultMaxSteps = 6
	MaxStepsCeiling = 20

	// DefaultTotalBytes is the most tool output one finding may be shown, across
	// all its calls.
	DefaultTotalBytes = 48 << 10
	// DefaultTimeout is the wall-clock limit for one finding.
	DefaultTimeout = 2 * time.Minute
	// DefaultContextRadius is how many lines either side of the finding the first
	// message shows.
	DefaultContextRadius = 15

	maxReasoningBytes = 2000
	maxEvidence       = 8
	maxTraceEntries   = 24
)

// Config bounds one Verifier. Zero values take the defaults above.
type Config struct {
	MaxSteps      int           // tool calls per finding (default 6, ceiling 20)
	Timeout       time.Duration // wall clock per finding
	TotalBytes    int           // tool output per finding
	ContextRadius int
	Limits        Limits
	// DenyPaths are extra files or directories (e.g. the vault) the tools must never show.
	DenyPaths []string
	// Budget, when set, is a tool-output cap shared by every finding of one run.
	Budget *Budget
}

// WithDefaults returns c with every zero field replaced by its default and every
// bound clamped to its ceiling.
func (c Config) WithDefaults() Config { return c.withDefaults() }

func (c Config) withDefaults() Config {
	if c.MaxSteps <= 0 {
		c.MaxSteps = DefaultMaxSteps
	}
	if c.MaxSteps > MaxStepsCeiling {
		c.MaxSteps = MaxStepsCeiling
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.TotalBytes <= 0 {
		c.TotalBytes = DefaultTotalBytes
	}
	if c.ContextRadius <= 0 {
		c.ContextRadius = DefaultContextRadius
	}
	c.Limits = c.Limits.withDefaults()
	return c
}

// Budget is a tool-output allowance shared across goroutines (one per run).
type Budget struct{ left atomic.Int64 }

// NewBudget returns a budget of n bytes.
func NewBudget(n int64) *Budget {
	b := &Budget{}
	b.left.Store(n)
	return b
}

// take grants up to n bytes and returns how many it granted.
func (b *Budget) take(n int) int {
	for {
		cur := b.left.Load()
		if cur <= 0 {
			return 0
		}
		g := int64(n)
		if g > cur {
			g = cur
		}
		if b.left.CompareAndSwap(cur, cur-g) {
			return int(g)
		}
	}
}

// Left is how many bytes remain.
func (b *Budget) Left() int64 { return b.left.Load() }

// EstimateTokens is a deliberately pessimistic upper bound on the tokens one deep
// verification can use, for --dry-run. Every turn resends the whole transcript, so
// prompt tokens grow with the tool output seen so far; this assumes the output
// budget is spent before the first turn and the model repairs every reply.
func EstimateTokens(cfg Config) (prompt, completion int) {
	cfg = cfg.withDefaults()
	const baseBytes = 4000 // system prompt + finding + first context window
	turns := (cfg.MaxSteps + 1) * 2
	perTurn := (baseBytes + cfg.TotalBytes + cfg.MaxSteps*300) / 4
	return turns * perTurn, turns * 400
}

// Verifier runs deep verification of findings against one scan root. It is safe for
// concurrent use; each call to Deep has its own transcript and budgets.
type Verifier struct {
	client llm.Client
	sb     *Sandbox
	root   string // the root as the caller gave it, for absolute finding paths
	cfg    Config

	mu    sync.Mutex
	usage llm.Usage
}

// New builds a Verifier over root using client for every model turn.
func New(client llm.Client, root string, cfg Config) (*Verifier, error) {
	if client == nil {
		return nil, errors.New("deep: no LLM client")
	}
	cfg = cfg.withDefaults()
	sb, err := NewSandbox(root, cfg.Limits, cfg.DenyPaths...)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(root)
	return &Verifier{client: client, sb: sb, root: abs, cfg: cfg}, nil
}

// Config returns the effective (defaulted) configuration.
func (v *Verifier) Config() Config { return v.cfg }

// Usage is the total token usage so far.
func (v *Verifier) Usage() llm.Usage {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.usage
}

func (v *Verifier) addUsage(u llm.Usage) {
	v.mu.Lock()
	v.usage.Add(u)
	v.mu.Unlock()
}

// session is one finding's tool state: the byte budget, the set of files a tool
// has shown the model (evidence must come from these), and the audit trace.
type session struct {
	sb        *Sandbox
	remaining int
	shared    *Budget
	used      int
	seen      map[string]bool
	// lines are the source lines the model has actually been shown, per file.
	lines map[string]map[int]bool
	trace []string
}

// sawLines records the source lines a tool result put in front of the model.
func (s *session) sawLines(shown []Shown) {
	for _, l := range shown {
		if s.lines[l.Path] == nil {
			s.lines[l.Path] = map[int]bool{}
		}
		s.lines[l.Path][l.Line] = true
	}
}

func (s *session) exhausted() bool {
	return s.remaining <= 0 || (s.shared != nil && s.shared.Left() <= 0)
}

func (s *session) run(ctx context.Context, a Action) string {
	if len(s.trace) < maxTraceEntries {
		s.trace = append(s.trace, a.Describe())
	}
	if s.exhausted() {
		return "tool output budget exhausted: no more tool calls are possible. Conclude now."
	}
	res := s.sb.Run(ctx, a)
	text := res.Text
	grant := min(len(text), s.remaining)
	if s.shared != nil {
		grant = s.shared.take(grant)
	}
	if grant < len(text) {
		text = capBytes(text, grant, "\n[truncated: the tool output budget for this finding is exhausted]")
	}
	s.remaining -= grant
	s.used += grant
	for _, p := range res.Paths {
		s.seen[p] = true
	}
	s.sawLines(res.shownIn(text))
	return text
}

// Deep investigates one finding. It never changes f. The returned verification is
// complete (Conclusion set) or carries Aborted; an error is returned only for
// failures a retry might fix (the endpoint, or the caller's context).
//
// A credential finding is refused outright: its matched text IS the secret and
// must never be sent to a model.
func (v *Verifier) Deep(ctx context.Context, f model.Finding) (model.DeepVerification, error) {
	d := model.DeepVerification{Conclusion: model.ClassUncertain, PromptVersion: PromptVersion}
	if f.IsSecret() {
		d.Aborted = "credential finding: never sent to the model"
		return d, nil
	}

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, v.cfg.Timeout)
	defer cancel()

	sess := &session{sb: v.sb, remaining: v.cfg.TotalBytes, shared: v.cfg.Budget, seen: map[string]bool{}, lines: map[string]map[int]bool{}}
	nonce := newNonce()

	// The finding's own file, through the sandbox: a finding inside a protected
	// path (say a .tfvars file) is never shown.
	file := v.relFile(f.Location.File)
	lo := max(1, f.Location.Region.StartLine-v.cfg.ContextRadius)
	hi := max(f.Location.Region.EndLine, f.Location.Region.StartLine) + v.cfg.ContextRadius
	if f.Location.Region.StartLine <= 0 {
		lo, hi = 1, 40
	}
	first := v.sb.ReadFile(file, lo, hi)
	if first.Denied {
		d.Aborted = "the finding's file is a protected path and is never shown to the model"
		return d, nil
	}
	for _, p := range first.Paths {
		sess.seen[p] = true
	}
	// The initial context also draws on the byte budget, so the cap is honest.
	ctxText := redact.Prompt(first.Text)
	if g := min(len(ctxText), sess.remaining); g < len(ctxText) {
		ctxText = capBytes(ctxText, g, "\n[truncated]")
	}
	// Count the lines that are actually sent: a line dropped by the cap above was
	// not shown. Taking a prefix is the cautious reading if the count is short for
	// any other reason.
	if n := strings.Count(ctxText, "\n") - first.header; n >= len(first.Lines) {
		sess.sawLines(first.Lines)
	} else if n > 0 {
		sess.sawLines(first.Lines[:n])
	}

	msgs := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt(v.cfg.MaxSteps)},
		{Role: llm.RoleUser, Content: firstUserMessage(f, file, ctxText, nonce)},
	}

	finish := func() model.DeepVerification {
		d.Steps = len(sess.trace)
		d.ToolBytes = sess.used
		d.Trace = make([]string, len(sess.trace))
		for i, t := range sess.trace {
			d.Trace[i] = redact.Prompt(t) // the model chose these arguments; they are stored and reported
		}
		return d
	}
	abort := func(reason string) (model.DeepVerification, error) {
		d.Aborted = reason
		d.Conclusion, d.Confidence = model.ClassUncertain, 0
		return finish(), nil
	}

	for steps := 0; ; {
		final := steps >= v.cfg.MaxSteps || sess.exhausted()
		act, err := v.turn(ctx, &msgs)
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

		if act.Action == ActionConclude {
			d.Conclusion = model.Classification(act.Classification)
			d.Confidence = float64(act.Confidence)
			d.Reasoning = redact.Prompt(capBytes(cleanText(act.Reasoning), maxReasoningBytes, " …"))
			d.Evidence, d.EvidenceDropped = filterEvidence(act.Evidence, sess.seen, sess.lines)
			return finish(), nil
		}
		if final {
			return abort("tool budget exhausted without a conclusion")
		}

		steps++
		text := sess.run(ctx, act)
		msgs = append(msgs,
			llm.Message{Role: llm.RoleAssistant, Content: act.compact()},
			llm.Message{Role: llm.RoleUser, Content: toolMessage(act, steps, v.cfg.MaxSteps, text, nonce, steps >= v.cfg.MaxSteps || sess.exhausted())})
	}
}

// relFile makes a finding's file root-relative when it is an absolute path inside
// the scan root; anything else is passed on as given and left to the sandbox.
func (v *Verifier) relFile(file string) string {
	if !filepath.IsAbs(file) {
		return file
	}
	for _, root := range []string{v.root, v.sb.root} {
		if rel, err := filepath.Rel(root, file); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return file
}

// badReplyError means the model's reply could not be decoded even after repair.
type badReplyError struct{ reason string }

func (e badReplyError) Error() string { return "deep: unusable model reply: " + e.reason }

// turn asks the model for its next action. A reply that does not parse earns ONE
// repair round-trip, then fails with badReplyError.
func (v *Verifier) turn(ctx context.Context, msgs *[]llm.Message) (Action, error) {
	resp, err := llm.CompleteJSON(ctx, v.client, *msgs, stepSchema)
	v.addUsage(resp.Usage)
	if err != nil {
		return Action{}, err
	}
	act, perr := ParseAction(resp.Content)
	if perr == nil {
		return act, nil
	}
	repair := append(append([]llm.Message(nil), *msgs...),
		llm.Message{Role: llm.RoleAssistant, Content: capBytes(cleanText(resp.Content), 1000, " …")},
		llm.Message{Role: llm.RoleUser, Content: "That reply was not acceptable: " + perr.Error() +
			". Reply with ONLY one JSON object, no prose and no markdown fences, whose \"action\" is one of " +
			"read_file, grep, list_dir, find_references or conclude, with that action's fields."})
	resp2, err := v.client.Complete(ctx, llm.Request{Messages: repair, Temperature: 0, JSON: true})
	v.addUsage(resp2.Usage)
	if err != nil {
		return Action{}, err
	}
	act, perr2 := ParseAction(resp2.Content)
	if perr2 != nil {
		return Action{}, badReplyError{reason: perr2.Error()}
	}
	return act, nil
}

// ---- evidence ----------------------------------------------------------------

var evidenceRef = regexp.MustCompile(`^(.+?):(\d+)(?:-(\d+))?$`)

// maxEvidenceSpan is the longest line range one reference may cover.
const maxEvidenceSpan = 400

// filterEvidence keeps only "file:line" references to lines a tool (or the
// finding's own context window) actually showed the model. Checking the file alone
// was not enough: a model could grep one token in auth.go and then cite
// auth.go:999 as the sanitizer, and the citation counted. Every line of a cited
// range has to have been shown. It returns the kept references, de-duplicated and
// capped, and how many were discarded.
func filterEvidence(refs []string, seen map[string]bool, lines map[string]map[int]bool) (kept []string, dropped int) {
	dup := map[string]bool{}
	for _, r := range refs {
		m := evidenceRef.FindStringSubmatch(strings.TrimSpace(cleanText(r)))
		if m == nil {
			dropped++
			continue
		}
		p := strings.TrimPrefix(path.Clean(strings.ReplaceAll(m[1], `\`, "/")), "./")
		if !seen[p] || !linesShown(lines[p], m[2], m[3]) {
			dropped++
			continue
		}
		key := p + ":" + m[2] + optionalRange(m[3])
		if dup[key] {
			continue
		}
		if len(kept) >= maxEvidence {
			dropped++
			continue
		}
		dup[key] = true
		kept = append(kept, capBytes(key, 200, ""))
	}
	return kept, dropped
}

// linesShown reports whether every line from lo to hi (hi may be empty: just lo)
// is among the lines shown.
func linesShown(shown map[int]bool, lo, hi string) bool {
	a, err := strconv.Atoi(lo)
	if err != nil || a < 1 {
		return false
	}
	b := a
	if hi != "" {
		if b, err = strconv.Atoi(hi); err != nil || b < a || b-a > maxEvidenceSpan {
			return false
		}
	}
	for n := a; n <= b; n++ {
		if !shown[n] {
			return false
		}
	}
	return true
}

func optionalRange(end string) string {
	if end == "" {
		return ""
	}
	return "-" + end
}

func newNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
