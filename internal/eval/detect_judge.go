package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// JudgeInput is one ambiguous pairing: a labeled vulnerability and a finding at the
// same place whose class/CWE the deterministic rule could not reconcile.
type JudgeInput struct {
	Entry   Vuln
	Finding model.Finding
	// Root is the scan root, used to read the code around the finding.
	Root string
}

// Judge adjudicates ambiguous matches. It is only ever consulted for same-place,
// class-incompatible pairs — never to turn a miss with no nearby finding into a
// detection — and its detections are counted separately (judge-assisted).
type Judge interface {
	SameVulnerability(ctx context.Context, in JudgeInput) (same bool, reason string, err error)
}

// LLMJudge asks a model. It is opt-in (--judge) and not used by any gate: a
// benchmark whose pass/fail depends on a model's mood cannot be a regression gate.
type LLMJudge struct {
	Client llm.Client
	// ContextLines is how many lines of code either side of the finding to show.
	ContextLines int
}

const judgeSystem = `You decide whether a security scanner finding and a labeled vulnerability describe the SAME weakness at the SAME place in the code.
Answer "same" only when fixing the labeled vulnerability would also resolve the finding, or the finding would be a reasonable way to report it, even if the scanner names the weakness differently (for example reporting an injection as "dangerous function use").
Answer not same when they are about different problems that merely sit on nearby lines.
Reply with a single JSON object: {"same": true|false, "reason": "<one sentence>"}.`

// SameVulnerability implements Judge.
func (j LLMJudge) SameVulnerability(ctx context.Context, in JudgeInput) (bool, string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Labeled vulnerability\n  class: %s\n  CWE: %s\n  location: %s lines %d-%d\n  description: %s\n\n",
		in.Entry.Class, orDash(strings.Join(in.Entry.CWE, ",")), in.Entry.File, in.Entry.StartLine, in.Entry.EndLine, in.Entry.Description)
	msg := in.Finding.Message
	fmt.Fprintf(&b, "Scanner finding\n  tool: %s\n  rule: %s\n  CWE: %s\n  location: %s line %d\n  message: %s\n",
		in.Finding.Tool, in.Finding.RuleID, orDash(strings.Join(in.Finding.CWE, ",")),
		in.Finding.Location.File, in.Finding.Location.Region.StartLine, clip(redact.Secrets(msg), 500))
	// Credentials are the finding; the code is the secret. Describe, never show.
	if !strings.EqualFold(in.Entry.Class, ClassHardcodedSecret) && !in.Finding.IsSecret() {
		if code := j.snippet(in); code != "" {
			fmt.Fprintf(&b, "\nCode around the finding:\n%s\n", redact.Prompt(code))
		}
	}
	resp, err := llm.CompleteJSON(ctx, j.Client, []llm.Message{
		{Role: llm.RoleSystem, Content: judgeSystem},
		{Role: llm.RoleUser, Content: b.String()},
	}, nil)
	if err != nil {
		return false, "", err
	}
	var out struct {
		Same   bool   `json:"same"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Content)), &out); err != nil {
		return false, "", fmt.Errorf("judge reply is not the expected JSON: %w", err)
	}
	return out.Same, clip(out.Reason, 300), nil
}

func (j LLMJudge) snippet(in JudgeInput) string {
	file := in.Finding.Location.File
	if in.Root == "" || filepath.IsAbs(file) || hasDotDot(file) {
		return "" // a path outside the scan root is never read into a prompt
	}
	n := j.ContextLines
	if n <= 0 {
		n = 6
	}
	data, err := os.ReadFile(filepath.Join(in.Root, filepath.FromSlash(in.Finding.Location.File))) // #nosec G304 -- path came through normalizeFindingPath under the scan root
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	at := in.Finding.Location.Region.StartLine
	lo, hi := at-n-1, at+n
	if lo < 0 {
		lo = 0
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	if lo >= hi {
		return ""
	}
	var b strings.Builder
	for i := lo; i < hi; i++ {
		fmt.Fprintf(&b, "%4d  %s\n", i+1, lines[i])
	}
	return b.String()
}
