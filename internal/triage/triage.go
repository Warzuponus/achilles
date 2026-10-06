// Package triage runs the LLM interpretation layer: enrich a finding with code
// context, get a structured verdict, then adversarially judge it, recording
// every step to the Evidence Vault (DESIGN.md §7). Everything is driven through
// the llm.Router so triage and judge can use different models.
package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// ExampleRetriever supplies few-shot examples of similar past findings for a
// code context (implemented by knowledge.RAG).
type ExampleRetriever interface {
	Similar(ctx context.Context, codeContext string, k int) ([]string, error)
}

// Calibrator can resolve a finding without an LLM call when its rule is
// chronically noisy (implemented by knowledge.Calibrator).
type Calibrator interface {
	AutoResolve(f model.Finding) (model.Verdict, bool)
}

// Engine performs triage + judge over findings.
type Engine struct {
	router     *llm.Router
	vault      vault.Store
	enricher   *enrich.Enricher
	root       string
	retriever  ExampleRetriever // optional (RAG); nil disables few-shot
	calibrator Calibrator       // optional; nil disables auto-resolution

	noCode bool // privacy mode: never put source code in a prompt

	mu    sync.Mutex // guards usage; findings are triaged concurrently
	usage llm.Usage  // accumulated token usage across all LLM calls this run
}

// ErrWithheld means a finding was deliberately not sent to the model: it is about
// a credential, so its content must not leave the machine. It is not a failure.
var ErrWithheld = errors.New("finding withheld from the model (it concerns a credential)")

// Usage returns the token usage accumulated across every LLM call this engine
// has made (triage + judge + remediation).
func (e *Engine) Usage() llm.Usage {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.usage
}

// SetNoCode makes every prompt carry the rule, message and location but never
// source code (--llm-no-code).
func (e *Engine) SetNoCode(on bool) *Engine { e.noCode = on; return e }

// promptView is what the model is allowed to see of a finding: the message has
// credentials masked, and the code context is bounded by the privacy settings.
func (e *Engine) promptView(f model.Finding) (model.Finding, string) {
	f.Message = redact.Prompt(f.Message)
	if e.noCode {
		return f, "(source code withheld by --llm-no-code)"
	}
	return f, redact.Prompt(e.enricher.Context(f, e.root))
}

// NewEngine wires the triage engine. root is the scanned tree root (for context
// reads). vault may be nil to skip provenance recording.
func NewEngine(router *llm.Router, v vault.Store, en *enrich.Enricher, root string) *Engine {
	return &Engine{router: router, vault: v, enricher: en, root: root}
}

// SetRetriever enables RAG few-shot examples in the triage prompt.
func (e *Engine) SetRetriever(r ExampleRetriever) *Engine { e.retriever = r; return e }

// SetCalibrator enables feedback-driven auto-resolution of noisy rules.
func (e *Engine) SetCalibrator(c Calibrator) *Engine { e.calibrator = c; return e }

// AutoResolve applies the feedback calibrator to f, resolving it in place
// without an LLM call when its rule is chronically false-positive (DESIGN.md
// §8). It reports whether the finding was resolved. Callers that triage a
// correlated cluster use this so that calibration stays a per-RULE decision:
// feedback about THIS finding's rule outranks a verdict inherited from a
// sibling reported by a different tool.
func (e *Engine) AutoResolve(runID string, f *model.Finding) bool {
	if e.calibrator == nil {
		return false
	}
	v, ok := e.calibrator.AutoResolve(*f)
	if !ok {
		return false
	}
	f.Verdict = &v
	f.Provenance = &model.Provenance{PromptVersion: "calibration"}
	e.record(runID, vault.KindVerdict, "calibration", f.Fingerprint, v)
	return true
}

// Inherit copies rep's verdict onto f without any LLM call, for a finding that
// another tool already reported at the same location and CWE (see
// internal/correlate). Provenance records which fingerprint the verdict came
// from, so the audit trail never implies f was triaged on its own evidence.
//
// Remediation is deliberately NOT inherited: a fix is a diff against one
// specific finding, and replaying it for every tool that reported the same line
// would hand --fix-pr the same patch several times.
func (e *Engine) Inherit(runID string, f *model.Finding, rep model.Finding) {
	if rep.Verdict == nil {
		return
	}
	v := *rep.Verdict
	f.Verdict = &v
	p := model.Provenance{PromptVersion: PromptVersion, CorrelatedFrom: rep.Fingerprint}
	if rep.Provenance != nil {
		p.TriageModel = rep.Provenance.TriageModel
		p.JudgeModel = rep.Provenance.JudgeModel
		p.PromptVersion = rep.Provenance.PromptVersion
	}
	f.Provenance = &p
	e.record(runID, vault.KindVerdict, "correlation", f.Fingerprint, v)
}

// Triage populates f.Verdict and f.Provenance in place.
func (e *Engine) Triage(ctx context.Context, runID string, f *model.Finding) error {
	if f.IsSecret() {
		return ErrWithheld
	}
	// Calibration short-circuit: a chronically false-positive rule is resolved
	// from feedback history without spending an LLM call (DESIGN.md §8).
	if e.AutoResolve(runID, f) {
		return nil
	}

	pf, codeContext := e.promptView(*f)

	// RAG few-shot: retrieve similar past findings with known verdicts.
	var examples []string
	if e.retriever != nil {
		if ex, err := e.retriever.Similar(ctx, codeContext, 3); err == nil {
			examples = ex
		}
	}

	// --- triage pass ---
	tResp, err := e.completeValidated(ctx, "triage", triageMessages(pf, codeContext, examples), "verdict", verdictSchema, &verdictCheck{})
	if err != nil {
		return fmt.Errorf("triage llm: %w", err)
	}
	e.record(runID, vault.KindLLMCall, "triage", f.Fingerprint, map[string]any{
		"task": "triage", "promptVersion": PromptVersion, "model": tResp.Model, "response": tResp.Content,
	})

	v, err := parseVerdict(tResp.Content)
	if err != nil {
		return fmt.Errorf("parse verdict for %s: %w", f.RuleID, err)
	}

	// --- adversarial judge pass ---
	jResp, err := e.completeValidated(ctx, "judge", judgeMessages(pf, codeContext, v), "judge", judgeSchema, &judgeCheck{})
	if err != nil {
		return fmt.Errorf("judge llm: %w", err)
	}
	e.record(runID, vault.KindLLMCall, "judge", f.Fingerprint, map[string]any{
		"task": "judge", "model": jResp.Model, "response": jResp.Content,
	})

	// The judge answers one question — "is this verdict wrong?" — but the
	// consequence depends on which way the verdict pointed. Refuting a
	// true-positive suppresses it; refuting a false-positive surfaces it. Before
	// this was symmetric, a refuted false-positive stayed suppressed, so the judge
	// could only ever lose findings, never recover one.
	refuted, reason := parseJudge(jResp.Content)
	v.RefuteReason = reason
	switch v.Classification {
	case model.ClassFalsePositive:
		v.Overturned = refuted
	default:
		// true_positive, and uncertain — which is already not surfaced, and where
		// "the verdict is wrong" does not say in which direction, so we do not
		// guess. See DESIGN §7.
		v.Refuted = refuted
	}

	f.Verdict = &v
	f.Provenance = &model.Provenance{TriageModel: tResp.Model, JudgeModel: jResp.Model, PromptVersion: PromptVersion}
	e.record(runID, vault.KindVerdict, "triage", f.Fingerprint, v)
	return nil
}

// Remediate proposes a fix for a high-confidence finding, in place. It is a
// no-op for findings that aren't confirmed high-confidence (we don't spend
// tokens fixing what we haven't verified). We propose; we never auto-apply.
func (e *Engine) Remediate(ctx context.Context, runID string, f *model.Finding) error {
	if f.Verdict == nil || !f.Verdict.HighConfidence() {
		return nil
	}
	if f.IsSecret() {
		return nil
	}
	pf, codeContext := e.promptView(*f)
	resp, err := e.completeValidated(ctx, "remediation", remediationMessages(pf, codeContext), "remediation", remediationSchema, &remediationCheck{})
	if err != nil {
		return fmt.Errorf("remediation llm: %w", err)
	}
	e.record(runID, vault.KindLLMCall, "remediation", f.Fingerprint, map[string]any{
		"task": "remediation", "model": resp.Model, "response": resp.Content,
	})

	var r model.Remediation
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Content)), &r); err != nil {
		return fmt.Errorf("parse remediation for %s: %w", f.RuleID, err)
	}
	f.Remediation = &r
	e.record(runID, vault.KindRemediation, "remediation", f.Fingerprint, r)
	return nil
}

// schemaCheck is a decode target that can say whether a reply is usable. A reply
// that parses but is unusable (missing or out-of-enum fields, which json.Unmarshal
// tolerates) earns one repair round-trip in completeValidated.
type schemaCheck interface{ validate() error }

// completeValidated requests structured output for a task's routed client and
// gives a loose model one repair round-trip (llm.CompleteAndDecode) when the reply
// is unparseable or fails check.validate.
//
// It deliberately does NOT turn a still-unusable reply into an error: it returns
// the last response and lets the caller's lenient parser (parseVerdict, parseJudge,
// remediation decode) apply its documented fail-safe defaults — in particular the
// judge's "an unparseable answer does not refute". Only a transport failure with
// no content at all is an error.
func (e *Engine) completeValidated(ctx context.Context, task string, msgs []llm.Message, schemaName string, schema json.RawMessage, check schemaCheck) (llm.Response, error) {
	resp, err := llm.CompleteAndDecode(ctx, e.router.For(task), msgs,
		&llm.Schema{Name: schemaName, Definition: schema}, check, check.validate)
	e.mu.Lock()
	e.usage.Add(resp.Usage) // accumulate even on partial success; zero when unreported
	e.mu.Unlock()
	if err != nil && resp.Content == "" {
		return resp, err
	}
	return resp, nil
}

type verdictCheck struct {
	Classification model.Classification `json:"classification"`
}

func (c *verdictCheck) validate() error {
	switch c.Classification {
	case model.ClassTruePositive, model.ClassFalsePositive, model.ClassUncertain:
		return nil
	}
	return fmt.Errorf("classification must be true_positive, false_positive or uncertain, got %q", c.Classification)
}

type judgeCheck struct {
	Refuted *bool `json:"refuted"`
}

func (c *judgeCheck) validate() error {
	if c.Refuted == nil {
		return fmt.Errorf("missing required boolean field %q", "refuted")
	}
	return nil
}

type remediationCheck struct {
	Summary string `json:"summary"`
}

func (c *remediationCheck) validate() error {
	if strings.TrimSpace(c.Summary) == "" {
		return fmt.Errorf("missing required field %q", "summary")
	}
	return nil
}

func (e *Engine) record(runID string, kind vault.Kind, source, fp string, payload any) {
	if e.vault == nil {
		return
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = e.vault.Append(vault.Record{
		RunID: runID, Phase: "triage", Kind: kind, Source: source, Fingerprint: fp, Payload: b,
	})
}

func parseVerdict(s string) (model.Verdict, error) {
	var v model.Verdict
	if err := json.Unmarshal([]byte(llm.ExtractJSON(s)), &v); err != nil {
		return model.Verdict{}, err
	}
	if v.Classification == "" {
		v.Classification = model.ClassUncertain
	}
	if v.Exploitability == "" {
		v.Exploitability = model.ExploitUnknown
	}
	return v, nil
}

func parseJudge(s string) (bool, string) {
	var j struct {
		Refuted bool   `json:"refuted"`
		Reason  string `json:"reason"`
	}
	// A judge response we can't parse is treated as "did not refute" — we never
	// silently upgrade confidence, only downgrade, so failing safe here is fine.
	_ = json.Unmarshal([]byte(llm.ExtractJSON(s)), &j)
	return j.Refuted, j.Reason
}
