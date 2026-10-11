package triage

import (
	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// Output sizes cannot be known before a call. These are the schema-bounded
// defaults the estimator assumes per task — a verdict is a few sentences of
// reasoning, a judge reply is shorter (a verdict, a confidence and a quoted line
// of evidence), and a remediation carries a diff so it is
// the largest. Compare them against real `--diagnostics` token usage and adjust
// if they drift; they are the least certain part of the estimate.
//
// The triage figure covers the five gate answers (each a short answer plus one
// line of evidence) on top of the reasoning: ~150 tokens more than before gates.
const (
	estTriageOutputTokens      = 400
	estJudgeOutputTokens       = 180
	estRemediationOutputTokens = 600
)

// PlanOpts mirrors the parts of a run that change how many LLM calls happen.
type PlanOpts struct {
	// Remediate reflects --remediate. Only findings that triage confirms as
	// high-confidence are ever remediated, which is unknowable before triage
	// runs, so planning counts EVERY triaged finding — an upper bound. The
	// caller is expected to label it as such.
	Remediate bool
}

// Plan reports the LLM calls that Triage (and optionally Remediate) would make
// over findings, sized for a cost estimate, WITHOUT calling any model. Pass only
// the findings that will actually be triaged — correlated duplicates inherit a
// verdict and cost nothing, so the caller excludes them (see internal/correlate).
//
// Findings the calibrator can auto-resolve are skipped here exactly as they are
// skipped at run time, so the estimate reflects the learning layer's savings.
//
// Self-consistency sampling (SetSamples(k)) re-asks only BORDERLINE verdicts, which
// cannot be known before triage runs, so the plan counts k-1 extra triage calls for
// EVERY finding — an upper bound, like Remediate. The caller should label it as such
// when Samples() > 1.
//
// Two known omissions, both of which make this a floor rather than a ceiling:
// RAG few-shot examples (--rag) add prompt tokens that depend on the retrieved
// corpus, and the judge prompt embeds the triage verdict, which is approximated
// by the triage pass's own projected output size.
//
// Call.Model is left empty: model routing lives with the caller (--model-config
// plus --llm-model), so fill it in with cost.AssignModels.
func (e *Engine) Plan(findings []model.Finding, o PlanOpts) []cost.Call {
	var out []cost.Call
	for i := range findings {
		f := findings[i]
		if f.IsSecret() || f.IsDependencyAdvisory() {
			continue // never sent to the model, so they cost nothing
		}
		if e.calibrator != nil {
			if _, resolved := e.calibrator.AutoResolve(f); resolved {
				continue
			}
		}
		codeContext := e.enricher.Context(f, e.root)

		out = append(out, cost.Call{
			Task:         "triage",
			InputTokens:  messageTokens(triageMessages(f, codeContext, nil)),
			OutputTokens: estTriageOutputTokens,
		})
		for i := 1; i < e.Samples(); i++ {
			out = append(out, cost.Call{
				Task:         "triage",
				InputTokens:  messageTokens(triageMessages(f, codeContext, nil)),
				OutputTokens: estTriageOutputTokens,
			})
		}
		out = append(out, cost.Call{
			Task: "judge",
			// The judge prompt carries the verdict under review, so add the
			// triage pass's projected output on top of the prompt scaffolding.
			InputTokens:  messageTokens(judgeMessages(f, codeContext, model.Verdict{})) + estTriageOutputTokens,
			OutputTokens: estJudgeOutputTokens,
		})
		if o.Remediate {
			out = append(out, cost.Call{
				Task:         "remediation",
				InputTokens:  messageTokens(remediationMessages(f, codeContext)),
				OutputTokens: estRemediationOutputTokens,
			})
		}
	}
	return out
}

// TriagePromptTokens estimates the size of the triage prompt for a finding with
// the given code context. Exported for the eval harness (internal/eval), which
// measures prompt growth against the real prompt rather than a copy of it.
func TriagePromptTokens(f model.Finding, codeContext string) int {
	return messageTokens(triageMessages(f, codeContext, nil))
}

// messageTokens estimates a chat request's prompt size. The small per-message
// constant stands in for the role/delimiter overhead every chat API adds around
// each message.
func messageTokens(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		n += cost.Tokens(m.Content) + cost.Tokens(m.Role) + perMessageOverheadTokens
	}
	return n
}

// perMessageOverheadTokens is the usual ~4-token framing each chat message
// carries on the wire.
const perMessageOverheadTokens = 4
