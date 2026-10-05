package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Warzuponus/achilles/internal/correlate"
	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

type triageOpts struct {
	baseURL, triageModel, judgeModel, embedModel string
	remediate, rag                               bool
	tasks                                        map[string]llm.TaskModel // per-task model routing (--model-config)

	// Cost pre-flight (--dry-run / --max-cost / --price-config). dryRun stops
	// after printing the estimate; maxCost of 0 means no cap.
	dryRun   bool
	maxCost  float64
	prices   cost.Table
	excluded []string // LLM work the estimate deliberately omits, for the report
}

// runTriage runs the LLM triage + judge layer over the scan's findings,
// mutating them in place and recording provenance to the vault. It applies the
// learning layer: calibration auto-resolves chronically-noisy rules (from
// feedback) without an LLM call, and RAG (opt-in) injects similar past findings.
func runTriage(ctx context.Context, ev vault.Store, runID string, scan *model.Scan, clusters []correlate.Cluster, o triageOpts) (llm.Usage, error) {
	if o.triageModel == "" {
		return llm.Usage{}, fmt.Errorf("--triage/--remediate requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return llm.Usage{}, err
	}

	// Per-task model routing: start from --model-config, then let the
	// --llm-judge-model flag fill in "judge" if the config didn't. The default
	// client (used for any unrouted task) is the --llm-model.
	tasks := map[string]llm.TaskModel{}
	for name, tm := range o.tasks {
		tasks[name] = tm
	}
	if o.judgeModel != "" && o.judgeModel != o.triageModel {
		if _, ok := tasks["judge"]; !ok {
			tasks["judge"] = llm.TaskModel{Model: o.judgeModel}
		}
	}
	router := llm.BuildRouter(factory(o.baseURL, o.triageModel), tasks, o.baseURL, factory)

	en := enrich.New(3)
	en.IncludeBlame = true // best-effort git attribution in the prompt context
	eng := triage.NewEngine(router, ev, en, scan.Target)

	// Learning layer (DESIGN.md §8): calibration from accumulated feedback.
	fb := knowledge.NewFeedbackStore(ev)
	eng.SetCalibrator(knowledge.NewCalibrator(fb, calMinSamples, calFPThreshold))

	// RAG few-shot (opt-in; needs an embeddings model).
	if o.rag {
		if o.embedModel == "" {
			return llm.Usage{}, fmt.Errorf("--rag requires --llm-embed-model (or ACHILLES_LLM_EMBED_MODEL)")
		}
		// The embeddings client (chromem-go's, not ours) only sends a Bearer key, so
		// it can't use the api-key header style — fail loudly rather than silently
		// sending a credential the endpoint will reject.
		if llmAuthMode == llm.ModeAPIKey {
			return llm.Usage{}, fmt.Errorf("--rag does not support --llm-auth %s yet "+
				"(the embeddings client sends a static Bearer key); drop --rag or use --llm-auth key", llmAuthMode)
		}
		rag, err := knowledge.NewRAGOpenAI(o.baseURL, envOr("ACHILLES_LLM_API_KEY", os.Getenv("OPENAI_API_KEY")), o.embedModel)
		if err != nil {
			return llm.Usage{}, fmt.Errorf("rag init: %w", err)
		}
		if n, err := rag.PopulateFromVault(ctx, ev); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: rag populate: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "achilles: rag seeded with %d labeled example(s)\n", n)
		}
		eng.SetRetriever(rag)
	}

	// Correlated duplicates inherit their representative's verdict instead of
	// paying for their own triage+judge pair. inheritFrom maps a member index to
	// the index of the representative it should copy from; anything absent is
	// triaged normally.
	inheritFrom := map[int]int{}
	for _, c := range clusters {
		for _, m := range c.Members {
			inheritFrom[m] = c.Rep
		}
	}

	// --- cost pre-flight: estimate BEFORE the first model call, so --dry-run can
	// show the bill and --max-cost can refuse it. Only findings that will really
	// be triaged are planned: correlated duplicates inherit a verdict for free,
	// and the calibrator's auto-resolutions are skipped inside Plan. ---
	toTriage := make([]model.Finding, 0, len(scan.Findings))
	for i := range scan.Findings {
		if _, inherited := inheritFrom[i]; !inherited {
			toTriage = append(toTriage, scan.Findings[i])
		}
	}
	planned := cost.AssignModels(eng.Plan(toTriage, triage.PlanOpts{Remediate: o.remediate}),
		func(task string) string {
			if tm, ok := tasks[task]; ok && tm.Model != "" {
				return tm.Model
			}
			return o.triageModel
		})
	est := cost.Project(planned, o.prices)
	est.Excluded = o.excluded
	if o.remediate {
		est.Excluded = append(est.Excluded,
			"NOTE: remediation is counted for every triaged finding — an upper bound, since only high-confidence ones are fixed")
	}
	if n := len(scan.Findings) - len(toTriage); n > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d correlated duplicate(s) will inherit a verdict at no LLM cost\n", n)
	}

	if o.dryRun {
		est.Write(os.Stderr)
		fmt.Fprintf(os.Stderr, "achilles: dry run — stopping before the first model call\n")
		return llm.Usage{}, nil
	}
	if o.maxCost > 0 {
		if !est.Complete() {
			return llm.Usage{}, fmt.Errorf("--max-cost cannot be enforced: no price for %s "+
				"(add it to --price-config, or drop --max-cost)", strings.Join(est.Unpriced, ", "))
		}
		if est.TotalUSD > o.maxCost {
			est.Write(os.Stderr)
			return llm.Usage{}, fmt.Errorf("estimated LLM spend $%.4f exceeds --max-cost $%.4f; "+
				"no model was called (raise the cap, narrow the scan with --diff/--baseline, or route cheaper models)",
				est.TotalUSD, o.maxCost)
		}
		fmt.Fprintf(os.Stderr, "achilles: estimated LLM spend $%.4f is within --max-cost $%.4f\n",
			est.TotalUSD, o.maxCost)
	}

	triageOne := func(i int) {
		f := &scan.Findings[i]
		if err := eng.Triage(ctx, runID, f); err != nil {
			fmt.Fprintf(os.Stderr, "achilles: triage failed for %s: %v\n", f.RuleID, err)
			return
		}
		if o.remediate {
			if err := eng.Remediate(ctx, runID, f); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: remediation failed for %s: %v\n", f.RuleID, err)
			}
		}
	}

	// Pass 1 — everything that gets its own triage: uncorrelated findings and
	// cluster representatives. A representative is not necessarily the lowest
	// index in its cluster (it's the highest-severity member), so this has to
	// complete before anything inherits.
	for i := range scan.Findings {
		if _, inherited := inheritFrom[i]; !inherited {
			triageOne(i)
		}
	}

	// Pass 2 — correlated duplicates inherit their representative's verdict.
	for i := range scan.Findings {
		rep, inherited := inheritFrom[i]
		if !inherited {
			continue
		}
		f := &scan.Findings[i]
		// Calibration first: feedback about THIS finding's own rule is stronger
		// evidence than a sibling's verdict, so a chronically-noisy rule still
		// auto-resolves even inside a cluster.
		if eng.AutoResolve(runID, f) {
			continue
		}
		// If the representative's own triage failed there is nothing to inherit;
		// triage this one directly rather than leaving the whole cluster unjudged.
		if scan.Findings[rep].Verdict == nil {
			triageOne(i)
			continue
		}
		eng.Inherit(runID, f, scan.Findings[rep])
	}

	u := eng.Usage()
	recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindScanMeta, Source: "llm-usage"},
		map[string]any{"promptTokens": u.PromptTokens, "completionTokens": u.CompletionTokens, "totalTokens": u.TotalTokens})
	fmt.Fprintf(os.Stderr, "achilles: llm usage — %d prompt + %d completion = %d total token(s)\n",
		u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	return u, nil
}
