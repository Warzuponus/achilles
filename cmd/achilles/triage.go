package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/correlate"
	"github.com/Warzuponus/achilles/internal/cost"
	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/knowledge"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

// loadTaskRouting reads --model-config: per-task model routing, shared by triage
// and the whole-repo agents. nil when no config is given.
func loadTaskRouting(path string) (map[string]llm.TaskModel, error) {
	if path == "" {
		return nil, nil
	}
	mr, err := config.LoadModelRouting(path)
	if err != nil {
		return nil, err
	}
	tasks := map[string]llm.TaskModel{}
	for name, tm := range mr.Tasks {
		tasks[name] = llm.TaskModel{Model: tm.Model, BaseURL: tm.BaseURL}
	}
	return tasks, nil
}

// triageScan is the LLM cost pre-flight (--dry-run / --max-cost) followed by
// triage of the surfaced findings when --triage or --remediate is set.
func triageScan(ctx context.Context, o *options, ev vault.Store, runID string, scan *model.Scan, clusters []correlate.Cluster, tasks map[string]llm.TaskModel) (llm.Usage, error) {
	var priceTable cost.Table
	if o.priceConfig != "" {
		pt, err := cost.LoadTable(o.priceConfig)
		if err != nil {
			return llm.Usage{}, err
		}
		priceTable = pt
	}
	if o.maxCost < 0 {
		return llm.Usage{}, fmt.Errorf("--max-cost must not be negative")
	}
	if o.maxCost > 0 && o.priceConfig == "" {
		return llm.Usage{}, fmt.Errorf("--max-cost needs --price-config: dollars require per-model prices, " +
			"which Achilles does not ship (see configs/prices.example.yaml)")
	}
	// From here every model call of the run is counted, and refused once the cap
	// is reached: the estimate below is a forecast of one phase, not a limit.
	if o.maxCost > 0 && !o.dryRun {
		runMeter = newSpendMeter(o.maxCost, priceTable)
	}
	// Other LLM work is not part of the per-finding estimate; name it rather than
	// let a partial number read as the whole bill.
	var excluded []string
	if o.deepVerify > 0 {
		excluded = append(excluded, fmt.Sprintf("--deep-verify (up to %d findings, several calls each)", o.deepVerify))
	}
	if o.reviewOn {
		excluded = append(excluded, "--review (one whole-repo call per scan)")
	}
	if o.scaAdvice {
		excluded = append(excluded, "--sca-advice (one whole-repo call per scan)")
	}
	if o.threatModelOut != "" {
		excluded = append(excluded, "--threat-model (one whole-repo call per scan)")
	}
	if o.researchOn && !o.dryRun {
		excluded = append(excluded, fmt.Sprintf("--research (up to %d dependencies researched + rules synthesized)", o.maxTargets))
	}
	if o.mineRules && !o.dryRun {
		excluded = append(excluded, fmt.Sprintf("--mine-rules (up to %d rules mined)", o.maxTargets))
	}
	if o.ragOn {
		excluded = append(excluded, "--rag few-shot examples added to each triage prompt")
	}

	// Triage runs only on surfaced findings (cheaper: no LLM spend on known/unchanged).
	if o.triageOn || o.remediateOn {
		opts := triageOpts{
			baseURL: o.llmBaseURL, triageModel: o.llmModel, judgeModel: o.llmJudge,
			embedModel: o.llmEmbed, remediate: o.remediateOn, rag: o.ragOn, tasks: tasks,
			dryRun: o.dryRun, maxCost: o.maxCost, prices: priceTable, excluded: excluded,
			noCode: o.llmNoCode, keepDismissed: o.keepDismissed, calibrate: o.calibrate, concurrency: o.llmConcurrency, samples: o.llmSamples,
		}
		if o.verdictCacheDays > 0 && !o.dryRun {
			// The key that makes cached verdicts trustworthy lives in the Achilles
			// home directory. Without it the cache is simply off for this run.
			if secret, err := verdictCacheSecret(); err != nil {
				fmt.Fprintf(os.Stderr, "achilles: verdict cache off for this run: %v\n", err)
			} else {
				opts.cacheMaxAge, opts.cacheSecret = time.Duration(o.verdictCacheDays)*24*time.Hour, secret
			}
		}
		if o.deepVerify > 0 {
			opts.afterTriage = func(c context.Context) error { return deepVerifyFindings(c, o, ev, runID, scan) }
		}
		return runTriage(ctx, ev, runID, scan, clusters, opts)
	}
	if o.dryRun {
		est := cost.Project(nil, priceTable)
		est.Excluded = excluded
		est.Write(os.Stderr)
		fmt.Fprintf(os.Stderr, "achilles: dry run — no per-finding LLM work requested (add --triage to estimate it)\n")
	}
	return llm.Usage{}, nil
}

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

	// Verdict cache (--verdict-cache-days): reuse a verdict for at most this long.
	// Zero, or no signing secret, leaves it off.
	cacheMaxAge time.Duration
	cacheSecret []byte

	noCode        bool // --llm-no-code: prompts carry no source; verdicts are then never trusted to dismiss
	keepDismissed bool // --keep-dismissed: leave AI-dismissed findings in scan.Findings
	calibrate     bool // --calibrate: resolve chronically noisy rules from feedback, with no model call
	concurrency   int  // findings triaged in parallel; <1 means 1
	samples       int  // --llm-samples: re-ask borderline verdicts this many times in total; <2 means once

	// afterTriage runs once every finding has its first verdict and before AI-dismissed
	// findings are moved out of the gate (--deep-verify hooks in here). nil = none.
	afterTriage func(context.Context) error
}

// abortAfterFailures is how many failed findings in a row, with not one success,
// mean the endpoint or key is broken rather than the findings: stop spending time.
const abortAfterFailures = 5

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
	eng := triage.NewEngine(router, ev, en, scan.Target).SetNoCode(o.noCode).SetSamples(o.samples)

	// Verdict cache: a finding whose code, prompt and models are unchanged since an
	// earlier run keeps that run's verdict instead of being reviewed again.
	if o.cacheMaxAge > 0 && len(o.cacheSecret) > 0 {
		scopeOf := func(task, fallback string) string {
			if tm, ok := tasks[task]; ok && tm.Model != "" {
				return tm.Model + "@" + tm.BaseURL
			}
			return fallback
		}
		eng.SetVerdictCache(
			triage.CacheScope(o.baseURL, scopeOf("triage", o.triageModel), scopeOf("judge", o.triageModel)),
			o.cacheMaxAge, o.cacheSecret, nil)
		// Fix proposals are cached the same way, under the model that writes them.
		eng.SetRemediationCacheScope(strings.TrimRight(o.baseURL, "/") + "|remediation=" + scopeOf("remediation", o.triageModel))
	}

	// Learning layer (DESIGN.md §8): calibration from accumulated feedback. Opt-in:
	// it takes findings out of the gate on past labels alone, with no model looking
	// at the code in front of it, so it never happens unless the operator asks.
	if o.calibrate {
		eng.SetCalibrator(knowledge.NewCalibrator(knowledge.NewFeedbackStore(ev), knowledge.DefaultPolicy, time.Now()))
	}

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
	if eng.Samples() > 1 {
		est.Excluded = append(est.Excluded, fmt.Sprintf(
			"NOTE: --llm-samples %d re-asks only borderline verdicts, which cannot be known in advance; the estimate counts the extra calls for every finding, an upper bound", eng.Samples()))
	}
	if o.remediate {
		est.Excluded = append(est.Excluded,
			"NOTE: remediation is counted for every triaged finding — an upper bound, since only high-confidence ones are fixed")
	}
	if n := len(scan.Findings) - len(toTriage); n > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d correlated duplicate(s) will inherit a verdict at no LLM cost\n", n)
	}

	if o.dryRun {
		est.Write(os.Stderr)
		if o.afterTriage != nil {
			if err := o.afterTriage(ctx); err != nil { // prints the deep-verify plan; calls no model
				return llm.Usage{}, err
			}
		}
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

	// A fatal error (rejected credential, exhausted credits, an endpoint that fails
	// every call) cancels the remaining work: minutes of per-finding errors help no one.
	llmCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu          sync.Mutex
		fatal       error
		failedN     int
		withheldN   int
		advisoryN   int
		succeeded   int
		consecutive int
	)
	triageOne := func(i int) {
		if llmCtx.Err() != nil {
			return // aborted or out of time: counted as "not reached"
		}
		f := &scan.Findings[i]
		err := eng.Triage(llmCtx, runID, f)
		switch {
		case errors.Is(err, triage.ErrWithheld):
			mu.Lock()
			withheldN++
			mu.Unlock()
			return
		case errors.Is(err, triage.ErrAdvisory):
			mu.Lock()
			advisoryN++
			mu.Unlock()
			return
		case errors.Is(err, errCostCap):
			// Not a failure of the endpoint: the cap stopped the call. This finding and
			// those after it are "not reached", as when the time budget runs out. Calls
			// already in flight are left to finish: their tokens are spent either way.
			return
		case err != nil:
			if llmCtx.Err() != nil {
				return
			}
			mu.Lock()
			failedN++
			consecutive++
			if fatal == nil && (fatalLLMError(err) || (consecutive >= abortAfterFailures && succeeded == 0)) {
				fatal = err
				cancel()
			}
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "achilles: triage failed for %s: %s\n", f.RuleID, oneLine(err))
			return
		}
		mu.Lock()
		succeeded++
		consecutive = 0
		mu.Unlock()
		if o.remediate {
			if err := eng.Remediate(llmCtx, runID, f); err != nil && llmCtx.Err() == nil && !errors.Is(err, errCostCap) {
				fmt.Fprintf(os.Stderr, "achilles: remediation failed for %s: %s\n", f.RuleID, oneLine(err))
			}
		}
	}

	// Pass 1 — everything that gets its own triage: uncorrelated findings and
	// cluster representatives. A representative is not necessarily the lowest
	// index in its cluster (it's the highest-severity member), so this has to
	// complete before anything inherits. Most severe first: if the LLM budget runs
	// out, what was reviewed is what matters most.
	var pass1 []int
	for i := range scan.Findings {
		if _, inherited := inheritFrom[i]; !inherited {
			pass1 = append(pass1, i)
		}
	}
	sort.SliceStable(pass1, func(a, b int) bool {
		return scan.Findings[pass1[a]].Severity.Rank() > scan.Findings[pass1[b]].Severity.Rank()
	})
	workers := o.concurrency
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, i := range pass1 {
		if llmCtx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			triageOne(i)
		}(i)
	}
	wg.Wait()

	// Pass 2 — correlated duplicates inherit their representative's verdict.
	for i := range scan.Findings {
		rep, inherited := inheritFrom[i]
		if !inherited || llmCtx.Err() != nil {
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

	// A broken key or endpoint ends the AI review, not the run. The scanners have
	// already done their work, possibly for many minutes; that result is still
	// reported, labeled as unreviewed, and the caller exits non-zero afterwards.
	var aborted *triageAbortedError
	if fatal != nil {
		aborted = &triageAbortedError{failed: failedN, cause: oneLine(fatal)}
	} else if o.afterTriage != nil {
		if err := o.afterTriage(ctx); err != nil {
			return u, err
		}
	}

	// Coverage: how much of the scan got a verdict. Reports print this beside the
	// verdicts so an unreviewed finding is never mistaken for a reviewed one.
	stats := model.TriageStats{Model: o.triageModel, Total: len(scan.Findings), Failed: failedN, Withheld: withheldN, Advisories: advisoryN}
	for _, f := range scan.Findings {
		if f.Verdict != nil {
			stats.Triaged++
		}
	}
	for _, f := range scan.Findings {
		if f.Verdict != nil && f.Provenance != nil && f.Provenance.ReusedFrom != "" {
			stats.Reused++
		}
	}
	fixesReused := 0
	for _, f := range scan.Findings {
		if f.Remediation != nil && f.Remediation.ReusedFrom != "" {
			fixesReused++
		}
	}
	if fixesReused > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d fix suggestion(s) reused from earlier runs: the same finding, code and position, with the same prompt and model\n", fixesReused)
	}
	if stats.Reused > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d verdict(s) reused from earlier runs: the same code was reviewed with the same prompt and models (--verdict-cache-days 0 to review everything afresh)\n", stats.Reused)
	}
	// Name what calibration decided: these verdicts are feedback history, not a review.
	calibratedRules := map[string]int{}
	for _, f := range scan.Findings {
		if f.Verdict != nil && f.Provenance != nil && f.Provenance.PromptVersion == "calibration" {
			stats.AutoResolved++
			calibratedRules[f.Tool+"/"+f.RuleID]++
		}
	}
	if stats.AutoResolved > 0 {
		names := make([]string, 0, len(calibratedRules))
		for r, n := range calibratedRules {
			names = append(names, fmt.Sprintf("%s (%d)", r, n))
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "achilles: --calibrate ruled out %d finding(s) from analyst feedback, with NO model review: %s\n"+
			"  (run --rule-health to see the labels behind this; drop --calibrate to have them reviewed)\n",
			stats.AutoResolved, strings.Join(names, ", "))
	}
	stats.Skipped = stats.Total - stats.Triaged - stats.Failed - stats.Withheld - stats.Advisories
	if stats.Skipped < 0 {
		stats.Skipped = 0
	}
	if aborted != nil {
		// Nothing is dismissed on the strength of a review that fell over: whatever
		// verdicts exist came from before the endpoint broke, and are too few to trust
		// as a pass over the scan.
		stats.Aborted = aborted.cause
		scan.Triage = &stats
		return u, aborted
	}
	switch {
	case o.keepDismissed:
	case o.noCode:
		fmt.Fprintln(os.Stderr, "achilles: --llm-no-code: the model never saw the code, so its false-positive calls are not used to dismiss findings")
	default:
		stats.Dismissed = scan.PartitionDismissed()
	}
	scan.Triage = &stats
	fmt.Fprintf(os.Stderr, "achilles: AI review — verdict on %d of %d finding(s); %d dismissed (false positives or hardening notes), %d failed, %d withheld (credentials), %d not reached\n",
		stats.Triaged, stats.Total, stats.Dismissed, stats.Failed, stats.Withheld, stats.Skipped)
	if stats.Advisories > 0 {
		fmt.Fprintf(os.Stderr, "achilles: %d dependency advisory finding(s) (known CVEs in dependencies) are kept as reported and were not sent to the model: "+
			"an advisory is fixed by upgrading, not by a verdict (--sca-advice plans the upgrades)\n", stats.Advisories)
	}
	if stats.Skipped > 0 && runMeter.reached() {
		fmt.Fprintf(os.Stderr, "achilles: --max-cost stopped the AI review: %d finding(s) were not reviewed (most severe were reviewed first). Raise --max-cost or narrow the scan with --diff / --baseline.\n", stats.Skipped)
	}
	if stats.Skipped > 0 && ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "achilles: the --llm-budget ran out; the findings above were reviewed most severe first. Raise --llm-budget or narrow the scan with --diff / --baseline.")
	}
	return u, nil
}

// triageAbortedError is returned when the AI review had to stop: the key was
// rejected, the credits ran out, or every call failed. The scan itself is intact,
// so the caller still writes the reports (without verdicts) and then exits 2.
type triageAbortedError struct {
	failed int
	cause  string
}

func (e *triageAbortedError) Error() string {
	return fmt.Sprintf("AI review aborted after %d failed finding(s) with no success: %s\n"+
		"  check the API key, --llm-base-url / --llm-provider and --llm-model, then re-run",
		e.failed, e.cause)
}

// fatalLLMError reports failures that no retry or later finding can fix: a rejected
// credential or exhausted credits.
func fatalLLMError(err error) bool {
	var he *llm.HTTPError
	if errors.As(err, &he) {
		return he.Status == 401 || he.Status == 402
	}
	return false
}

// oneLine trims an error to a single readable line for the run log.
func oneLine(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
