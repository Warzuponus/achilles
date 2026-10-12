package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/deep"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// errDeepNoCode is the refusal for --deep-verify with --llm-no-code: the deep pass
// exists to read source files, which that flag promises never to send.
var errDeepNoCode = errors.New("--deep-verify lets the model read files from the repository, which --llm-no-code forbids; " +
	"drop one of the two flags (deep verification was NOT run)")

// deepVerifyFindings runs the bounded, read-only deep verification (internal/deep)
// over the findings that matter most and folds each outcome into its finding with
// deep.Apply. It is a no-op when --deep-verify is 0.
//
// Ordering: call it AFTER the first triage pass (it needs the verdicts to choose
// findings and to merge safely) and BEFORE scan.PartitionDismissed, so a deep
// confirmation can rescue a finding triage had dismissed and a deep dismissal that
// passes the safe-merge policy is moved out with the rest.
func deepVerifyFindings(ctx context.Context, o *options, ev vault.Store, runID string, scan *model.Scan) error {
	return runDeepVerify(ctx, o, ev, runID, scan, os.Stderr)
}

func runDeepVerify(ctx context.Context, o *options, ev vault.Store, runID string, scan *model.Scan, w io.Writer) error {
	if o.deepVerify < 0 {
		return fmt.Errorf("--deep-verify must not be negative")
	}
	if o.deepVerify == 0 {
		return nil
	}
	if o.llmNoCode {
		return errDeepNoCode
	}

	// Per-task routing: `deep` in --model-config picks a model (and endpoint) for
	// this pass; otherwise it uses the triage model.
	tasks, err := loadTaskRouting(o.modelConfig)
	if err != nil {
		return err
	}
	baseURL, modelName := o.llmBaseURL, o.llmModel
	if tm, ok := tasks["deep"]; ok {
		if tm.Model != "" {
			modelName = tm.Model
		}
		if tm.BaseURL != "" {
			baseURL = tm.BaseURL
		}
	}

	cfg := deepConfig(o, scan.Target).WithDefaults()
	idx := deep.Select(scan.Findings, o.deepVerify)
	if len(idx) == 0 {
		fmt.Fprintf(w, "achilles: deep verification — no finding qualifies (credential findings are never sent to a model)\n")
		return nil
	}

	if o.dryRun {
		prompt, completion := deep.EstimateTokens(cfg)
		fmt.Fprintf(w, "achilles: dry run — deep verification would examine %d of %d finding(s): up to %d tool call(s) each, "+
			"upper bound ~%d prompt + %d completion token(s) in total (read-only; it reads repository files and sends redacted excerpts to the model). No model was called.\n",
			len(idx), len(scan.Findings), cfg.MaxSteps, prompt*len(idx), completion*len(idx))
		return nil
	}
	if modelName == "" {
		return fmt.Errorf("--deep-verify requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return err
	}
	cfg.Budget = deep.NewBudget(int64(len(idx)) * int64(cfg.TotalBytes))
	verifier, err := deep.New(factory(baseURL, modelName), scan.Target, cfg)
	if err != nil {
		return err
	}

	type outcome struct {
		d   model.DeepVerification
		err error
		ran bool
	}
	results := make([]outcome, len(idx))
	workers := max(o.llmConcurrency, 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	llmCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for n, i := range idx {
		if llmCtx.Err() != nil {
			break // out of time or a fatal error: the rest are "not reached"
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(n int, f model.Finding) { // f is a copy: nothing mutates the scan until all workers are done
			defer wg.Done()
			defer func() { <-sem }()
			d, err := verifier.Deep(llmCtx, f)
			results[n] = outcome{d: d, err: err, ran: true}
			if err != nil && (fatalLLMError(err) || errors.Is(err, errCostCap)) {
				cancel()
			}
		}(n, scan.Findings[i])
	}
	wg.Wait()

	// Apply and record on one goroutine: Apply mutates the scan and recordJSON keeps
	// unsynchronized failure counters.
	var confirmed, dismissals, contested, uncertain, aborted, failed, notReached, toolCalls int
	for n, i := range idx {
		r := results[n]
		f := &scan.Findings[i]
		switch {
		case !r.ran:
			notReached++
			continue
		case r.err != nil:
			if llmCtx.Err() == nil || !errors.Is(r.err, context.Canceled) {
				failed++
				fmt.Fprintf(w, "achilles: deep verification failed for %s: %s\n", f.RuleID, oneLine(r.err))
			} else {
				notReached++
			}
			continue
		}
		toolCalls += r.d.Steps
		before := f.Verdict
		var beforeCopy model.Verdict
		if before != nil {
			beforeCopy = *before
		}
		wasDismissed := f.Dismissed()
		deep.Apply(f, r.d)

		switch {
		case r.d.Aborted != "":
			aborted++
		case r.d.Conclusion == model.ClassTruePositive:
			confirmed++
		case r.d.Conclusion == model.ClassFalsePositive && f.Dismissed() && !wasDismissed:
			dismissals++
		case r.d.Conclusion == model.ClassFalsePositive && f.Verdict != nil && f.Verdict.Classification == model.ClassUncertain:
			contested++
		default:
			uncertain++
		}

		recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindLLMCall, Source: "deep-verify",
			PromptVersion: deep.PromptVersion, Fingerprint: f.Fingerprint},
			map[string]any{"task": "deep", "model": modelName, "deep": r.d})
		if f.Verdict != nil && (before == nil || !reflect.DeepEqual(beforeCopy, *f.Verdict)) {
			// Same payload shape as a triage verdict, so anything that rebuilds a run
			// from the vault picks the merged verdict up as the latest one.
			recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindVerdict, Source: "deep-verify",
				PromptVersion: deep.PromptVersion, Fingerprint: f.Fingerprint}, f.Verdict)
		}
	}

	u := verifier.Usage()
	recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindScanMeta, Source: "llm-usage-deep"},
		map[string]any{"promptTokens": u.PromptTokens, "completionTokens": u.CompletionTokens, "totalTokens": u.TotalTokens,
			"toolCalls": toolCalls, "toolBytesBudget": cfg.Budget.Left()})

	fmt.Fprintf(w, "achilles: deep verification — %d finding(s) examined with %d tool call(s) and %d token(s): "+
		"%d confirmed, %d support dismissal, %d contested (left uncertain), %d inconclusive, %d aborted, %d failed, %d not reached\n",
		len(idx)-notReached-failed, toolCalls, u.TotalTokens, confirmed, dismissals, contested, uncertain, aborted, failed, notReached)
	if notReached > 0 && ctx.Err() != nil {
		fmt.Fprintln(w, "achilles: the --llm-budget ran out during deep verification; the findings were taken most important first.")
	}
	return nil
}

// deepConfig builds the verifier limits from the flags. The vault file and the
// Achilles state directory are denied to the tools even when they sit inside the
// scanned tree.
func deepConfig(o *options, target string) deep.Config {
	cfg := deep.Config{MaxSteps: o.deepMaxSteps}
	cfg.DenyPaths = append(cfg.DenyPaths, filepath.Join(target, ".achilles"))
	for _, p := range []string{o.vaultPath, o.ruleRepoDir} {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
		}
		cfg.DenyPaths = append(cfg.DenyPaths, p)
	}
	return cfg
}
