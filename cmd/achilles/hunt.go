package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Warzuponus/achilles/internal/deep"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/vcs"
)

// errHuntNoCode is the refusal for --hunt with --llm-no-code: a hunt reads source
// files, which that flag promises never to send.
var errHuntNoCode = errors.New("--hunt lets the model read files from the repository, which --llm-no-code forbids; " +
	"drop one of the two flags (hunt mode was NOT run)")

// huntNearScanner is how close (in lines, same file) a hunted candidate may be to
// a scanner finding before it is taken to be the same issue and dropped.
const huntNearScanner = 2

// huntFindings runs hunt mode: from up to --hunt entry points, the model follows
// the data with the deep-verification tools and reports what it can trace to a
// dangerous operation. Each candidate becomes a finding marked Hunted and is
// reviewed by triage like any other; PartitionUnconfirmedHunts later moves those
// the review did not confirm into Scan.Hunted, where they never gate the build.
//
// Call it before correlation and triage, after every filter that removes findings
// (diff, baseline, suppressions): a hunted finding is new by construction, and a
// --diff run hunts only in the files it changed.
func huntFindings(ctx context.Context, o *options, ev vault.Store, runID string, scan *model.Scan) error {
	return runHunt(ctx, o, ev, runID, scan, os.Stderr)
}

func runHunt(ctx context.Context, o *options, ev vault.Store, runID string, scan *model.Scan, w io.Writer) error {
	switch {
	case o.hunt < 0:
		return fmt.Errorf("--hunt must not be negative")
	case o.hunt == 0:
		return nil
	case o.llmNoCode:
		return errHuntNoCode
	}
	tasks, err := loadTaskRouting(o.modelConfig)
	if err != nil {
		return err
	}
	// `hunt` in --model-config picks the model; else `deep`; else the triage model.
	baseURL, modelName := o.llmBaseURL, o.llmModel
	for _, task := range []string{"deep", "hunt"} {
		if tm, ok := tasks[task]; ok {
			if tm.Model != "" {
				modelName = tm.Model
			}
			if tm.BaseURL != "" {
				baseURL = tm.BaseURL
			}
		}
	}

	cfg := deepConfig(o, scan.Target)
	cfg.MaxSteps = o.huntMaxSteps
	cfg = cfg.WithDefaults()
	var only map[string]bool
	if o.diffRef != "" {
		changed, err := vcs.ChangedFiles(scan.Target, o.diffRef)
		if err != nil {
			return fmt.Errorf("--hunt with --diff: %w", err)
		}
		only = map[string]bool{}
		for _, f := range changed {
			only[filepath.ToSlash(f)] = true
		}
	}

	// Seeds come from a walk that needs no model, so a dry run can count them.
	seeder, err := deep.New(noModel{}, scan.Target, cfg)
	if err != nil {
		return err
	}
	seeds := seeder.Seeds(o.hunt, only)
	if len(seeds) == 0 {
		fmt.Fprintln(w, "achilles: hunt — no entry point found to start from (HTTP routes, request handlers, consumers)")
		return nil
	}
	if o.dryRun {
		prompt, completion := deep.EstimateTokens(cfg)
		fmt.Fprintf(w, "achilles: dry run — hunt mode would start from %d entry point(s): up to %d tool call(s) each, "+
			"upper bound ~%d prompt + %d completion token(s) in total, plus the AI review of what it reports "+
			"(read-only; it reads repository files and sends redacted excerpts to the model). No model was called.\n",
			len(seeds), cfg.MaxSteps, prompt*len(seeds), completion*len(seeds))
		return nil
	}
	if modelName == "" {
		return fmt.Errorf("--hunt requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	factory, err := newLLMFactory()
	if err != nil {
		return err
	}
	cfg.Budget = deep.NewBudget(int64(len(seeds)) * int64(cfg.TotalBytes))
	hunter, err := deep.New(factory(baseURL, modelName), scan.Target, cfg)
	if err != nil {
		return err
	}

	type outcome struct {
		r   deep.HuntResult
		err error
		ran bool
	}
	results := make([]outcome, len(seeds))
	sem := make(chan struct{}, max(o.llmConcurrency, 1))
	var wg sync.WaitGroup
	huntCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, sd := range seeds {
		if huntCtx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, sd deep.HuntSeed) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := hunter.Hunt(huntCtx, sd)
			results[i] = outcome{r: r, err: err, ran: true}
			if err != nil && (fatalLLMError(err) || errors.Is(err, errCostCap)) {
				cancel()
			}
		}(i, sd)
	}
	wg.Wait()

	var added, near, aborted, failed, notReached, toolCalls int
	for i, res := range results {
		switch {
		case !res.ran:
			notReached++
			continue
		case res.err != nil:
			if huntCtx.Err() == nil || !errors.Is(res.err, context.Canceled) {
				failed++
				fmt.Fprintf(w, "achilles: hunt from %s:%d failed: %s\n", seeds[i].File, seeds[i].Line, oneLine(res.err))
			} else {
				notReached++
			}
			continue
		}
		toolCalls += res.r.Steps
		if res.r.Aborted != "" {
			aborted++
		}
		recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindLLMCall, Source: "hunt",
			PromptVersion: deep.HuntPromptVersion},
			map[string]any{"task": "hunt", "model": modelName, "hunt": res.r})
		for _, c := range res.r.Candidates {
			if nearScannerFinding(scan.Findings, c.File, c.Line) {
				near++
				continue
			}
			f := deep.HuntFinding(c, res.r.Seed)
			f.ID = model.ComputeID(f.Tool, f.RuleID, f.Location)
			f.Fingerprint = model.ComputeFingerprint(f.Tool, f.RuleID, f.Location.File, sourceLine(scan.Target, c.File, c.Line))
			scan.Findings = append(scan.Findings, f)
			added++
		}
	}
	u := hunter.Usage()
	recordJSON(ev, vault.Record{RunID: runID, Phase: "triage", Kind: vault.KindScanMeta, Source: "llm-usage-hunt"},
		map[string]any{"promptTokens": u.PromptTokens, "completionTokens": u.CompletionTokens, "totalTokens": u.TotalTokens,
			"toolCalls": toolCalls, "seeds": len(seeds)})
	fmt.Fprintf(w, "achilles: hunt — %d entry point(s) followed with %d tool call(s) and %d token(s): "+
		"%d candidate(s) added for review, %d already reported by a scanner, %d aborted, %d failed, %d not reached. "+
		"Candidates the review does not confirm are listed apart and never gate the build.\n",
		len(seeds)-notReached-failed, toolCalls, u.TotalTokens, added, near, aborted, failed, notReached)
	return nil
}

// nearScannerFinding reports whether a scanner already reported something within
// huntNearScanner lines of file:line.
func nearScannerFinding(fs []model.Finding, file string, line int) bool {
	for _, f := range fs {
		if f.Hunted || filepath.ToSlash(f.Location.File) != file {
			continue
		}
		if d := f.Location.Region.StartLine - line; d >= -huntNearScanner && d <= huntNearScanner {
			return true
		}
	}
	return false
}

// sourceLine is the text of one line of a file under root, for a fingerprint that
// survives the line moving. Empty when it cannot be read.
func sourceLine(root, file string, line int) string {
	r, err := os.OpenRoot(root)
	if err != nil {
		return ""
	}
	defer r.Close()
	f, err := r.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if n == line {
			return strings.TrimSpace(sc.Text())
		}
	}
	return ""
}

// noModel is the client of a Verifier used only to find seeds; it is never called.
type noModel struct{}

func (noModel) Complete(context.Context, llm.Request) (llm.Response, error) {
	return llm.Response{}, errors.New("hunt: seed walk made a model call")
}
