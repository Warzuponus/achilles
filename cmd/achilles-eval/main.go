// Command achilles-eval measures the triage layer against a labeled corpus, so a
// change to prompts, context, or model routing can be proven rather than argued
// (DESIGN.md §8 "Metrics we track to prove it's working").
//
// It is a SEPARATE binary from `achilles` for the same reason achilles-fleet is:
// the eval harness is developer/CI tooling, not part of the scanning engine, and
// nothing in a customer scan should be able to reach it.
//
// Modes:
//
//	achilles-eval --mode context                      # hermetic: no model, no key, CI-safe
//	achilles-eval --mode verdict --llm-model MODEL     # needs a live model
//	achilles-eval --mode detect                        # recall on known-vulnerable code; needs the real scanners
//	achilles-eval --mode juice-shop                    # precision and recall on OWASP Juice Shop (see juiceshop.go)
//
// All write JSON with --out and diff against a previous run with --baseline,
// which is the point: a metric with no baseline proves nothing. The detect mode
// (see detect.go) measures scanner RECALL and traces every miss to the pipeline
// stage that lost it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/enrich"
	"github.com/Warzuponus/achilles/internal/eval"
	"github.com/Warzuponus/achilles/internal/threatmodel"
	"github.com/Warzuponus/achilles/internal/triage"
	"github.com/Warzuponus/achilles/internal/triage/llm"
	"github.com/Warzuponus/achilles/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "achilles-eval: "+err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("achilles-eval", flag.ContinueOnError)
	var (
		corpusPath = fs.String("corpus", "evals/triage/corpus.yaml", "labeled corpus manifest")
		mode       = fs.String("mode", "context", "context (hermetic, no model) | corpus (no model, needs gosec/bandit) | detect (recall + miss tracing; needs the real scanners) | owasp (OWASP Benchmark scorecard, Java or Python; needs --owasp-dir) | juice-shop (precision and recall on OWASP Juice Shop, out of sample) | verdict | remediate | threat-model (these three need a live model)")
		outPath    = fs.String("out", "", "write the report as JSON to this file")
		basePath   = fs.String("baseline", "", "compare against a previously written JSON report")
		verbose    = fs.Bool("verbose", false, "print a per-case table")
		failOnReg  = fs.Bool("fail-on-regression", false, "with --baseline: exit non-zero if any case lost evidence coverage")
		repeat     = fs.Int("repeat", 1, "verdict mode: run each case N times (models are nondeterministic)")

		contextRadius = fs.Int("context-radius", 3, "minimum lines of context either side (matches the scan default)")
		maxScope      = fs.Int("max-scope-lines", 0, "cap on enclosing-scope context; 0 = the enricher default, -1 = disable scope widening")

		baseURL     = fs.String("llm-base-url", envOr("ACHILLES_LLM_BASE_URL", "https://api.openai.com/v1"), "OpenAI-compatible base URL")
		llmModel    = fs.String("llm-model", os.Getenv("ACHILLES_LLM_MODEL"), "model under test (required for --mode verdict)")
		judgeModel  = fs.String("llm-judge-model", "", "model for the judge pass (default: same as --llm-model)")
		modelConfig = fs.String("model-config", "", "per-task model-routing YAML — the right way to eval production, since triage and judge routinely use different models")
		llmAuth     = fs.String("llm-auth", envOr("ACHILLES_LLM_AUTH", "key"), "credential: key (Bearer, from ACHILLES_LLM_API_KEY; optional for local runtimes) | api-key (Azure `api-key:` header) | none")
		vaultPath   = fs.String("vault", ".achilles/eval-vault.jsonl", "record every raw LLM response here, so a failed screen is diagnosable")
		noVault     = fs.Bool("no-vault", false, "do not record raw LLM responses (loses the ability to explain a bad screen)")
		timeout     = fs.Duration("timeout", 30*time.Minute, "overall timeout for a verdict run")
	)
	dflags := registerDetectFlags(fs)
	owaspDir := fs.String("owasp-dir", "", "owasp: a checkout of github.com/OWASP-Benchmark/BenchmarkJava or BenchmarkPython")
	juiceDir := fs.String("juice-shop-dir", "", "juice-shop: a checkout of OWASP Juice Shop at the pinned commit (default: check it out into --cache-dir)")
	juiceTruth := fs.String("juice-shop-truth", "evals/juice-shop/truth.json", "juice-shop: the pinned commit, the out-of-reach challenges and the hand judgements")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: achilles-eval [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Measures triage quality against a labeled corpus (--mode context|verdict|...) and\n")
		fmt.Fprintf(fs.Output(), "scanner recall against known-vulnerable code (--mode detect).\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *mode == "juice-shop" {
		return runJuiceShop(*juiceDir, *juiceTruth, dflags.achillesBin, dflags.cacheDir, *outPath, *timeout)
	}
	if *mode == "owasp" {
		return runOWASP(*owaspDir, dflags.achillesBin, dflags.cacheDir, *outPath, *timeout)
	}
	if *mode == "detect" {
		// Detect mode has its own ground truth and needs no triage corpus.
		explicit := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		return runDetect(detectArgs{
			flags: *dflags, explicit: explicit,
			out: *outPath, baseline: *basePath, verbose: *verbose, failOnReg: *failOnReg, repeat: *repeat,
			timeout: *timeout, baseURL: *baseURL, model: *llmModel, judgeModel: *judgeModel,
			modelConfig: *modelConfig, auth: *llmAuth,
		})
	}

	corpus, err := eval.LoadCorpus(*corpusPath)
	if err != nil {
		return err
	}
	tp, fp := corpus.Counts()
	fmt.Fprintf(os.Stderr, "achilles-eval: corpus %s — %d case(s): %d tp / %d fp\n", *corpusPath, len(corpus.Cases), tp, fp)

	en := enrich.New(*contextRadius)
	switch {
	case *maxScope < 0:
		en.MaxScopeLines = 0 // explicit "no scope widening", for before/after runs
	case *maxScope > 0:
		en.MaxScopeLines = *maxScope
	}

	switch *mode {
	case "context":
		return runContext(corpus, en, *outPath, *basePath, *verbose, *failOnReg)
	case "corpus":
		return runCorpusCheck(corpus, *outPath)
	case "verdict", "remediate", "threat-model":
		return runModelMode(*mode, corpus, en, verdictOpts{
			out: *outPath, baseline: *basePath, verbose: *verbose, repeat: *repeat,
			baseURL: *baseURL, model: *llmModel, judge: *judgeModel,
			modelConfig: *modelConfig, auth: *llmAuth, timeout: *timeout,
			vaultPath: *vaultPath, noVault: *noVault,
		})
	default:
		return fmt.Errorf("--mode must be context, corpus, detect, verdict, remediate or threat-model, got %q", *mode)
	}
}

// runCorpusCheck validates the corpus's claims about external tools by running
// those tools. It needs no model and no key, but it does need the scanners — and a
// case it cannot check is reported as skipped, never as a pass, so this stays
// runnable on a machine with neither gosec nor bandit installed.
func runCorpusCheck(corpus eval.Corpus, out string) error {
	rep := eval.ValidateCorpusAgainstTools(corpus, func(id string, done, total int) {
		fmt.Fprintf(os.Stderr, "  [%d/%d] %s\n", done, total, id)
	})
	rep.Write(os.Stdout)
	if out != "" {
		if err := writeJSON(out, rep.WriteJSON); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", out)
	}
	if !rep.Sound() {
		return fmt.Errorf("%d corpus claim(s) contradicted by the tools", rep.Mismatch)
	}
	return nil
}

func runContext(corpus eval.Corpus, en *enrich.Enricher, out, baseline string, verbose, failOnReg bool) error {
	rep := eval.ScoreContext(corpus, en)
	rep.Write(os.Stdout, verbose)

	var regressions []string
	if baseline != "" {
		base, err := eval.LoadContextReport(baseline)
		if err != nil {
			return err
		}
		eval.CompareContext(base, rep, os.Stdout)
		regressions = eval.ContextRegressions(base, rep)
	} else if failOnReg {
		return fmt.Errorf("--fail-on-regression needs --baseline to compare against")
	}
	if out != "" {
		if err := writeJSON(out, rep.WriteJSON); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", out)
	}
	if failOnReg && len(regressions) > 0 {
		return fmt.Errorf("context coverage regressed for %d case(s): %v", len(regressions), regressions)
	}
	return nil
}

type verdictOpts struct {
	out, baseline         string
	verbose               bool
	repeat                int
	baseURL, model, judge string
	modelConfig           string
	auth                  string // key | api-key | none
	timeout               time.Duration
	vaultPath             string
	noVault               bool
}

// runModelMode builds the router once and then dispatches to the seat under test.
// verdict, remediate and threat-model all need the same credential/routing setup,
// and each screens a DIFFERENT seat with its own ground truth — see the package
// docs in internal/eval for why one score cannot cover all three.
func runModelMode(mode string, corpus eval.Corpus, en *enrich.Enricher, o verdictOpts) error {
	if o.model == "" {
		return fmt.Errorf("--mode verdict requires --llm-model (or ACHILLES_LLM_MODEL)")
	}
	// Credential selection is shared with the scanner (llm.NewFactory): the eval
	// must be able to measure the models we actually run, whatever their auth.
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	factory, err := llm.NewFactory(o.auth)
	if err != nil {
		return err
	}

	tasks := map[string]llm.TaskModel{}
	if o.modelConfig != "" {
		mr, err := config.LoadModelRouting(o.modelConfig)
		if err != nil {
			return err
		}
		for name, tm := range mr.Tasks {
			tasks[name] = llm.TaskModel{Model: tm.Model, BaseURL: tm.BaseURL}
		}
	}
	if o.judge != "" && o.judge != o.model {
		if _, ok := tasks["judge"]; !ok {
			tasks["judge"] = llm.TaskModel{Model: o.judge}
		}
	}
	router := llm.BuildRouter(factory(o.baseURL, o.model), tasks, o.baseURL, factory)

	// Record raw LLM responses. Without this a screen can report a bad score and
	// leave no way to tell whether the model sent something wrong or we decoded it
	// wrongly — which is exactly what happened to the threat-model seat, where a
	// blank-category bug took several runs to pin down because this mode passed a
	// nil vault. Recording is additive: nothing READS this vault during a screen.
	//
	// The calibrator stays nil, and that part matters — calibration resolves
	// findings from prior feedback and would short-circuit the behaviour under
	// measurement. A vault alone does not enable it.
	var store vault.Store
	if !o.noVault {
		fst, err := vault.NewFileStore(o.vaultPath)
		if err != nil {
			return fmt.Errorf("eval vault %s: %w", o.vaultPath, err)
		}
		store = fst
		fmt.Fprintf(os.Stderr, "achilles-eval: recording raw LLM responses to %s\n", o.vaultPath)
	}
	eng := triage.NewEngine(router, store, en, corpus.Root)

	switch mode {
	case "remediate":
		rep := eval.RemediationRunner{Engine: eng, Repeat: o.repeat,
			Progress: func(id string, done, total int) {
				fmt.Fprintf(os.Stderr, "  [%d/%d] %s\n", done, total, id)
			}}.Run(ctx, corpus, "eval-"+time.Now().UTC().Format("20060102T150405Z"))
		rep.Model = modelFor("remediation", tasks, o.model)
		rep.Write(os.Stdout, o.verbose)
		if o.out != "" {
			if err := writeJSON(o.out, rep.WriteJSON); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", o.out)
		}
		return nil
	case "threat-model":
		tmEng := threatmodel.NewEngine(router, store)
		rep := eval.ThreatModelRunner{Engine: tmEng, Repeat: o.repeat,
			Progress: func(done, total int) {
				fmt.Fprintf(os.Stderr, "  [%d/%d]\n", done, total)
			}}.Run(ctx, corpus, "eval-"+time.Now().UTC().Format("20060102T150405Z"))
		rep.Model = modelFor("threat-model", tasks, o.model)
		rep.Write(os.Stdout, o.verbose)
		if o.out != "" {
			if err := writeJSON(o.out, rep.WriteJSON); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", o.out)
		}
		return nil
	}

	runner := eval.Runner{
		Engine: eng,
		Repeat: o.repeat,
		Progress: func(id string, done, total int) {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s\n", done, total, id)
		},
	}
	rep := runner.Run(ctx, corpus, "eval-"+time.Now().UTC().Format("20060102T150405Z"))
	rep.Model = o.model
	// Record what each pass really used. Only triage and judge fire in verdict
	// mode, so naming just those two avoids implying the run exercised routing it
	// never touched.
	rep.Routing = map[string]string{}
	for _, task := range []string{"triage", "judge"} {
		if tm, ok := tasks[task]; ok && tm.Model != "" {
			rep.Routing[task] = tm.Model
		} else {
			rep.Routing[task] = o.model
		}
	}
	rep.Write(os.Stdout, o.verbose)

	if o.baseline != "" {
		base, err := eval.LoadVerdictReport(o.baseline)
		if err != nil {
			return err
		}
		eval.CompareVerdict(base, rep, os.Stdout)
	}
	if o.out != "" {
		if err := writeJSON(o.out, rep.WriteJSON); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", o.out)
	}
	return nil
}

// modelFor resolves which model a task will actually use, so a report names the
// seat's model rather than the fallback.
func modelFor(task string, tasks map[string]llm.TaskModel, fallback string) string {
	if tm, ok := tasks[task]; ok && tm.Model != "" {
		return tm.Model
	}
	return fallback
}

func writeJSON(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
