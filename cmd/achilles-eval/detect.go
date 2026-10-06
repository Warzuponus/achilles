package main

// --mode detect: the detection benchmark. See internal/eval/detect_*.go for the
// ground-truth schema, the matching rule and the loss-point analysis, and
// docs/benchmarking.md for the operator's view.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/eval"
	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, " ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// detectFlags are the flags only --mode detect reads.
type detectFlags struct {
	groundTruth    string
	targets        string
	achillesBin    string
	cacheDir       string
	lineTolerance  int
	judge          bool
	ai             bool
	llmProvider    string
	llmNoCode      bool
	exclude        string
	noDefaultExcl  bool
	diff           string
	scanBaseline   string
	scanConfig     string
	scanArgs       stringList
	scanTimeout    time.Duration
	markdown       string
	regressionTol  float64
	requireComplte bool
	noHistory      bool
}

func registerDetectFlags(fs *flag.FlagSet) *detectFlags {
	d := &detectFlags{}
	fs.StringVar(&d.groundTruth, "ground-truth", "evals/detect/ground_truth", "detect: ground-truth file or directory (one JSON per target; *.example.json files are skipped)")
	fs.StringVar(&d.targets, "detect-target", "", "detect: comma-separated target ids to run (default: all)")
	fs.StringVar(&d.achillesBin, "achilles-bin", "", "detect: the achilles binary to benchmark (default: ./bin/achilles, then PATH, else built from ./cmd/achilles)")
	fs.StringVar(&d.cacheDir, "cache-dir", ".achilles/detect-cache", "detect: where git targets are checked out (reused when already at the pinned commit)")
	fs.IntVar(&d.lineTolerance, "line-tolerance", eval.DefaultLineTolerance, "detect: lines a finding may sit outside a labeled range and still match")
	fs.BoolVar(&d.judge, "judge", false, "detect: let a model adjudicate same-place findings whose class/CWE disagrees (needs --llm-model; its detections are reported separately)")
	fs.BoolVar(&d.ai, "ai", false, "detect: run the scans with AI review (--triage) and also score the AI-filtered result; needs an LLM key and --llm-model/--llm-provider. Costs two scans per target")
	fs.StringVar(&d.llmProvider, "llm-provider", os.Getenv("ACHILLES_LLM_PROVIDER"), "detect --ai: endpoint preset passed to achilles (openai | openrouter | ollama)")
	fs.BoolVar(&d.llmNoCode, "llm-no-code", false, "detect --ai: privacy mode passed to achilles")
	fs.StringVar(&d.exclude, "exclude", "", "detect: --exclude passed to achilles (also used to attribute noise-filter losses)")
	fs.BoolVar(&d.noDefaultExcl, "no-default-excludes", false, "detect: pass --no-default-excludes to achilles")
	fs.StringVar(&d.diff, "diff", "", "detect: pass --diff REF to achilles")
	fs.StringVar(&d.scanBaseline, "scan-baseline", "", "detect: pass --baseline FILE (suppression baseline) to achilles; not the same as --baseline, which compares eval reports")
	fs.StringVar(&d.scanConfig, "scan-config", "", "detect: pass --config FILE (tool registry) to achilles")
	fs.Var(&d.scanArgs, "scan-arg", "detect: any other achilles flag, repeatable (the loss-point analysis does not understand what it does)")
	fs.DurationVar(&d.scanTimeout, "scan-timeout", 20*time.Minute, "detect: per-scan timeout")
	fs.StringVar(&d.markdown, "markdown", "", "detect: also write the scorecard as Markdown to this file")
	fs.Float64Var(&d.regressionTol, "regression-tolerance", 0.02, "detect: with --fail-on-regression, the recall drop (fraction; 0.02 = 2 points) tolerated overall and per class")
	fs.BoolVar(&d.requireComplte, "require-complete", false, "detect: exit non-zero if any scanner failed or was missing on any target")
	fs.BoolVar(&d.noHistory, "no-history", false, "detect: do not carry the run history forward from the existing --out file")
	return d
}

type detectArgs struct {
	flags                      detectFlags
	explicit                   map[string]bool
	out, baseline              string
	verbose, failOnReg         bool
	repeat                     int
	timeout                    time.Duration
	baseURL, model, judgeModel string
	modelConfig, auth          string
}

func runDetect(a detectArgs) error {
	d := a.flags
	if a.failOnReg && a.baseline == "" {
		return fmt.Errorf("--fail-on-regression needs --baseline to compare against")
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	truths, err := eval.LoadGroundTruth(d.groundTruth)
	if err != nil {
		return err
	}
	if d.targets != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(d.targets, ",") {
			want[strings.TrimSpace(id)] = true
		}
		var kept []eval.GroundTruth
		for _, g := range truths {
			if want[g.ID] {
				kept = append(kept, g)
				delete(want, g.ID)
			}
		}
		if len(want) > 0 {
			return fmt.Errorf("--detect-target: unknown target id(s) %v", keys(want))
		}
		truths = kept
	}
	entries := 0
	for _, g := range truths {
		entries += len(g.Vulns)
	}
	fmt.Fprintf(os.Stderr, "achilles-eval: detect — %d target(s), %d labeled vulnerabilit(ies) from %s\n", len(truths), entries, d.groundTruth)

	// Refuses unpinned git sources before anything is scanned.
	targets, err := eval.ResolveTargets(ctx, truths, d.cacheDir, eval.ExecGit{})
	if err != nil {
		return err
	}

	bin, err := locateAchilles(ctx, d.achillesBin, d.cacheDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "achilles-eval: scanning with %s\n", bin)

	scanArgs := achillesArgs(d)
	aiArgs, err := achillesAIArgs(a)
	if err != nil {
		return err
	}
	runner := eval.BinaryScanRunner{Bin: bin, Args: scanArgs, AIArgs: aiArgs, Timeout: d.scanTimeout}

	opts := eval.DetectOptions{
		LineTolerance: d.lineTolerance, AI: d.ai,
		Excludes: d.exclude, NoDefaultExcludes: d.noDefaultExcl,
		ScanBaselineUsed: d.scanBaseline != "", DiffUsed: d.diff != "",
		ToolLanguages: toolLanguages(d.scanConfig),
		Repeat:        a.repeat, GroundTruthLabel: d.groundTruth,
		Progress: func(id string, done, total int) {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s\n", done, total, id)
		},
	}
	if d.judge {
		j, err := buildJudge(a)
		if err != nil {
			return err
		}
		opts.Judge = j
	}

	rep := eval.DetectRunner{Scan: runner, Opts: opts}.Run(ctx, targets)

	if a.out != "" && !d.noHistory {
		if prev, err := eval.LoadDetectReport(a.out); err == nil {
			rep.CarryHistory(prev)
		}
	}
	rep.Write(os.Stdout, a.verbose)

	var regressions []string
	if a.baseline != "" {
		base, err := eval.LoadDetectReport(a.baseline)
		if err != nil {
			return err
		}
		eval.CompareDetect(base, rep, os.Stdout)
		regressions = eval.DetectRegressions(base, rep, d.regressionTol)
	}
	if a.out != "" {
		if err := writeJSON(a.out, rep.WriteJSON); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", a.out)
	}
	if d.markdown != "" {
		if err := writeJSON(d.markdown, rep.WriteMarkdown); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "achilles-eval: wrote %s\n", d.markdown)
	}
	if a.failOnReg && len(regressions) > 0 {
		return fmt.Errorf("detection recall regressed beyond %.1f point(s): %s", 100*d.regressionTol, strings.Join(regressions, "; "))
	}
	if d.requireComplte && len(rep.IncompleteTargets) > 0 {
		return fmt.Errorf("incomplete scan on %s: a scanner failed or was missing (see the loss points)", strings.Join(rep.IncompleteTargets, ", "))
	}
	return nil
}

// achillesArgs are the flags every scan gets.
func achillesArgs(d detectFlags) []string {
	var args []string
	if d.exclude != "" {
		args = append(args, "--exclude", d.exclude)
	}
	if d.noDefaultExcl {
		args = append(args, "--no-default-excludes")
	}
	if d.diff != "" {
		args = append(args, "--diff", d.diff)
	}
	if d.scanBaseline != "" {
		args = append(args, "--baseline", d.scanBaseline)
	}
	if d.scanConfig != "" {
		args = append(args, "--config", d.scanConfig)
	}
	return append(args, d.scanArgs...)
}

// achillesAIArgs are added to scans that run with AI review. Only flags the
// operator gave are forwarded, so achilles keeps its own env-driven defaults.
func achillesAIArgs(a detectArgs) ([]string, error) {
	if !a.flags.ai {
		return nil, nil
	}
	if a.model == "" && a.modelConfig == "" {
		return nil, fmt.Errorf("--ai needs a model: set --llm-model (or ACHILLES_LLM_MODEL) or --model-config")
	}
	args := []string{"--triage"}
	add := func(flagName, val string) {
		if val != "" {
			args = append(args, "--"+flagName, val)
		}
	}
	add("llm-model", a.model)
	add("llm-judge-model", a.judgeModel)
	add("model-config", a.modelConfig)
	add("llm-provider", a.flags.llmProvider)
	if a.explicit["llm-base-url"] {
		add("llm-base-url", a.baseURL)
	}
	if a.explicit["llm-auth"] {
		add("llm-auth", a.auth)
	}
	if a.flags.llmNoCode {
		args = append(args, "--llm-no-code")
	}
	return args, nil
}

func buildJudge(a detectArgs) (eval.Judge, error) {
	model := a.judgeModel
	if model == "" {
		model = a.model
	}
	if model == "" {
		return nil, fmt.Errorf("--judge needs a model: set --llm-model (or --llm-judge-model)")
	}
	factory, err := llm.NewFactory(a.auth)
	if err != nil {
		return nil, err
	}
	base := a.baseURL
	if a.flags.llmProvider != "" && !a.explicit["llm-base-url"] {
		if b, err := llm.ProviderBaseURL(a.flags.llmProvider); err == nil {
			base = b
		}
	}
	return eval.LLMJudge{Client: factory(base, model)}, nil
}

// toolLanguages reads each registered tool's declared languages from the registry
// the scans use, so the loss-point analysis can say whether a scanner covers a
// file. nil (unknown) on any error: the analysis then assumes every tool applies.
func toolLanguages(path string) map[string][]string {
	cfg, err := config.Load(path)
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, t := range cfg.Tools {
		out[t.ID] = t.Languages
	}
	return out
}

// locateAchilles finds the binary to benchmark: the explicit flag, ./bin/achilles,
// one on PATH, or — inside the repository — a fresh build in the cache dir.
func locateAchilles(ctx context.Context, flagVal, cacheDir string) (string, error) {
	check := func(p string) (string, bool) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", false
		}
		st, err := os.Stat(abs)
		return abs, err == nil && !st.IsDir()
	}
	if flagVal != "" {
		if abs, ok := check(flagVal); ok {
			return abs, nil
		}
		return "", fmt.Errorf("--achilles-bin %s: not a file (build it with `make build`)", flagVal)
	}
	if abs, ok := check(filepath.Join("bin", "achilles")); ok {
		return abs, nil
	}
	if p, err := exec.LookPath("achilles"); err == nil {
		return p, nil
	}
	if _, err := os.Stat(filepath.Join("cmd", "achilles")); err == nil {
		if err := os.MkdirAll(cacheDir, 0o750); err != nil {
			return "", err
		}
		out, _ := filepath.Abs(filepath.Join(cacheDir, "achilles"))
		fmt.Fprintf(os.Stderr, "achilles-eval: no achilles binary found; building ./cmd/achilles -> %s\n", out)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/achilles") // #nosec G204 -- fixed arguments
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("build achilles: %w", err)
		}
		return out, nil
	}
	return "", fmt.Errorf("no achilles binary: pass --achilles-bin, run `make build`, or put achilles on PATH")
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
