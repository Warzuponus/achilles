package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/triage"
)

// RunOutcome is one triage→judge pass over one case.
type RunOutcome struct {
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Refuted        bool    `json:"refuted"`
	// Surfaced is what the product would actually do with this verdict:
	// Verdict.Surfaced() — an unrefuted true_positive at >= 0.7, OR a
	// false_positive the judge overturned. Scoring on this rather than on the raw
	// classification is deliberate, because it is the whole shipped chain (triage
	// prompt + judge + threshold) that decides whether a human ever sees the
	// finding.
	Surfaced  bool   `json:"surfaced"`
	Predicted Label  `json:"predicted"`
	Correct   bool   `json:"correct"`
	LatencyMS int64  `json:"latencyMs"`
	Err       string `json:"error,omitempty"`
}

// VerdictResult aggregates the repeats for one case.
type VerdictResult struct {
	CaseID    string       `json:"caseId"`
	Label     Label        `json:"label"`
	Why       string       `json:"why"`
	Runs      []RunOutcome `json:"runs"`
	Predicted Label        `json:"predicted"` // majority across repeats
	Correct   bool         `json:"correct"`
	// Unstable marks a case whose repeats disagreed — a model that flips on the
	// same input is a finding in its own right, and averaging hides it.
	Unstable bool `json:"unstable,omitempty"`
}

// VerdictReport is the scored result of a verdict run.
type VerdictReport struct {
	Mode string `json:"mode"`
	// Model is the default/fallback model. It is NOT the whole story: production
	// routes tasks to different models, so Routing records what each pass actually
	// used — a report claiming one model name would misattribute the score.
	Routing map[string]string `json:"routing,omitempty"`
	Model   string            `json:"model"`
	Repeat  int               `json:"repeat"`

	Cases   int `json:"cases"`
	TPCases int `json:"tpCases"`
	FPCases int `json:"fpCases"`

	Correct  int     `json:"correct"`
	Accuracy float64 `json:"accuracy"`
	// TPRecall is the share of genuine issues surfaced (missing these is the
	// expensive failure). FPSuppression is the share of safe-but-flagged findings
	// correctly kept quiet (the noise the product exists to remove).
	TPRecall         float64 `json:"tpRecall"`
	FPSuppression    float64 `json:"fpSuppression"`
	BalancedAccuracy float64 `json:"balancedAccuracy"`

	MeanConfidenceCorrect float64 `json:"meanConfidenceCorrect"`
	MeanConfidenceWrong   float64 `json:"meanConfidenceWrong"`
	// CalibrationGap is |mean confidence - accuracy|. A well-calibrated triager
	// is about as confident as it is right; a large gap means the confidence
	// number cannot be trusted for gating.
	CalibrationGap float64 `json:"calibrationGap"`

	Unstable int `json:"unstableCases"`
	Errors   int `json:"errors"`

	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`

	Results []VerdictResult `json:"results"`
}

// Runner executes verdict mode against a live model.
type Runner struct {
	Engine *triage.Engine
	// Repeat runs each case N times. Models are nondeterministic, so a single
	// pass cannot distinguish a real change from run-to-run noise.
	Repeat int
	// Progress, when set, is called as each case completes.
	Progress func(caseID string, done, total int)
}

// Run scores every case in the corpus. The engine should be built WITHOUT a
// calibrator: calibration resolves findings from prior feedback, which would
// short-circuit the very thing being measured.
func (rn Runner) Run(ctx context.Context, c Corpus, runID string) VerdictReport {
	repeat := rn.Repeat
	if repeat < 1 {
		repeat = 1
	}
	cases := c.SortedCases()
	tp, fp := c.Counts()
	rep := VerdictReport{Mode: "verdict", Repeat: repeat, Cases: len(cases), TPCases: tp, FPCases: fp}

	var confCorrect, confWrong []float64
	var allConf []float64
	tpHit, fpHit := 0, 0

	for i, cs := range cases {
		res := VerdictResult{CaseID: cs.ID, Label: cs.Label, Why: cs.Why}
		votes := map[Label]int{}

		for r := 0; r < repeat; r++ {
			f := cs.ToFinding()
			started := time.Now()
			err := rn.Engine.Triage(ctx, runID, &f)
			out := RunOutcome{LatencyMS: time.Since(started).Milliseconds()}

			switch {
			case err != nil:
				out.Err = err.Error()
				rep.Errors++
				// An unusable verdict is not a correct one; count it as the
				// opposite of the label so failures can never flatter a score.
				out.Predicted = flip(cs.Label)
			case f.Verdict == nil:
				out.Err = "no verdict attached"
				rep.Errors++
				out.Predicted = flip(cs.Label)
			default:
				v := *f.Verdict
				out.Classification = string(v.Classification)
				out.Confidence = v.Confidence
				out.Refuted = v.Refuted
				out.Surfaced = v.Surfaced()
				out.Predicted = LabelFP
				if out.Surfaced {
					out.Predicted = LabelTP
				}
				allConf = append(allConf, v.Confidence)
			}
			out.Correct = out.Predicted == cs.Label
			if out.Err == "" {
				if out.Correct {
					confCorrect = append(confCorrect, out.Confidence)
				} else {
					confWrong = append(confWrong, out.Confidence)
				}
			}
			votes[out.Predicted]++
			res.Runs = append(res.Runs, out)
		}

		res.Predicted = LabelFP
		if votes[LabelTP] > votes[LabelFP] {
			res.Predicted = LabelTP
		}
		res.Correct = res.Predicted == cs.Label
		res.Unstable = votes[LabelTP] > 0 && votes[LabelFP] > 0

		if res.Correct {
			rep.Correct++
			switch cs.Label {
			case LabelTP:
				tpHit++
			case LabelFP:
				fpHit++
			}
		}
		if res.Unstable {
			rep.Unstable++
		}
		rep.Results = append(rep.Results, res)
		if rn.Progress != nil {
			rn.Progress(cs.ID, i+1, len(cases))
		}
	}

	if rep.Cases > 0 {
		rep.Accuracy = float64(rep.Correct) / float64(rep.Cases)
	}
	if tp > 0 {
		rep.TPRecall = float64(tpHit) / float64(tp)
	}
	if fp > 0 {
		rep.FPSuppression = float64(fpHit) / float64(fp)
	}
	// Balanced accuracy weights both classes equally, so a triager that just says
	// "true_positive" to everything scores 0.5 instead of looking respectable on
	// a TP-heavy corpus.
	switch {
	case tp > 0 && fp > 0:
		rep.BalancedAccuracy = (rep.TPRecall + rep.FPSuppression) / 2
	default:
		rep.BalancedAccuracy = rep.Accuracy
	}
	rep.MeanConfidenceCorrect = mean(confCorrect)
	rep.MeanConfidenceWrong = mean(confWrong)
	if len(allConf) > 0 {
		rep.CalibrationGap = abs(mean(allConf) - rep.Accuracy)
	}

	u := rn.Engine.Usage()
	rep.PromptTokens, rep.CompletionTokens = u.PromptTokens, u.CompletionTokens
	return rep
}

func flip(l Label) Label {
	if l == LabelTP {
		return LabelFP
	}
	return LabelTP
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// ErrorRate is the share of runs that failed outright (transport, entitlement, or
// unparseable output) rather than producing a verdict.
func (r VerdictReport) ErrorRate() float64 {
	total := r.Cases * r.Repeat
	if total == 0 {
		return 0
	}
	return float64(r.Errors) / float64(total)
}

// Unreliable reports whether enough runs failed that the scores describe our
// plumbing rather than the model. Errors count as wrong so a broken run can never
// flatter a score — but that also means a run where nothing succeeded prints 0%,
// which reads like a capability finding. A `kimi-k3` screen once returned exactly
// that: 54/54 HTTP 402s and a headline "balanced accuracy 0.0%". The number was
// arithmetically right and completely misleading.
func (r VerdictReport) Unreliable() bool { return r.ErrorRate() >= 0.2 }

// Write renders the verdict report for a terminal.
func (r VerdictReport) Write(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "Triage verdict accuracy — %d case(s) x %d repeat(s)\n", r.Cases, r.Repeat)
	if r.Unreliable() {
		fmt.Fprintf(w, "\n  *** SCORES BELOW ARE NOT A MODEL RESULT ***\n")
		fmt.Fprintf(w, "  %.0f%% of runs FAILED (%d of %d). Fix the failures and re-run before\n",
			100*r.ErrorRate(), r.Errors, r.Cases*r.Repeat)
		fmt.Fprintf(w, "  comparing these numbers to anything — a run that could not reach the\n")
		fmt.Fprintf(w, "  model still scores 0%%, which is a plumbing fact, not a capability one.\n")
	}
	if len(r.Routing) == 0 {
		fmt.Fprintf(w, "  model: %s\n\n", r.Model)
	} else {
		// Name every pass: the score belongs to the routing, not to one model.
		tasks := make([]string, 0, len(r.Routing))
		for task := range r.Routing {
			tasks = append(tasks, task)
		}
		sort.Strings(tasks)
		fmt.Fprintf(w, "  routing: ")
		for i, task := range tasks {
			if i > 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%s=%s", task, r.Routing[task])
		}
		fmt.Fprintf(w, "\n\n")
	}
	fmt.Fprintf(w, "  balanced accuracy:   %.1f%%   <- the headline (both classes weighted equally)\n", 100*r.BalancedAccuracy)
	fmt.Fprintf(w, "  accuracy:            %.1f%%  (%d/%d)\n", 100*r.Accuracy, r.Correct, r.Cases)
	fmt.Fprintf(w, "  TP recall:           %.1f%%  (genuine issues surfaced, %d TP case(s))\n", 100*r.TPRecall, r.TPCases)
	fmt.Fprintf(w, "  FP suppression:      %.1f%%  (safe code kept quiet, %d FP case(s))\n", 100*r.FPSuppression, r.FPCases)
	// A mean over no samples is not 0.00 — printing it as a number invites reading
	// "no wrong answers" as "wrong answers had zero confidence".
	fmt.Fprintf(w, "  confidence when right/wrong: %s / %s\n",
		confStr(r.MeanConfidenceCorrect, r.Correct > 0),
		confStr(r.MeanConfidenceWrong, r.Correct < r.Cases))
	fmt.Fprintf(w, "  calibration gap:     %.2f  (|mean confidence - accuracy|; lower is better)\n", r.CalibrationGap)
	if r.Repeat > 1 {
		fmt.Fprintf(w, "  unstable cases:      %d  (repeats disagreed on the same input)\n", r.Unstable)
	}
	if r.Errors > 0 {
		fmt.Fprintf(w, "  errors:              %d  (counted as wrong, never as correct)\n", r.Errors)
	}
	fmt.Fprintf(w, "  tokens:              %d prompt + %d completion\n", r.PromptTokens, r.CompletionTokens)

	var wrong []VerdictResult
	for _, res := range r.Results {
		if !res.Correct {
			wrong = append(wrong, res)
		}
	}
	if len(wrong) > 0 {
		fmt.Fprintf(w, "\n  wrong answers:\n")
		for _, res := range wrong {
			got := "—"
			if len(res.Runs) > 0 {
				got = res.Runs[0].Classification
				if res.Runs[0].Err != "" {
					got = "error: " + res.Runs[0].Err
				}
			}
			fmt.Fprintf(w, "    %-28s expected %s, got %s (surfaced=%v)\n",
				res.CaseID, res.Label, got, res.Predicted == LabelTP)
			fmt.Fprintf(w, "      ground truth: %s\n", trimWhy(res.Why))
		}
	}
	if verbose {
		fmt.Fprintf(w, "\n  %-28s %-8s %-10s %6s %5s\n", "CASE", "EXPECTED", "PREDICTED", "CONF", "OK")
		for _, res := range r.Results {
			conf := 0.0
			if len(res.Runs) > 0 {
				conf = res.Runs[0].Confidence
			}
			ok := "no"
			if res.Correct {
				ok = "yes"
			}
			fmt.Fprintf(w, "  %-28s %-8s %-10s %6.2f %5s\n", res.CaseID, res.Label, res.Predicted, conf, ok)
		}
	}
}

// confStr renders a mean confidence, or "n/a" when the set it averages is empty.
func confStr(v float64, any bool) string {
	if !any {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", v)
}

func trimWhy(s string) string {
	out := ""
	for _, w := range splitWords(s) {
		if len(out)+len(w)+1 > 110 {
			return out + " …"
		}
		if out != "" {
			out += " "
		}
		out += w
	}
	return out
}

func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// WriteJSON persists the report for later comparison.
func (r VerdictReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// LoadVerdictReport reads a persisted verdict report.
func LoadVerdictReport(path string) (VerdictReport, error) {
	data, err := readFile(path)
	if err != nil {
		return VerdictReport{}, err
	}
	var r VerdictReport
	if err := json.Unmarshal(data, &r); err != nil {
		return VerdictReport{}, fmt.Errorf("parse verdict report %s: %w", path, err)
	}
	return r, nil
}

// CompareVerdict prints what changed between two verdict runs, including which
// individual cases flipped — the aggregate can hold still while cases churn
// underneath it.
func CompareVerdict(base, cur VerdictReport, w io.Writer) {
	fmt.Fprintf(w, "\nvs baseline (%s -> %s):\n", routingLabel(base), routingLabel(cur))
	fmt.Fprintf(w, "  balanced accuracy: %.1f%% -> %.1f%%  (%+.1f pp)\n",
		100*base.BalancedAccuracy, 100*cur.BalancedAccuracy,
		100*(cur.BalancedAccuracy-base.BalancedAccuracy))
	fmt.Fprintf(w, "  TP recall:         %.1f%% -> %.1f%%  (%+.1f pp)\n",
		100*base.TPRecall, 100*cur.TPRecall, 100*(cur.TPRecall-base.TPRecall))
	fmt.Fprintf(w, "  FP suppression:    %.1f%% -> %.1f%%  (%+.1f pp)\n",
		100*base.FPSuppression, 100*cur.FPSuppression, 100*(cur.FPSuppression-base.FPSuppression))
	fmt.Fprintf(w, "  calibration gap:   %.2f -> %.2f  (%+.2f)\n",
		base.CalibrationGap, cur.CalibrationGap, cur.CalibrationGap-base.CalibrationGap)
	fmt.Fprintf(w, "  tokens:            %d -> %d  (%+.1f%%)\n",
		base.PromptTokens, cur.PromptTokens, pctChange(base.PromptTokens, cur.PromptTokens))

	byID := map[string]VerdictResult{}
	for _, res := range base.Results {
		byID[res.CaseID] = res
	}
	var fixed, broken []string
	for _, res := range cur.Results {
		b, ok := byID[res.CaseID]
		if !ok {
			continue
		}
		switch {
		case !b.Correct && res.Correct:
			fixed = append(fixed, res.CaseID)
		case b.Correct && !res.Correct:
			broken = append(broken, res.CaseID)
		}
	}
	if len(fixed) > 0 {
		fmt.Fprintf(w, "  now correct:       %v\n", fixed)
	}
	if len(broken) > 0 {
		fmt.Fprintf(w, "  REGRESSED:         %v\n", broken)
	}
	if len(fixed) == 0 && len(broken) == 0 {
		fmt.Fprintf(w, "  no per-case changes\n")
	}
	if base.Repeat < 2 || cur.Repeat < 2 {
		fmt.Fprintf(w, "\n  NOTE: with --repeat < 2, a small delta here is indistinguishable\n")
		fmt.Fprintf(w, "        from run-to-run model noise.\n")
	}
}

// routingLabel names what produced a report, preferring the per-task routing over
// the fallback model so a diff between two runs says what actually changed.
func routingLabel(r VerdictReport) string {
	if len(r.Routing) == 0 {
		return r.Model
	}
	tasks := make([]string, 0, len(r.Routing))
	for t := range r.Routing {
		tasks = append(tasks, t)
	}
	sort.Strings(tasks)
	parts := make([]string, 0, len(tasks))
	for _, t := range tasks {
		parts = append(parts, t+"="+r.Routing[t])
	}
	return strings.Join(parts, ",")
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
