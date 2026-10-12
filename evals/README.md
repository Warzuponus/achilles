# Evals

Ground truth for the triage layer. Until this existed, every change to prompts,
context, or model routing was argued rather than measured — DESIGN §8 promises
"precision/recall of LLM triage vs human ground truth over time", and this is
where that number comes from.

## Two modes, split by what they need

```bash
make eval-context                                 # hermetic: no model, no API key, no cost
make eval-gate                                    # the same, failing if coverage regressed
make eval-corpus                                  # no model, but needs gosec/bandit on PATH
make eval-verdict EVAL_MODEL=<model> EVAL_ARGS="--model-config <routing.yaml> --repeat 3"   # needs a key; spends money
```

**Every model-calling mode records raw LLM responses** to `--vault`
(default `.achilles/eval-vault.jsonl`; `--no-vault` opts out). This is not
optional polish: a screen that reports a bad score without the raw response leaves
you unable to tell whether the model sent something wrong or we decoded it wrongly.
That distinction took several runs to establish for a blank-category bug precisely
because this mode used to pass a nil vault. Nothing reads the vault during a screen
— the calibrator stays disabled, since it would short-circuit what is being measured.

**Eval the routing, not a model.** The verdict target drives a committed
`--model-config`, because triage and judge use *different* models in production
(see `configs/models.ollama.yaml`). A score belongs to that pair, so the report records both rather than one model name.
Evaluating a model you do not actually run measures nothing you care about.

**Context mode** builds the prompt Achilles *would* send for each case and checks
whether the case's declared `evidenceLines` — the lines a triager must see to
decide correctly — are actually in it. It answers *"did we give the model what it
needed?"*, runs in CI, and gates on regressions.

**Verdict mode** runs the real triage→judge path against a live model and scores
the verdicts against the labels. It answers *"did the model get the right
answer?"* It reports two things, and they are different questions:

- **Did the review confirm the right findings?** Balanced accuracy, TP recall and FP
  suppression are scored on `Verdict.Surfaced()`: an unrefuted `true_positive` at
  ≥ 0.7, or a false positive the judge overturned. "FP suppression" here means *not
  confirmed*.
- **What did the product do with each finding?** A finding that is not confirmed is
  not necessarily removed: one the review left uncertain, or the judge disputed
  without backing, stays in the report and in the `--fail-on` gate. The report
  therefore also prints a three-way table per ground-truth class (confirmed / kept,
  unverified / dismissed) with the two numbers a user feels: the share of genuine
  issues **dismissed** (the costly error) and the share of safe findings
  **dismissed** (the noise actually removed).

The first set alone flatters a cautious model: one that answers "uncertain" to
everything scores 100% FP suppression while removing nothing from anyone's report.
Read both. The measurements recorded below predate the second table and the
current prompt version, so they are confirmation scores only.

Keep the two straight: context mode can improve while verdict mode does not.
That gap is information, not a contradiction.

**Corpus mode** validates the corpus itself. Each case claims something about an
external tool — "gosec reports G701 on this file" — and nothing checked those claims
until it existed. It runs each case's tool on each case's fixture and compares. This
is a *self-check on the ground truth*, not a measurement of Achilles.

It exists because a wrong claim is close to invisible: three cases said `G201` where
gosec emits `G701`, and that survived four merged changes because verdict mode only
passes the rule id through as prompt text, so a wrong id still yields a plausible
prompt and a plausible score. It surfaced only when the scanner-based fix check began
reporting "unknown" for a third of runs.

A case it cannot check is **skipped, never passed** — a missing scanner is an
environment gap, not a corpus defect, so this mode stays runnable on a machine with
neither gosec nor bandit. It is not wired into CI for that reason; CI has no scanners
and would skip every case, reporting a green that means nothing.

## The corpus

[`triage/corpus.yaml`](triage/corpus.yaml) — 18 cases, 9 `tp` / 9 `fp`, over real
source files in `triage/testdata/`.

The **FP half is the point**. A triager that answers "true_positive" to everything
scores 100% on a TP-only corpus and 50% balanced accuracy here, which is why
balanced accuracy is the headline metric rather than raw accuracy.

An FP case must be a finding the scanner **actually emits**. Safe code the tool
stays quiet about is not a false positive — it is the tool being right, there is
nothing for the pipeline to suppress, and no LLM call is saved by suppressing it.
Four cases got this wrong for four merged changes; `make eval-corpus` now refuses
to let it happen again. Write an FP as *code the scanner flags because it cannot
model the mitigation* — an allowlist check, a bounds check, containment by prefix
— not as code that merely looks alarming.

Fixtures live under `testdata/` deliberately: the Go tool skips such directories,
so deliberately-vulnerable Go fixtures can never be built or shipped. gosec does
*not* skip them, so the self-scan workflow passes `--exclude evals` — without it
the corpus reports ~11 high-severity findings and gates its own repo.

## Adding a case

1. Write the fixture under `triage/testdata/`. Make it realistic: the deciding
   evidence should sit at a plausible distance from the finding, because a
   fixture where everything fits in three lines cannot measure context at all.
   **Comments may describe what the code does; they must not state the verdict.**
   The first version of this corpus violated that — every FP fixture carried a
   comment like *"Nothing here is a security decision: the digest is never compared
   against a secret"*, i.e. the ground-truth rationale written into the model's
   input. It scored 100%, and the suspicion was that the prose was doing the work.
   **That was tested and refuted:** rewriting all 14 fixtures with neutral comments
   changed no verdict at all (still 14/14; mean confidence 0.98 → 0.97). So the rule
   stands on principle rather than on measured effect — the leak would invalidate a
   score whether or not it did here. Write `why` in the manifest (never sent to a
   model) and keep fixture comments neutral.
2. Add the manifest entry: `id`, `fixture`, `label`, `why`, the `finding` a real
   scanner would report, and `evidenceLines`.
3. Run `make eval-context`. Loading **validates every line number against the
   file**, so a stale entry fails loudly instead of silently scoring the wrong
   span.
4. If the change is an intentional context change, refresh the committed baseline
   with `make eval-baseline` and say why in the commit.

`why` is required. A label nobody can review is not ground truth, and it is
printed next to every wrong answer so a failure is diagnosable without opening
the fixture.

## Comparing runs

Both modes write JSON with `--out` and diff against a previous run with
`--baseline`:

```bash
achilles-eval --mode context --out after.json --baseline before.json
```

A metric with no baseline proves nothing, so this is the normal way to use the
harness — not an afterthought.

## Known limits

- **The corpus found a real defect, and it is now fixed.** An earlier routing on a
  hosted frontier-model API (a small, cheap triage model with a stronger judge; no
  longer in this repo) scored **94.4% balanced accuracy / 88.9% TP recall**:
  `go-trap-md5-auth-compare` came back `false_positive` at 0.95 confidence,
  consistently — a **missed vulnerability**. Three experiments, in order:
  1. Adding the missing evidence (call sites + file-scope declarations) took
     coverage from 11/18 to **18/18** and changed **no verdict**. Necessary, not
     sufficient.
  2. Routing triage to the stronger of the two models — same prompt, same judge — scored
     **100%/100%** with 1% fewer tokens. So the cause was triage-model capability.
  3. Making the judge **bidirectional** scored **100%/100% on the cheap routing**,
     because the stronger judge model already ran on every finding and its
     disagreement was being discarded. That is what shipped (DESIGN §7).
- **The Ollama judge seat was screened four ways, and fixed.** Triage held fixed at
  `minimax-m2.7`, 18 cases x 3 repeats each. The **routed** pairing was re-run on the
  corrected corpus on 2026-08-10 and its row is exact; the three runner-up rows are
  still the pre-2026-08-05 measurement (`screens/*.json`), where four FP cases
  described findings gosec does not emit — their ranking is sound, since it turned on
  judge behaviour rather than on those cases, but their absolute numbers are not
  restated:

  | judge | bal.acc | recall | suppr | refutes correct TPs | unstable |
  |---|---|---|---|---|---|
  | `kimi-k2.6` (was shipped) | 66.7% | 33.3% | 100% | 74% | 6 |
  | `minimax-m2.7` | 88.9% | 88.9% | 88.9% | 15% | 6 |
  | **`minimax-m3`** (routed, re-measured) | **94.4%** | 88.9% | 100% | 11% | 4 |
  | `deepseek-v4-pro` | 77.8% | 77.8% | 77.8% | 26% | 7 |

  `kimi-k2.6` was not weak, it was **biased**: it refuted 74% of *correct*
  true_positive verdicts and only 7% of false_positive ones, deleting 6 of 9 true
  positives while its 100% FP suppression made it look healthy. Triage had been
  right 27/27 the whole time.
- **Re-running Ollama on the corrected corpus changed nothing.** 94.4% / 88.9% /
  100%, 4 unstable, calibration gap 0.04 — every headline identical, so the routing
  decision stands and the 100% suppression now covers 9 real FP cases instead of 5.
  Same single miss (`go-rand-session-token`: triage says true_positive, the judge
  refutes, so it is never surfaced), and `refutes-correct-TPs` improved 15% → 11%.
  Unstable stayed at 4 but the *set* shifted, and only one rewritten case joined it —
  the harder FP fixtures did not concentrate the instability.
  **One number moved and it is not a result:** prompt tokens read 41.9k before and
  15.6k now, for an identical 108 calls and slightly *longer* prompts. That is
  provider-side accounting, not an efficiency gain, and it is recorded here so nobody
  cites it as one. Completion tokens went 76k → 83k, ordinary variance for a
  reasoning model.
- **`refutes-correct-TPs` is the cheap screening metric for a judge.** It predicted
  recall across all four candidates (74%→33%, 26%→78%, 15%→89%). Use it when adding
  a candidate rather than running a full comparison first.
- **A model listed in the API is not a model you can call.** `kimi-k3` appears in
  `/v1/models` but the account used for these runs was not entitled to call it (every
  request was refused), so it is **unmeasured**, not bad. Probe entitlement with one real request before
  committing a 70-minute run — this applies to any provider whose model listing is
  broader than your entitlement.
- **Ollama trailed that hosted routing even at 94.4%** — on accuracy, on stability (4
  of 18 cases flip across repeats vs 0), and on tokens (~7x). Choose it for data
  residency or cost, not because it is better.
- **Scoring a model does not tell you how it behaves in a SEAT.** The 2026-07-13
  bake-off gave both models ~92% by running each as the *default* model across the
  whole path; it never scored one in the judge seat specifically. Judging is a
  different task from triaging, and a strong triager can be a pathological judge.
  When routing changes, measure the pairing.
- **The same model drifts across JSON shapes run to run.** `kimi-k2.6` on one fixed
  prompt emitted the STRIDE category three different ways across three runs —
  `"category":"…"`, `"stride":"…"`, and `"categories":["…"]` (plural key AND an array
  where the schema declares a scalar) — and in a fourth run omitted the field
  entirely. `Threat.UnmarshalJSON` now accepts the alias shapes; outright omission is
  a model defect the screen correctly reports as an invalid enum. Expect shape drift
  from open models and decode defensively rather than assuming one response proves a
  format.
- **Open models emit ~25x the completion tokens.** 257k vs ~10k for the same corpus
  — reasoning-model chain-of-thought. Budget latency and cost accordingly; `--repeat
  3` took ~70 minutes.
- **Watch FP suppression, not just recall, after the judge change.** Overturning is
  a new way to *add* noise, and 9 FP cases cannot prove the rate did not rise a
  little: suppression held at 100% here, but that is 9 cases. Overturned findings
  are marked distinctly in every report format and never trigger remediation, so
  they are auditable — check the ratio on a real scan before trusting it broadly.
- **Every case's metadata is now derived from the tool, and `make eval-corpus`
  enforces it.** This was not true until 2026-08-05: four FP cases described gosec
  findings gosec does not emit (it resolves constants and recognizes
  `filepath.Clean` containment, so it reported *nothing* on them — its correct
  negatives, not its false positives), and twelve more had a drifted `line`,
  `severity`, or `message`. The FP fixtures were rewritten into patterns gosec
  genuinely over-reports, and re-measuring produced **the same 100%/100%/100%/0** on
  the hosted routing. The score did not move; what it means did. Before, FP
  suppression was computed with 4 of 9 cases contributing findings that never occur.
- **18 cases is small.** It catches gross regressions and obvious wins; it cannot
  resolve a two-point difference between models.
- **There is no held-out set.** The routing and the prompt revisions below were
  chosen on the same 18 cases their scores are reported on, so those scores are
  optimistic by an unknown amount. Treat them as "this configuration is not broken",
  not as an estimate of accuracy on your code.
- **Verdict mode costs money and is nondeterministic.** Use `--repeat 3` or more
  before believing a small delta; the report flags cases whose repeats disagreed
  rather than averaging the instability away.
- **Context mode measures availability, not comprehension.** Evidence being in
  the prompt does not prove the model used it. Only verdict mode can say that.
