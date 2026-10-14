# Benchmarking detection

Achilles has two measurements, and they answer different questions:

| Benchmark | Question | Needs |
|---|---|---|
| Triage eval (`evals/triage`, `--mode context\|verdict`) | Given a finding, does the AI layer judge it correctly? | a model (verdict) or nothing (context) |
| **Detection benchmark** (`evals/detect`, `--mode detect`) | Of the vulnerabilities that are really in this code, how many does a scan report — and for the ones it misses, where were they lost? | the real scanners; a model only with `--ai` / `--judge` |

A vulnerability that no scanner reports never reaches triage, so a strong triage
score says nothing about it. Detection recall is the number that bounds everything
downstream. The approach — a labeled corpus of known vulnerabilities, deterministic
matching with an optional model judge, and loss-point analysis of the misses — is
adapted from the open-source VulnHunter project's benchmark harness; the schema,
matcher and prompts here are our own.

## Running it

```bash
make eval-detect                                    # scorecard on the committed fixtures
make eval-detect-gate                               # same, exit non-zero if recall regressed
make eval-detect DETECT_ARGS="--out evals/detect/baseline.json"   # refresh the baseline
```

Both targets build `bin/achilles` first and benchmark that binary. They are **not**
part of CI: they need the real scanners on `PATH` (`opengrep`, `gosec`, `gitleaks`,
`osv-scanner`, and `trivy` for the default registry), and `osv-scanner` queries the
OSV database over the network.

Directly:

```bash
go run ./cmd/achilles-eval --mode detect --verbose \
    --out run.json --markdown run.md \
    --baseline evals/detect/baseline.json --fail-on-regression
```

| Flag | Meaning |
|---|---|
| `--ground-truth PATH` | A target file or a directory of them (default `evals/detect/ground_truth`). `*.example.json` files are skipped in a directory. |
| `--detect-target a,b` | Run only these target ids. |
| `--achilles-bin PATH` | The binary to benchmark. Default: `./bin/achilles`, then `achilles` on `PATH`, else built from `./cmd/achilles` into the cache dir. |
| `--cache-dir DIR` | Where git targets are checked out (default `.achilles/detect-cache`). |
| `--line-tolerance N` | Lines a finding may sit outside a labeled range (default 3). |
| `--exclude`, `--no-default-excludes`, `--diff`, `--scan-baseline`, `--scan-config` | Passed to `achilles`, and understood by the loss-point analysis (a drop caused by them is named). |
| `--scan-arg ARG` | Any other `achilles` flag, repeatable. The analysis does not know what it does. |
| `--scan-timeout D` | Per-scan timeout (default 20m). |
| `--ai` | Also score the AI-reviewed result (see below). Needs `--llm-model` or `--model-config`, and a key; takes `--llm-base-url`, `--llm-provider`, `--llm-auth`, `--llm-judge-model`, `--llm-no-code`. |
| `--judge` | Let a model adjudicate same-place findings whose class/CWE disagrees. Reported separately; never use it in a gate. |
| `--repeat N` | Run the benchmark N times and report which entries flap. |
| `--out FILE` / `--markdown FILE` | Write the JSON scorecard / a Markdown report. `--out` carries run history forward from the file it overwrites when the configuration is unchanged (`--no-history` to skip). |
| `--baseline FILE` | Compare against an earlier JSON scorecard. |
| `--fail-on-regression` | With `--baseline`: exit non-zero if overall or any class's recall dropped by more than `--regression-tolerance` (default 0.02, i.e. 2 points). Entry flips are printed but do not fail the gate by themselves: scanners and advisory data move. |
| `--require-complete` | Exit non-zero if any scanner failed or was missing on any target. |

## Reading the scorecard

**Recall** is detected / scored entries. Entries whose label does not fit the
checkout (file missing, line past the end) are `invalid` and left out, not counted
as misses.

**Incomplete** means a scanner failed or was not installed on that target. The
recall there is a lower bound on what the scanners can do, not a measurement of
their reach. A missing scanner is a loss point (`tool-missing`) so an environment
gap cannot pass as a clean miss. On a machine without `trivy`, every target is
incomplete under the default registry; install it, or pass `--scan-config` with a
registry of the tools you actually run.

**Loss points** (the `lossPoints` histogram and the trace under each miss) say where
a miss was lost. They are derived from the scan's own artifacts, not from a
re-implementation of the pipeline:

- the SARIF report says what survived, and what the AI review suppressed;
- the Evidence Vault says which scanners produced output, which failed (the
  diagnostics record), every finding **before** the noise/baseline/diff filters,
  and the AI verdicts with their reasoning.

| If the loss point is... | the fix is probably... |
|---|---|
| `not-detected` | a rule: no scanner that covers this class reported anything nearby |
| `no-coverage` | a scanner: nothing that ran covers this language/class |
| `tool-missing` / `scan-incomplete` | the environment, before reading anything into the number |
| `class-mismatch` / `line-mismatch` | the label or the rule's metadata (try `--judge` to see which) |
| `noise-filter` | decide whether that path should be in scope; adjust `--exclude` or the label |
| `ai-dismissed` | the triage prompt, context or model: the trace has the verdict and its reasoning |

**Precision proxy.** The benchmark labels known vulnerabilities, not every line of
code, so a finding outside the labels is *unlabeled*, not a false positive. The
scorecard reports findings that matched a label, findings in labeled files that
matched none, and findings in files with no label. Use the triage eval for false-
positive behavior.

**With `--ai`** each target is scanned twice: with `--keep-dismissed` (what the
scanners found, verdicts attached) and without (what the AI review let through).
Recall is scored on the second; the first is reported beside it, and the gap is what
the AI review cost. It is real model spend, twice per target.

## The committed baseline

`evals/detect/baseline.json` was generated on the maintainer's machine with all five
default scanners installed (`opengrep`, `gosec`, `gitleaks`, `osv-scanner`, `trivy`)
and **`--mode commercial`**, so only the built-in Achilles rules were loaded, not the
community pack (3 runs; no entry flapped):

| | Recall |
|---|---|
| **Overall** | **91.7%** (22 of 24) |
| injection | 87.5% (7 of 8) |
| hardcoded-secret | 100% (5 of 5) |
| path-traversal, ssrf, weak-crypto, vulnerable-dependency | 100% (2 of 2 each) |
| xss, deserialization | 100% (1 of 1 each) |
| authz | 0% (0 of 1) |

| Target | Recall |
|---|---|
| go-service | 100% (6 of 6) |
| deps-manifest | 100% (2 of 2) |
| secrets-config | 100% (3 of 3) |
| py-webapp | 88% (7 of 8) |
| js-express | 80% (4 of 5) |

Loss points of the 2 misses: `not-detected` 1 (`JS-IDOR-1`), `noise-filter` 1
(`PY-THIRDPARTY-EVAL-1`).

The previous baseline, with only three built-in rules, was 45.8% (11 of 24); the
community pack took it to 75%. The rules in `configs/rules/achilles-*.yaml` account
for the difference, and every finding they added is on a labeled issue: the count of
findings in labeled files that matched no label did not grow. The scan surfaces 61
findings: 37 on a labeled issue and 24 elsewhere in the labeled files (unlabeled, not
necessarily false; see the precision proxy above). Before Achilles dropped repeated
scanner results (osv-scanner reports some advisories several times) and the two
credential rules were tightened, the same scan counted 85.

How to read it honestly:

- **The new rules were written with these fixtures in view.** They target the
  vulnerability classes in the fixtures, and the rule tests
  (`internal/config/testdata/rules/`) hold their own true and false cases, but a
  benchmark the rules were tuned on overstates what they catch elsewhere. Treat 91.7%
  as "the classes in the benchmark are covered", not as an estimate of real-world
  recall; external targets (below) are the stronger evidence.
- **The `noise-filter` miss is deliberate**: a `third_party/` file the default noise
  filter drops, kept to exercise that loss point.
- **`JS-IDOR-1` is a business-logic flaw** (no ownership check) that no pattern
  scanner is expected to find. The AI review and the research agents are the parts
  of Achilles that can.
- **24 entries is small.** One entry is 4.2 points, which is why the gate tolerance
  is 2 points: any lost entry fails it. It catches regressions in rules and tool
  wiring; it cannot rank two scanners that differ by a few points.
- The fixtures were written and labeled **before** looking at scanner output, but
  by the people who maintain the scanners.
- `deps-manifest` depends on live OSV advisory data. The two labeled advisories are
  long-standing, but a future database change could still move that target.

## External targets

Point the benchmark at pinned commits of public intentionally-vulnerable apps (OWASP
Juice Shop, NodeGoat, WebGoat) with `evals/detect/ground_truth/external.example.json`
as the template. The example carries no real commit SHA and the runner refuses it,
with instructions, until you pin one and verify every label against that commit. See
`evals/detect/README.md` for the steps.

## Ideas this does not do

- It does not label false positives; see the triage eval.
- It scores one finding to one label by location. It does not do taint-path
  matching, and it does not try to credit a scanner for finding "the same bug via a
  different sink".
- The loss-point analysis can only say what the scan's artifacts record. Flags it
  does not know about (`--scan-arg`) are reported as `dropped-unknown`, not guessed.
